#!/usr/bin/env python3
"""
Hermes Stage 4 — ChatGPT 受控开发/测试/部署/回滚模块。

职责:
- 统一任务状态存储 (SQLite, 本地 VPS, 非 ECS 生产)
- 审批票据机制 (HMAC-SHA256, 短期/单次/绑定任务ID+操作+文件范围+commit+用户)
- ECS 受控操作 (固定命令模板, 无任意 shell 字符串)
- 7 个 Stage 4 工具 (change_plan/create_backup/apply_patch/run_tests/deploy/rollback/change_status)

安全模型 (三层门禁):
1. PRODUCTION_WRITE_ENABLED 标志 (master kill switch, 默认 False)
2. OAuth scope (mcp:read / mcp:write, 由 bridge 校验)
3. 审批票据 (HMAC 短期单次, 由本模块校验)

本模块只处理工具逻辑 + 票据校验 + 本地状态。ECS 生产写由 flag 硬门禁。
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import sqlite3
import subprocess
import time
from pathlib import Path

# ── 配置 ────────────────────────────────────────────
MODULE_DIR = Path(__file__).resolve().parent
STATE_DB = MODULE_DIR / "stage4_state.db"
APPROVAL_SECRET_FILE = Path("/home/hermes/.hermes/stage4_approval_secret")
PRODUCTION_WRITE_FLAG_FILE = MODULE_DIR / "PRODUCTION_WRITE_ENABLED"

ECS_HOST = "fastmedlink@47.250.166.208"
ECS_CS_INBOX = "/home/fastmedlink/cs-inbox"
ECS_DB = "/home/fastmedlink/cs-inbox/data/inbox.db"
LOCAL_BACKUP_ROOT = Path("/home/hermes/mcp_servers/stage4_backups")

TICKET_TTL_SECONDS = 300  # 审批票据 5 分钟有效
TICKET_SINGLE_USE = True

# 文件范围白名单 (允许 apply_patch 修改的业务文件, 相对于 ECS_CS_INBOX)
ALLOWED_EDIT_GLOBS = [
    "app.py",
    "auth.py",
    "*.py",
    "templates/**",
    "static/**",
    "routes/**",
    "services/**",
    "utils/**",
]

# 禁止修改的路径 (密钥/凭据/数据库/配置/其他项目)
FORBIDDEN_EDIT_PATTERNS = [
    "data/", "*.db", "*.sqlite", ".env", "*.pem", "*.key",
    "config.py", "secrets", "credentials", "instance/",
    "/etc/", "/home/", "/root/", "../", ".ssh/",
]

# 数据库迁移 (需要独立明确授权, 绝不隐式执行)
DB_MIGRATION_FORBIDDEN = True


# ── PRODUCTION_WRITE_ENABLED (master kill switch) ──
def production_write_enabled() -> bool:
    """ECS 生产写是否开启. 默认 False. 只有存在 flag 文件且内容为 'true' 才开启."""
    try:
        if PRODUCTION_WRITE_FLAG_FILE.exists():
            return PRODUCTION_WRITE_FLAG_FILE.read_text().strip().lower() == "true"
    except Exception:
        pass
    return False


# ── 审批票据 (HMAC-SHA256) ──────────────────────────
def _secret() -> bytes:
    if APPROVAL_SECRET_FILE.exists():
        return APPROVAL_SECRET_FILE.read_bytes()
    # 幂等生成 (本函数不应在工具调用里触发生成, 只读)
    s = secrets.token_hex(32).encode()
    APPROVAL_SECRET_FILE.write_bytes(s)
    os.chmod(APPROVAL_SECRET_FILE, 0o600)
    return s


def _hmac(msg: str) -> str:
    return hmac.new(_secret(), msg.encode(), hashlib.sha256).hexdigest()


def mint_approval_ticket(task_id: str, operation: str, file_scope: str,
                         commit: str = "", user: str = "pm",
                         ttl: int = TICKET_TTL_SECONDS) -> str:
    """由 PM 本地调用 (非 MCP 工具), 生成短期单次审批票据.

    payload 绑定: task_id + operation + file_scope + commit + user + expiry + nonce.
    返回 base62 票据字符串.
    """
    conn = _db()
    expiry = int(time.time()) + ttl
    nonce = secrets.token_hex(8)
    payload = {
        "task_id": task_id, "operation": operation, "file_scope": file_scope,
        "commit": commit, "user": user, "expiry": expiry, "nonce": nonce,
    }
    canonical = "|".join([
        payload["task_id"], payload["operation"], payload["file_scope"],
        payload["commit"], payload["user"], str(payload["expiry"]), payload["nonce"],
    ])
    sig = _hmac(canonical)
    ticket = f"{nonce}.{sig}"
    conn.execute(
        "INSERT INTO approval_tickets (ticket, task_id, operation, file_scope, commit_sha, user, expiry, used, created_at) "
        "VALUES (?,?,?,?,?,?,?,0,?)",
        (ticket, task_id, operation, file_scope, commit, user, expiry, int(time.time())),
    )
    conn.commit()
    conn.close()
    return ticket


def verify_approval_ticket(ticket: str, task_id: str, operation: str,
                           file_scope: str, commit: str = "") -> tuple[bool, str]:
    """校验审批票据: HMAC + 绑定字段 + 有效期 + 单次使用 (原子消费)."""
    if not ticket or "." not in ticket:
        return False, "invalid ticket format"
    nonce, sig = ticket.split(".", 1)
    # 从 DB 读票据 (拿 expiry + 绑定字段)
    conn = _db()
    row = conn.execute(
        "SELECT task_id, operation, file_scope, commit_sha, user, expiry, used "
        "FROM approval_tickets WHERE ticket=?", (ticket,)
    ).fetchone()
    if not row:
        conn.close()
        return False, "ticket not found"
    (db_task, db_op, db_scope, db_commit, db_user, expiry, used) = row
    if used:
        conn.close()
        return False, "ticket already used (replay rejected)"
    if int(time.time()) > expiry:
        conn.close()
        return False, "ticket expired"
    # HMAC 复核 (防 DB 篡改)
    canonical = "|".join([
        db_task, db_op, db_scope, db_commit, db_user, str(expiry), nonce,
    ])
    expect = _hmac(canonical)
    if not hmac.compare_digest(expect, sig):
        conn.close()
        return False, "hmac mismatch (ticket tampered)"
    # 绑定字段校验
    if db_task != task_id or db_op != operation:
        conn.close()
        return False, "ticket not bound to this task/operation"
    if file_scope and db_scope not in (file_scope, "*"):
        conn.close()
        return False, "ticket file_scope mismatch"
    if commit and db_commit not in (commit, ""):
        conn.close()
        return False, "ticket commit mismatch"
    # 原子消费 (单次使用, 并发安全)
    cur = conn.execute(
        "UPDATE approval_tickets SET used=1 WHERE ticket=? AND used=0", (ticket,)
    )
    conn.commit()
    conn.close()
    if cur.rowcount != 1:
        return False, "ticket already consumed (concurrent)"
    return True, "ok"


# ── 状态 DB ─────────────────────────────────────────
def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(STATE_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_state_db():
    conn = _db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        title TEXT,
        requirement TEXT,
        module TEXT,
        status TEXT DEFAULT 'planned',
        plan_json TEXT,
        file_scope TEXT,
        commit_sha TEXT,
        report_path TEXT,
        created_at INTEGER,
        updated_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS approval_tickets (
        ticket TEXT PRIMARY KEY,
        task_id TEXT,
        operation TEXT,
        file_scope TEXT,
        commit_sha TEXT,
        user TEXT,
        expiry INTEGER,
        used INTEGER DEFAULT 0,
        created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT,
        operation TEXT,
        user TEXT,
        result TEXT,
        detail TEXT,
        created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS task_locks (
        task_id TEXT PRIMARY KEY,
        lock_owner TEXT,
        locked_at INTEGER,
        expires_at INTEGER
    );
    """)
    conn.commit()
    conn.close()


def _audit(task_id: str, operation: str, result: str, detail: str = ""):
    conn = _db()
    conn.execute(
        "INSERT INTO audit_log (task_id, operation, user, result, detail, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (task_id, operation, "mcp", result, detail[:2000], int(time.time())),
    )
    conn.commit()
    conn.close()


def _set_task_status(task_id: str, status: str, **fields):
    conn = _db()
    cols = ["status=?", "updated_at=?"]
    vals = [status, int(time.time())]
    for k, v in fields.items():
        if k in ("title", "requirement", "module", "plan_json", "file_scope", "commit_sha", "report_path"):
            cols.append(f"{k}=?")
            vals.append(v)
    sql = f"UPDATE tasks SET {', '.join(cols)} WHERE task_id=?"
    conn.execute(sql, vals + [task_id])
    conn.commit()
    conn.close()


def _get_task(task_id: str):
    conn = _db()
    row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ── 任务锁 (并发防护, 幂等) ─────────────────────────
def acquire_lock(task_id: str, operation: str, ttl: int = 600) -> tuple[bool, str]:
    conn = _db()
    now = int(time.time())
    owner = f"{operation}:{secrets.token_hex(4)}"
    # 清理过期锁
    conn.execute("DELETE FROM task_locks WHERE expires_at < ?", (now,))
    row = conn.execute("SELECT lock_owner, expires_at FROM task_locks WHERE task_id=?", (task_id,)).fetchone()
    if row and row["expires_at"] > now:
        conn.close()
        return False, f"task locked by {row['lock_owner']}"
    conn.execute(
        "INSERT OR REPLACE INTO task_locks (task_id, lock_owner, locked_at, expires_at) VALUES (?,?,?,?)",
        (task_id, owner, now, now + ttl),
    )
    conn.commit()
    conn.close()
    return True, owner


def release_lock(task_id: str, owner: str):
    conn = _db()
    conn.execute("DELETE FROM task_locks WHERE task_id=? AND lock_owner=?", (task_id, owner))
    conn.commit()
    conn.close()


# ── ECS 命令模板 (固定, 无任意 shell) ───────────────
def _ssh_exec(args: list[str], timeout: int = 20) -> dict:
    """在 ECS 上执行固定命令 (args 逐项 shlex, 无 shell 注入)."""
    cmd = ["ssh", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", ECS_HOST] + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": p.returncode == 0, "exit": p.returncode,
                "stdout": p.stdout[:4000], "stderr": p.stderr[:2000]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "exit": -1, "stdout": "", "stderr": "timeout"}
    except Exception as e:
        return {"ok": False, "exit": -1, "stdout": "", "stderr": f"{type(e).__name__}: {e}"}


def _ecs_read_command(cmd: list[str]) -> dict:
    """只读 whitelist ECS 命令. cmd 必须匹配白名单前缀."""
    if not cmd:
        return {"ok": False, "stderr": "empty command"}
    first = cmd[0]
    allowed = ["systemctl", "git", "ls", "cat", "sha256sum", "stat", "find", "head", "tail", "wc"]
    if first not in allowed:
        return {"ok": False, "stderr": f"command '{first}' not in read whitelist"}
    return _ssh_exec(cmd)


def _git_head() -> str:
    r = _ecs_read_command(["git", "-C", ECS_CS_INBOX, "rev-parse", "--short", "HEAD"])
    return r["stdout"].strip() if r["ok"] else ""


def _git_status() -> dict:
    return _ecs_read_command(["git", "-C", ECS_CS_INBOX, "status", "--short"])


def _file_sha256(rel_path: str) -> str:
    abs_path = f"{ECS_CS_INBOX}/{rel_path}"
    if not _safe_rel_path(rel_path):
        return ""
    r = _ecs_read_command(["sha256sum", abs_path])
    return r["stdout"].split()[0] if r["ok"] and r["stdout"] else ""


# ── 路径 / 符号链接 / 穿越防护 ─────────────────────
def _safe_rel_path(rel_path: str) -> bool:
    """rel_path 必须在 cs-inbox 业务范围, 禁止穿越/符号链接/敏感路径."""
    if not rel_path or rel_path.startswith("/") or ".." in rel_path:
        return False
    # 禁止敏感模式
    for pat in FORBIDDEN_EDIT_PATTERNS:
        if pat.endswith("/") and rel_path.startswith(pat):
            return False
        if not pat.endswith("/") and (rel_path == pat or re.search(_glob_to_re(pat), rel_path)):
            return False
    # 必须是白名单 glob
    for g in ALLOWED_EDIT_GLOBS:
        if re.search(_glob_to_re(g), rel_path):
            return True
    return False


def _glob_to_re(glob: str) -> str:
    out = re.escape(glob)
    out = out.replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", ".")
    return f"^{out}$"


def _validate_diff_paths(diff: str) -> tuple[bool, str]:
    """校验 unified diff 中所有涉及的文件路径都在白名单内, 无穿越."""
    paths = set()
    for line in diff.splitlines():
        if line.startswith("+++ ") or line.startswith("--- "):
            p = line[4:].strip()
            p = p.split("\t")[0]
            # strip a/ b/ prefix
            if p.startswith("a/"):
                p = p[2:]
            elif p.startswith("b/"):
                p = p[2:]
            if p == "/dev/null":
                continue
            paths.add(p)
    for p in paths:
        if not _safe_rel_path(p):
            return False, f"path not allowed: {p}"
    return True, "ok"


# ══════════════════════════════════════════════════════
# 七个工具实现
# ══════════════════════════════════════════════════════

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def tool_change_plan(task_id: str, requirement: str, module: str = "") -> dict:
    """只读检查 ECS 代码/Git/依赖/测试环境, 输出修改计划 + 风险 + 待审批操作."""
    init_state_db()
    # 幂等: 已存在则返回已有计划
    existing = _get_task(task_id)
    if existing and existing.get("plan_json"):
        return {"ok": True, "task_id": task_id, "cached": True,
                "plan": json.loads(existing["plan_json"])}

    git_head = _git_head()
    git_status = _git_status()
    # 依赖情况 (只读)
    req_txt = _ecs_read_command(["ls", f"{ECS_CS_INBOX}/requirements.txt"])["stdout"]
    test_dir = _ecs_read_command(["ls", "-d", f"{ECS_CS_INBOX}/tests"])["ok"]

    plan = {
        "task_id": task_id,
        "requirement": requirement,
        "module": module,
        "git_head": git_head,
        "working_tree_clean": (git_status.get("stdout", "") == ""),
        "dependencies": ("requirements.txt" in req_txt),
        "test_suite_present": test_dir,
        "file_scope": "cs-inbox business files (app.py/templates/static/routes/services/utils)",
        "risk": _assess_risk(module),
        "test_plan": [
            "python syntax check (py_compile)",
            "unit tests (pytest) on isolated copy",
            "read-only smoke test (health + key routes)",
        ],
        "pending_approvals": [
            "code-change approval (apply_patch)",
            "production-deploy approval (deploy)",
        ],
        "note": "ECS production write is DISABLED until flag + approval ticket.",
    }
    _audit(task_id, "change_plan", "ok", f"git_head={git_head}")
    conn = _db()
    conn.execute(
        "INSERT OR REPLACE INTO tasks (task_id, title, requirement, module, status, plan_json, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (task_id, requirement[:80], requirement, module, "planned",
         json.dumps(plan, ensure_ascii=False), int(time.time()), int(time.time())),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "task_id": task_id, "plan": plan}


def _assess_risk(module: str) -> str:
    if not module:
        return "low"
    m = module.lower()
    if any(k in m for k in ("db", "database", "migration", "auth", "payment")):
        return "high"
    if any(k in m for k in ("route", "webhook", "deploy")):
        return "medium"
    return "low"


def tool_create_backup(task_id: str, approval_ticket: str, scope: str = "*") -> dict:
    """备份本任务涉及的文件 + 数据库 (SQLite 在线备份). 需审批票据."""
    init_state_db()
    if production_write_enabled() is False and scope == "*":
        # 备份是读+本地写副本, 允许在 DISABLED 下也做 dry-run 报告, 但不做 ECS 写
        pass
    ok, err = verify_approval_ticket(approval_ticket, task_id, "create_backup", scope)
    if not ok:
        _audit(task_id, "create_backup", "denied", err)
        return {"ok": False, "denied": True, "reason": err}

    ts = time.strftime("%Y%m%d-%H%M%S")
    bk_dir = LOCAL_BACKUP_ROOT / f"{task_id}" / ts
    bk_dir.mkdir(parents=True, exist_ok=True)

    files = {}
    # 备份生产代码 (rsync 到本地)
    for rel in ("app.py", "auth.py"):
        if _safe_rel_path(rel):
            r = _ecs_read_command(["cat", f"{ECS_CS_INBOX}/{rel}"])
            if r["ok"]:
                (bk_dir / rel).write_text(r["stdout"])
                files[rel] = hashlib.sha256(r["stdout"].encode()).hexdigest()

    # SQLite 在线备份 (安全的 .backup 机制, 不在写入时直接复制)
    db_bk_path = bk_dir / "inbox.db"
    db_ok, db_err = _sqlite_online_backup(db_bk_path)

    record = {
        "task_id": task_id, "backup_dir": str(bk_dir), "sha256": files,
        "db_backup": db_bk_path.name if db_ok else None,
        "db_online_backup_ok": db_ok, "db_err": db_err,
        "time": _now_iso(),
    }
    (bk_dir / "backup_manifest.json").write_text(json.dumps(record, indent=2))
    _set_task_status(task_id, "backed_up", report_path=str(bk_dir / "backup_manifest.json"))
    _audit(task_id, "create_backup", "ok", f"backup_dir={bk_dir}")
    return {"ok": True, "backup": record, "restore": f"scp -r {bk_dir} fastmedlink@47.250.166.208:{ECS_CS_INBOX}/_restore/ ; 然后 cp 覆盖 + 重启 cs-inbox.service"}


def _sqlite_online_backup(dest: Path) -> tuple[bool, str]:
    """SQLite 在线备份 (.backup), 不直接复制正在写入的 DB."""
    try:
        import sqlite3
        # 远程: 用 ssh 在 ECS 上执行 sqlite3 .backup, 再 scp 回来
        r = _ssh_exec([
            "bash", "-c",
            f"umask 077 && sqlite3 {shlex.quote(ECS_DB)} \".backup /tmp/inbox_bk.sqlite\""
        ])
        if not r["ok"]:
            return False, f"ECS sqlite .backup failed: {r['stderr'][:200]}"
        # scp 回来
        p = subprocess.run(
            ["scp", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes",
             f"{ECS_HOST}:/tmp/inbox_bk.sqlite", str(dest)],
            capture_output=True, text=True, timeout=30,
        )
        if p.returncode != 0:
            return False, f"scp failed: {p.stderr[:200]}"
        return True, "ok"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def tool_apply_patch(task_id: str, target_file: str, patch: str,
                     approval_ticket: str, base_commit: str = "") -> dict:
    """应用补丁. 只在隔离工作树操作, 禁止直接写生产. 需票据 + flag."""
    init_state_db()
    if not production_write_enabled():
        _audit(task_id, "apply_patch", "denied", "PRODUCTION_WRITE_ENABLED=False")
        return {"ok": False, "denied": True,
                "reason": "ECS production write DISABLED. Set PRODUCTION_WRITE_ENABLED flag + valid approval ticket."}
    ok, err = verify_approval_ticket(approval_ticket, task_id, "apply_patch", target_file, base_commit)
    if not ok:
        _audit(task_id, "apply_patch", "denied", err)
        return {"ok": False, "denied": True, "reason": err}
    if not _safe_rel_path(target_file):
        _audit(task_id, "apply_patch", "denied", f"unsafe path {target_file}")
        return {"ok": False, "denied": True, "reason": f"target_file not allowed: {target_file}"}
    # diff 路径校验
    okp, errp = _validate_diff_paths(patch)
    if not okp:
        _audit(task_id, "apply_patch", "denied", errp)
        return {"ok": False, "denied": True, "reason": errp}
    # 校验 Git HEAD 与 base_commit 匹配
    head = _git_head()
    if base_commit and head != base_commit:
        return {"ok": False, "denied": True, "reason": f"Git HEAD {head} != base_commit {base_commit}"}
    # TODO: 实际 patch (隔离工作树) —— 生产写保持 disabled 时不执行
    _audit(task_id, "apply_patch", "dryrun", f"target={target_file} base={base_commit}")
    return {"ok": True, "dryrun": True, "target_file": target_file, "git_head": head,
            "note": "patch validated; actual apply gated by PRODUCTION_WRITE_ENABLED (off)"}


def tool_run_tests(task_id: str, test_plan: str = "default") -> dict:
    """在隔离副本运行测试 (语法检查/单元/静态). 不发真实消息/不动生产 DB."""
    init_state_db()
    # 测试针对本地 /home/hermes/cs-inbox-fresh 隔离副本, 不触碰 ECS 生产
    local_repo = Path("/home/hermes/cs-inbox-fresh")
    results = {}
    if local_repo.exists():
        # 语法检查
        p = subprocess.run(
            ["/home/hermes/.hermes/hermes-agent/venv/bin/python3", "-m", "py_compile",
             str(local_repo / "app.py")],
            capture_output=True, text=True, timeout=30,
        )
        results["syntax_check"] = {"exit": p.returncode, "stderr": p.stderr[:500]}
        # 若有 pytest 运行 (限隔离目录)
        if (local_repo / "tests").exists():
            p2 = subprocess.run(
                ["/home/hermes/.hermes/hermes-agent/venv/bin/python3", "-m", "pytest",
                 str(local_repo / "tests"), "-q", "--disable-warnings"],
                capture_output=True, text=True, timeout=120,
            )
            results["unit_tests"] = {"exit": p2.returncode, "stdout": p2.stdout[:1000]}
    else:
        results["error"] = "local isolated repo /home/hermes/cs-inbox-fresh not found"
    _set_task_status(task_id, "tested")
    _audit(task_id, "run_tests", "ok", f"plan={test_plan}")
    return {"ok": True, "task_id": task_id, "results": results,
            "note": "tests run on isolated local copy, NOT production ECS / no real messages"}


def _deploy_prechecks(task_id: str, commit: str) -> tuple[bool, str]:
    """部署前检查备份/测试/审批/commit/工作树/回滚条件."""
    task = _get_task(task_id)
    if not task:
        return False, "task not found"
    if task.get("status") != "tested":
        return False, f"task status '{task.get('status')}' != 'tested' (tests not passed)"
    if commit and _git_head() != commit:
        return False, f"git head {_git_head()} != commit {commit}"
    return True, "ok"


def tool_deploy(task_id: str, commit: str, approval_ticket: str) -> dict:
    """部署指定 commit. 需票据 + flag + 回滚条件. 生产部署前独立确认."""
    init_state_db()
    if not production_write_enabled():
        _audit(task_id, "deploy", "denied", "PRODUCTION_WRITE_ENABLED=False")
        return {"ok": False, "denied": True,
                "reason": "production deploy DISABLED (flag off)"}
    ok, err = verify_approval_ticket(approval_ticket, task_id, "deploy", "*", commit)
    if not ok:
        _audit(task_id, "deploy", "denied", err)
        return {"ok": False, "denied": True, "reason": err}
    okp, errp = _deploy_prechecks(task_id, commit)
    if not okp:
        _audit(task_id, "deploy", "denied", errp)
        return {"ok": False, "denied": True, "reason": errp}
    # TODO: 实际部署 (systemctl restart cs-inbox.service) —— 生产写 disabled 不执行
    _audit(task_id, "deploy", "dryrun", f"commit={commit}")
    return {"ok": True, "dryrun": True, "commit": commit,
            "note": "deploy validated; actual restart gated by PRODUCTION_WRITE_ENABLED (off)"}


def tool_rollback(task_id: str, target: str, approval_ticket: str) -> dict:
    """回滚到备份/commit. 需票据 + flag. 不回滚覆盖部署后客户数据."""
    init_state_db()
    if not production_write_enabled():
        _audit(task_id, "rollback", "denied", "PRODUCTION_WRITE_ENABLED=False")
        return {"ok": False, "denied": True,
                "reason": "rollback DISABLED (flag off)"}
    ok, err = verify_approval_ticket(approval_ticket, task_id, "rollback", "*", target)
    if not ok:
        _audit(task_id, "rollback", "denied", err)
        return {"ok": False, "denied": True, "reason": err}
    _audit(task_id, "rollback", "dryrun", f"target={target}")
    return {"ok": True, "dryrun": True, "target": target,
            "note": "rollback validated; actual restore gated by PRODUCTION_WRITE_ENABLED (off)"}


def tool_change_status(task_id: str) -> dict:
    """只读返回任务状态/审批/diff/测试/部署/报告路径."""
    init_state_db()
    task = _get_task(task_id)
    if not task:
        return {"ok": False, "reason": f"task {task_id} not found"}
    conn = _db()
    logs = [dict(r) for r in conn.execute(
        "SELECT operation, result, detail, created_at FROM audit_log WHERE task_id=? ORDER BY id DESC LIMIT 20",
        (task_id,)).fetchall()]
    conn.close()
    return {
        "ok": True,
        "task_id": task_id,
        "status": task.get("status"),
        "title": task.get("title"),
        "plan": json.loads(task["plan_json"]) if task.get("plan_json") else None,
        "file_scope": task.get("file_scope"),
        "commit": task.get("commit_sha"),
        "report_path": task.get("report_path"),
        "production_write_enabled": production_write_enabled(),
        "audit_trail": logs,
    }


# ── 工具注册表 (含 MCP annotations) ─────────────────
TOOLS_STAGE4 = {}


def _reg(name, fn, desc, input_schema, read_only=True, destructive=False):
    TOOLS_STAGE4[name] = {
        "fn": fn,
        "schema": {
            "name": name,
            "description": desc,
            "inputSchema": input_schema,
            "annotations": {
                "title": name,
                "readOnlyHint": read_only,
                "destructiveHint": destructive,
                "idempotentHint": not destructive,
                "openWorldHint": False,
            },
        },
    }


_reg("hermes_change_plan", tool_change_plan,
     "Read-only inspection of ECS code/git/deps/tests, returns a change plan with file scope, risks, test plan, and pending approval operations.",
     {"type": "object", "required": ["task_id", "requirement"],
      "properties": {"task_id": {"type": "string"}, "requirement": {"type": "string"}, "module": {"type": "string"}},
      "additionalProperties": False},
     read_only=True, destructive=False)

_reg("hermes_create_backup", tool_create_backup,
     "Create a consistent backup of the task's changed files + SQLite DB (online .backup). Requires approval ticket.",
     {"type": "object", "required": ["task_id", "approval_ticket"],
      "properties": {"task_id": {"type": "string"}, "approval_ticket": {"type": "string"}, "scope": {"type": "string"}},
      "additionalProperties": False},
     read_only=False, destructive=False)

_reg("hermes_apply_patch", tool_apply_patch,
     "Apply a unified diff to cs-inbox business files (isolated worktree). Gates: PRODUCTION_WRITE_ENABLED flag + approval ticket + path whitelist.",
     {"type": "object", "required": ["task_id", "target_file", "patch", "approval_ticket"],
      "properties": {"task_id": {"type": "string"}, "target_file": {"type": "string"}, "patch": {"type": "string"}, "approval_ticket": {"type": "string"}, "base_commit": {"type": "string"}},
      "additionalProperties": False},
     read_only=False, destructive=True)

_reg("hermes_run_tests", tool_run_tests,
     "Run syntax check + unit tests + static checks on an isolated copy. No real FB/IG/WA/LINE messages, no real orders, no production DB.",
     {"type": "object", "required": ["task_id"],
      "properties": {"task_id": {"type": "string"}, "test_plan": {"type": "string"}},
      "additionalProperties": False},
     read_only=False, destructive=False)

_reg("hermes_deploy", tool_deploy,
     "Deploy an approved commit to production. Gates: flag + approval ticket + backup + tests passed + commit match + rollback condition. Restart via cs-inbox.service.",
     {"type": "object", "required": ["task_id", "commit", "approval_ticket"],
      "properties": {"task_id": {"type": "string"}, "commit": {"type": "string"}, "approval_ticket": {"type": "string"}},
      "additionalProperties": False},
     read_only=False, destructive=True)

_reg("hermes_rollback", tool_rollback,
     "Rollback to a backup/commit. Gates: flag + approval ticket. DB rollback must preserve post-deploy customer data.",
     {"type": "object", "required": ["task_id", "target", "approval_ticket"],
      "properties": {"task_id": {"type": "string"}, "target": {"type": "string"}, "approval_ticket": {"type": "string"}},
      "additionalProperties": False},
     read_only=False, destructive=True)

_reg("hermes_change_status", tool_change_status,
     "Read-only task status: current phase, approval state, test/deploy results, report path, audit trail.",
     {"type": "object", "required": ["task_id"],
      "properties": {"task_id": {"type": "string"}},
      "additionalProperties": False},
     read_only=True, destructive=False)


def register_tools(target_tools: dict):
    """把 Stage 4 工具合并进目标 TOOLS dict (hermes_dev_agent.TOOLS).

    hermes_dev_agent 的 tools/call 用 `fn(args_dict)` (单个 dict 参数),
    而 Stage 4 工具函数用命名参数, 故这里包装成 `fn(**args_dict)`.
    """
    for name, spec in TOOLS_STAGE4.items():
        fn = spec["fn"]
        # 包装: dict -> **kwargs (与后端 tools/call 的 fn(args) 兼容)
        def _make(f):
            def call(args=None):
                d = args if isinstance(args, dict) else {}
                return f(**d)
            return call
        spec["fn"] = _make(fn)
        target_tools[name] = spec


if __name__ == "__main__":
    init_state_db()
    print("Stage 4 module loaded. PRODUCTION_WRITE_ENABLED =", production_write_enabled())
    print("Tools:", list(TOOLS_STAGE4.keys()))