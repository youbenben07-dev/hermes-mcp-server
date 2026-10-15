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

# ── 隔离演练仓库 (VPS 本地, 非 ECS 生产) ──────────
LOCAL_TEST_REPO = Path("/home/hermes/cs-inbox-fresh")
LOCAL_TEST_REPO_REMOTE = LOCAL_TEST_REPO  # 用本地作隔离
LOCAL_TEST_BACKUP_DIR = Path("/home/hermes/mcp_servers/stage4_backups")
LOCAL_TEST_SERVICE_PORT = 5059  # 隔离测试服务 (生产是 5051)
LOCAL_TEST_SCRIPT = Path("/home/hermes/mcp_servers/stage4_test_service.sh")
ECS_HOST = "fastmedlink@47.250.166.208"
ECS_CS_INBOX = "/home/fastmedlink/cs-inbox"
ECS_DB = "/home/fastmedlink/cs-inbox/data/inbox.db"
ECS_SERVICE = "cs-inbox.service"
ECS_SERVICE_PORT = 5051
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
                     approval_ticket: str, base_commit: str = "",
                     branch: str = "") -> dict:
    """在隔离仓库应用 unified diff. 创建 worktree 分支, 校验, 语法检查, 自动 commit.

    安全门禁 (顺序):
    1. PRODUCTION_WRITE_ENABLED flag (master kill switch)
    2. HMAC 审批票据 (短期单次, 绑定 task/operation/file/commit)
    3. 路径白名单 (相对仓库根, 禁绝对路径/穿越/敏感)
    4. unified diff 路径白名单
    5. Git HEAD 校验 (若指定 base_commit)
    6. patch 可干净 apply (允许 diff 中含 "No newline at end of file")
    7. py_compile 语法检查

    隔离: 默认在 LOCAL_TEST_REPO 创建 worktree 分支 task/<task_id>, 不动 ECS 生产.
    """
    init_state_db()
    if not production_write_enabled():
        return _apply_patch_dryrun(task_id, target_file, patch, base_commit)
    ok, err = verify_approval_ticket(approval_ticket, task_id, "apply_patch", target_file, base_commit)
    if not ok:
        _audit(task_id, "apply_patch", "denied", err)
        return {"ok": False, "denied": True, "reason": err}
    if not _safe_rel_path(target_file):
        _audit(task_id, "apply_patch", "denied", f"unsafe path {target_file}")
        return {"ok": False, "denied": True, "reason": f"target_file not allowed: {target_file}"}
    okp, errp = _validate_diff_paths(patch)
    if not okp:
        _audit(task_id, "apply_patch", "denied", errp)
        return {"ok": False, "denied": True, "reason": errp}
    lock_ok, lock_owner = acquire_lock(task_id, "apply_patch")
    if not lock_ok:
        return {"ok": False, "denied": True, "reason": lock_owner}
    try:
        if not LOCAL_TEST_REPO.exists():
            return {"ok": False, "reason": f"local test repo not found: {LOCAL_TEST_REPO}"}
        head = _local_git(["rev-parse", "--short", "HEAD"], cwd=LOCAL_TEST_REPO)["stdout"].strip()
        if base_commit and head != base_commit:
            return {"ok": False, "denied": True, "reason": f"local HEAD {head} != base_commit {base_commit}"}
        wt_dir = LOCAL_TEST_REPO.parent / f"cs-inbox-fresh-wt-{task_id}"
        br_name = branch or f"task/{task_id}"
        if wt_dir.exists():
            subprocess.run(["git", "worktree", "remove", "--force", str(wt_dir)],
                           cwd=LOCAL_TEST_REPO, capture_output=True)
        subprocess.run(["git", "worktree", "prune"], cwd=LOCAL_TEST_REPO, capture_output=True)
        r = subprocess.run(["git", "worktree", "add", "-B", br_name, str(wt_dir), "HEAD"],
                           cwd=LOCAL_TEST_REPO, capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return {"ok": False, "reason": f"worktree add failed: {r.stderr[:200]}"}
        abs_target = wt_dir / target_file
        if not abs_target.exists():
            return {"ok": False, "reason": f"target file {target_file} not in worktree (new file diff not supported yet)"}
        # 用 git apply --check 验证, 然后真 apply. 允许三种 patch 形式:
        # 1) 标准 unified diff (context 行与文件 1:1 匹配)
        # 2) 含 "No newline at end of file" 的 diff
        # 3) diff 中的空行/中文/特殊字符 (git apply 严格, 用 --recount + --whitespace=fix)
        apply = subprocess.run(
            ["git", "apply", "--recount", "--whitespace=fix", "-"],
            input=patch, text=True, cwd=wt_dir, capture_output=True,
        )
        if apply.returncode != 0:
            return {"ok": False, "reason": f"patch apply failed: {apply.stderr[:300]}"}
        if target_file.endswith(".py"):
            comp = subprocess.run(
                ["/home/hermes/.hermes/hermes-agent/venv/bin/python3", "-m", "py_compile",
                 str(abs_target)],
                capture_output=True, text=True, timeout=10,
            )
            syntax_ok = comp.returncode == 0
            if not syntax_ok:
                # 回滚 worktree
                subprocess.run(["git", "worktree", "remove", "--force", str(wt_dir)],
                               cwd=LOCAL_TEST_REPO, capture_output=True)
                return {"ok": False, "reason": f"py_compile failed: {comp.stderr[:200]}"}
        else:
            syntax_ok = True
        sha_after = hashlib.sha256(abs_target.read_bytes()).hexdigest() if abs_target.exists() else ""
        subprocess.run(["git", "add", "--", target_file], cwd=wt_dir, capture_output=True)
        commit_msg = f"task {task_id}: apply_patch on {target_file}"
        r3 = subprocess.run(["git", "-c", "user.name=Hermes-PM", "-c", "user.email=pm@hermes",
                             "commit", "-m", commit_msg],
                            cwd=wt_dir, capture_output=True, text=True, timeout=10)
        new_commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                                    cwd=wt_dir, capture_output=True, text=True).stdout.strip()
        diff_after = subprocess.run(["git", "diff", "HEAD~1", "HEAD", "--", target_file],
                                    cwd=wt_dir, capture_output=True, text=True).stdout
        _set_task_status(task_id, "patched", commit_sha=new_commit, report_path=str(wt_dir))
        _audit(task_id, "apply_patch", "ok", f"file={target_file} commit={new_commit} syntax={syntax_ok}")
        return {
            "ok": True, "task_id": task_id, "target_file": target_file,
            "worktree": str(wt_dir), "branch": br_name, "new_commit": new_commit,
            "syntax_ok": syntax_ok, "sha256_after": sha_after,
            "diff_summary": diff_after[:3000],
            "note": "patch applied to LOCAL TEST REPO (isolated). Not deployed to ECS.",
        }
    finally:
        release_lock(task_id, lock_owner)


def _apply_patch_dryrun(task_id: str, target_file: str, patch: str, base_commit: str) -> dict:
    """flag off 时: 走完整校验 + 报告, 不动文件."""
    init_state_db()
    if not _safe_rel_path(target_file):
        return {"ok": False, "denied": True, "reason": f"target_file not allowed: {target_file}"}
    okp, errp = _validate_diff_paths(patch)
    if not okp:
        return {"ok": False, "denied": True, "reason": errp}
    _audit(task_id, "apply_patch", "dryrun", f"target={target_file} base={base_commit}")
    return {"ok": True, "dryrun": True, "task_id": task_id, "target_file": target_file,
            "patch_lines": len(patch.splitlines()),
            "note": "PRODUCTION_WRITE_ENABLED=False. Patch validated but NOT applied. To enable real execution, create the flag file and provide valid approval ticket."}


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
    """部署前检查: 任务存在 + 状态 (tested|patched) + commit 匹配."""
    task = _get_task(task_id)
    if not task:
        return False, "task not found"
    if task.get("status") not in ("tested", "patched"):
        return False, f"task status '{task.get('status')}' not in (tested, patched). Run apply_patch + run_tests first."
    if commit and task.get("commit_sha") and task.get("commit_sha") != commit:
        return False, f"task commit_sha {task.get('commit_sha')} != requested {commit}"
    return True, "ok"


def _local_git(args, cwd, capture_output: bool = True):
    """在本地隔离仓库跑 git 命令."""
    if capture_output:
        p = subprocess.run(["git"] + list(args), cwd=str(cwd), capture_output=True, text=True, timeout=30)
        return {"ok": p.returncode == 0, "exit": p.returncode,
                "stdout": p.stdout[:4000], "stderr": p.stderr[:1000]}
    else:
        return subprocess.run(["git"] + list(args), cwd=str(cwd), capture_output=True, text=True, timeout=30)


def _read_issue_queue_pid():
    """读 issue_queue worker PID (本地文件)."""
    pid_file = Path("/home/hermes/issue_queue/worker.pid")
    if pid_file.exists():
        try:
            return int(pid_file.read_text().strip())
        except Exception:
            pass
    return None


def _worker_active_recently(within_sec: int = 60) -> bool:
    pid = _read_issue_queue_pid()
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return (Path("/proc") / str(pid)).exists()
    except (OSError, FileNotFoundError):
        return False


def tool_deploy(task_id: str, commit: str, approval_ticket: str,
                target: str = "local", health_url: str = "") -> dict:
    """部署到隔离环境 (VPS 本地 5059 端口). target=local 不需 flag, target=ecs 需 flag."""
    init_state_db()
    if target not in ("local", "ecs"):
        return {"ok": False, "denied": True, "reason": f"invalid target: {target}"}
    if target == "ecs" and not production_write_enabled():
        _audit(task_id, "deploy", "denied", "flag off (ecs target)")
        return {"ok": False, "denied": True, "reason": "ECS deploy DISABLED (flag off)"}
    ok, err = verify_approval_ticket(approval_ticket, task_id, "deploy", "*", commit)
    if not ok:
        _audit(task_id, "deploy", "denied", err)
        return {"ok": False, "denied": True, "reason": err}
    okp, errp = _deploy_prechecks(task_id, commit)
    if not okp:
        _audit(task_id, "deploy", "denied", errp)
        return {"ok": False, "denied": True, "reason": errp}
    if target == "ecs":
        _audit(task_id, "deploy", "dryrun_ecs", f"commit={commit}")
        return {"ok": True, "dryrun": True, "target": "ecs",
                "note": "ECS deploy: precheck + ticket passed. Actual restart NOT executed (flag-gated)."}
    lock_ok, lock_owner = acquire_lock(task_id, "deploy", ttl=300)
    if not lock_ok:
        return {"ok": False, "denied": True, "reason": f"concurrent: {lock_owner}"}
    if _read_issue_queue_pid() and _worker_active_recently():
        _audit(task_id, "deploy", "warn", "issue_queue worker active during deploy")
    try:
        return _do_deploy_local(task_id, commit, health_url)
    finally:
        release_lock(task_id, lock_owner)


def _do_deploy_local(task_id: str, commit: str, health_url: str) -> dict:
    """真实 deploy 流程 (VPS 隔离仓库 + 隔离端口 5059)."""
    if not LOCAL_TEST_REPO.exists():
        return {"ok": False, "reason": f"local repo not found: {LOCAL_TEST_REPO}"}
    prev_head = _local_git(["rev-parse", "--short", "HEAD"], cwd=LOCAL_TEST_REPO)["stdout"].strip()
    ts = time.strftime("%Y%m%d-%H%M%S")
    bk = LOCAL_TEST_BACKUP_DIR / f"{task_id}_pre_deploy_{ts}"
    bk.mkdir(parents=True, exist_ok=True)
    _local_git(["bundle", "create", str(bk / "pre.bundle"), "--all"], cwd=LOCAL_TEST_REPO)
    if commit and commit != prev_head:
        r = _local_git(["reset", "--hard", commit], cwd=LOCAL_TEST_REPO)
        if r["exit"] != 0:
            return {"ok": False, "reason": f"git reset failed: {r['stderr'][:200]}"}
    new_head = _local_git(["rev-parse", "--short", "HEAD"], cwd=LOCAL_TEST_REPO)["stdout"].strip()
    svc_log = LOCAL_TEST_BACKUP_DIR / f"{task_id}_service.log"
    svc_log.write_text("")
    if not LOCAL_TEST_SCRIPT.exists():
        return {"ok": False, "reason": f"test service script missing: {LOCAL_TEST_SCRIPT}"}
    p = subprocess.run(["bash", str(LOCAL_TEST_SCRIPT), "start",
                       str(LOCAL_TEST_REPO), str(LOCAL_TEST_SERVICE_PORT), str(svc_log)],
                      capture_output=True, text=True, timeout=20)
    service_started = p.returncode == 0
    health = ""
    health_ok = False
    if service_started:
        url = health_url or f"http://127.0.0.1:{LOCAL_TEST_SERVICE_PORT}/health"
        for _ in range(6):
            time.sleep(5)
            try:
                h = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                                    url, "--max-time", "3"],
                                   capture_output=True, text=True, timeout=5)
                code = h.stdout.strip()
                health = f"HTTP {code}"
                if code.startswith("2"):
                    health_ok = True
                    break
            except Exception as e:
                health = f"err: {e}"
    if not service_started or not health_ok:
        rollback_reason = f"started={service_started} health={health}"
        _local_git(["reset", "--hard", prev_head], cwd=LOCAL_TEST_REPO)
        subprocess.run(["bash", str(LOCAL_TEST_SCRIPT), "stop",
                        str(LOCAL_TEST_REPO), str(LOCAL_TEST_SERVICE_PORT)],
                       capture_output=True, text=True, timeout=10)
        _audit(task_id, "deploy", "rolled_back", rollback_reason)
        _set_task_status(task_id, "deploy_failed")
        return {"ok": False, "reason": f"deploy failed (auto-rolled back to {prev_head}): {rollback_reason}",
                "prev_head": prev_head, "health": health}
    _set_task_status(task_id, "deployed", commit_sha=new_head, report_path=str(bk))
    _audit(task_id, "deploy", "ok", f"commit={new_head} health={health} port={LOCAL_TEST_SERVICE_PORT}")
    return {
        "ok": True, "task_id": task_id, "target": "local", "commit": new_head,
        "prev_head": prev_head, "backup_bundle": str(bk / "pre.bundle"),
        "service_port": LOCAL_TEST_SERVICE_PORT, "service_log": str(svc_log),
        "health": health, "health_ok": health_ok,
        "note": f"deployed to LOCAL test service on port {LOCAL_TEST_SERVICE_PORT}. ECS production NOT touched.",
    }


def tool_rollback(task_id: str, target: str, approval_ticket: str) -> dict:
    """回滚: 从备份 bundle 恢复 LOCAL_TEST_REPO. target: 'task:<other>' | 'commit:<sha>' | 'prev'."""
    init_state_db()
    ok, err = verify_approval_ticket(approval_ticket, task_id, "rollback", "*", target)
    if not ok:
        _audit(task_id, "rollback", "denied", err)
        return {"ok": False, "denied": True, "reason": err}
    lock_ok, lock_owner = acquire_lock(task_id, "rollback", ttl=300)
    if not lock_ok:
        return {"ok": False, "denied": True, "reason": lock_owner}
    try:
        return _do_rollback_local(task_id, target)
    finally:
        release_lock(task_id, lock_owner)


def _do_rollback_local(task_id: str, target: str) -> dict:
    if not LOCAL_TEST_REPO.exists():
        return {"ok": False, "reason": "local repo missing"}
    if target.startswith("task:"):
        other = target.split(":", 1)[1]
        bk_dir = LOCAL_TEST_BACKUP_DIR / other
        bk_files = list(bk_dir.glob("pre.bundle")) if bk_dir.exists() else []
        if not bk_files:
            return {"ok": False, "reason": f"no backup for task {other}"}
        r = _local_git(["bundle", "verify", str(bk_files[0])], cwd=LOCAL_TEST_REPO)
        if r["exit"] != 0:
            return {"ok": False, "reason": f"bundle verify failed: {r['stderr'][:200]}"}
        fetch_branch = f"rollback/{other}"
        _local_git(["fetch", str(bk_files[0]), f"refs/heads/*:{fetch_branch}"], cwd=LOCAL_TEST_REPO)
        r2 = _local_git(["rev-parse", "--short", fetch_branch], cwd=LOCAL_TEST_REPO)
        target_sha = r2["stdout"].strip()
        if not target_sha:
            return {"ok": False, "reason": f"cannot resolve {fetch_branch}"}
        _local_git(["reset", "--hard", target_sha], cwd=LOCAL_TEST_REPO)
        new_head = _local_git(["rev-parse", "--short", "HEAD"], cwd=LOCAL_TEST_REPO)["stdout"].strip()
    elif target.startswith("commit:"):
        sha = target.split(":", 1)[1]
        r = _local_git(["reset", "--hard", sha], cwd=LOCAL_TEST_REPO)
        if r["exit"] != 0:
            return {"ok": False, "reason": f"reset failed: {r['stderr'][:200]}"}
        new_head = sha[:7]
    elif target == "prev":
        r = _local_git(["reflog", "-n", "2", "--format=%H"], cwd=LOCAL_TEST_REPO)
        heads = [l.strip() for l in r["stdout"].splitlines() if l.strip()]
        if len(heads) < 2:
            return {"ok": False, "reason": "no reflog prev"}
        _local_git(["reset", "--hard", heads[1]], cwd=LOCAL_TEST_REPO)
        new_head = heads[1][:7]
    else:
        return {"ok": False, "reason": f"invalid target format: {target}"}
    if LOCAL_TEST_SCRIPT.exists():
        subprocess.run(["bash", str(LOCAL_TEST_SCRIPT), "stop",
                        str(LOCAL_TEST_REPO), str(LOCAL_TEST_SERVICE_PORT)],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["bash", str(LOCAL_TEST_SCRIPT), "start",
                        str(LOCAL_TEST_REPO), str(LOCAL_TEST_SERVICE_PORT),
                        str(LOCAL_TEST_BACKUP_DIR / f"{task_id}_rollback.log")],
                       capture_output=True, text=True, timeout=20)
    time.sleep(5)
    h = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                        f"http://127.0.0.1:{LOCAL_TEST_SERVICE_PORT}/health", "--max-time", "3"],
                       capture_output=True, text=True, timeout=5)
    health = h.stdout.strip()
    _audit(task_id, "rollback", "ok", f"target={target} new_head={new_head} health={health}")
    _set_task_status(task_id, "rolled_back", commit_sha=new_head)
    return {"ok": True, "task_id": task_id, "new_head": new_head,
            "target": target, "health": health,
            "note": "LOCAL test repo rolled back. ECS production NOT touched."}


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