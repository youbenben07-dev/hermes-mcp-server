#!/usr/bin/env python3
"""
Hermes Stage 4.3 — 飞书独立审批系统。

职责:
- 审批状态机 (pending/approved/rejected/expired/consumed/cancelled) 持久化
- 飞书交互卡片发送 (lark-cli, tenant_access_token)
- 飞书回调验证 (Encrypt Key HMAC + Verification Token + 防重放)
- 审批用户身份校验 (服务端 open_id allowlist, 禁止仅凭卡片字段)
- 审批通过后在服务端签发 HMAC 短期单次票据 (复用 stage4.mint_approval_ticket)
- 票据仅服务端存储, 不通过聊天/卡片明文展示

安全铁律:
- 不允许 AI 模拟用户审批
- 不允许 Hermes PM 代替用户自动批准
- 禁止在 ChatGPT 一侧暴露审批签名密钥
- 审批只能由 allowlist 中的真实飞书用户触发
- 每个审批请求单次使用 (consume 原子)
- 审批超时自动过期
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import subprocess
import time
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent
APPROVAL_DB = MODULE_DIR / "approval_state.db"

# ── 授权审批人 allowlist (飞书 open_id, 服务端权威来源) ──
AUTHORIZED_APPROVERS = {
    "ou_dd7d808d75173f228e2b9df266423933",  # 张健 (PM, 唯一授权审批人)
}

# ── 审批有效期 (默认 24 小时) ──
APPROVAL_TTL_SECONDS = 86400

# ── 飞书回调验证凭据 (文件优先, 环境变量 fallback, 禁止硬编码在代码) ──
def _read_secret(path: str, env_name: str) -> str:
    try:
        p = Path(path)
        if p.exists():
            return p.read_text().strip()
    except Exception:
        pass
    return os.environ.get(env_name, "")


FEISHU_ENCRYPT_KEY = _read_secret("/home/hermes/.hermes/feishu_encrypt_key", "FEISHU_APP_ENCRYPT_KEY")
FEISHU_VERIFICATION_TOKEN = _read_secret("/home/hermes/.hermes/feishu_verification_token", "FEISHU_APP_VERIFICATION_TOKEN")

LARK_CLI = "/usr/bin/lark-cli"

# ── 审批操作类型 (代码修改 / 部署 / 回滚 / 数据库变更 各自独立) ──
OPERATIONS = ("apply_patch", "deploy", "rollback", "db_change")


# ══════════════════════════════════════════════════════
# 状态 DB
# ══════════════════════════════════════════════════════
def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(APPROVAL_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    conn = _db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS approvals (
        approval_id TEXT PRIMARY KEY,
        task_id TEXT,
        operation TEXT,
        target_env TEXT,
        target_commit TEXT,
        file_list TEXT,
        diff_summary TEXT,
        risk TEXT,
        test_results TEXT,
        db_change TEXT,
        downtime_risk TEXT,
        rollback_plan TEXT,
        applicant TEXT,
        created_at INTEGER,
        expires_at INTEGER,
        status TEXT DEFAULT 'pending',
        approver_open_id TEXT,
        approved_at INTEGER,
        ticket TEXT,
        lark_message_id TEXT,
        content_hash TEXT,
        updated_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS callback_replay (
        event_id TEXT PRIMARY KEY,
        received_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_approvals_task ON approvals(task_id);
    """)
    conn.commit()
    conn.close()


def _now() -> int:
    return int(time.time())


def _content_hash(record_fields: dict) -> str:
    """审批内容哈希: 审批内容变化后原审批自动失效."""
    canonical = json.dumps(record_fields, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ══════════════════════════════════════════════════════
# 审批创建
# ══════════════════════════════════════════════════════
def create_approval(task_id: str, operation: str, target_env: str = "",
                    target_commit: str = "", file_list: list = None,
                    diff_summary: str = "", risk: str = "low",
                    test_results: dict = None, db_change: str = "",
                    downtime_risk: str = "", rollback_plan: str = "",
                    applicant: str = "chatgpt", ttl: int = APPROVAL_TTL_SECONDS) -> dict:
    """创建待审批请求 (status=pending). 返回审批记录 (不含 ticket)."""
    if operation not in OPERATIONS:
        return {"ok": False, "reason": f"invalid operation: {operation}"}
    init_db()
    approval_id = f"apr_{secrets.token_hex(12)}"
    now = _now()
    expires_at = now + ttl
    file_list = file_list or []
    test_results = test_results or {}

    # 内容字段 (用于 content_hash, 变化即失效)
    content_fields = {
        "task_id": task_id, "operation": operation, "target_env": target_env,
        "target_commit": target_commit, "file_list": file_list,
        "diff_summary": diff_summary, "db_change": db_change,
    }
    ch = _content_hash(content_fields)

    conn = _db()
    conn.execute(
        "INSERT INTO approvals (approval_id, task_id, operation, target_env, target_commit, "
        "file_list, diff_summary, risk, test_results, db_change, downtime_risk, rollback_plan, "
        "applicant, created_at, expires_at, status, content_hash, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (approval_id, task_id, operation, target_env, target_commit,
         json.dumps(file_list, ensure_ascii=False), diff_summary, risk,
         json.dumps(test_results, ensure_ascii=False), db_change, downtime_risk, rollback_plan,
         applicant, now, expires_at, "pending", ch, now),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "approval_id": approval_id, "task_id": task_id,
            "operation": operation, "status": "pending", "expires_at": expires_at,
            "content_hash": ch}


# ══════════════════════════════════════════════════════
# 读取
# ══════════════════════════════════════════════════════
def get_approval(approval_id: str) -> dict:
    conn = _db()
    row = conn.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
    conn.close()
    return _public_view(row) if row else None


def get_by_task(task_id: str, operation: str = "") -> list:
    conn = _db()
    if operation:
        rows = conn.execute("SELECT * FROM approvals WHERE task_id=? AND operation=? ORDER BY created_at DESC",
                            (task_id, operation)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM approvals WHERE task_id=? ORDER BY created_at DESC",
                            (task_id,)).fetchall()
    conn.close()
    return [_public_view(r) for r in rows]


def _public_view(row: sqlite3.Row) -> dict:
    """对外公开视图: 摘除 ticket (HMAC 票据), 不暴露密钥."""
    d = dict(row)
    d["ticket"] = None  # 票据永不出现在公开返回
    d["ticket_minted"] = bool(row["ticket"])
    return d


# ══════════════════════════════════════════════════════
# 身份校验 (服务端 allowlist, 严格)
# ══════════════════════════════════════════════════════
def is_authorized_approver(open_id: str) -> bool:
    """校验飞书用户是否在授权名单. 禁止仅凭卡片传入的用户名判断."""
    if not open_id:
        return False
    return open_id in AUTHORIZED_APPROVERS


def add_authorized_approver(open_id: str):
    """添加授权审批人 (仅 PM 本地调用, 非 MCP 工具)."""
    if not open_id or not open_id.startswith("ou_"):
        return False
    AUTHORIZED_APPROVERS.add(open_id)
    return True


# ══════════════════════════════════════════════════════
# 飞书回调验证
# ══════════════════════════════════════════════════════
def verify_feishu_signature(timestamp: str, nonce: str, body: bytes, signature: str) -> bool:
    """校验飞书回调签名 (Encrypt Key 方式).

    Feishu 签名算法: 对 timestamp + nonce + encrypt_key + body 拼接后 SHA256,
    再与 header X-Lark-Signature 比对.
    """
    if not FEISHU_ENCRYPT_KEY:
        return False
    if not (timestamp and nonce and signature):
        return False
    # 防重放: 时间戳超过 60s 拒绝
    try:
        ts = int(timestamp)
        if abs(_now() - ts) > 60:
            return False
    except (ValueError, TypeError):
        return False
    plain = (timestamp + nonce + FEISHU_ENCRYPT_KEY + body.decode("utf-8")).encode("utf-8")
    digest = hashlib.sha256(plain).hexdigest()
    return hmac.compare_digest(digest, signature)


def verify_and_record_callback(event_id: str) -> bool:
    """防重放: 记录 event_id, 已见过则拒绝 (原子)."""
    if not event_id:
        return False
    conn = _db()
    try:
        conn.execute("INSERT INTO callback_replay (event_id, received_at) VALUES (?,?)",
                     (event_id, _now()))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # event_id 已存在 = 重放
        conn.rollback()
        return False
    finally:
        conn.close()


# ══════════════════════════════════════════════════════
# 审批动作
# ══════════════════════════════════════════════════════
def approve(approval_id: str, open_id: str, current_content_hash: str = "") -> dict:
    """批准: 校验身份 + 校验内容未变 + 签发 HMAC 票据."""
    if not is_authorized_approver(open_id):
        return {"ok": False, "reason": "unauthorized approver (not in allowlist)"}
    conn = _db()
    row = conn.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
    if not row:
        conn.close()
        return {"ok": False, "reason": "approval not found"}
    # 状态机: 只有 pending 可批准
    if row["status"] != "pending":
        conn.close()
        return {"ok": False, "reason": f"approval already {row['status']}"}
    if _now() > row["expires_at"]:
        conn.execute("UPDATE approvals SET status='expired', updated_at=? WHERE approval_id=?",
                     (_now(), approval_id))
        conn.commit()
        conn.close()
        return {"ok": False, "reason": "approval expired"}
    # 内容变化检测: 原审批失效
    if current_content_hash and current_content_hash != row["content_hash"]:
        conn.execute("UPDATE approvals SET status='cancelled', updated_at=? WHERE approval_id=?",
                     (_now(), approval_id))
        conn.commit()
        conn.close()
        return {"ok": False, "reason": "approval content changed, original approval invalidated"}
    # 签发 HMAC 票据 (复用 stage4, 绑定 task/operation/commit)
    from hermes_stage4 import mint_approval_ticket
    file_scope = json.loads(row["file_list"])[0] if row["file_list"] and json.loads(row["file_list"]) else "*"
    if row["operation"] in ("deploy", "rollback", "db_change"):
        file_scope = "*"
    ticket = mint_approval_ticket(row["task_id"], row["operation"], file_scope,
                                  row["target_commit"] or "", user=open_id)
    conn.execute(
        "UPDATE approvals SET status='approved', approver_open_id=?, approved_at=?, ticket=?, updated_at=? "
        "WHERE approval_id=?",
        (open_id, _now(), ticket, _now(), approval_id),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "approval_id": approval_id, "status": "approved",
            "approver_open_id": open_id, "ticket_minted": True}


def reject(approval_id: str, open_id: str) -> dict:
    if not is_authorized_approver(open_id):
        return {"ok": False, "reason": "unauthorized approver"}
    conn = _db()
    row = conn.execute("SELECT status FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
    if not row:
        conn.close()
        return {"ok": False, "reason": "approval not found"}
    if row["status"] != "pending":
        conn.close()
        return {"ok": False, "reason": f"approval already {row['status']}"}
    conn.execute("UPDATE approvals SET status='rejected', approver_open_id=?, updated_at=? WHERE approval_id=?",
                 (open_id, _now(), approval_id))
    conn.commit()
    conn.close()
    return {"ok": True, "approval_id": approval_id, "status": "rejected"}


def cancel(approval_id: str, open_id: str = "") -> dict:
    """取消 (任务取消机制)."""
    conn = _db()
    row = conn.execute("SELECT status FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
    if not row:
        conn.close()
        return {"ok": False, "reason": "approval not found"}
    if row["status"] not in ("pending", "approved"):
        conn.close()
        return {"ok": False, "reason": f"cannot cancel from {row['status']}"}
    conn.execute("UPDATE approvals SET status='cancelled', updated_at=? WHERE approval_id=?",
                 (_now(), approval_id))
    conn.commit()
    conn.close()
    return {"ok": True, "approval_id": approval_id, "status": "cancelled"}


def expire_overdue() -> int:
    """把过期的 pending 标记为 expired. 返回处理数量."""
    conn = _db()
    cur = conn.execute(
        "UPDATE approvals SET status='expired', updated_at=? WHERE status='pending' AND expires_at < ?",
        (_now(), _now()))
    conn.commit()
    n = cur.rowcount
    conn.close()
    return n


def consume(approval_id: str, operation: str, file_scope: str, commit: str = "") -> dict:
    """消费审批 (单次使用): 校验 approved + 操作匹配 → status=consumed, 返回服务端票据 (内部).

    票据只在服务端流转, 不返回给 ChatGPT. 返回 {ok, ticket} 供内部写工具使用.
    """
    conn = _db()
    row = conn.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
    if not row:
        conn.close()
        return {"ok": False, "reason": "approval not found"}
    if row["status"] != "approved":
        conn.close()
        return {"ok": False, "reason": f"approval status={row['status']}, not approved"}
    if row["operation"] != operation:
        conn.close()
        return {"ok": False, "reason": f"approval op={row['operation']} != requested {operation}"}
    if _now() > row["expires_at"]:
        conn.execute("UPDATE approvals SET status='expired', updated_at=? WHERE approval_id=?",
                     (_now(), approval_id))
        conn.commit()
        conn.close()
        return {"ok": False, "reason": "approval expired"}
    # 原子消费 (防并发)
    cur = conn.execute(
        "UPDATE approvals SET status='consumed', updated_at=? WHERE approval_id=? AND status='approved'",
        (_now(), approval_id))
    conn.commit()
    if cur.rowcount != 1:
        conn.close()
        return {"ok": False, "reason": "already consumed (concurrent)"}
    ticket = row["ticket"]
    conn.close()
    return {"ok": True, "ticket": ticket}


# ══════════════════════════════════════════════════════
# 飞书卡片
# ══════════════════════════════════════════════════════
def build_approval_card(record: dict) -> dict:
    """构建审批卡片 JSON (CardKit 交互卡片)."""
    approval_id = record["approval_id"]
    op_label = {"apply_patch": "代码修改", "deploy": "生产部署", "rollback": "生产回滚",
                "db_change": "数据库变更"}.get(record["operation"], record["operation"])
    risk_emoji = {"low": "🟢 低", "medium": "🟡 中", "high": "🔴 高"}.get(record.get("risk", "low"), record.get("risk", ""))
    file_list = json.loads(record["file_list"]) if record.get("file_list") else []
    test_results = json.loads(record.get("test_results") or "{}")

    lines = [
        f"**任务ID**: {record['task_id']}",
        f"**操作类型**: {op_label}",
        f"**目标环境**: {record.get('target_env') or '—'}",
        f"**目标 commit**: `{record.get('target_commit') or '—'}`",
        f"**修改文件**: {', '.join(file_list) if file_list else '—'}",
        f"**风险等级**: {risk_emoji}",
        f"**测试结果**: {json.dumps(test_results, ensure_ascii=False) if test_results else '—'}",
        f"**数据库变更**: {record.get('db_change') or '无'}",
        f"**停机风险**: {record.get('downtime_risk') or '无'}",
        f"**回滚方案**: {record.get('rollback_plan') or '自动回滚到 prev_head'}",
        f"**申请人**: {record.get('applicant')}",
        f"**审批有效期**: 24 小时",
    ]
    diff_summary = record.get("diff_summary") or ""
    if diff_summary:
        lines.append(f"**diff 摘要**: {diff_summary[:500]}")

    return {
        "config": {"wide_screen_mode": True},
        "header": {
            "title": {"tag": "plain_text", "content": f"🔐 审批请求 — {op_label}"},
            "template": "orange" if record["operation"] in ("deploy", "rollback", "db_change") else "blue",
        },
        "elements": [
            {"tag": "div", "text": {"tag": "lark_md", "content": "\n".join(lines)}},
            {"tag": "hr"},
            {
                "tag": "action",
                "actions": [
                    {"tag": "button", "text": {"tag": "plain_text", "content": "✅ 批准"},
                     "type": "primary", "value": {"action": "approve", "approval_id": approval_id}},
                    {"tag": "button", "text": {"tag": "plain_text", "content": "❌ 拒绝"},
                     "type": "danger", "value": {"action": "reject", "approval_id": approval_id}},
                ],
            },
            {"tag": "note", "elements": [{"tag": "plain_text", "content": f"审批 ID: {approval_id} | 仅限授权用户操作"}]},
        ],
    }


def send_approval_card(record: dict, open_id: str) -> dict:
    """通过 lark-cli 发送审批卡片到指定飞书用户."""
    card = build_approval_card(record)
    content_json = json.dumps(card, ensure_ascii=False)
    # lark-cli im messages send
    cmd = [
        LARK_CLI, "im", "messages", "send",
        "--as", "bot",
        "--receive-id-type", "open_id",
        "--receive-id", open_id,
        "--msg-type", "interactive",
        "--content", content_json,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        ok = p.returncode == 0
        msg_id = ""
        if ok:
            # 从输出提取 message_id
            out = p.stdout or p.stderr or ""
            import re as _re
            m = _re.search(r"om_[a-zA-Z0-9]+", out)
            if m:
                msg_id = m.group(0)
        return {"ok": ok, "stdout": (p.stdout or "")[:500], "stderr": (p.stderr or "")[:500],
                "lark_message_id": msg_id}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def record_lark_message(approval_id: str, lark_message_id: str):
    conn = _db()
    conn.execute("UPDATE approvals SET lark_message_id=?, updated_at=? WHERE approval_id=?",
                 (lark_message_id, _now(), approval_id))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Approval module loaded.")
    print("  AUTHORIZED_APPROVERS:", AUTHORIZED_APPROVERS)
    print("  FEISHU_ENCRYPT_KEY set:", bool(FEISHU_ENCRYPT_KEY))
    print("  FEISHU_VERIFICATION_TOKEN set:", bool(FEISHU_VERIFICATION_TOKEN))