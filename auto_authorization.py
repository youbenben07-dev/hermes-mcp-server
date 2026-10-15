#!/usr/bin/env python3
"""
Hermes Stage 4.4 — 持久化自动执行授权策略.

替代飞书逐次人工审批: 由服务器管理员在初始化时一次性启用,
限定 MCP 授权用户身份、仓库、文件类型/目录、部署目标、并发、高风险禁区、有效期与撤销方法。

策略文件: /home/hermes/.hermes/auto_authorization.json (mode 600, 不入 git)

安全铁律:
- 策略默认 enabled=false (无人值守模式关闭)
- 必须由管理员显式一次性启用
- ChatGPT 文本不能自行提升服务器权限
- 任意用户通过 OAuth 登录后不能执行生产写入 (需 mcp:write scope + 策略授权 + flag)
- 高风险操作 (DB 迁移/删客户数据/批量发消息/改SSH/sudoers/防火墙/支付) 明确拒绝
"""

import json
import os
import time
from pathlib import Path

POLICY_FILE = Path("/home/hermes/.hermes/auto_authorization.json")

# 默认策略 (enabled=false, 除非管理员启用)
DEFAULT_POLICY = {
    "enabled": False,
    # MCP 授权用户身份 (OAuth client_id 或 "static-token" 代表 PM 静态 token)
    "authorized_clients": [],
    # 授权 redirect_uri (ChatGPT connector 固定标识, 每次 DCR client_id 会变)
    "authorized_redirect_uris": [],
    # 指定客服系统仓库
    "allowed_repos": ["/home/fastmedlink/cs-inbox"],
    # 允许修改的文件类型及目录 (glob)
    "allowed_file_globs": [
        "app.py", "auth.py", "config.py",
        "templates/*.html", "templates/**/*.html",
        "static/css/*.css", "static/js/*.js",
        "routes/*.py", "services/*.py", "utils/*.py",
    ],
    # 允许的部署目标
    "allowed_targets": ["local", "mock_ecs"],
    # 最大并发任务数
    "max_concurrent_tasks": 3,
    # 禁止的高风险操作 (关键词)
    "forbidden_operations": [
        "db_migration", "delete_customer_data", "batch_send_messages",
        "ssh_config", "sudoers", "firewall", "payment",
        "migrate", "drop_table", "truncate",
    ],
    # 有效期
    "valid_until": "",
    # 撤销方法说明
    "revocation": "delete this file OR set enabled=false",
}


def load_policy() -> dict:
    """加载策略 (不存在则返回默认, enabled=false)."""
    if not POLICY_FILE.exists():
        return dict(DEFAULT_POLICY)
    try:
        data = json.loads(POLICY_FILE.read_text())
        # 合并默认 (保证新字段有值)
        merged = dict(DEFAULT_POLICY)
        merged.update(data)
        return merged
    except Exception:
        return dict(DEFAULT_POLICY)


def save_policy(policy: dict) -> bool:
    """管理员初始化时保存策略 (本地调用, 非 MCP 工具)."""
    try:
        POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
        POLICY_FILE.write_text(json.dumps(policy, indent=2, ensure_ascii=False))
        os.chmod(POLICY_FILE, 0o600)
        return True
    except Exception:
        return False


def policy_enabled() -> bool:
    p = load_policy()
    if not p.get("enabled"):
        return False
    # 有效期检查
    vu = p.get("valid_until", "")
    if vu:
        try:
            if time.time() > time.mktime(time.strptime(vu, "%Y-%m-%d")):
                return False
        except Exception:
            return False
    return True


def is_client_authorized(client_identity: str) -> bool:
    """校验 MCP 客户端身份是否在授权名单 (auto-execute 用, 受 enabled 门禁)."""
    if not policy_enabled():
        return False
    p = load_policy()
    clients = p.get("authorized_clients", [])
    # 空名单 = 不授权任何人 (安全默认)
    if not clients:
        return False
    if "*" in clients:
        return True
    return client_identity in clients


def is_scope_authorized(client_identity: str, redirect_uri: str = "") -> bool:
    """校验 client 是否在 mcp:write 白名单 (与 enabled 解耦, 只看名单).

    Stage 4.5.1 修复: mcp:write scope 的签发不应被 auto_authorization.enabled 绑死.
    enabled 控制无人值守 auto-execute, 而 mcp:write 只应看管理员是否把该 client 列入白名单.
    这样管理员可以在 enabled=false 时先给 ChatGPT 签发 mcp:write 授权,
    再单独启 flag 才真正写 ECS (分层控制).

    匹配规则 (OR):
    - client_id 精确命中 authorized_clients
    - redirect_uri 命中 authorized_redirect_uris (ChatGPT 每次 DCR 会换 client_id,
      但 redirect_uri 是 connector 固定标识; 安全由 OAuth 密码门禁保证)
    """
    p = load_policy()
    clients = p.get("authorized_clients", [])
    redirects = p.get("authorized_redirect_uris", [])
    if not clients and not redirects:
        return False
    # "*" 不代表具体白名单身份 — 不开放给全部客户端
    if clients and "*" in clients:
        return False
    if clients and client_identity in clients:
        return True
    if redirects and redirect_uri in redirects:
        return True
    return False


def check_forbidden(operation: str, file_paths: list, patch_text: str = "") -> tuple[bool, str]:
    """检查是否触发高风险禁区. 返回 (是否安全, 原因)."""
    p = load_policy()
    forbidden = p.get("forbidden_operations", [])
    combined = " ".join([operation] + (file_paths or []) + [patch_text or ""]).lower()
    for kw in forbidden:
        if kw.lower() in combined:
            return False, f"forbidden high-risk operation matched: '{kw}'"
    return True, "ok"


def check_file_allowed(file_paths: list) -> tuple[bool, str]:
    """检查文件是否在允许修改的 glob 范围内."""
    p = load_policy()
    allowed = p.get("allowed_file_globs", [])
    import fnmatch
    for fp in file_paths:
        matched = any(fnmatch.fnmatch(fp, g) for g in allowed)
        if not matched:
            return False, f"file '{fp}' not in allowed globs"
    return True, "ok"


def check_target_allowed(target: str) -> tuple[bool, str]:
    p = load_policy()
    allowed = p.get("allowed_targets", [])
    if target not in allowed:
        return False, f"target '{target}' not in allowed_targets {allowed}"
    return True, "ok"


def check_auto_authorized(client_identity: str, operation: str, target: str,
                          file_paths: list, patch_text: str = "") -> tuple[bool, str]:
    """综合授权检查 (auto-execute 入口)."""
    if not policy_enabled():
        return False, "auto-execute mode disabled (policy not enabled)"
    if not is_client_authorized(client_identity):
        return False, "client identity not in authorized_clients"
    ok, reason = check_target_allowed(target)
    if not ok:
        return False, reason
    ok, reason = check_file_allowed(file_paths)
    if not ok:
        return False, reason
    ok, reason = check_forbidden(operation, file_paths, patch_text)
    if not ok:
        return False, reason
    return True, "ok"


if __name__ == "__main__":
    print("Auto-authorization policy module.")
    print("  policy file:", POLICY_FILE)
    print("  enabled:", policy_enabled())
    print("  policy:", json.dumps(load_policy(), indent=2, ensure_ascii=False))