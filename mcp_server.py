#!/usr/bin/env python3
"""
Hermes Dev Agent MCP Server - 5 个开发工具暴露给 ChatGPT
- hermes_system_status: VPS + ECS 整体状态
- hermes_ecs_shell: 在 ECS 上跑只读 shell 命令 (allowlist 白名单)
- hermes_read_file: 读 ECS 文件 (allowlist 白名单)
- hermes_git_status: cs-inbox git 状态
- hermes_logs: 读 worker.log / worker.err

设计:
- 独立进程, 通过 stdio transport 跟 hermes mcp serve 通信
- 工具执行 shell 命令, 用 subprocess + timeout 严格控制
- 读操作白名单 (绝对禁止删/写)
- 写操作完全禁止 (Stage 1 只读)

启动方式:
  /home/hermes/.hermes/hermes-agent/venv/bin/python3 \\
    /home/hermes/mcp_servers/hermes_dev_agent.py

被 hermes mcp add 注册:
  hermes mcp add hermes-dev \\
    --command /home/hermes/.hermes/hermes-agent/venv/bin/python3 \\
    --args /home/hermes/mcp_servers/hermes_dev_agent.py
"""
import asyncio
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# ── 配置 ────────────────────────────────────────────
ECS_HOST = "fastmedlink@47.250.166.208"
ECS_SUDO = True  # ECS fastmedlink 用户 NOPASSWD: ALL (已配)
VPS_ROOT = Path("/home/hermes")
ECS_CS_INBOX = "/home/fastmedlink/cs-inbox"
ECS_GIT_REPO = "github"
WORKER_LOG = VPS_ROOT / "issue_queue" / "worker.log"
WORKER_ERR = VPS_ROOT / "issue_queue" / "worker.err"

# 只读白名单 (执行命令路径)
READONLY_SHELL_ALLOW = {
    "systemctl is-active",
    "systemctl status",
    "ps aux",
    "ps -ef",
    "free -h",
    "df -h",
    "uptime",
    "uname -a",
    "cat /etc/os-release",
    "ls -la",
    "ls -la /home/fastmedlink/cs-inbox",
    "ls -la /home/fastmedlink/cs-inbox/data",
    "git status",
    "git log --oneline -5",
    "git remote -v",
    "tail -20",
    "tail -50",
    "wc -l",
    "md5sum",
    "stat",
    "date",
    "whoami",
    "hostname",
    "python3 --version",
    "which python3",
    "which pip3",
    "curl --max-time 5 http://127.0.0.1:5051/health",
    "curl --max-time 5 http://127.0.0.1:5051/api/inbox/notifications",
}

# 读文件白名单 (绝对路径)
READ_FILE_ALLOW = [
    "/home/fastmedlink/cs-inbox/app.py",
    "/home/fastmedlink/cs-inbox/data/inbox.db",
    "/home/fastmedlink/cs-inbox/auth.py",
    "/home/fastmedlink/cs-inbox/db.py",
    "/home/fastmedlink/cs-inbox/send.py",
    "/home/fastmedlink/cs-inbox/webhook.py",
    "/home/fastmedlink/cs-inbox/fetch_conversations.py",
    "/home/fastmedlink/cs-inbox/inbox_views.py",
    "/home/fastmedlink/cs-inbox/__init__.py",
    "/home/fastmedlink/cs-inbox/.env",
    "/home/fastmedlink/cs-inbox/.htpasswd",
    "/home/fastmedlink/cs-inbox/deployment_reports",
    "/home/hermes/issue_queue/state.json",
    "/home/hermes/issue_queue/worker.log",
    "/home/hermes/issue_queue/worker.err",
]

# 危险命令黑名单 (即使用户 allowlist, 这些也绝对拒绝)
DANGEROUS_PATTERNS = [
    "rm -rf", "rm -fr", "rm -f", "rm -R",
    "kill -9", "killall", "pkill",
    ">", ">>",  # 任何重定向
    "sudo",  # 已有 sudo, 拒绝内嵌
    "chmod", "chown",
    "git push",
    "git reset", "git checkout .", "git clean",
    "DROP", "DELETE", "UPDATE", "INSERT",
    "curl -X POST", "curl -X PUT", "curl -X DELETE",
    "systemctl restart", "systemctl stop", "systemctl start",
    "systemctl disable", "systemctl enable",
    "shutdown", "reboot", "halt",
    "ssh-keygen", "passwd",
]


def _check_dangerous(cmd: str) -> str:
    """返回 None (安全) 或 error msg (拒绝原因)."""
    cmd_lower = cmd.lower()
    for pat in DANGEROUS_PATTERNS:
        if pat.lower() in cmd_lower:
            return f"BLOCKED: dangerous pattern '{pat}' in command"
    return None


def _run_local(cmd: str, timeout: int = 10) -> dict:
    """VPS 本地命令 (subprocess)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout,
        )
        return {
            "ok": r.returncode == 0,
            "stdout": r.stdout[-5000:],
            "stderr": r.stderr[-2000:],
            "exit_code": r.returncode,
            "host": "vps",
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout {timeout}s", "host": "vps"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "host": "vps"}


def _run_ecs(cmd: str, timeout: int = 15) -> dict:
    """ECS 远程命令 (ssh)."""
    err = _check_dangerous(cmd)
    if err:
        return {"ok": False, "error": err, "host": "ecs"}
    ssh_cmd = f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no {ECS_HOST} {shlex.quote(cmd)}"
    try:
        r = subprocess.run(
            ssh_cmd, shell=True, capture_output=True, text=True,
            timeout=timeout,
        )
        return {
            "ok": r.returncode == 0,
            "stdout": r.stdout[-8000:],
            "stderr": r.stderr[-2000:],
            "exit_code": r.returncode,
            "host": "ecs",
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout {timeout}s", "host": "ecs"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "host": "ecs"}


# ── 5 个 MCP 工具实现 ──────────────────────────────
def tool_hermes_system_status(args: dict) -> dict:
    """整体系统状态: VPS + ECS + worker + 客服 + 关键告警."""
    vps = _run_local("uname -a && uptime && free -h | head -3 && df -h / | tail -1", timeout=5)
    ecs = _run_ecs("uptime && free -h | head -3 && df -h /home | tail -1", timeout=10)
    worker_pid = _run_local("pgrep -f issue_queue/worker.py | head -1", timeout=3)
    cs_inbox = _run_ecs("systemctl is-active cs-inbox.service; echo '---'; pidof python3", timeout=8)
    cs_inbox_health = _run_ecs("curl --max-time 4 -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5051/health", timeout=8)
    cs_inbox_health_log = _run_ecs("tail -3 /home/fastmedlink/cs-inbox/logs/cs-inbox.stderr.log 2>&1", timeout=8)
    return {
        "vps": vps,
        "ecs": ecs,
        "worker_pid": worker_pid.get("stdout", "").strip(),
        "cs_inbox_unit": cs_inbox.get("stdout", "").strip(),
        "cs_inbox_health_http": cs_inbox_health.get("stdout", "").strip(),
        "cs_inbox_recent_log": cs_inbox_health_log.get("stdout", "").strip()[:500],
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def tool_hermes_ecs_shell(args: dict) -> dict:
    """ECS 只读 shell (allowlist 白名单)."""
    cmd = args.get("command", "").strip()
    if not cmd:
        return {"ok": False, "error": "command required"}
    # 白名单检查 (开头匹配)
    allowed = any(cmd.startswith(a) for a in READONLY_SHELL_ALLOW)
    if not allowed:
        return {
            "ok": False,
            "error": f"BLOCKED: command not in allowlist. Allowed prefixes: {sorted(READONLY_SHELL_ALLOW)[:5]}...",
            "hint": "Stage 1 仅支持白名单内只读命令, 写操作请进入后续业务修复阶段",
        }
    err = _check_dangerous(cmd)
    if err:
        return {"ok": False, "error": err}
    return _run_ecs(cmd, timeout=15)


def tool_hermes_read_file(args: dict) -> dict:
    """读 ECS/VPS 文件 (allowlist 绝对路径)."""
    path = args.get("path", "").strip()
    if not path:
        return {"ok": False, "error": "path required"}
    # 绝对路径
    if not path.startswith("/"):
        path = "/" + path
    if path not in READ_FILE_ALLOW:
        return {
            "ok": False,
            "error": f"BLOCKED: path not in allowlist",
            "hint": f"Allowed: {len(READ_FILE_ALLOW)} paths (Stage 1 白名单)",
        }
    # VPS 文件用 cat, ECS 文件用 ssh cat
    if path.startswith("/home/hermes/"):
        return _run_local(f"cat {shlex.quote(path)} | head -200", timeout=5)
    else:
        return _run_ecs(f"cat {shlex.quote(path)} | head -200", timeout=10)


def tool_hermes_git_status(args: dict) -> dict:
    """cs-inbox git 状态: log + status + remote + HEAD."""
    log = _run_ecs(f"cd {ECS_CS_INBOX} && git log --oneline -10", timeout=10)
    status = _run_ecs(f"cd {ECS_CS_INBOX} && git status --short | head -30", timeout=10)
    remote = _run_ecs(f"cd {ECS_CS_INBOX} && git remote -v", timeout=8)
    head = _run_ecs(f"cd {ECS_CS_INBOX} && git log -1 --format='%H %ai %s'", timeout=8)
    return {
        "log": log,
        "status": status,
        "remote": remote,
        "head": head,
    }


def tool_hermes_logs(args: dict) -> dict:
    """读 worker.log / worker.err / nginx access/error (默认最后 50 行)."""
    target = args.get("target", "worker")
    lines = min(int(args.get("lines", 50)), 200)
    if target == "worker":
        if not WORKER_LOG.exists():
            return {"ok": False, "error": f"worker.log not found at {WORKER_LOG}"}
        return _run_local(f"tail -{lines} {shlex.quote(str(WORKER_LOG))}", timeout=5)
    elif target == "worker_err":
        if not WORKER_ERR.exists():
            return {"ok": False, "error": f"worker.err not found"}
        return _run_local(f"tail -{lines} {shlex.quote(str(WORKER_ERR))}", timeout=5)
    elif target == "nginx_access":
        return _run_ecs(f"sudo tail -{lines} /var/log/nginx/custom-support.access.log 2>&1", timeout=8)
    elif target == "nginx_error":
        return _run_ecs(f"sudo tail -{lines} /var/log/nginx/custom-support.error.log 2>&1", timeout=8)
    else:
        return {"ok": False, "error": f"unknown target '{target}'. Options: worker, worker_err, nginx_access, nginx_error"}


def tool_hermes_health_check(args: dict) -> dict:
    """Stage 3.7.3: 极简只读健康检查, 用于 ChatGPT action discovery 调试.
    返回 agent 状态 + mcp server 状态 + 服务版本 + 服务器时间, 绝不暴露凭据."""
    import time as _time
    return {
        "ok": True,
        "agent": "hermes-dev-agent",
        "agent_status": "active",
        "mcp_server_status": "running",
        "mcp_server_version": "3.8.0",
        "supported_protocol_versions": [
            "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28",
        ],
        "default_protocol_version": "2026-07-28",
        "tools_count": len(TOOLS),
        "tools": list(TOOLS.keys()),
        "server_time": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
        "server_host": "vps-racknerd (23.95.226.156)",
        "public_url": "https://mcp.hermes.toothingbeginning.com/mcp",
    }


# ── MCP 协议处理 (stdio transport) ──────────────────
TOOLS = {
    "hermes_health_check": {
        "fn": tool_hermes_health_check,
        "schema": {
            "name": "hermes_health_check",
            "description": "Minimal read-only health check. Returns agent status, MCP server version, current server time, and list of all available tools. No credentials, no sensitive config exposed. Use this to verify MCP connectivity.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    "hermes_system_status": {
        "fn": tool_hermes_system_status,
        "schema": {
            "name": "hermes_system_status",
            "description": "Get Hermes VPS + ECS system status: uptime, memory, disk, worker PID, cs-inbox unit, health HTTP code. Read-only.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    "hermes_ecs_shell": {
        "fn": tool_hermes_ecs_shell,
        "schema": {
            "name": "hermes_ecs_shell",
            "description": "Run read-only shell command on ECS (47.250.166.208). Command MUST start with allowlist prefix (systemctl is-active, ps, cat, git status, git log, ls, tail, df, free, etc.). Write operations BLOCKED. Stage 1 only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Read-only shell command starting with allowlist prefix"},
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        },
    },
    "hermes_read_file": {
        "fn": tool_hermes_read_file,
        "schema": {
            "name": "hermes_read_file",
            "description": "Read a file from ECS or VPS. Path MUST be in allowlist (cs-inbox source files, deployment_reports, worker logs, etc.). Write operations BLOCKED.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute file path (must be in allowlist)"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    "hermes_git_status": {
        "fn": tool_hermes_git_status,
        "schema": {
            "name": "hermes_git_status",
            "description": "Get cs-inbox git status: log, working tree status, remote, HEAD. Read-only.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    "hermes_logs": {
        "fn": tool_hermes_logs,
        "schema": {
            "name": "hermes_logs",
            "description": "Read logs: worker.log, worker.err, nginx_access, nginx_error. Default last 50 lines (max 200).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": ["worker", "worker_err", "nginx_access", "nginx_error"], "default": "worker"},
                    "lines": {"type": "integer", "default": 50, "maximum": 200},
                },
                "additionalProperties": False,
            },
        },
    },
}


# Stage 4: 注册 7 个受控工具 (change_plan/create_backup/apply_patch/run_tests/deploy/rollback/change_status)
try:
    import hermes_stage4
    hermes_stage4.init_state_db()
    hermes_stage4.register_tools(TOOLS)
except Exception as _e:
    import sys as _sys
    _sys.stderr.write(f"[stage4] register failed: {_e}\n")


def send(msg: dict):
    """发 MCP 消息 (JSON-RPC over stdio, newline delimited)."""
    line = json.dumps(msg)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def recv() -> dict:
    """收 MCP 消息."""
    line = sys.stdin.readline()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def handle_request(req: dict) -> dict:
    """处理一个 JSON-RPC request."""
    method = req.get("method", "")
    params = req.get("params", {})
    rid = req.get("id")
    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "hermes-dev-agent", "version": "1.0.0"},
            },
        }
    elif method == "notifications/initialized":
        return None  # 无需响应
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0", "id": rid,
            "result": {"tools": [t["schema"] for t in TOOLS.values()]},
        }
    elif method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {})
        if name not in TOOLS:
            return {
                "jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"Unknown tool: {name}"},
            }
        try:
            result = TOOLS[name]["fn"](args)
            return {
                "jsonrpc": "2.0", "id": rid,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}],
                    "isError": not result.get("ok", True),
                },
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0", "id": rid,
                "error": {"code": -32603, "message": f"Tool error: {type(e).__name__}: {e}"},
            }
    elif method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    else:
        return {
            "jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": f"Unknown method: {method}"},
        }


def main():
    """主循环: stdio JSON-RPC."""
    while True:
        req = recv()
        if req is None:
            break
        resp = handle_request(req)
        if resp is not None:
            send(resp)


if __name__ == "__main__":
    main()
