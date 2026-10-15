#!/usr/bin/env python3
"""Stage 4.6 隔离测试: 验证 bridge 注入可信 client_id + 授权矩阵."""
import json, subprocess, sys

TOK = json.load(open('/tmp/stage46_tokens.json'))
LEGIT = TOK['legit']
OLD = TOK['old']       # 不在白名单的旧 client
READONLY = TOK['readonly']  # 只有 mcp:read

URL = "https://mcp.hermes.toothingbeginning.com/mcp"


def call_auto_execute(token, client_identity="chatgpt", patch="x = 1  # test",
                      target="mock_ecs", task_id="t46"):
    """用给定 token 调 hermes_auto_execute, 返回 JSON-RPC 响应文本."""
    args = {
        "task_id": task_id, "requirement": "stage46 test",
        "target_file": "app.py", "patch": patch,
        "target": target, "client_identity": client_identity,
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "hermes_auto_execute", "arguments": args}}
    headers = ["-H", "Content-Type: application/json", "-H", "Accept: application/json",
               "-H", "Mcp-Method: tools/call"]
    if token:
        headers += ["-H", f"Authorization: Bearer {token}"]
    cmd = ["curl", "-s", "-X", "POST", URL] + headers + ["-d", json.dumps(body)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return r.stdout


def extract(out):
    """提取 (是否 scope 拒绝, 返回 json)."""
    try:
        d = json.loads(out)
    except Exception:
        return ("PARSE_ERR", out[:120])
    txt = json.dumps(d, ensure_ascii=False)
    if "mcp:write scope required" in txt:
        return ("SCOPE_DENIED", d)
    if "Authorization" in txt or "Invalid bearer" in txt or "Missing or invalid" in txt:
        return ("AUTH_DENIED", d)
    # 提取 tool 返回的 text
    try:
        content = d["result"]["content"][0]["text"]
        inner = json.loads(content)
        reason = inner.get("reason", "")
        return ("TOOL_RESULT", {"ok": inner.get("ok"), "reason": reason, "stage": inner.get("stage")})
    except Exception:
        return ("OTHER", d)


results = []
def check(name, cond, detail):
    results.append((name, cond, detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}: {detail}")

print("=== Stage 4.6 隔离测试 ===")
print()
print("--- T1: 合法客户端 + 伪造 client_identity='chatgpt' (bridge 应注入真实 client_id) ---")
kind, d = extract(call_auto_execute(LEGIT, client_identity="chatgpt"))
if kind == "TOOL_RESULT":
    # 期望: 不是 "client identity not in authorized_clients"
    is_identity_denied = "client identity not in authorized_clients" in d["reason"]
    check("T1 合法客户端通过身份判定", not is_identity_denied,
          f"reason={d['reason'][:60]}")
else:
    check("T1 合法客户端", False, f"kind={kind} detail={json.dumps(d, ensure_ascii=False)[:120]}")

print()
print("--- T2: 旧 client (AgYsC, 不在白名单) → 应拒绝 client identity ---")
kind, d = extract(call_auto_execute(OLD, client_identity=""))
if kind == "TOOL_RESULT":
    is_identity_denied = "client identity not in authorized_clients" in d["reason"]
    check("T2 未知客户端被拒绝", is_identity_denied, f"reason={d['reason'][:60]}")
else:
    check("T2 未知客户端", False, f"kind={kind} detail={json.dumps(d, ensure_ascii=False)[:120]}")

print()
print("--- T3: mcp:read 客户端 → 应 scope 拒绝 ---")
kind, d = extract(call_auto_execute(READONLY, client_identity="chatgpt"))
check("T3 mcp:read scope 拒绝", kind == "SCOPE_DENIED", f"kind={kind}")

print()
print("--- T4: 无 token → 应 401 认证拒绝 ---")
kind, d = extract(call_auto_execute(None, client_identity="chatgpt"))
check("T4 无 token 401 拒绝", kind == "AUTH_DENIED", f"kind={kind}")

print()
print("--- T5: 危险操作 (DROP TABLE) → 应 forbidden 拒绝 ---")
kind, d = extract(call_auto_execute(LEGIT, client_identity="chatgpt",
                                    patch="DROP TABLE customers;"))
if kind == "TOOL_RESULT":
    is_forbidden = "forbidden" in d["reason"] or "high-risk" in d["reason"]
    check("T5 危险操作拒绝", is_forbidden, f"reason={d['reason'][:60]}")
else:
    check("T5 危险操作", False, f"kind={kind} detail={json.dumps(d, ensure_ascii=False)[:120]}")

print()
print("=== 结果汇总 ===")
passed = sum(1 for _, c, _ in results if c)
print(f"  {passed}/{len(results)} PASS")
sys.exit(0 if passed == len(results) else 1)