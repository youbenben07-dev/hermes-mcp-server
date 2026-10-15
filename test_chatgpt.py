#!/usr/bin/env python3
"""Stage 3.7 完整端到端测试 - 真实模拟 ChatGPT Custom MCP Connector."""
import base64, hashlib, json, secrets, urllib.parse, urllib.request, urllib.error

BASE = "https://mcp.hermes.toothingbeginning.com"
REDIRECT = "https://chatgpt.com/connector/callback"

def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

def req(method, url, data=None, headers=None, form=False, raw=False):
    h = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}
    if form:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        h["Content-Type"] = "application/json"
    if headers: h.update(headers)
    body = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(r, timeout=20)
        return resp.status, dict(resp.info()), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()

results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"  {'✅' if ok else '❌'} {name}: {detail}")

print("=== Stage 3.7 ChatGPT 兼容性端到端测试 ===\n")

# 1. 401 + WWW-Authenticate
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ChatGPT-MCP-Connector/1.0","version":"1.0"}}})
wa = h.get('www-authenticate', h.get('Www-Authenticate', ''))
check("1. initialize 401 + WWW-Authenticate", status == 401 and "resource_metadata" in wa, f"status={status}, WWW-Auth={wa[:80]}")

# 2. DCR
status, h, body = req("POST", f"{BASE}/oauth/register",
    data={"client_name":"ChatGPT-test","redirect_uris":[REDIRECT],
          "grant_types":["authorization_code","refresh_token"],"response_types":["code"],
          "token_endpoint_auth_method":"none","scope":"mcp:read"})
client_id = json.loads(body).get("client_id", "")
check("2. DCR 注册", status in (200,201) and client_id, f"client_id={client_id[:16]}...")

# 3. PKCE
verifier = b64url(secrets.token_bytes(32))
challenge = b64url(hashlib.sha256(verifier.encode()).digest())

# 4. authorize 显示密码页
aq = urllib.parse.urlencode({
    "client_id": client_id, "redirect_uri": REDIRECT, "response_type": "code",
    "code_challenge": challenge, "code_challenge_method": "S256", "scope": "mcp:read", "state": "st123",
})
status, h, body = req("GET", f"{BASE}/oauth/authorize?{aq}")
check("4. authorize GET 显示密码页", status == 200 and "password" in body.lower(), f"status={status}, 含password={'password' in body.lower()}")

# 5. 错误密码 -> 401
status, h, body = req("POST", f"{BASE}/oauth/authorize", form=True, data={
    "client_id": client_id, "redirect_uri": REDIRECT,
    "code_challenge": challenge, "code_challenge_method": "S256",
    "state": "st123", "scope": "mcp:read", "password": "wrong",
})
check("5. 错密码 -> 401", status == 401, f"status={status}")

# 6. 正确密码 -> 302 + code (Stage 3.7.1: 直接给 code, 无 grant_token 中转)
status, h, body = req("POST", f"{BASE}/oauth/authorize", form=True, data={
    "client_id": client_id, "redirect_uri": REDIRECT,
    "code_challenge": challenge, "code_challenge_method": "S256",
    "state": "st123", "scope": "mcp:read", "password": "hermes-oauth-2026",
})
loc = h.get('Location', h.get('location', ''))
check("6. 对密码 -> 302 + code (直接)", status == 302 and "code=" in loc and "state=st123" in loc,
      f"status={status}, loc={loc[:100]}")
code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get('code', [''])[0]

# 9. code -> token
status, h, body = req("POST", f"{BASE}/oauth/token", form=True, data={
    "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
    "client_id": client_id, "code_verifier": verifier,
})
t = json.loads(body)
access = t.get("access_token", "")
refresh = t.get("refresh_token", "")
check("9. token 交换", status == 200 and access, f"access={access[:16]}...")
check("9b. 标准 token 字段", all(k in t for k in ["access_token","token_type","expires_in","refresh_token","scope"]), f"keys={list(t.keys())}")
check("9c. scope = mcp:read", t.get("scope") == "mcp:read", f"scope={t.get('scope')}")

# 10. MCP initialize (MCP 2025-06-18) -> Mcp-Session-Id + protocolVersion
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ChatGPT-MCP-Connector/1.0","version":"1.0"}}},
    headers={"Authorization": f"Bearer {access}"})
sid = h.get('mcp-session-id', h.get('Mcp-Session-Id', ''))
r = json.loads(body) if body else {}
check("10. initialize 200 + Mcp-Session-Id", status == 200 and sid, f"status={status}, sid={sid[:16] if sid else 'NONE'}")
check("10b. protocolVersion = 2025-06-18", r.get("result",{}).get("protocolVersion") == "2025-06-18",
      f"proto={r.get('result',{}).get('protocolVersion')}")

# 11. notifications/initialized -> 202 no body
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","method":"notifications/initialized"},
    headers={"Authorization": f"Bearer {access}", "Mcp-Session-Id": sid})
check("11. notifications/initialized = 202", status == 202, f"status={status}, body={body[:50] if body else '(empty)'}")

# 12. tools/list (5 工具)
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":2,"method":"tools/list"},
    headers={"Authorization": f"Bearer {access}", "Mcp-Session-Id": sid})
tools = json.loads(body).get("result",{}).get("tools",[])
check("12. tools/list 5 工具", status == 200 and len(tools) == 5, f"tools={[t['name'] for t in tools]}")

# 13. tools/call hermes_system_status
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":3,"method":"tools/call",
    "params":{"name":"hermes_system_status","arguments":{}}},
    headers={"Authorization": f"Bearer {access}", "Mcp-Session-Id": sid})
c = json.loads(body).get("result",{}).get("content",[])
data = json.loads(c[0]["text"]) if c else {}
health = data.get("cs_inbox_health_http")
check("13. tools/call hermes_system_status", status == 200 and str(health) == "200",
      f"health={health} (type={type(health).__name__}), worker_pid={data.get('worker_pid')}")

# 14. 5 工具全测
all_pass = True
for tname in ["hermes_ecs_shell","hermes_read_file","hermes_git_status","hermes_logs"]:
    if tname == "hermes_ecs_shell":
        args = {"command": "ps aux | head -3"}
    elif tname == "hermes_read_file":
        args = {"path": "/home/fastmedlink/cs-inbox/app.py"}
    elif tname == "hermes_git_status":
        args = {}
    elif tname == "hermes_logs":
        args = {"target": "worker", "lines": 5}
    status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":4,"method":"tools/call",
        "params":{"name":tname,"arguments":args}},
        headers={"Authorization": f"Bearer {access}", "Mcp-Session-Id": sid})
    r = json.loads(body)
    if status != 200 or "error" in r:
        all_pass = False
        print(f"    ❌ {tname}: status={status}, error={r.get('error')}")
    else:
        print(f"    ✅ {tname}: 200")
check("14. 5 工具全调", all_pass, "")

# 15. 危险命令仍拦截
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":5,"method":"tools/call",
    "params":{"name":"hermes_ecs_shell","arguments":{"command":"rm -rf /tmp/x"}}},
    headers={"Authorization": f"Bearer {access}", "Mcp-Session-Id": sid})
r = json.loads(body)
c = json.loads(r["result"]["content"][0]["text"])
check("15. 危险命令拦截", not c.get("ok"), f"error={c.get('error','')[:50]}")

# 16. 401 测试
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":6,"method":"tools/list"})
check("16. 无 token -> 401", status == 401, f"status={status}")
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":7,"method":"tools/list"},
    headers={"Authorization": "Bearer wrong"})
check("16b. 错 token -> 401", status == 401, f"status={status}")

# 17. refresh token
status, h, body = req("POST", f"{BASE}/oauth/token", form=True, data={
    "grant_type": "refresh_token", "refresh_token": refresh, "client_id": client_id,
})
t2 = json.loads(body)
check("17. refresh 成功", status == 200 and t2.get("access_token"), f"new_access={t2.get('access_token','')[:16]}")

# 汇总
print(f"\n=== 结果: {sum(1 for _,ok,_ in results if ok)}/{len(results)} 通过 ===")
for n, ok, d in results:
    if not ok: print(f"  ❌ {n}: {d}")