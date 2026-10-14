#!/usr/bin/env python3
"""OAuth 2.1 完整流程端到端测试 (模拟 ChatGPT 连接 Hermes MCP)."""
import base64
import hashlib
import json
import secrets
import urllib.parse
import urllib.request
import urllib.error

BASE = "https://mcp.hermes.toothingbeginning.com"
REDIRECT = "https://chatgpt.com/connector/callback"  # 模拟 ChatGPT redirect_uri

def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def req(method, url, data=None, headers=None, form=False):
    h = {"Accept": "application/json", **({"Content-Type": "application/x-www-form-urlencoded"} if form else {"Content-Type": "application/json"}), **(headers or {})}
    body = None
    if data is not None:
        body = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    # 禁用自动重定向, 手动捕获 302 Location
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(r, timeout=20)
        return resp.status, dict(resp.info()), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"  {'✅' if ok else '❌'} {name}: {detail}")

print("=== OAuth 2.1 端到端测试 ===\n")

# 1. metadata
status, h, body = req("GET", f"{BASE}/.well-known/oauth-authorization-server")
meta = json.loads(body)
check("1. metadata 端点", status == 200 and "authorization_endpoint" in meta,
      f"status={status}, auth_ep={meta.get('authorization_endpoint','')[:50]}")

# 2. DCR 注册 client
print("\n--- 2. DCR 客户端注册 ---")
dcr = {"client_name": "ChatGPT-test-connector", "redirect_uris": [REDIRECT],
       "grant_types": ["authorization_code", "refresh_token"],
       "response_types": ["code"], "token_endpoint_auth_method": "none"}
status, h, body = req("POST", f"{BASE}/oauth/register", data=dcr)
d = json.loads(body)
client_id = d.get("client_id", "")
check("2. DCR 注册", status in (200, 201) and client_id, f"status={status}, client_id={client_id[:16]}...")

# 3. PKCE
verifier = b64url(secrets.token_bytes(32))
challenge = b64url(hashlib.sha256(verifier.encode()).digest())
print(f"--- 3. PKCE: verifier={verifier[:16]}... challenge={challenge[:16]}...")

# 4. authorize (显示授权页)
print("\n--- 4. authorize 授权码流程 ---")
aq = urllib.parse.urlencode({
    "client_id": client_id, "redirect_uri": REDIRECT, "response_type": "code",
    "code_challenge": challenge, "code_challenge_method": "S256",
    "scope": "mcp:read", "state": "teststate123",
})
status, h, body = req("GET", f"{BASE}/oauth/authorize?{aq}")
check("4a. authorize 显示授权页", status == 200 and "授权" in body or "允许" in body,
      f"status={status}, 页面含'允许'={('允许' in body or '授权' in body)}")

# 5. 用户允许 → 302 redirect 拿 code
print("\n--- 5. 用户点允许 (allowed=1) ---")
status, h, body = req("GET", f"{BASE}/oauth/authorize?{aq}&allowed=1")
location = h.get("Location", h.get("location", ""))
check("5a. allowed=1 → 302", status == 302 and "code=" in location, f"status={status}, location含code={'code=' in location}")
# 从 location 提取 code
parsed = urllib.parse.urlparse(location)
qs = urllib.parse.parse_qs(parsed.query)
code = qs.get("code", [""])[0]
state_back = qs.get("state", [""])[0]
check("5b. 提取 code", bool(code), f"code={code[:16]}...")
check("5c. state 回传", state_back == "teststate123", f"state={state_back}")

# 6. code + verifier 换 token
print("\n--- 6. code → access token ---")
status, h, body = req("POST", f"{BASE}/oauth/token", form=True, data={
    "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
    "client_id": client_id, "code_verifier": verifier,
})
t = json.loads(body)
access_token = t.get("access_token", "")
refresh_token = t.get("refresh_token", "")
check("6. token 交换", status == 200 and access_token, f"status={status}, access={access_token[:16]}...")
check("6b. scope", t.get("scope") == "mcp:read", f"scope={t.get('scope')}")

# 7. 用 access_token 调 MCP initialize
print("\n--- 7. access_token 调 /mcp ---")
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":1,"method":"initialize",
    "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"chatgpt","version":"1.0"}}},
    headers={"Authorization": f"Bearer {access_token}"})
r = json.loads(body)
check("7. MCP initialize (OAuth token)", status == 200 and "serverInfo" in r.get("result", {}),
      f"status={status}, serverInfo={r.get('result',{}).get('serverInfo')}")

# 8. tools/list
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":2,"method":"tools/list"},
    headers={"Authorization": f"Bearer {access_token}"})
r = json.loads(body)
tools = [t["name"] for t in r.get("result", {}).get("tools", [])]
check("8. tools/list (OAuth token)", status == 200 and len(tools) == 5, f"status={status}, tools={tools}")

# 9. 无 token / 错 token → 401
print("\n--- 9. 安全测试 ---")
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":3,"method":"tools/list"})
check("9a. 无 token → 401", status == 401, f"status={status}")
status, h, body = req("POST", f"{BASE}/mcp", data={"jsonrpc":"2.0","id":4,"method":"tools/list"},
    headers={"Authorization": "Bearer wrong-access-token"})
check("9b. 错 token → 401", status == 401, f"status={status}")

# 10. refresh token
print("\n--- 10. refresh_token 轮换 ---")
status, h, body = req("POST", f"{BASE}/oauth/token", form=True, data={
    "grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id,
})
t2 = json.loads(body)
check("10. refresh 成功", status == 200 and t2.get("access_token"), f"status={status}, new_access={t2.get('access_token','')[:16]}...")

# 汇总
print("\n" + "=" * 50)
passed = sum(1 for _, ok, _ in results if ok)
total = len(results)
print(f"结果: {passed}/{total} 通过")
for name, ok, detail in results:
    if not ok:
        print(f"  失败: {name} — {detail}")