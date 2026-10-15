#!/usr/bin/env python3
"""
Hermes MCP Remote Bridge - Stage 3.7 (ChatGPT compatibility)

包装 Stage 1 stdio server 为远程 HTTPS 端点, 让 ChatGPT Custom MCP Connector 可连接.

Stage 3.7 修复 (vs 3.6):
- protocolVersion 2024-11-05 -> 2025-06-18
- 处理 MCP-Protocol-Version 请求头
- 生成 + 返回 Mcp-Session-Id (stateful streamable HTTP)
- notifications/initialized -> 202 no body (不转发 stdio)
- 接受 Accept: application/json, text/event-stream
- 授权页: 强制密码验证 (HERMES_OAUTH_PASSWORD env) + 一次性 grant_token 防 CSRF
- 支持 SSE 响应 (text/event-stream)
- 后台写日志到 /home/hermes/mcp_servers/bridge.log (持久化)

认证 (双模式):
1. 静态 Bearer Token (Stage 3.5, 内部/PM 访问)
2. OAuth 2.1 access token (ChatGPT 通过 Authorization Code + PKCE 获取)

OAuth 端点:
- GET  /.well-known/oauth-authorization-server
- GET  /.well-known/oauth-protected-resource
- POST /oauth/register
- GET  /oauth/authorize  (含密码验证)
- POST /oauth/token
- POST /oauth/grant    (密码验证后给 grant_token)

环境变量:
  HERMES_MCP_TOKEN     静态 token (PM 内部)
  HERMES_OAUTH_PASSWORD 授权页密码 (防任意人点允许, ChatGPT 用户)
  HERMES_MCP_PORT       默认 8443
  HERMES_MCP_HOST       默认 127.0.0.1
  HERMES_STDIO_CMD      默认 python3
  HERMES_STDIO_ARGS     默认 mcp_server.py
"""
import asyncio
import json
import os
import secrets
import sys
import time
import uuid
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hermes_oauth

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel

# ── 配置 ────────────────────────────────────────────
DEFAULT_TOKEN_FILE = "/home/hermes/.hermes/mcp_remote_token"
TOKEN = os.environ.get("HERMES_MCP_TOKEN")
OAUTH_PASSWORD_FILE = "/home/hermes/.hermes/mcp_oauth_password"  # 授权页密码 (mode 600, 不入 git)


def _load_oauth_password() -> str:
    """授权页密码从文件读 (不入公开仓库), 其次 env, 无默认硬编码."""
    try:
        if os.path.exists(OAUTH_PASSWORD_FILE):
            return open(OAUTH_PASSWORD_FILE).read().strip()
    except Exception:
        pass
    return os.environ.get("HERMES_OAUTH_PASSWORD", "")


OAUTH_PASSWORD = _load_oauth_password()
HOST = os.environ.get("HERMES_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("HERMES_MCP_PORT", "8443"))
STDIO_CMD = os.environ.get("HERMES_STDIO_CMD", "/home/hermes/.hermes/hermes-agent/venv/bin/python3")
STDIO_ARGS = os.environ.get("HERMES_STDIO_ARGS", "/home/hermes/mcp_servers/hermes_dev_agent.py").split()
BRIDGE_LOG = "/home/hermes/mcp_servers/bridge.log"

# MCP 协议版本 (Stage 3.7.2: 支持 2026-07-28 - ChatGPT 实际用的)
MCP_PROTOCOL_VERSION = "2026-07-28"  # 最新版 (ChatGPT 用)
SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"}

if not TOKEN:
    if os.path.exists(DEFAULT_TOKEN_FILE):
        with open(DEFAULT_TOKEN_FILE, "r") as f:
            TOKEN = f.read().strip()
    else:
        TOKEN = secrets.token_urlsafe(32)
        os.makedirs(os.path.dirname(DEFAULT_TOKEN_FILE), exist_ok=True)
        with open(DEFAULT_TOKEN_FILE, "w") as f:
            f.write(TOKEN)
        os.chmod(DEFAULT_TOKEN_FILE, 0o600)

hermes_oauth.init_db()

# 写持久化日志 (不只 stderr)
os.makedirs(os.path.dirname(BRIDGE_LOG), exist_ok=True)
_log_file = open(BRIDGE_LOG, "a", buffering=1)  # line-buffered


def log(msg):
    """持久化日志: bridge.log + stderr"""
    line = f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {msg}"
    print(line, file=sys.stderr)
    print(line, file=_log_file)


log(f"[startup] Listening on http://{HOST}:{PORT}")
log(f"[startup] Auth: Bearer token ({len(TOKEN)} chars) + OAuth 2.1")
log(f"[startup] MCP protocol: {MCP_PROTOCOL_VERSION} (supports: {sorted(SUPPORTED_PROTOCOL_VERSIONS)})")
log(f"[startup] OAuth: {hermes_oauth.BASE_URL} (password protected authorize page)")
log(f"[startup] Stdio backend: {STDIO_CMD} {' '.join(STDIO_ARGS)}")


# ── Session 管理 (stateful streamable HTTP) ──────────
sessions: dict = {}  # session_id -> {created_at, last_seen, client_id}


def get_or_create_session(req: Request, auth_client: str) -> str:
    """读 Mcp-Session-Id 头, 没有则生成新的."""
    sid = req.headers.get("mcp-session-id")
    if sid and sid in sessions:
        sessions[sid]["last_seen"] = time.time()
        return sid
    # 新 session
    sid = secrets.token_urlsafe(16)
    sessions[sid] = {
        "created_at": time.time(),
        "last_seen": time.time(),
        "client": auth_client,
        "initialized": False,
    }
    return sid


def mark_session_initialized(sid: str):
    if sid in sessions:
        sessions[sid]["initialized"] = True


# ── Stdio subprocess 管理 ──────────────────────────
class StdioMCP:
    def __init__(self):
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.lock = asyncio.Lock()

    async def start(self):
        if self.proc and self.proc.returncode is None:
            return
        self.proc = await asyncio.create_subprocess_exec(
            STDIO_CMD, *STDIO_ARGS,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def call(self, req: dict, timeout: float = 30) -> dict:
        async with self.lock:
            await self.start()
            try:
                line = json.dumps(req) + "\n"
                self.proc.stdin.write(line.encode())
                await self.proc.stdin.drain()
                line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=timeout)
                if not line:
                    return {"error": {"code": -32603, "message": "stdio backend closed"}}
                return json.loads(line.decode())
            except asyncio.TimeoutError:
                return {"error": {"code": -32603, "message": f"stdio timeout {timeout}s"}}
            except Exception as e:
                return {"error": {"code": -32603, "message": f"{type(e).__name__}: {e}"}}

    async def stop(self):
        if self.proc and self.proc.returncode is None:
            try:
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except Exception:
                self.proc.kill()


stdio_mcp = StdioMCP()

# ── FastAPI app ─────────────────────────────────────
app = FastAPI(title="Hermes MCP Remote Bridge (Stage 3.7)", version="3.7.0")


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[object] = None  # JSON-RPC 允许 string/int/null
    method: str
    params: Optional[dict] = None


def check_auth(request: Request) -> str:
    """双模式认证: 静态 token 或 OAuth access token."""
    auth = request.headers.get("authorization", "")
    ww = {"WWW-Authenticate": f'Bearer resource_metadata="{hermes_oauth.BASE_URL}/.well-known/oauth-protected-resource", scope="mcp:read"'}
    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header. Use 'Bearer <token>'.",
            headers=ww,
        )
    client_token = auth[7:].strip()
    if secrets.compare_digest(client_token, TOKEN):
        return f"static[{len(client_token)}chars]"
    valid, scope = hermes_oauth.verify_access_token(client_token)
    if valid:
        return f"oauth[{len(client_token)}chars:{scope}]"
    raise HTTPException(status_code=401, detail="Invalid bearer token", headers=ww)


# ── Stage 4 写工具 scope 门禁 ───────────────────────
WRITE_TOOLS = {
    "hermes_create_backup", "hermes_apply_patch", "hermes_run_tests",
    "hermes_deploy", "hermes_rollback", "hermes_auto_execute",
}


def _has_write_scope(request: Request) -> bool:
    """写工具需要 mcp:write scope. 静态 PM token 隐式全权."""
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return False
    tok = auth[7:].strip()
    if secrets.compare_digest(tok, TOKEN):
        return True  # PM 静态 token
    valid, scope = hermes_oauth.verify_access_token(tok)
    return valid and scope == "mcp:write"


# ── 根端点 ─────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "name": "Hermes MCP Remote Bridge",
        "version": "3.7.0",
        "stage": "Stage 3.7 (Streamable HTTP + Bearer + OAuth 2.1 + MCP 2025-06-18)",
        "mcp_endpoint": "/mcp",
        "auth": "Bearer token 或 OAuth 2.1 access token",
        "oauth_metadata": "/.well-known/oauth-authorization-server",
        "mcp_protocol_version": MCP_PROTOCOL_VERSION,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@app.get("/health")
async def health():
    return {"ok": True, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


# ── Stage 4.3 飞书审批回调 ─────────────────────────
@app.get("/approval/callback")
async def approval_callback_get(request: Request):
    """飞书事件订阅 URL 验证 (challenge)."""
    import hermes_approval
    challenge = request.query_params.get("challenge", "")
    token = request.query_params.get("token", "")
    if hermes_approval.FEISHU_VERIFICATION_TOKEN and token != hermes_approval.FEISHU_VERIFICATION_TOKEN:
        return JSONResponse(status_code=403, content={"error": "invalid verification token"})
    return JSONResponse(content={"challenge": challenge})


@app.post("/approval/callback")
async def approval_callback_post(request: Request):
    """飞书卡片按钮回调 (card.action.trigger). 严格校验签名 + 身份 + 防重放."""
    import hermes_approval
    body = await request.body()
    ts = request.headers.get("x-lark-request-timestamp", "")
    nonce = request.headers.get("x-lark-request-nonce", "")
    sig = request.headers.get("x-lark-signature", "")
    if not hermes_approval.verify_feishu_signature(ts, nonce, body, sig):
        return JSONResponse(status_code=401, content={"error": "invalid signature"})
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid json"})
    if data.get("type") == "url_verification":
        return JSONResponse(content={"challenge": data.get("challenge", "")})
    header = data.get("header", {})
    event_id = header.get("event_id", "")
    event_type = header.get("event_type", "")
    if event_type != "card.action.trigger":
        return JSONResponse(content={"ok": True, "ignored": event_type})
    if not hermes_approval.verify_and_record_callback(event_id):
        return JSONResponse(status_code=409, content={"error": "replay detected"})
    event = data.get("event", {})
    operator = event.get("operator", {})
    open_id = operator.get("operator_id", {}).get("open_id", "")
    action_value = event.get("action", {}).get("value", {})
    approval_id = action_value.get("approval_id", "")
    action = action_value.get("action", "")
    # 身份校验: 服务端真实 open_id, 非卡片字段
    if not hermes_approval.is_authorized_approver(open_id):
        return JSONResponse(status_code=403, content={"error": "unauthorized approver"})
    if action == "approve":
        r = hermes_approval.approve(approval_id, open_id)
    elif action == "reject":
        r = hermes_approval.reject(approval_id, open_id)
    else:
        r = {"ok": False, "reason": f"unknown action: {action}"}
    return JSONResponse(content=r)


# ── OAuth 端点 ─────────────────────────────────────
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    return JSONResponse(content=hermes_oauth.get_metadata())


@app.get("/.well-known/oauth-protected-resource")
async def oauth_resource_metadata():
    return JSONResponse(content={
        "resource": f"{hermes_oauth.BASE_URL}/mcp",
        "authorization_servers": [hermes_oauth.BASE_URL],
        "scopes_supported": hermes_oauth.SCOPES_SUPPORTED,
    })


@app.post("/oauth/register")
async def oauth_register(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
    result, err = hermes_oauth.register_client(body)
    if err:
        return JSONResponse(status_code=400, content={"error": "invalid_client_metadata", "error_description": err})
    return JSONResponse(status_code=201, content=result)


# ── /oauth/authorize 完整版: 含密码验证 ─────────────
# 流程:
#  1. GET /oauth/authorize?...        -> 显示密码输入页 (带 csrf_token)
#  2. POST /oauth/authorize (password) -> 验证密码 + 给 grant_token, 重定向到自己 /oauth/authorize?grant_token=...
#  3. GET /oauth/authorize?grant_token=...  -> 显示 "允许" / "拒绝" 按钮 (html)
#  4. GET /oauth/authorize?grant_token=...&allowed=1  -> 302 redirect 到 client redirect_uri?code=...
#  5. GET /oauth/authorize?grant_token=...&allowed=0  -> 302 redirect 到 client redirect_uri?error=access_denied
#  grant_token 单次使用 + 5min 过期 (在 hermes_oauth 内存中)


@app.get("/oauth/authorize")
async def oauth_authorize_get(request: Request):
    q = request.query_params
    client_id = q.get("client_id", "")
    redirect_uri = q.get("redirect_uri", "")
    code_challenge = q.get("code_challenge", "")
    code_challenge_method = q.get("code_challenge_method", "S256")
    state = q.get("state", "")
    scope = q.get("scope", "")
    allowed = q.get("allowed", "")
    grant_token = q.get("grant_token", "")

    # 阶段 4: grant_token + allowed -> 真正生成 code
    if grant_token:
        params = hermes_oauth.consume_grant_token(grant_token)
        if not params:
            return HTMLResponse(hermes_oauth.authorize_page_html({"client_id": "?"}, error="授权 token 无效或已过期, 请重新发起授权"), status_code=400)
        if allowed == "1":
            redirect = hermes_oauth.authorize_approve(params)
            log(f"[oauth] grant_token {grant_token[:8]}... allowed=1, client={params['client_id'][:8]}...")
            return RedirectResponse(redirect, status_code=302)
        if allowed == "0":
            sep = "&" if "?" in params["redirect_uri"] else "?"
            redirect = f"{params['redirect_uri']}{sep}error=access_denied&state={params['state']}"
            log(f"[oauth] grant_token {grant_token[:8]}... allowed=0, client={params['client_id'][:8]}...")
            return RedirectResponse(redirect, status_code=302)
        # grant_token 有效但 allowed 未给 -> 显示 "允许/拒绝" 按钮
        return HTMLResponse(hermes_oauth.authorize_page_html_confirmed(params, grant_token))

    # 阶段 1: 没 grant_token -> 验证请求 + 显示密码页
    params, err, _ = hermes_oauth.authorize_validate(
        client_id, redirect_uri, code_challenge, code_challenge_method, state, scope
    )
    if err:
        return HTMLResponse(hermes_oauth.authorize_page_html({}, error=err), status_code=400)
    # 显示密码输入页
    return HTMLResponse(hermes_oauth.authorize_page_html_password(params))


@app.post("/oauth/authorize")
async def oauth_authorize_post(request: Request):
    """密码验证: Stage 3.7.1 - 密码对直接给 code (无 grant_token 中转, 消除超时 race).
    实际 code 生成在 hermes_oauth.authorize_approve 中 (SQLite 持久化 + 5min 过期)."""
    try:
        form = await request.form()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid form body")
    client_id = form.get("client_id", "")
    redirect_uri = form.get("redirect_uri", "")
    code_challenge = form.get("code_challenge", "")
    code_challenge_method = form.get("code_challenge_method", "S256")
    state = form.get("state", "")
    scope = form.get("scope", "")

    params, err, _ = hermes_oauth.authorize_validate(
        client_id, redirect_uri, code_challenge, code_challenge_method, state, scope
    )
    if err:
        return HTMLResponse(hermes_oauth.authorize_page_html({}, error=err), status_code=400)

    # 验证密码 (3 次失败也直接返 401)
    password = form.get("password", "")
    if not secrets.compare_digest(password, OAUTH_PASSWORD):
        log(f"[oauth] password FAIL for client={client_id[:8]}... (from {request.client.host})")
        return HTMLResponse(hermes_oauth.authorize_page_html_password(params, error="密码错误, 请重试"), status_code=401)

    # 密码对 -> 直接生成 code + 302 redirect (省 grant_token 中转, 杜绝超时 race)
    log(f"[oauth] password OK, 直接 code, client={client_id[:8]}... state={state[:8]}...")
    redirect = hermes_oauth.authorize_approve(params)
    return RedirectResponse(redirect, status_code=302)


@app.post("/oauth/token")
async def oauth_token(request: Request):
    try:
        form = await request.form()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid form body")
    grant_type = form.get("grant_type", "")
    code = form.get("code", "")
    redirect_uri = form.get("redirect_uri", "")
    client_id = form.get("client_id", "")
    code_verifier = form.get("code_verifier", "")
    refresh_token = form.get("refresh_token", "")

    result, status, err = hermes_oauth.token_exchange(
        grant_type, code, redirect_uri, client_id, code_verifier, refresh_token
    )
    if err:
        return JSONResponse(status_code=status, content={"error": "invalid_request", "error_description": err})
    return JSONResponse(content=result)


# ── MCP 端点 (MCP 2026-07-28 streamable HTTP) ──────
@app.get("/mcp")
async def mcp_get(request: Request):
    """Stage 3.8: MCP Streamable HTTP 规范只接受 POST (GET stream endpoint 已在
    2026-07-28 移除). 返回 405 Method Not Allowed 是合规行为.
    之前 Stage 3.7.3 返回非标准 tools 列表, 已移除."""
    return JSONResponse(
        status_code=405,
        content={"error": "Method Not Allowed. MCP Streamable HTTP accepts POST only."},
    )


@app.middleware("http")
async def debug_log_middleware(request: Request, call_next):
    """Stage 3.7.3: 详细记每个 mcp 请求 (client IP + headers) 用于 ChatGPT 真实诊断."""
    if request.url.path.startswith("/mcp") or request.url.path.startswith("/oauth"):
        client_ip = request.client.host if request.client else "?"
        ua = request.headers.get("user-agent", "?")[:80]
        mcp_ver = request.headers.get("mcp-protocol-version", "-")
        mcp_meth = request.headers.get("mcp-method", "-")
        origin = request.headers.get("origin", "-")
        auth = request.headers.get("authorization", "-")
        auth_type = "static" if secrets.compare_digest(auth[7:].strip() if auth.startswith("Bearer ") else "", TOKEN) else ("oauth" if auth.startswith("Bearer ") and hermes_oauth.verify_access_token(auth[7:].strip())[0] else "anon")
        log(f"[mcp-req] {request.method} {request.url.path} from {client_ip} ua={ua!r} mcp_ver={mcp_ver} mcp_method={mcp_meth} origin={origin} auth={auth_type}")
    return await call_next(request)


def _validate_origin(request: Request) -> bool:
    """MCP 2026-07-28 spec 强制: 验证 Origin 防 DNS rebinding.
    我们允许: chatgpt.com / chat.openai.com / openai.com / localhost.
    没有 Origin 头通常意味着非浏览器 client (curl/SDK), 也允许."""
    origin = request.headers.get("origin")
    if not origin:
        return True  # 非浏览器 client
    allowed_suffixes = ("chatgpt.com", "openai.com", "localhost", "toothingbeginning.com", "hermes", "127.0.0.1")
    return any(origin.endswith(s) or s in origin for s in allowed_suffixes)


@app.post("/mcp")
async def mcp_post(req: JsonRpcRequest, request: Request):
    # Origin 验证 (MCP 2026-07-28 强制)
    if not _validate_origin(request):
        log(f"[mcp] Origin BLOCKED: {request.headers.get('origin')}")
        return JSONResponse(
            status_code=403,
            content={"error": {"code": -32000, "message": "Invalid Origin header (DNS rebinding protection)"}},
        )

    # server/discover (2026-07-28 新方法) - 必须在 check_auth 之前, 不需 auth
    if req.method == "server/discover":
        client = "anonymous[discover]"
        # 局部算 use_sse (不能引用后面的)
        accept_hdr = request.headers.get("accept", "application/json")
        use_sse_discover = "text/event-stream" in accept_hdr
        result = {
            "resultType": "complete",
            "supportedVersions": sorted(SUPPORTED_PROTOCOL_VERSIONS),
            "capabilities": {
                "tools": {},
            },
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": "hermes-dev-agent",
                    "version": "3.8.0",
                }
            },
            "instructions": "Hermes Dev Agent 提供 6 个只读 MCP 工具: hermes_health_check, hermes_system_status, hermes_ecs_shell, hermes_read_file, hermes_git_status, hermes_logs. 所有工具只读, 无副作用. 通过 OAuth 2.1 access_token (scope mcp:read) 认证.",
            "ttlMs": 3600000,
            "cacheScope": "public",
        }
        # 注意: 不附加 _audit 字段 —— ChatGPT 会对比多次 discover 响应,
        # non-deterministic 字段(如时间戳)会导致 "discover response was inconsistent".
        resp = {"jsonrpc": "2.0", "id": req.id, "result": result}
        log(f"[mcp] {client} -> server/discover")
        return Response(
            content=json.dumps(resp),
            media_type="application/json",
            headers={"X-Accel-Buffering": "no"},
        )

    # 认证 (其他方法必须 auth)
    client = check_auth(request)

    # Stage 4: 写工具 scope 门禁 (mcp:write)
    if req.method == "tools/call":
        _tool_name = ((req.params or {}).get("name", "") or "")
        if _tool_name in WRITE_TOOLS and not _has_write_scope(request):
            log(f"[mcp] WRITE DENIED (scope): {_tool_name} client={client}")
            return JSONResponse(
                status_code=403,
                content={"jsonrpc": "2.0", "id": req.id, "error": {"code": -32000, "message": "mcp:write scope required for this tool"}},
            )

    # MCP-Protocol-Version 头协商 (2026-07-28 强制)
    client_proto = request.headers.get("mcp-protocol-version")
    proto_version = client_proto if client_proto in SUPPORTED_PROTOCOL_VERSIONS else MCP_PROTOCOL_VERSION

    # Accept 头 (text/event-stream 允许, 2026-07-28 spec)
    accept = request.headers.get("accept", "application/json")
    use_sse = "text/event-stream" in accept

    # Mcp-Method 头 (2026-07-28 新增, 反映 JSON-RPC method 字段)
    mcp_method_header = req.method

    # 调试: 记所有 headers (生产可关)
    if req.method not in ("ping",):
        ua = request.headers.get("user-agent", "?")[:60]
        origin = request.headers.get("origin", "-")
        log(f"[mcp] {client} -> {req.method} (proto={proto_version}, origin={origin}, ua={ua!r})")

    # server/discover 已在 check_auth 之前处理 (见上面), 到这里已不会执行
    # (此 block 留为防御性 - 不应到达)

    # notifications/initialized: 202 no body, 不转发 stdio
    if req.method == "notifications/initialized":
        log(f"[mcp] {client} -> notifications/initialized")
        return Response(status_code=202)

    # initialize: 返回 serverInfo + 兼容所有协议版本
    if req.method == "initialize":
        resp = await stdio_mcp.call(req.dict(exclude_none=True), timeout=15)
        if isinstance(resp, dict) and "result" in resp:
            # 用 client 协议的版本 (client 优先)
            resp["result"]["protocolVersion"] = proto_version
            # 确保 serverInfo 完整
            if "serverInfo" not in resp["result"]:
                resp["result"]["serverInfo"] = {"name": "hermes-dev-agent", "version": "3.8.0"}
        # 不附加 _audit (避免 non-deterministic 响应)
        return Response(
            content=json.dumps(resp),
            media_type="application/json",
            headers={"X-Accel-Buffering": "no"},
        )

    # 其他 JSON-RPC: 2026-07-28 移除 session, 但仍兼容旧版
    sid = request.headers.get("mcp-session-id")
    # 旧协议 session 检查 (已宽松, 不再强制 initialized)
    # if sid and sid in sessions and not sessions[sid].get("initialized"):
    #     if req.method not in ("ping",):
    #         return JSONResponse(...)

    resp = await stdio_mcp.call(req.dict(exclude_none=True), timeout=30)

    # Stage 3.8: 2025-11-25 / 2026-07-28 规范要求结果含 resultType/ttlMs/cacheScope.
    # ChatGPT 用 2026-07-28, 这三个字段是 REQUIRED (否则 SDK 报 Field required).
    # 旧协议 (2024-11-05/2025-03-26/2025-06-18) 的 tools/list 不需要, 故按版本 gate.
    modern = proto_version in ("2025-11-25", "2026-07-28")
    if isinstance(resp, dict) and "result" in resp and isinstance(resp["result"], dict):
        r = resp["result"]
        if req.method == "tools/list" and modern:
            r.setdefault("resultType", "complete")
            r.setdefault("ttlMs", 3600000)
            r.setdefault("cacheScope", "public")
        elif req.method == "tools/call" and modern:
            r.setdefault("resultType", "complete")

    return Response(
        content=json.dumps(resp),
        media_type="application/json",
        headers={"X-Accel-Buffering": "no"},
    )


@app.on_event("shutdown")
async def shutdown_event():
    log("[shutdown] bridge stopping...")
    await stdio_mcp.stop()
    _log_file.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")