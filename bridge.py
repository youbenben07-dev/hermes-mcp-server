#!/usr/bin/env python3
"""
Hermes MCP Remote Bridge - Stage 3.6 (Streamable HTTP + Bearer + OAuth 2.1)

包装 Stage 1 stdio server 为远程 HTTPS 端点, 让 ChatGPT Custom MCP Connector 可连接.

认证 (双模式):
1. 静态 Bearer Token (Stage 3.5, 内部/PM 访问)
2. OAuth 2.1 access token (ChatGPT 通过 Authorization Code + PKCE 获取)

OAuth 端点 (见 hermes_oauth.py):
- GET  /.well-known/oauth-authorization-server
- POST /oauth/register
- GET  /oauth/authorize
- POST /oauth/token

Caddy 反代 127.0.0.1:8443 → 公网 HTTPS (mcp.hermes.toothingbeginning.com)
"""
import asyncio
import json
import os
import secrets
import sys
import time
from typing import Optional

# 允许 import 同目录的 hermes_oauth
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hermes_oauth

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel

# ── 配置 ────────────────────────────────────────────
DEFAULT_TOKEN_FILE = "/home/hermes/.hermes/mcp_remote_token"
TOKEN = os.environ.get("HERMES_MCP_TOKEN")
HOST = os.environ.get("HERMES_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("HERMES_MCP_PORT", "8443"))
STDIO_CMD = os.environ.get("HERMES_STDIO_CMD", "/home/hermes/.hermes/hermes-agent/venv/bin/python3")
STDIO_ARGS = os.environ.get("HERMES_STDIO_ARGS", "/home/hermes/mcp_servers/hermes_dev_agent.py").split()

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

# 初始化 OAuth DB
hermes_oauth.init_db()

print(f"[hermes-mcp-remote] Listening on http://{HOST}:{PORT}", file=sys.stderr)
print(f"[hermes-mcp-remote] Auth: Bearer token ({len(TOKEN)} chars) + OAuth 2.1", file=sys.stderr)
print(f"[hermes-mcp-remote] OAuth: {hermes_oauth.BASE_URL}", file=sys.stderr)
print(f"[hermes-mcp-remote] Stdio backend: {STDIO_CMD} {' '.join(STDIO_ARGS)}", file=sys.stderr)

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

    async def call(self, req: dict, timeout: float = 60) -> dict:
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
app = FastAPI(title="Hermes MCP Remote Bridge (Stage 3.6)", version="3.6.0")


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[int] = None
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
    # 1. 静态 token (Stage 3.5, PM/内部)
    if secrets.compare_digest(client_token, TOKEN):
        return f"static[{len(client_token)}chars]"
    # 2. OAuth access token (ChatGPT)
    valid, scope = hermes_oauth.verify_access_token(client_token)
    if valid:
        return f"oauth[{len(client_token)}chars:{scope}]"
    raise HTTPException(
        status_code=401,
        detail="Invalid bearer token",
        headers=ww,
    )


@app.get("/")
async def root():
    return {
        "name": "Hermes MCP Remote Bridge",
        "version": "3.6.0",
        "stage": "Stage 3.6 (Streamable HTTP + Bearer + OAuth 2.1)",
        "mcp_endpoint": "/mcp",
        "auth": "Bearer token 或 OAuth 2.1 access token",
        "oauth_metadata": "/.well-known/oauth-authorization-server",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@app.get("/health")
async def health():
    return {"ok": True, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


# ── OAuth 2.1 端点 ─────────────────────────────────
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    return JSONResponse(content=hermes_oauth.get_metadata())


@app.get("/.well-known/oauth-protected-resource")
async def oauth_resource_metadata():
    """资源服务器元数据 (MCP 规范, 供客户端发现 OAuth AS)."""
    return JSONResponse(content={
        "resource": f"{hermes_oauth.BASE_URL}/mcp",
        "authorization_servers": [hermes_oauth.BASE_URL],
        "scopes_supported": [hermes_oauth.SCOPE],
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


@app.get("/oauth/authorize")
async def oauth_authorize(request: Request):
    q = request.query_params
    client_id = q.get("client_id", "")
    redirect_uri = q.get("redirect_uri", "")
    code_challenge = q.get("code_challenge", "")
    code_challenge_method = q.get("code_challenge_method", "S256")
    state = q.get("state", "")
    scope = q.get("scope", "")
    allowed = q.get("allowed", "")

    params, err, _ = hermes_oauth.authorize_validate(
        client_id, redirect_uri, code_challenge, code_challenge_method, state, scope
    )
    if err:
        return HTMLResponse(hermes_oauth.authorize_page_html({}, error=err), status_code=400)

    if allowed == "1":
        redirect = hermes_oauth.authorize_approve(params)
        return RedirectResponse(redirect, status_code=302)
    if allowed == "0":
        sep = "&" if "?" in params["redirect_uri"] else "?"
        redirect = f"{params['redirect_uri']}{sep}error=access_denied&state={params['state']}"
        return RedirectResponse(redirect, status_code=302)

    # 显示授权确认页
    return HTMLResponse(hermes_oauth.authorize_page_html(params))


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


# ── MCP 端点 ───────────────────────────────────────
@app.get("/mcp")
async def mcp_get():
    return JSONResponse(
        status_code=405,
        content={"error": "Method Not Allowed. Use POST with JSON-RPC body."},
    )


@app.post("/mcp")
async def mcp_post(req: JsonRpcRequest, request: Request):
    client = check_auth(request)
    print(f"[hermes-mcp-remote] {client} -> {req.method} (id={req.id})", file=sys.stderr)
    resp = await stdio_mcp.call(req.dict(exclude_none=True))
    if isinstance(resp, dict) and "result" in resp:
        resp["_audit"] = {"client": client, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    return JSONResponse(content=resp)


@app.on_event("shutdown")
async def shutdown_event():
    await stdio_mcp.stop()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")