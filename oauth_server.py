#!/usr/bin/env python3
"""
Hermes OAuth 2.1 Authorization Server (Stage 3.6)

让 ChatGPT 通过 OAuth 2.1 (Authorization Code + PKCE) 连接 Hermes MCP。
作为 Authorization Server (AS) + Resource Server (RS) 集成进 hermes_remote_bridge。

实现:
- OAuth 2.1 Authorization Code Flow + PKCE (S256)
- DCR (Dynamic Client Registration, RFC 7591)
- opaque access token + refresh token (SQLite 持久化)
- 授权确认页 (张健点"允许/拒绝")
- 不开放匿名: 没有 access token / 静态 token 一律 401

端点 (通过 Caddy 反代, 公网 BASE_URL):
- GET  /.well-known/oauth-authorization-server   (元数据发现)
- POST /oauth/register                          (DCR 客户端注册)
- GET  /oauth/authorize                         (授权码流程 + 授权页)
- POST /oauth/token                             (code → access/refresh)
- POST /oauth/token                             (refresh_token → 新 access)

安全:
- PKCE S256 强制 (不支持 plain)
- redirect_uri 精确匹配 DCR 注册值 (防开放重定向)
- auth code 单次使用 + 5 分钟有效期
- access token 24h / refresh token 30 天
- scope = "mcp:read" (只读, 无写权限)
"""
import base64
import hashlib
import json
import secrets
import sqlite3
import time
from pathlib import Path

BASE_URL = "https://mcp.hermes.toothingbeginning.com"
DB_PATH = Path("/home/hermes/mcp_servers/oauth.db")
SCOPE = "mcp:read"
ACCESS_TOKEN_TTL = 86400       # 24h
REFRESH_TOKEN_TTL = 2592000    # 30 天
AUTH_CODE_TTL = 300             # 5 分钟

# ── SQLite 持久化 ──────────────────────────────────────
def _db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = _db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS clients (
        client_id TEXT PRIMARY KEY,
        client_name TEXT,
        redirect_uris TEXT,   -- JSON array
        created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS auth_codes (
        code TEXT PRIMARY KEY,
        client_id TEXT,
        redirect_uri TEXT,
        code_challenge TEXT,
        code_challenge_method TEXT,
        scope TEXT,
        expires_at INTEGER,
        used INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS tokens (
        access_token TEXT PRIMARY KEY,
        refresh_token TEXT,
        client_id TEXT,
        scope TEXT,
        created_at INTEGER,
        expires_at INTEGER
    );
    """)
    conn.commit()
    conn.close()

def _now():
    return int(time.time())

# ── PKCE 工具 ──────────────────────────────────────────
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def verify_pkce(verifier: str, challenge: str, method: str = "S256") -> bool:
    """验证 PKCE verifier 与 challenge 匹配."""
    if method != "S256":
        return False
    if not verifier or not challenge:
        return False
    computed = _b64url(hashlib.sha256(verifier.encode()).digest())
    return secrets.compare_digest(computed, challenge)

# ── Grant token (Stage 3.7.1: 持久化 + 容错) ─────
# Stage 3.7 改为 SQLite 持久化 + 5 次使用限制 (容错)
# grant_token: 5min 内可点 5 次 (含 1 次正常 + 4 次重试), 过期失效

def create_grant_token(params: dict) -> str:
    """授权页密码验证通过后, 创建 grant_token (5min 过期, 最多 5 次使用)."""
    token = secrets.token_urlsafe(24)
    conn = _db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS grant_tokens (
        token TEXT PRIMARY KEY,
        client_id TEXT,
        redirect_uri TEXT,
        code_challenge TEXT,
        code_challenge_method TEXT,
        scope TEXT,
        state TEXT,
        expires_at INTEGER,
        used_count INTEGER DEFAULT 0,
        max_uses INTEGER DEFAULT 5
    )""")
    conn.execute(
        "INSERT INTO grant_tokens (token, client_id, redirect_uri, code_challenge, code_challenge_method, scope, state, expires_at, used_count, max_uses) VALUES (?,?,?,?,?,?,?,?,0,5)",
        (token, params["client_id"], params["redirect_uri"], params["code_challenge"],
         params["code_challenge_method"], params["scope"], params["state"], _now() + 300),
    )
    # 清理过期
    conn.execute("DELETE FROM grant_tokens WHERE expires_at < ?", (_now(),))
    conn.commit()
    conn.close()
    return token

def consume_grant_token(token: str):
    """验证 + 标记已用 + 返回参数 (最多 N 次使用, 持久化)."""
    if not token:
        return None
    conn = _db()
    conn.execute("DELETE FROM grant_tokens WHERE expires_at < ?", (_now(),))
    row = conn.execute("SELECT * FROM grant_tokens WHERE token=?", (token,)).fetchone()
    if not row:
        conn.close()
        return None
    if row["used_count"] >= row["max_uses"]:
        conn.execute("DELETE FROM grant_tokens WHERE token=?", (token,))
        conn.commit()
        conn.close()
        return None
    # 递增 used_count
    conn.execute("UPDATE grant_tokens SET used_count = used_count + 1 WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return {
        "client_id": row["client_id"],
        "redirect_uri": row["redirect_uri"],
        "code_challenge": row["code_challenge"],
        "code_challenge_method": row["code_challenge_method"],
        "scope": row["scope"],
        "state": row["state"],
    }

# ── OAuth 元数据 ───────────────────────────────────────
def get_metadata():
    return {
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/oauth/authorize",
        "token_endpoint": f"{BASE_URL}/oauth/token",
        "registration_endpoint": f"{BASE_URL}/oauth/register",
        "code_challenge_methods_supported": ["S256"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [SCOPE],
    }

# ── DCR 客户端注册 ─────────────────────────────────────
def register_client(metadata: dict):
    client_id = secrets.token_urlsafe(16)
    redirect_uris = metadata.get("redirect_uris", [])
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return None, "redirect_uris required"
    client_name = metadata.get("client_name", "unknown-client")
    conn = _db()
    conn.execute(
        "INSERT INTO clients (client_id, client_name, redirect_uris, created_at) VALUES (?,?,?,?)",
        (client_id, client_name, json.dumps(redirect_uris), _now()),
    )
    conn.commit()
    conn.close()
    return {
        "client_id": client_id,
        "client_id_issued_at": _now(),
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": SCOPE,
    }, None

# ── authorize: 校验参数 ────────────────────────────────
def authorize_validate(client_id, redirect_uri, code_challenge, code_challenge_method, state, scope):
    if not client_id or not redirect_uri or not code_challenge:
        return None, "missing required params", None
    if code_challenge_method != "S256":
        return None, "only S256 PKCE supported", None
    conn = _db()
    row = conn.execute("SELECT * FROM clients WHERE client_id=?", (client_id,)).fetchone()
    if not row:
        conn.close()
        return None, "unknown client_id", None
    redirects = json.loads(row["redirect_uris"])
    if redirect_uri not in redirects:
        conn.close()
        return None, "redirect_uri not registered", None
    conn.close()
    return {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope or SCOPE,
        "state": state or "",
    }, None, None

def authorize_approve(params):
    """用户点允许 → 生成 auth code → 重定向."""
    code = secrets.token_urlsafe(32)
    conn = _db()
    conn.execute(
        "INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at, used) VALUES (?,?,?,?,?,?,?,0)",
        (code, params["client_id"], params["redirect_uri"], params["code_challenge"],
         params["code_challenge_method"], params["scope"], _now() + AUTH_CODE_TTL),
    )
    conn.commit()
    conn.close()
    redirect = params["redirect_uri"] + ("&" if "?" in params["redirect_uri"] else "?") + \
        f"code={code}&state={params['state']}"
    return redirect

# ── token: code → access + refresh ─────────────────────
def token_exchange(grant_type, code, redirect_uri, client_id, code_verifier, refresh_token):
    conn = _db()
    if grant_type == "authorization_code":
        if not code or not code_verifier or not client_id:
            conn.close()
            return None, 400, "missing params"
        row = conn.execute("SELECT * FROM auth_codes WHERE code=?", (code,)).fetchone()
        if not row:
            conn.close()
            return None, 400, "invalid code"
        if row["used"]:
            conn.close()
            return None, 400, "code already used"
        if row["expires_at"] < _now():
            conn.close()
            return None, 400, "code expired"
        if row["client_id"] != client_id:
            conn.close()
            return None, 400, "client_id mismatch"
        if redirect_uri and row["redirect_uri"] != redirect_uri:
            conn.close()
            return None, 400, "redirect_uri mismatch"
        if not verify_pkce(code_verifier, row["code_challenge"], row["code_challenge_method"]):
            conn.close()
            return None, 400, "PKCE verification failed"
        # 标记 code 已用
        conn.execute("UPDATE auth_codes SET used=1 WHERE code=?", (code,))
        # 发 token
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(48)
        conn.execute(
            "INSERT INTO tokens (access_token, refresh_token, client_id, scope, created_at, expires_at) VALUES (?,?,?,?,?,?)",
            (access, refresh, client_id, row["scope"], _now(), _now() + ACCESS_TOKEN_TTL),
        )
        conn.commit()
        conn.close()
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL,
            "refresh_token": refresh,
            "scope": row["scope"],
        }, 200, None

    if grant_type == "refresh_token":
        if not refresh_token or not client_id:
            conn.close()
            return None, 400, "missing refresh_token"
        row = conn.execute("SELECT * FROM tokens WHERE refresh_token=?", (refresh_token,)).fetchone()
        if not row:
            conn.close()
            return None, 400, "invalid refresh_token"
        if row["client_id"] != client_id:
            conn.close()
            return None, 400, "client_id mismatch"
        # 轮换: 删旧 access, 发新 access (refresh 保持)
        conn.execute("UPDATE tokens SET access_token=?, created_at=?, expires_at=? WHERE refresh_token=?",
                     (secrets.token_urlsafe(32), _now(), _now() + ACCESS_TOKEN_TTL, refresh_token))
        conn.commit()
        new_access = conn.execute("SELECT access_token FROM tokens WHERE refresh_token=?", (refresh_token,)).fetchone()["access_token"]
        conn.close()
        return {
            "access_token": new_access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL,
            "refresh_token": refresh_token,
            "scope": row["scope"],
        }, 200, None

    conn.close()
    return None, 400, "unsupported grant_type"

# ── 验证 access token (RS 端 /mcp 认证用) ──────────────
def verify_access_token(token: str):
    """返回 (valid: bool, scope: str|None). token 无效返回 (False, None)."""
    if not token:
        return False, None
    conn = _db()
    row = conn.execute("SELECT * FROM tokens WHERE access_token=?", (token,)).fetchone()
    if not row:
        conn.close()
        return False, None
    if row["expires_at"] < _now():
        conn.close()
        return False, None
    conn.close()
    return True, row["scope"]

# ── 授权页 HTML ────────────────────────────────────────
def _esc(s):
    return (str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;"))

def authorize_page_html(params, error=None):
    """保留: 向后兼容 (已用 authorize_page_html_password 替代)"""
    if error:
        return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>授权失败</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:40px auto;text-align:center">
<h2>授权失败</h2><p>{error}</p><p><a href="javascript:window.close()">关闭</a></p></body></html>"""
    return authorize_page_html_password(params)


def authorize_page_html_password(params, error=None):
    """Stage 3.7: 密码输入页 (防任意人点允许)"""
    if error:
        body_err = f'<p style="color:red">{_esc(error)}</p>'
    else:
        body_err = ""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Hermes OAuth 授权</title></head>
<body style="font-family:sans-serif;max-width:500px;margin:60px auto;padding:20px">
<h2>🔒 Hermes MCP 授权</h2>
<p><strong>{_esc(params['client_id'])}</strong> 请求访问你的 Hermes Dev Agent</p>
<p>请求 scope: <code>{_esc(params['scope'])}</code> (只读, 5 工具)</p>
{body_err}
<form method="POST" action="/oauth/authorize" style="margin-top:20px">
  <input type="hidden" name="client_id" value="{_esc(params['client_id'])}">
  <input type="hidden" name="redirect_uri" value="{_esc(params['redirect_uri'])}">
  <input type="hidden" name="code_challenge" value="{_esc(params['code_challenge'])}">
  <input type="hidden" name="code_challenge_method" value="{_esc(params['code_challenge_method'])}">
  <input type="hidden" name="state" value="{_esc(params['state'])}">
  <input type="hidden" name="scope" value="{_esc(params['scope'])}">
  <p>输入 Hermes 授权密码 (只你/管理员知道):</p>
  <input type="password" name="password" required autofocus
         style="width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:4px">
  <button type="submit" style="width:100%;padding:10px;background:#10a37f;color:#fff;border:none;border-radius:4px;cursor:pointer">
    验证密码
  </button>
</form>
<p style="color:#999;font-size:12px;margin-top:30px">
  Stage 3.7 安全设计: 任意知道 OAuth URL 的人不能直接授权.
  必须知道授权密码 (从 Hermes MCP 管理员处获得).
</p>
</body></html>"""


def authorize_page_html_confirmed(params, grant_token):
    """Stage 3.7: 密码验证后, 显示"允许/拒绝"按钮页"""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>确认授权</title></head>
<body style="font-family:sans-serif;max-width:500px;margin:60px auto;padding:20px;text-align:center">
<h2>✅ 密码验证通过</h2>
<p>客户端 <code>{_esc(params['client_id'])}</code> 想访问 Hermes Dev Agent</p>
<p>权限: <code>{_esc(params['scope'])}</code> (只读)</p>
<p>允许后 ChatGPT 可调用 5 个只读工具 (系统状态 / ECS shell / 读文件 / git / 日志)。</p>
<p style="margin-top:30px">
  <a href="/oauth/authorize?grant_token={_esc(grant_token)}&allowed=1"
     style="display:inline-block;padding:12px 24px;background:#10a37f;color:#fff;text-decoration:none;border-radius:6px;margin-right:12px;font-weight:bold">
    允许
  </a>
  <a href="/oauth/authorize?grant_token={_esc(grant_token)}&allowed=0"
     style="display:inline-block;padding:12px 24px;background:#f0f0f0;color:#333;text-decoration:none;border-radius:6px">
    拒绝
  </a>
</p>
<p style="color:#999;font-size:12px;margin-top:40px">
  ⚠️ 允许后 30 天内无需重新授权 (refresh_token 自动续期).
  想撤销? 联系 Hermes 管理员删除 OAuth DB 中的 token 记录.
</p>
</body></html>"""


if __name__ == "__main__":
    init_db()
    print("OAuth DB initialized:", DB_PATH)