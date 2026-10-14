# Hermes MCP Server (Streamable HTTP + OAuth 2.1)

> 把任意 Python MCP server (stdio) 包装成 **公网 HTTPS Streamable HTTP** + **OAuth 2.1** 认证服务,
> 让 ChatGPT/Claude/任何 MCP client 通过 OAuth 远程接入.
>
> **生产实跑**: https://mcp.hermes.toothingbeginning.com/mcp (2026-10-14 上线, 验证通过)

---

## 📑 目录

- [为什么需要这个项目](#-为什么需要这个项目)
- [架构](#-架构)
- [5 分钟快速复制](#-5-分钟快速复制)
- [完整部署步骤](#-完整部署步骤)
- [OAuth 2.1 流程详解](#-oauth-21-流程详解)
- [5 个只读工具](#-5-个只读工具)
- [安全模型](#-安全模型)
- [测试 + 验证](#-测试--验证)
- [已知限制 + 路线图](#-已知限制--路线图)
- [给下一个 Agent 的接手清单](#-给下一个-agent-的接手清单)

---

## 🎯 为什么需要这个项目

ChatGPT/Claude/Cline 等 MCP client **不能直接调 stdio** MCP server (stdin/stdout 通信).
它们需要 **Streamable HTTP** 协议, 且自定义 connector 强制要求 **OAuth 2.1** (或匿名, 不可用 Bearer Token).

**本项目解决**:
1. 把任意 Python stdio MCP server → Streamable HTTP 包装
2. 加 OAuth 2.1 Authorization Server (Authorization Code + PKCE + DCR)
3. 加 Caddy 反代 + Let's Encrypt 自动证书
4. 全程只读, 写工具通过白名单硬阻止

---

## 🏗️ 架构

```
ChatGPT (Custom MCP Connector)
    │
    │ HTTPS + OAuth 2.1 + Streamable HTTP
    ▼
┌────────────────────────────────────────┐
│  Caddy (TLS 1.3 + Let's Encrypt)       │
│  mcp.hermes.toothingbeginning.com       │
│  /mcp          → 127.0.0.1:8443 (MCP)  │
│  /oauth/*      → 127.0.0.1:8443 (AS)   │
│  /.well-known/*→ 127.0.0.1:8443        │
└────────────────────┬───────────────────┘
                     │
                     ▼
┌────────────────────────────────────────┐
│  bridge.py (FastAPI/uvicorn)           │
│  - /mcp             (MCP 端点)        │
│  - /.well-known/    (OAuth 发现)       │
│  - /oauth/register  (DCR)              │
│  - /oauth/authorize (授权码流程)        │
│  - /oauth/token     (code → token)     │
│  - 认证: 静态 Bearer + OAuth token     │
│     都被 check_auth() 验证              │
└────────────────────┬───────────────────┘
                     │ stdio
                     ▼
┌────────────────────────────────────────┐
│  mcp_server.py (5 只读工具)            │
│  - hermes_system_status                │
│  - hermes_ecs_shell                    │
│  - hermes_read_file                    │
│  - hermes_git_status                   │
│  - hermes_logs                         │
└────────────────────────────────────────┘
```

**4 个核心 Python 文件**:
| 文件 | 作用 |
|---|---|
| `mcp_server.py` | Stage 1 - stdio MCP server, 5 只读工具 (独立可跑) |
| `oauth_server.py` | OAuth 2.1 AS 核心 (SQLite + PKCE + DCR) |
| `bridge.py` | Streamable HTTP + 双 token 认证 + OAuth 端点路由 |
| `test_oauth_flow.py` | 端到端测试 (DCR → PKCE → authorize → token → MCP) |

---

## ⚡ 5 分钟快速复制

```bash
# 1. clone
git clone https://github.com/<your-org>/hermes-mcp-server.git
cd hermes-mcp-server

# 2. 装依赖 (用项目内 venv 或系统 venv)
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn pydantic

# 3. 改 bridge.py 顶部的 BASE_URL 改为你自己的域名
#    BASE_URL = "https://mcp.your-domain.com"
#    HERMES_STDIO_ARGS 默认调 mcp_server.py (可换其他 stdio MCP server)

# 4. 启 (用 systemd / nohup 二选一)
python3 bridge.py
# 监听 127.0.0.1:8443 (Caddy 反代, 不要直绑 0.0.0.0)

# 5. Caddy 反代 + Let's Encrypt
# 详见 "完整部署步骤" 第 6 步
```

---

## 📋 完整部署步骤

### Step 1: 准备环境

```bash
# Ubuntu 24.04+ VPS, 公网 IP, 域名 A 记录 → VPS
# Python 3.10+
# 已装 caddy 2.6+ (snap install caddy 或 apt install caddy)
```

### Step 2: clone + 依赖

```bash
git clone https://github.com/<your-org>/hermes-mcp-server.git
cd hermes-mcp-server
python3 -m venv venv && source venv/bin/activate
pip install fastapi uvicorn pydantic
```

### Step 3: 配 mcp_server.py (你的工具实现)

打开 `mcp_server.py`:
- **5 个工具是示例** (针对 fastmedlink cs-inbox 系统)
- **替换为你的实际工具**: 改 `_run_*` 函数和 `TOOLS` 列表
- **保留安全白名单** (32 个 shell 前缀, 15 个文件路径)
- **保持只读**: 任何写操作必须加 `--dry-run` 或在白名单外拒绝

### Step 4: 配 oauth_server.py (OAuth AS)

打开 `oauth_server.py`:
```python
BASE_URL = "https://mcp.your-domain.com"   # 必改
SCOPE = "mcp:read"                          # 你的 scope 名
ACCESS_TOKEN_TTL = 86400                    # access 24h
REFRESH_TOKEN_TTL = 2592000                 # refresh 30d
AUTH_CODE_TTL = 300                         # code 5min
```

OAuth 特性已固定:
- Authorization Code + PKCE (S256)
- DCR (Dynamic Client Registration)
- 公共 client (`token_endpoint_auth_method: none`)
- SQLite 持久化

### Step 5: 配 bridge.py

打开 `bridge.py`:
```python
DEFAULT_TOKEN_FILE = "/home/hermes/.hermes/mcp_remote_token"  # 静态 token 位置
HOST = "127.0.0.1"
PORT = 8443
STDIO_CMD = "/path/to/venv/bin/python3"      # 改!
STDIO_ARGS = ["/path/to/mcp_server.py"]      # 改!
```

**静态 Bearer Token** (双模式认证, 内部/PM 访问):
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))" \
  > /home/hermes/.hermes/mcp_remote_token
chmod 600 /home/hermes/.hermes/mcp_remote_token
```

### Step 6: Caddy 反代 + Let's Encrypt

`/etc/caddy/Caddyfile`:
```caddy
{
    admin off
    email your-email@your-domain.com
}

mcp.your-domain.com {
    @mcp { path /mcp* }
    handle @mcp { reverse_proxy 127.0.0.1:8443 }
    handle /oauth/* { reverse_proxy 127.0.0.1:8443 }
    handle /.well-known/* { reverse_proxy 127.0.0.1:8443 }
    handle { reverse_proxy 127.0.0.1:8443 }
}
```

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
# 重启 caddy (admin off 需 stop + start)
sudo systemctl restart caddy
```

Caddy 自动从 Let's Encrypt 申请证书. 查看申请日志:
```bash
sudo journalctl -u caddy -n 50
```

### Step 7: systemd 守护 bridge

`/etc/systemd/system/hermes-mcp-bridge.service`:
```ini
[Unit]
Description=Hermes MCP Remote Bridge
After=network.target

[Service]
Type=simple
User=hermes
WorkingDirectory=/home/hermes/repos/hermes-mcp-server
ExecStart=/home/hermes/repos/hermes-mcp-server/venv/bin/python3 bridge.py
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hermes-mcp-bridge
sudo systemctl status hermes-mcp-bridge
```

### Step 8: 端到端验证

```bash
# 1. 静态 token 健康检查
TOKEN=$(cat /home/hermes/.hermes/mcp_remote_token)
curl -s -w "\nHTTPS %{http_code}\n" https://mcp.your-domain.com/mcp -X POST \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
# 期望: 200, serverInfo.name=hermes-dev-agent

# 2. 完整 OAuth flow
python3 test_oauth_flow.py
# 期望: 13/13 通过
```

### Step 9: 接入 ChatGPT

1. ChatGPT 网页 → Settings → Connectors → Add custom connector
2. 填 URL: `https://mcp.your-domain.com/mcp`
3. Save → 开对话
4. ChatGPT 自动: DCR 注册 → 跳授权页 → 你点"允许" → 调用 5 工具

---

## 🔐 OAuth 2.1 流程详解

### 完整时序 (DCR + PKCE + Authorization Code)

```
[1] ChatGPT 收到 401 + WWW-Authenticate: Bearer resource_metadata=".../.well-known/oauth-protected-resource"
   ↓
[2] ChatGPT 读 resource metadata → 拿 authorization_servers
   ↓
[3] ChatGPT 读 /.well-known/oauth-authorization-server → 4 个端点
   ↓
[4] ChatGPT POST /oauth/register (DCR) → 拿 client_id
   ↓
[5] ChatGPT 生成 PKCE: verifier (随机) + challenge = base64url(sha256(verifier))
   ↓
[6] ChatGPT 浏览器跳 /oauth/authorize?client_id=...&code_challenge=...&scope=mcp:read
   ↓
[7] 你在授权页点"允许" → 服务器生成 code (单次, 5min 有效) → 302 到 redirect_uri?code=...&state=...
   ↓
[8] ChatGPT POST /oauth/token (form: grant_type=authorization_code, code, code_verifier, client_id)
   ↓
[9] 服务器验证 PKCE: sha256(code_verifier) == code_challenge
   ↓
[10] 服务器发 access_token (24h) + refresh_token (30d)
   ↓
[11] ChatGPT 用 access_token 调 /mcp → 拿 5 工具
   ↓
[12] access 过期后 ChatGPT 自动用 refresh_token 换新 (无需用户重新授权)
```

### 关键安全保证

| 攻击 | 防御 |
|---|---|
| 跨站请求伪造 (CSRF) | state 参数 + PKCE |
| 授权码重放 | code 单次使用 + 5min 过期 |
| 中间人 | HTTPS (Let's Encrypt) + TLS 1.3 |
| 开放重定向 | redirect_uri 精确匹配 DCR 注册值 |
| scope 升级 | server 强制 scope = `mcp:read` |
| 暴力破解 access token | 32 字节随机, base64url(48 字节) |
| 静态 token 泄露 | 双模式认证, 随时轮换 |

### 关闭匿名访问

**所有 5 个 MCP 端点 + OAuth 端点** 都有认证, 无匿名访问:
- `/mcp`: Bearer token 必填, 错 → 401
- `/oauth/authorize`: 不需 token, 但需要合法 client_id + PKCE + 人工点"允许"
- `/oauth/token`: 不需 token, 但需要合法 code/refresh_token + 合法 client_id
- `/.well-known/*`: 公开, 仅元数据

---

## 🛠️ 5 个只读工具 (示例)

| 工具 | 范围 | 说明 |
|---|---|---|
| `hermes_system_status` | VPS+ECS | uptime/内存/磁盘/worker PID/cs-inbox unit/health HTTP |
| `hermes_ecs_shell` | ECS 远程 shell | 32 个只读命令白名单 |
| `hermes_read_file` | ECS/VPS 文件 | 15 个白名单绝对路径 |
| `hermes_git_status` | cs-inbox git | log + status + remote + HEAD |
| `hermes_logs` | VPS/ECS | worker.log / worker.err / nginx access/error |

**白名单设计**:
```python
SHELL_ALLOWLIST = [
    "systemctl is-active", "ps", "cat /etc/os-release", "git status",
    "git log", "ls", "tail", "df", "free", "uptime", "uname", "pidof",
    "systemctl status", "journalctl", "ss", "netstat", "ping -c",
    "head", "wc", "grep", "date", "whoami", "hostname",
    # ... 共 32 个
]

FILE_ALLOWLIST = [
    "/home/fastmedlink/cs-inbox/app.py",
    "/home/fastmedlink/cs-inbox/db.py",
    # ... 共 15 个
]

# 危险模式黑名单 (22 种)
DANGEROUS_PATTERNS = [
    r"\brm\s", r"\bgit\s+push", r"\bgit\s+reset", r"\bsudo\b",
    r"\bkill\b", r"\bchmod\b", r"\bchown\b", r">\s*/", r"\|.*sh",
    # ...
]
```

**替换为你的工具**: 编辑 `mcp_server.py` 的 `TOOLS` list + `_run_*` 函数即可.

---

## 🧪 测试 + 验证

### 自动端到端测试

```bash
cd /home/hermes/repos/hermes-mcp-server
python3 test_oauth_flow.py
```

**13 项断言** (应全过):
1. metadata 端点 200
2. DCR 注册 201 + client_id 返回
3. PKCE S256 challenge 生成
4. authorize 授权页 200
5. 用户允许 → 302 + code
6. state 回传一致
7. code → access token
8. scope = `mcp:read`
9. access token 调 `/mcp` initialize
10. tools/list 5 工具
11. 无 token → 401
12. 错 token → 401
13. refresh token 轮换

### 手动测试

```bash
# 1. 静态 Bearer token 测试
TOKEN=$(cat /home/hermes/.hermes/mcp_remote_token)
curl -s -w "\nHTTPS %{http_code}\n" https://mcp.your-domain.com/mcp -X POST \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# 2. OAuth 发现测试
curl -s https://mcp.your-domain.com/.well-known/oauth-authorization-server | python3 -m json.tool

# 3. 安全测试 (无 token)
curl -s -o /dev/null -w "HTTPS %{http_code}\n" https://mcp.your-domain.com/mcp -X POST \
  -H "Content-Type: application/json" -d '{}'
# 期望: 401
```

---

## ⚠️ 已知限制 + 路线图

### 当前限制

| 项 | 说明 |
|---|---|
| 单 scope | 仅 `mcp:read`, 无 `mcp:write` |
| 单用户 | 授权页无登录态 (靠人工确认 + state 防 CSRF) |
| token 存储 | SQLite 单文件, 重启不丢 |
| 无 rate limit | 客户端可无限制调 |
| 无 audit log | 工具调用只 stderr 短期 |
| 无 mTLS | 仅 Bearer Token |

### 路线图 (Stage 4+)

- [ ] 写工具 (`mcp:write` scope, 更严审计)
- [ ] 多用户登录 (邮箱 + 密码)
- [ ] Rate limit (10 req/min/client)
- [ ] Audit log 持久化 (lark_outbox 同步)
- [ ] 多 token 支持
- [ ] OAuth 2.1 完整 (PKCE + DPoP)

---

## 🤖 给下一个 Agent 的接手清单

如果你是新接手的 Agent (无论 LLM/人), 按这个顺序快速恢复:

### 1. 理解架构 (5 分钟)
读本 README "架构" + "OAuth 2.1 流程详解" 2 节.

### 2. 拉代码 (1 分钟)
```bash
git clone https://github.com/<your-org>/hermes-mcp-server.git
cd hermes-mcp-server
```

### 3. 装依赖 + 启 (3 分钟)
按 "完整部署步骤" Step 2-7 走.

### 4. 跑端到端测试 (1 分钟)
```bash
python3 test_oauth_flow.py
# 13/13 通过 = 服务正常
```

### 5. 接入新 client (5 分钟)
- ChatGPT: Settings → Connectors → Add custom connector → 填 URL → 浏览器授权
- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`:
  ```json
  {
    "mcpServers": {
      "hermes-dev": {
        "url": "https://mcp.your-domain.com/mcp",
        "transport": "streamable-http"
      }
    }
  }
  ```
- Cline/Continue 同理 (URL + transport)

### 6. 关键命令速查

| 操作 | 命令 |
|---|---|
| 启 | `systemctl start hermes-mcp-bridge` |
| 停 | `systemctl stop hermes-mcp-bridge` |
| 重启 | `systemctl restart hermes-mcp-bridge` |
| 看日志 | `journalctl -u hermes-mcp-bridge -f` |
| 轮换静态 token | `python3 -c "import secrets; print(secrets.token_urlsafe(48))" > /home/hermes/.hermes/mcp_remote_token && systemctl restart hermes-mcp-bridge` |
| 跑端到端测试 | `cd /path/to/repo && python3 test_oauth_flow.py` |
| 看 OAuth DB | `sqlite3 /home/hermes/mcp_servers/oauth.db` |

### 7. 出问题怎么办?

| 现象 | 原因 | 修复 |
|---|---|---|
| 401 全部 | token 错 / bridge 没用新 token | 轮换 token + restart |
| 502 Bad Gateway | bridge 没启 | `systemctl restart hermes-mcp-bridge` |
| TLS 证书过期 | Caddy 没自动续 | `systemctl restart caddy` |
| OAuth metadata 404 | Caddy 没反代 /.well-known/* | 改 Caddyfile + restart |
| authorize 拒绝 | client 没 DCR 注册 | 检查 /oauth/register 端点 |
| 工具调失败 | bridge → stdio 后端断 | `journalctl -u hermes-mcp-bridge` |

---

## 📜 License & 维护

- 维护: Hermes PM Agent (VPS, youbenben07-dev)
- 上次更新: 2026-10-14
- 实跑: https://mcp.hermes.toothingbeginning.com/mcp
- 报告: [Stage 1](docs/STAGE1.md) | [Stage 3](docs/STAGE3.md) | [Stage 3.5](docs/STAGE3.5.md) | [Stage 3.6](docs/STAGE3.6.md)
