# Hermes MCP OAuth Compatibility Upgrade — Stage 3.6 部署报告

> 报告时间: 2026-10-14 19:55 北京
> 性质: VPS 本地升级 (新增 OAuth 2.1 认证, ChatGPT 可连接)
> 阶段: Stage 3.6 (OAuth 2.1 Authorization Code + PKCE + DCR)

---

## 1. OAuth 方案

**OAuth 2.1 Authorization Code Flow + PKCE (S256) + DCR (RFC 7591)**

| 特性 | 值 |
|---|---|
| 授权模式 | Authorization Code + PKCE |
| PKCE 方法 | S256 (强制, 不支持 plain) |
| 客户端注册 | DCR 动态注册 (ChatGPT 无需预注册 Client ID/Secret) |
| token 类型 | opaque (随机 bearer token) |
| access token 有效期 | 24 小时 |
| refresh token 有效期 | 30 天 (支持轮换) |
| scope | `mcp:read` (只读) |
| token 端点认证方法 | `none` (公共客户端) |
| 匿名访问 | ❌ 关闭 (无 token → 401) |

---

## 2. OAuth 端点

| 端点 | URL |
|---|---|
| **Authorization URL** | `https://mcp.hermes.toothingbeginning.com/oauth/authorize` |
| **Token URL** | `https://mcp.hermes.toothingbeginning.com/oauth/token` |
| **Registration URL (DCR)** | `https://mcp.hermes.toothingbeginning.com/oauth/register` |
| **OAuth 元数据发现** | `https://mcp.hermes.toothingbeginning.com/.well-known/oauth-authorization-server` |
| **资源服务器元数据** | `https://mcp.hermes.toothingbeginning.com/.well-known/oauth-protected-resource` |
| **MCP endpoint** | `https://mcp.hermes.toothingbeginning.com/mcp` |

---

## 3. Client 配置方式 (DCR)

ChatGPT 作为 OAuth client，通过 **DCR 自动注册**，无需手动获取 Client ID/Secret。

DCR 请求示例 (ChatGPT 自动发起):
```json
POST /oauth/register
{
  "client_name": "ChatGPT Connector",
  "redirect_uris": ["https://chatgpt.com/.../callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

服务器返回 `client_id`，后续 authorization code flow 全自动。

---

## 4. ChatGPT 填写方式

### 连接参数

| 项 | 值 |
|---|---|
| **Connector Name** | `Hermes Dev Agent` |
| **Server URL** | `https://mcp.hermes.toothingbeginning.com/mcp` |
| **Transport** | Streamable HTTP |
| **Authentication** | OAuth (Authorization Code + PKCE) |

### 操作步骤

1. ChatGPT 网页 → Settings → Connectors → Custom connectors → Add
2. 填 URL: `https://mcp.hermes.toothingbeginning.com/mcp`
3. ChatGPT 自动发现 OAuth 元数据 (`/.well-known/oauth-authorization-server`)
4. ChatGPT 自动 DCR 注册 client
5. 浏览器跳转到授权页 (`/oauth/authorize`)
6. 张健在授权页点 **"允许"** (授权 scope: `mcp:read`)
7. ChatGPT 拿到 access token → 自动调用 5 个只读工具
8. access token 过期后 ChatGPT 自动用 refresh token 续期 (30 天内无需重新授权)

---

## 5. 测试结果 (13/13 通过)

```
=== OAuth 2.1 端到端 ===
 1. metadata 端点             ✅ 200
 2. DCR 客户端注册            ✅ 201 client_id 返回
 3. PKCE S256                 ✅ challenge 生成
 4. authorize 授权页          ✅ 200 页面含"允许"
 5. 用户允许 → 302 + code     ✅ code 返回
 6. code → access token       ✅ 200 access_token + refresh_token
 7. access token 调 /mcp      ✅ 200 initialize serverInfo={hermes-dev-agent}
 8. tools/list                ✅ 200 5 工具
 9. 无 token → 401            ✅
10. 错 token → 401            ✅
11. refresh token 轮换        ✅ 200 新 access_token
12. 401 WWW-Authenticate 头   ✅ Bearer resource_metadata="..."
13. resource metadata 端点    ✅ 200

PASS: 13/13
```

### 安全验证

| 项 | 结果 |
|---|---|
| 匿名访问 | ❌ 关闭 (401) |
| PKCE 强制 S256 | ✅ plain 拒绝 |
| redirect_uri 精确匹配 | ✅ 未注册 URI 拒绝 |
| code 单次使用 | ✅ 重放拒绝 |
| 写工具 | ❌ 无 (保持 5 个只读工具) |

---

## 6. 完整 OAuth 发现机制 (MCP 规范)

1. ChatGPT 发 `POST /mcp` initialize → 收到 401 + `WWW-Authenticate: Bearer resource_metadata=".../.well-known/oauth-protected-resource", scope="mcp:read"`
2. ChatGPT 读 resource metadata → 拿到 `authorization_servers`
3. ChatGPT 读 `/.well-known/oauth-authorization-server` → 拿到 authorize/token/register 端点
4. ChatGPT DCR 注册 → 走 authorization code + PKCE flow
5. 用户授权 → ChatGPT 拿 access token → 调用工具

---

## 7. 文件清单

### 新增文件
| 文件 | 大小 | 说明 |
|---|---|---|
| `/home/hermes/mcp_servers/hermes_oauth.py` | 12296 字节 | OAuth 2.1 AS 核心 (SQLite + PKCE + DCR) |
| `/home/hermes/mcp_servers/test_oauth_flow.py` | 6079 字节 | 端到端测试脚本 |
| `/home/hermes/mcp_servers/oauth.db` | SQLite | client/auth_code/token 持久化 |

### 修改文件
| 文件 | 改动 |
|---|---|
| `/home/hermes/mcp_servers/hermes_remote_bridge.py` | 集成 OAuth 5 端点 + 双 token 认证 + WWW-Authenticate 头 |

### 运行进程
| 进程 | 状态 |
|---|---|
| hermes_remote_bridge | ✅ PID 317323, listen 127.0.0.1:8443 |
| caddy | ✅ PID 315380 (反代不变) |
| Let's Encrypt 证书 | ✅ 不变 |

---

## 8. 保留的现有能力 (未破坏)

| 项 | 状态 |
|---|---|
| MCP endpoint `/mcp` | ✅ 未变 |
| Streamable HTTP transport | ✅ 未变 |
| 静态 Bearer Token | ✅ 仍兼容 (内部/PM 访问) |
| 5 个只读工具 | ✅ 未变 |
| 写权限 | ❌ 仍无 (未增加) |
| ECS 业务代码 | ✅ 未动 |

---

## 9. 已知限制 + 后续建议

| 项 | 说明 |
|---|---|
| 授权页 | 极简 HTML, 无登录态 (仅张健一人用, 靠 PKCE + state 防 CSRF) |
| 单 scope | 仅 `mcp:read` (只读), 后续可扩展 `mcp:write` |
| access token 存储 | SQLite 单文件, 重启不丢 |
| 建议 | 加 rate limit / audit log / 多用户登录 |

— PM Agent