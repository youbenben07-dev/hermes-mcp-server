# Hermes MCP Production Connection Upgrade — Stage 3.5 部署报告

> 报告时间: 2026-10-14 19:30 北京
> 性质: VPS 本地升级 (IP → 正式域名 + Let's Encrypt)
> 阶段: Stage 3.5 (生产正式域名 HTTPS MCP)

---

## 1. 正式 MCP URL

```
https://mcp.hermes.toothingbeginning.com/mcp
```

**升级内容**: 从临时 IP `https://23.95.226.156/mcp` → 正式域名 `https://mcp.hermes.toothingbeginning.com/mcp`。

---

## 2. DNS 解析结果

| 域名 | A 记录 | 状态 |
|---|---|---|
| `mcp.hermes.toothingbeginning.com` | **23.95.226.156** | ✅ 正确指向 VPS |
| `hermes.toothingbeginning.com` | 23.95.226.156 | ✅ 父域名同指 VPS |
| `toothingbeginning.com` | 23.227.38.65 | 根域名指向别处（无影响）|

验证: `dig +short mcp.hermes.toothingbeginning.com A` → `23.95.226.156` ✅

---

## 3. TLS 证书状态

| 项 | 值 |
|---|---|
| **证书类型** | Let's Encrypt (公开可信 CA) |
| **CN** | `mcp.hermes.toothingbeginning.com` |
| **Issuer** | C=US, O=Let's Encrypt, CN=YE2 |
| **有效期** | 2026-10-14 → 2027-01-12 (90 天自动续期) |
| **TLS 版本** | 1.3 (同时支持 1.2) |
| **自动续期** | ✅ Caddy 自动 (background maintenance) |
| **已弃用** | IP 自签证书 (CN=23.95.226.156) |

**Caddy 证书存储**: `/root/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/mcp.hermes.toothingbeginning.com/`

---

## 4. Transport 类型

**Streamable HTTP** (over HTTPS)

- `POST /mcp` with JSON-RPC 2.0 body
- Content-Type: `application/json`
- MCP protocolVersion: `2024-11-05`

---

## 5. Authentication 方式

**Bearer Token** (静态)

```
Authorization: Bearer stage3-test-token-CHANGEME-2026-10-14
```

- Token 持久化: `/home/hermes/.hermes/mcp_remote_token` (mode 600)
- 401 拒绝: 无 Authorization / Basic auth / 错误 token
- ⚠️ **TODO**: 测试 token 已在报告中, 上线前必须改 (`HERMES_MCP_TOKEN` env 或重写 token 文件)

---

## 6. Tools 列表 (5 个, 全部只读)

| 工具 | 范围 | 说明 |
|---|---|---|
| `hermes_system_status` | VPS+ECS | uptime/内存/磁盘/worker PID/cs-inbox unit/health HTTP |
| `hermes_ecs_shell` | ECS | 32 个只读命令白名单 |
| `hermes_read_file` | ECS/VPS | 15 个白名单绝对路径 |
| `hermes_git_status` | cs-inbox | log + status + remote + HEAD |
| `hermes_logs` | VPS/ECS | worker.log / worker.err / nginx access/error |

**写工具**: ❌ 无（Stage 1 只读安全模型保持）

---

## 7. 测试结果（端到端 13/13 通过）

```
=== Step 5 端到端 (正式域名) ===
5.1 TLS handshake: 200, 公开可信证书 ✅
5.2 证书 subject=CN=mcp.hermes.toothingbeginning.com, issuer=Let's Encrypt YE2 ✅
5.3 MCP initialize: 200, serverInfo={hermes-dev-agent, 1.0.0} ✅
5.4 tools/list: 200, 5 tools ✅
5.5 tools/call hermes_system_status: 200
    ECS cs-inbox.service: active ✅
    ECS health HTTP: 200 ✅
    worker PID: 310177 ✅

=== Step 6 安全测试 ===
6.1 无 Authorization → 401 ✅
6.2 错误 Bearer → 401 ✅
6.3 Basic auth → 401 ✅
6.4 正确 Bearer → 200 ✅
6.5 rm -rf → blocked ✅
6.6 git push → blocked ✅
6.7 /etc/passwd → blocked ✅
6.8 重定向 → blocked ✅

PASS: 13/13
```

---

## 8. ChatGPT Connector 配置步骤

### 连接参数

| 项 | 值 |
|---|---|
| **Connector Name** | `Hermes Dev Agent` |
| **Server URL** | `https://mcp.hermes.toothingbeginning.com/mcp` |
| **Transport** | Streamable HTTP |
| **Authentication** | Bearer Token |
| **Token** | `stage3-test-token-CHANGEME-2026-10-14` |

### 操作步骤

1. 登录 ChatGPT 网页 → Settings → Connectors → Custom connectors
2. 点击 "Add custom connector"
3. 填写:
   - Name: `Hermes Dev Agent`
   - URL: `https://mcp.hermes.toothingbeginning.com/mcp`
   - Authentication: `Bearer`
   - Token: `stage3-test-token-CHANGEME-2026-10-14`
4. Save 保存
5. 新开对话，选该 connector，问: "Run hermes_system_status"
6. ChatGPT 调用工具 → 返回 ECS/cs-inbox 状态

---

## 9. 文件清单 + 配置改动

### 新增文件
| 文件 | 大小 |
|---|---|
| `/home/hermes/codes/cs-inbox/deployment_reports/hermes-mcp-production-stage3.5.md` | 本报告 |
| `/home/hermes/mcp_servers/Caddyfile.backup-pre-stage35-20261014-111724` | Caddy 配置备份 |

### 修改文件
| 文件 | 改动 |
|---|---|
| `/etc/caddy/Caddyfile` | IP catch-all → 域名站点 + IP 站点分离（修复 SNI 证书路由）|

### 关键配置 (Caddyfile)
```caddy
mcp.hermes.toothingbeginning.com {
    @mcp { path /mcp* }
    handle @mcp { reverse_proxy 127.0.0.1:8443 }
    handle { reverse_proxy 127.0.0.1:8443 }
}

https://23.95.226.156 {
    tls /etc/caddy/certs/fullchain.pem /etc/caddy/certs/privkey.pem
    @webhook { path /webhook/* }
    handle @webhook { reverse_proxy 127.0.0.1:5051 }
    handle { reverse_proxy 127.0.0.1:5050 }
}

:80 { reverse_proxy 127.0.0.1:5050 }
```

---

## 10. 关键修复记录

**SNI 证书路由 bug（已修复）**:
- 现象: 域名返回 IP 自签证书 (CN=23.95.226.156)，未返回 Let's Encrypt 证书
- 根因: Caddy 2.6.2 中 catch-all `:443` 的显式 `tls /path/cert`（IP 证书）成为全局默认证书，覆盖命名站点的 Let's Encrypt 证书 SNI 路由
- 修复: 把 catch-all `:443` 改为显式 `https://23.95.226.156` 站点，IP 证书绑定到 IP 站点，命名站点独立走 Let's Encrypt
- 结果: 域名 → Let's Encrypt ✅ / IP → IP 证书 ✅

---

## 11. 生产上线前 TODO（重要）

| 项 | 说明 |
|---|---|
| ⚠️ **改 token** | `stage3-test-token-CHANGEME-2026-10-14` 是测试 token，必须改 |
| ⚠️ **改 email** | Caddy 配置用 `admin@toothingbeginning.com`，确认是否真实邮箱（用于证书过期通知）|
| 建议 | 加 rate limit (FastAPI middleware) |
| 建议 | 加 audit log (工具调用持久化) |
| 建议 | 多客户端独立 token |

— PM Agent