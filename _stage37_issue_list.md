# Stage 3.7 ChatGPT 兼容性问题清单

## 用户测试 ChatGPT 实际遇到的问题
1. **bridge 进程死亡** — 11:29-11:46 期间 502 连接拒绝（死机 17 分钟），无自动拉起
2. **MCP protocolVersion 错** — 返回 `2024-11-05`，ChatGPT 用 `2025-06-18`
3. **缺少 MCP-Protocol-Version 请求头处理** — 2025-06-18 spec 强制
4. **缺少 Mcp-Session-Id 响应头** — Stateful streamable HTTP 必须有
5. **没处理 notifications/initialized** — 应 202 no body，实测 422
6. **不支持 SSE 流式响应** — 2025-06-18 spec `Accept: application/json, text/event-stream`
7. **授权页无身份验证** — **任何人**通过 DCR + 直接 allowed=1 就能拿 access token（重大安全漏洞）

## 修复优先级

### P0 (立刻)
1. **修复授权页身份验证** — 强制要求 PM/Tailscale/特殊密码/时间敏感 nonce
2. **修复 MCP protocolVersion** — 返回 `2025-06-18`，处理 `MCP-Protocol-Version` 头
3. **修复 Mcp-Session-Id** — initialize 后生成 session_id，subsequent 请求带
4. **修复 notifications/initialized** — 202 no body，不转发 stdio
5. **支持 SSE Accept 头** — 2025-06-18 spec 要求

### P1 (同样必要)
6. **加 systemd 服务** — bridge 死了自动拉起
7. **加 health check 自动修复 cron** — 每分钟检查，死了重启
8. **Caddy 上游健康检查** — caddy 自动剔除死 upstream

### P2 (待评估)
9. **日志持久化** — bridge stderr 现在是 pipe，重启就丢
