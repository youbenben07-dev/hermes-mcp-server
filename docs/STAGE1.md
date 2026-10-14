# Hermes Dev Agent Upgrade — Stage 1 部署报告

> 报告时间: 2026-10-14 18:55 北京
> 性质: VPS 本地部署, 不影响 ECS 生产
> 阶段: Stage 1 (MCP stdio + 5 工具, 只读)

---

## 1. 修改文件 (VPS 本地, 不动 ECS)

| 文件 | 操作 | 大小 |
|---|---|---|
| `/home/hermes/mcp_servers/hermes_dev_agent.py` | **新增** | 15097 字节 |
| `~/.hermes/mcp_config.json` (自动) | **修改** | +1 server entry (hermes-dev) |

**未修改**:
- ❌ `/home/fastmedlink/cs-inbox/` (ECS 生产, 严令禁止)
- ❌ `app.py` / 业务 routes / DB schema / 客户数据
- ❌ VPS 上的 hermes-agent 源码
- ❌ 任何 systemd unit

---

## 2. 新增能力 (5 个 MCP 工具)

### 工具清单
| 工具名 | 能力 | 范围 |
|---|---|---|
| `hermes_system_status` | 一次性返回 VPS + ECS 整体状态 (uptime/memory/disk/worker PID/cs-inbox 单元/健康 HTTP) | 只读 |
| `hermes_ecs_shell` | 在 ECS (47.250.166.208) 上跑只读 shell | 只读 (白名单) |
| `hermes_read_file` | 读 ECS/VPS 文件 (15 个白名单绝对路径) | 只读 |
| `hermes_git_status` | cs-inbox git 状态 (log/status/remote/HEAD) | 只读 |
| `hermes_logs` | 读 worker.log / worker.err / nginx access/error | 只读 |

### 安全设计 (Stage 1 强约束)
- ✅ **白名单 shell 命令** (32 个允许前缀)
- ✅ **白名单文件路径** (15 个绝对路径)
- ✅ **黑名单危险模式** (rm -rf, git push, 重定向, sudo, systemctl restart 等 22 种)
- ✅ **超时控制** (VPS 3-5s, ECS 8-15s)
- ✅ **stdin/stdout 字符数截断** (stdout 5-8KB)
- ✅ **完全无写操作** — Stage 1 阶段任何写/改/删都被拒

---

## 3. 测试结果 (7/7 端到端通过)

```
=== E2E 1: hermes_system_status (VPS+ECS 整体) ===
  VPS uname: Linux racknerd-a36dd2b 6.19.6-x64v3-xanmod1
  ECS uptime:  18:55:23 up 158 days, 27 min, 3 users, load average: 0.09, 0.06, 0.01
  worker_pid: 310177
  cs_inbox_unit: active
  cs_inbox_health_http: 200  ✅ 健康

=== E2E 2: hermes_ecs_shell (systemctl + ps) ===
  systemctl is-active cs-inbox.service: active ✅
  ps aux cs-inbox/app.py: PID 70223 alive ✅

=== E2E 3: hermes_read_file (app.py 前 10 行) ===
  成功读到 ECS app.py, 确认端口 5051, Flask 独立进程
  """FastMedLink 客服工作台 — 独立 Flask app ..."""

=== E2E 4: hermes_git_status ===
  HEAD: 098c1ac9f311fe0f23b11b623ab259bb878cc439 (2026-10-14 11:54:57 +0800)
  log top 3:
    - 098c1ac issue59-pm-deploy-report-20261014-1152
    - 89d4b13 issue-queue report 2026-10-14-0304-issue-deploy-62.md
    - 364afca issue-queue report 2026-10-14-0239-issue-deploy-60.md
  working tree: clean ✅

=== E2E 5: hermes_logs (worker, 10 lines) ===
  成功读到 worker.log (注: 历史 sleep_state 痕迹不影响当前)

=== E2E 6: 安全测试 ===
  'rm -rf /tmp/test':          BLOCKED ✅
  'git push origin main':      BLOCKED ✅
  'echo x > /etc/test':        BLOCKED ✅

=== E2E 7: 安全测试 (/etc/passwd) ===
  非白名单文件: BLOCKED ✅

PASS: 7/7 end-to-end
```

---

## 4. 注册到 hermes

```bash
$ hermes mcp add hermes-dev \
    --command /home/hermes/.hermes/hermes-agent/venv/bin/python3 \
    --args /home/hermes/mcp_servers/hermes_dev_agent.py
  ✓ Connected! Found 5 tool(s) from 'hermes-dev'
```

**注意**：`hermes mcp list` 缓存不刷新（hermes 自身 bug），但 `mcp add` 实际已成功（`mcp test` 能看到 5 工具）。Stage 1 阶段不影响功能。

---

## 5. 使用方式

### 方式 A: hermes mcp serve (stdin/stdout)
```bash
# 直接启 server (前台)
hermes-dev  # 5 工具等待调用

# 或通过 hermes:
hermes mcp test hermes-dev
```

### 方式 B: 接 ChatGPT/Claude Desktop 等 MCP 客户端
在客户端配置:
```json
{
  "mcpServers": {
    "hermes-dev": {
      "command": "/home/hermes/.hermes/hermes-agent/venv/bin/python3",
      "args": ["/home/hermes/mcp_servers/hermes_dev_agent.py"]
    }
  }
}
```

### 方式 C: Python SDK 调
```python
import json, subprocess
proc = subprocess.Popen([...], stdin=PIPE, stdout=PIPE, text=True)
proc.stdin.write(json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call",
    "params":{"name":"hermes_system_status","arguments":{}}}) + "\n")
print(proc.stdout.readline())
```

---

## 6. 下一阶段建议

### Stage 2 (待您授权):
| 工具 | 用途 | 风险 |
|---|---|---|
| `hermes_ecs_write_file` | 写文件到 ECS 白名单路径 (.env/auth.py 等) | **高**, 需您单独授权 |
| `hermes_ecs_run_command` | 跑非只读命令 (systemctl restart / git pull) | **高**, 需白名单 + 干跑模式 |
| `hermes_pm_dispatch` | PM-direct dispatch 任务给子 agent | 中 |
| `hermes_worker_control` | restart worker / 调 worker.py | 中 |
| `hermes_ecs_backup` | 触发 _backup_issue*_datetime/ 备份 | 中 |

### Stage 3 (ChatGPT 远程接入):
| 组件 | 用途 |
|---|---|
| **Streamable HTTP 反向代理** | caddy/streamable-http-bridge (VPS 上) |
| **OAuth 2.1 适配** | 复用 VPS 已有身份提供方, 或自建 |
| **域名 + DNS + TLS** | 例 mcp.hermes.fastmedlink.com |
| **ChatGPT Custom MCP Connector** | 用户在 ChatGPT 管理页面配置 |

### 优先级建议:
1. **先 Stage 2 写工具** (您之前定的"业务修复"工作流)
2. **再 Stage 3 远程接入** (把 #59 acceptance 的承诺落地)

### Stage 1 已知限制:
- ❌ 暂不支持远程 HTTP, 仅 stdio (本机或 SSH)
- ❌ 暂无 OAuth, 任何能调 stdio 的进程都能用 (Stage 2 加白名单 + 密钥)
- ❌ 暂无 audit log, 工具调用没记录 (Stage 2 加)

---

## 7. 文件清单 (curl/ls 验证)

```bash
# 主文件
$ ls -la /home/hermes/mcp_servers/hermes_dev_agent.py
-rw------- 1 hermes hermes 15097 Oct 14 18:55

# 验证 ast.parse
$ python3 -c "import ast; ast.parse(open('/home/hermes/mcp_servers/hermes_dev_agent.py').read()); print('OK')"
OK

# 验证 5 工具注册
$ hermes mcp add hermes-dev ...
✓ Connected! Found 5 tool(s) from 'hermes-dev'
```

---

## 8. 回退方法

```bash
# 1. 移除 MCP 注册
hermes mcp remove hermes-dev

# 2. 删除 server 文件
rm -rf /home/hermes/mcp_servers/

# 3. (可选) 重启 hermes gateway 让 list 刷新
# (hermes mcp list 缓存 bug 不影响功能, 不必重启)
```

---

**报告 SHA**: `2026-10-14-1855-stage1-deploy.md` (本地, 未推 GitHub)
**Codex 评审**: 待 (Stage 1 是您直接授权, 不走 Codex)
**下一阶段**: 等您飞书指示进入 Stage 2 (写工具) 或 Stage 3 (远程 HTTP/OAuth)

— PM Agent
