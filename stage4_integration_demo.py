#!/usr/bin/env python3
"""Stage 4.1 隔离集成演练 (end-to-end)."""
import json, sqlite3, sys, time, subprocess
from pathlib import Path
sys.path.insert(0, '/home/hermes/mcp_servers')
import hermes_stage4 as s4

BASE = "https://mcp.hermes.toothingbeginning.com/mcp"
STATIC_TOKEN = Path("/home/hermes/.hermes/mcp_remote_token").read_text().strip()
import urllib.request

def http_post(body, auth=True):
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2026-07-28",
               "Mcp-Method": body.get("method", ""),
               "Origin": "https://chatgpt.com"}
    if auth:
        headers["Authorization"] = f"Bearer {STATIC_TOKEN}"
    req = urllib.request.Request(BASE, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())

def call_tool(name, args):
    r = http_post({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": name, "arguments": args}})
    if "error" in r:
        return {"_error": r["error"]}
    t = r["result"]["content"][0]["text"]
    return json.loads(t)

TID = "stage4-demo-1"

# 清干净 (需要的话)
# 0. 清状态 (干净开始)
import os
db = "/home/hermes/mcp_servers/stage4_state.db"
if os.path.exists(db):
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM approval_tickets")
    conn.execute("DELETE FROM tasks")
    conn.execute("DELETE FROM audit_log")
    conn.execute("DELETE FROM task_locks")
    conn.commit()
    conn.close()
s4.init_state_db()

print("=" * 60)
print("Stage 4.1 隔离集成演练 (chatGPT → VPS → 隔离环境)")
print("=" * 60)

# 1. change_plan (只读, 不需票据)
print("\n[1] change_plan (只读)")
r = call_tool("hermes_change_plan", {"task_id": TID, "requirement": "加 stage4 标记注释到 app.py", "module": "demo"})
print(f"  ok={r.get('ok')} git_head={r.get('plan',{}).get('git_head')} risk={r.get('plan',{}).get('risk')}")

# 2. PM mint 票据 (本地 PM 端)
print("\n[2] PM mint 票据 (本地)")
t_ap = s4.mint_approval_ticket(TID, "apply_patch", "app.py")
t_dep = s4.mint_approval_ticket(TID, "deploy", "*")
t_rb = s4.mint_approval_ticket(TID, "rollback", "*")
print(f"  apply_patch: {t_ap[:20]}...")
print(f"  deploy:      {t_dep[:20]}...")
print(f"  rollback:    {t_rb[:20]}...")

# 3. run_tests (隔离副本)
print("\n[3] run_tests (隔离副本)")
r = call_tool("hermes_run_tests", {"task_id": TID, "test_plan": "syntax"})
print(f"  ok={r.get('ok')} results_keys={list(r.get('results',{}).keys())}")

# 4. apply_patch (worktree + diff + commit)
# 真实生成 patch: 用 git diff 拿精确 diff (避免 hand-patch 编码问题)
import subprocess as sp
print("\n[4] apply_patch (创建 worktree + git apply + syntax + commit)")
# 临时改 cs-inbox-fresh/app.py 末尾加一行 stage4 标记, 拿 diff
sp.run(["git", "-C", "/home/hermes/cs-inbox-fresh", "checkout", "--", "app.py"], check=False, capture_output=True)
sp.run(["bash", "-c", 'echo "# Stage 4.1 isolated test marker (NOT deployed to ECS)" >> /home/hermes/cs-inbox-fresh/app.py'])
diff_proc = sp.run(["git", "-C", "/home/hermes/cs-inbox-fresh", "diff", "app.py"], capture_output=True, text=True)
diff = diff_proc.stdout
# 立刻 reset (apply_patch 工具会再 reset)
sp.run(["git", "-C", "/home/hermes/cs-inbox-fresh", "checkout", "--", "app.py"], capture_output=True)
print(f"  diff lines: {len(diff.splitlines())}")
r = call_tool("hermes_apply_patch", {
    "task_id": TID, "target_file": "app.py",
    "patch": diff, "approval_ticket": t_ap,
})
if r.get("ok"):
    print(f"  ✅ ok={r['ok']} new_commit={r['new_commit']} branch={r['branch']}")
    print(f"     worktree={r['worktree']}")
    print(f"     syntax_ok={r['syntax_ok']} sha256={r.get('sha256_after','')[:16]}...")
    new_commit = r["new_commit"]
else:
    print(f"  ❌ {r}")
    sys.exit(1)

# 5. deploy (本地隔离服务 + health)
print("\n[5] deploy (本地 5059 隔离服务 + health check)")
r = call_tool("hermes_deploy", {
    "task_id": TID, "commit": new_commit,
    "approval_ticket": t_dep, "target": "local",
})
if r.get("ok"):
    print(f"  ✅ ok={r['ok']} commit={r['commit']} health={r['health']}")
    print(f"     prev_head={r['prev_head']} port={r['service_port']}")
    print(f"     backup={r['backup_bundle']}")
else:
    print(f"  ❌ {r}")
    sys.exit(1)

# 6. rollback (从备份恢复)
print("\n[6] rollback (从备份 bundle 恢复)")
r = call_tool("hermes_rollback", {
    "task_id": TID, "target": "commit:" + r["prev_head"],
    "approval_ticket": t_rb,
})
if r.get("ok"):
    print(f"  ✅ ok={r['ok']} new_head={r['new_head']} health={r['health']}")
else:
    print(f"  ❌ {r}")

# 7. change_status (审计)
print("\n[7] change_status (审计追踪)")
r = call_tool("hermes_change_status", {"task_id": TID})
print(f"  status={r.get('status')} write_enabled={r.get('production_write_enabled')}")
print(f"  audit_trail 条数={len(r.get('audit_trail',[]))}")
for ev in r.get("audit_trail", [])[:6]:
    print(f"    {ev.get('operation'):20} {ev.get('result'):20} {ev.get('detail','')[:60]}")

print()
print("=" * 60)
print("集成演练完成: change_plan → run_tests → apply_patch → deploy → rollback → status")
print("=" * 60)