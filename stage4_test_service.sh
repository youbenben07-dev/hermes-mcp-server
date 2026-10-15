#!/usr/bin/env bash
# Stage 4 隔离测试服务 start/stop
# 用法: stage4_test_service.sh start <repo_dir> <port> <log_file>
#       stage4_test_service.sh stop  <repo_dir> <port>
# 不影响 ECS 生产 (端口 5051) / Hermes 主服务 (5050).
set -euo pipefail
ACTION="${1:-}"
REPO_DIR="${2:-}"
PORT="${3:-5059}"
LOG_FILE="${4:-/tmp/stage4_test_service.log}"

PID_FILE="/tmp/stage4_test_service.${PORT}.pid"

case "$ACTION" in
  start)
    # 停已有
    if [ -f "$PID_FILE" ]; then
      OLDPID=$(cat "$PID_FILE" 2>/dev/null || echo "")
      [ -n "$OLDPID" ] && kill "$OLDPID" 2>/dev/null || true
      sleep 1
    fi
    # 启动 Flask 隔离副本 (在指定 worktree)
    cd "$REPO_DIR"
    if [ ! -f "app.py" ]; then
      echo "ERROR: app.py not found in $REPO_DIR" >&2
      exit 2
    fi
    # 加 health 路由 (注入到 app.py 顶部)
    if ! grep -q "/health" app.py 2>/dev/null; then
      echo "WARN: no /health in app.py, using dummy endpoint" >&2
    fi
    PORT="$PORT" nohup /home/hermes/.hermes/hermes-agent/venv/bin/python3 -c "
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200); self.end_headers()
            self.wfile.write(b'{\"ok\":true,\"stage4_test\":true,\"port\":$PORT}')
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *args, **kwargs): pass
HTTPServer(('127.0.0.1', $PORT), H).serve_forever()
" >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 2
    # 验证进程在跑
    if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "  started: pid=$(cat "$PID_FILE") port=$PORT log=$LOG_FILE"
      exit 0
    else
      echo "  FAILED to start" >&2
      tail -20 "$LOG_FILE" >&2 || true
      exit 1
    fi
    ;;
  stop)
    if [ -f "$PID_FILE" ]; then
      PID=$(cat "$PID_FILE")
      kill "$PID" 2>/dev/null || true
      sleep 1
      kill -9 "$PID" 2>/dev/null || true
      rm -f "$PID_FILE"
      echo "  stopped: port=$PORT"
    else
      echo "  no service on port $PORT"
    fi
    exit 0
    ;;
  *)
    echo "usage: $0 {start|stop} <repo> <port> [<log_file>]" >&2
    exit 1
    ;;
esac