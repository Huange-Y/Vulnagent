#!/bin/bash
# Deploy Emulation Agent to Ubuntu VM (user@host:22)
# Run from vulnagent project root

TARGET="${EMU_HOST:-user@vm-host}"
PORT="${EMU_PORT:-22}"
KEY="${EMU_SSH_KEY:-$HOME/.ssh/id_ed25519}"
REMOTE_DIR="/tmp/emulation_agent"

echo "=== Deploying Emulation Agent to ${TARGET}:${PORT} ==="

# Copy server
scp -i "$KEY" -P "$PORT" -r \
  src/vulnagent/emulation_agent/server.py \
  "${TARGET}:${REMOTE_DIR}/"

# Install deps and start
ssh -i "$KEY" -p "$PORT" "$TARGET" << 'REMOTE'
  set -e
  pip3 install fastapi uvicorn python-multipart 2>/dev/null || true
  pkill -f "uvicorn.*emulation_agent" 2>/dev/null || true
  sleep 1
  cd /tmp/emulation_agent
  nohup python3 -m uvicorn server:app --host 0.0.0.0 --port 9100 > /tmp/emu_agent.log 2>&1 &
  echo "PID=$!"
  sleep 2
  curl -s http://127.0.0.1:9100/api/health || echo "START FAILED"
REMOTE

echo "=== Done ==="
