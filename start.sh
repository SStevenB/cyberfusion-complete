#!/usr/bin/env bash
# start.sh — one-command launcher for the CyberFusion web app.
#
# What it does:
#   1. moves into the project folder (wherever this script lives)
#   2. activates the Python virtual environment
#   3. frees port 8000 if a previous server is still running
#   4. starts the FastAPI server (which serves both the API and the React app)
#
# Usage:   ./start.sh
# Then open:  http://localhost:8000
# Stop with:  Ctrl+C

set -e
cd "$(dirname "$0")"

PORT=8000

# 1. activate venv
if [ -d "venv" ]; then
  source venv/bin/activate
else
  echo "No venv found. Create one first:  python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
  exit 1
fi

# 2. free the port if something is already listening on it
if lsof -ti:$PORT >/dev/null 2>&1; then
  echo "Port $PORT is in use — stopping the old server first…"
  lsof -ti:$PORT | xargs kill 2>/dev/null || true
  sleep 1
fi

# 3. start the server
echo ""
echo "  CyberFusion is starting…"
echo "  → Open your browser to:  http://localhost:$PORT"
echo "  → Press Ctrl+C here to stop."
echo ""
exec uvicorn api.main:app --port $PORT
