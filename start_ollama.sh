#!/usr/bin/env bash
# start_ollama.sh — start the local Ollama server in the background so the
# "Generate briefing" button produces real AI-written prose instead of templates.
#
# Usage:   ./start_ollama.sh
# Stop with:  pkill ollama   (or just close your laptop — it'll restart with this script)

if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama isn't installed. Install with:  brew install ollama"
  exit 1
fi

if lsof -ti:11434 >/dev/null 2>&1; then
  echo "Ollama is already running on :11434."
else
  echo "Starting Ollama in the background…"
  nohup ollama serve > /tmp/ollama.log 2>&1 &
  sleep 3
fi

# Make sure llama3 is available
if ! ollama list 2>/dev/null | grep -q "llama3"; then
  echo "Downloading llama3 model (~4.6 GB, one-time)…"
  ollama pull llama3
fi

echo ""
echo "✓ Ollama ready."
echo "  CyberFusion briefings will now use real AI (free, local)."
echo "  /api/briefing/status will show backend=ollama:llama3:latest"
