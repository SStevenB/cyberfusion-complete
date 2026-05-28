#!/usr/bin/env bash
# build.sh — full production build for CyberFusion (Option B: React + FastAPI).
# Used by deployment hosts (e.g. Render) and for local production builds.
#
# Steps:
#   1. install Python deps
#   2. install Node deps + build the React frontend → frontend/dist
#      (the API serves that dist/ directory in production)
set -e

echo "── 1/3 · Python dependencies ──"
pip install -r requirements.txt

echo "── 2/3 · Frontend dependencies ──"
cd frontend
# NODE_ENV=production makes npm skip devDependencies (vite!), so force-include them.
npm install --include=dev

echo "── 3/3 · Build React frontend ──"
node assemble.mjs        # regenerate src/CyberFusionApp.jsx from src/mockup/*
npm run build            # → frontend/dist
cd ..

echo "✓ Build complete. Start with:  uvicorn api.main:app --host 0.0.0.0 --port \$PORT"
