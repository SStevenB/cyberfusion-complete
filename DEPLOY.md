# Deploying CyberFusion (React + FastAPI)

CyberFusion's web app is a **React frontend** served by a **FastAPI backend**.
In production both run as **one process**: FastAPI serves the REST API at
`/api/*` and the built React app (`frontend/dist`) at everything else.

## Local — development (two servers, hot reload)
```bash
# terminal 1 — API
source venv/bin/activate
uvicorn api.main:app --reload --port 8000

# terminal 2 — Vite dev server (proxies /api → :8000)
cd frontend
unset NODE_ENV        # NODE_ENV=production breaks npm install (skips vite)
npm install --include=dev
npm run dev           # http://localhost:5173
```

## Local — production (one server)
```bash
./build.sh                                    # installs deps + builds frontend/dist
uvicorn api.main:app --host 0.0.0.0 --port 8000
# open http://localhost:8000  (API + app on one port)
```

## Deploy to Render (recommended — free tier, Python-native)
1. Push the repo to GitHub.
2. In Render: **New → Blueprint**, point it at the repo. It reads `render.yaml`.
3. Render runs `./build.sh` then starts `uvicorn api.main:app --host 0.0.0.0 --port $PORT`.
4. Done — one public URL serves both the app and the API.

## Deploy with Docker (Fly.io, Railway, any container host)
```bash
docker build -t cyberfusion .
docker run -p 8000:8000 cyberfusion
# open http://localhost:8000
```
The multi-stage `Dockerfile` builds the frontend with Node, then runs it with Python.

## Notes
- **Secrets:** locally, connector API keys go in your OS keychain (`keyring`). On a
  server there's no keychain, so the gitignored file fallback is used. For real
  connector keys in production, set them as host env vars and read them in the
  connector layer.
- **Pipeline data** (`data/raw|processed|outputs`) is generated at runtime via
  `POST /api/pipeline/run` or the "Run pipeline now" button — it isn't committed.
- **The Streamlit app still works** (`streamlit run dashboard/app.py`) as an
  alternative interface; the React app is the primary product UI.
