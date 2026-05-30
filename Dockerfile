# ── Stage 1: build the React frontend ─────────────────────────────────────────
FROM node:22-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install --include=dev
COPY frontend/ ./
RUN node assemble.mjs && npm run build      # → /app/frontend/dist

# ── Stage 2: Python runtime serving API + built frontend ──────────────────────
FROM python:3.12-slim AS runtime
WORKDIR /app

# System deps kept minimal; nmap not required (uploads are parsed, not run).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY api/ ./api/
COPY analysis/ ./analysis/
COPY ingestion/ ./ingestion/
COPY data_collection/ ./data_collection/
COPY scanning/ ./scanning/
COPY dashboard/ ./dashboard/
COPY samples/ ./samples/
COPY config/ ./config/
COPY build_demo.py run_pipeline.py ./
RUN mkdir -p data/raw data/processed data/outputs data/uploads

# Bring in the built frontend from stage 1
COPY --from=frontend /app/frontend/dist ./frontend/dist

EXPOSE 8000
# $PORT is provided by most PaaS hosts; default to 8000 locally.
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
