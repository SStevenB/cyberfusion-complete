CyberFusion — Threat Intelligence Prioritization Platform

> A cyber risk fusion engine built in Python — designed to mirror real SOC/CTI analyst workflows using public intelligence sources, authorized telemetry, and rule-based signal correlation.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red.svg)](https://streamlit.io/)
[![React](https://img.shields.io/badge/Web%20App-React%20%2B%20FastAPI-0FB5A8.svg)](#two-ways-to-run-the-web-app)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ethics: Lab Safe](https://img.shields.io/badge/Scope-Lab%20Safe-green.svg)](#ethics--scope)

---

## 🔗 Live Demo

**[View the interactive demo →](https://SStevenB.github.io/cyberfusion-complete/)**

A static, self-contained build of the dashboard hosted on GitHub Pages. The
findings, risk scores, CVEs (NIST NVD), CISA KEV entries, security news, and
lab port-scan results shown are **real output from a pipeline run**. A few
elements are clearly tagged `illustrative` in the UI (30-day trend, peer
benchmark, MTTR, briefing history), and breach/exposure records are
clearly-labeled synthetic. The in-app **Methodology → About This Demo** panel
spells out exactly what is real vs. illustrative.


---

## What This Project Does

CyberFusion is a multi-source threat intelligence aggregation and risk prioritization platform. It ingests signals from public/authorized data sources **and from security evidence a user uploads or connects** (vulnerability scans, asset inventories, breach exports, identity-risk logs, STIX threat intel), normalizes everything into a unified schema, applies rule-based correlation logic, scores the resulting findings by business risk, and presents them in an interactive analyst dashboard. Configured sources are **saved to a local workspace** so a returning user doesn't re-upload each session.

**The core pipeline: Collect → Normalize → Correlate → Score → Visualize**

This mirrors the core workflow of real CTI platforms like Recorded Future, ThreatConnect, and enterprise SIEM correlation engines — built entirely from public data and open-source tools.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Data Collection Layer                    │
│  NVD CVEs │ RSS News │ Shodan (free) │ GreyNoise │ HaveIBeenPwned│
└──────────────────────────┬──────────────────────────────────────┘
                           │  raw JSON
┌──────────────────────────▼──────────────────────────────────────┐
│                       Normalization Layer                       │
│         Unified schema: source, type, severity, asset, tags     │
└──────────────────────────┬──────────────────────────────────────┘
                           │  normalized items
┌──────────────────────────▼──────────────────────────────────────┐
│                       Correlation Engine                        │
│   8 detection rules linking signals across sources              │
│   Every finding is explainable — no black boxes                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │  correlated findings
┌──────────────────────────▼──────────────────────────────────────┐
│                        Risk Scoring Layer                       │
│   Numeric score with full breakdown: severity + confidence      │
│   + rule weight + evidence count + asset criticality            │
└──────────────────────────┬──────────────────────────────────────┘
                           │  scored findings
┌──────────────────────────▼──────────────────────────────────────┐
│                      Presentation Layer                         │
│   React SPA + FastAPI  ·OR·  Streamlit dashboard                │
│   Executive · Data Sources · Upload · Findings · Methodology    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Two Ways to Run the Web App

CyberFusion ships **two interchangeable frontends** over the same Python pipeline:

| | React + FastAPI (primary) | Streamlit (alternative) |
|---|---|---|
| **Stack** | Vite React SPA + FastAPI REST API | Pure Python |
| **Feel** | Polished, product-grade UI | Fast to run, functional |
| **Run (dev)** | `uvicorn api.main:app --port 8000` + `cd frontend && npm run dev` | `streamlit run dashboard/app.py` |
| **Run (prod)** | `./build.sh` then one `uvicorn` process serves API + built app | n/a |

The React app reads live data from the FastAPI backend (`/api/data`), uploads
evidence (`/api/upload`), runs the pipeline (`/api/pipeline/run`), and manages
configured sources — all backed by the **same** `analysis/`, `ingestion/`, and
`run_pipeline.py` code. See **[DEPLOY.md](DEPLOY.md)** for production + Docker + Render.

---

## Features

### Data Sources (All Public / Authorized)
| Source | What It Provides | API Key |
|--------|-----------------|----------|
| NIST NVD | CVE vulnerability data | None required |
| RSS Feeds | Security news (Krebs, BleepingComputer) | None |
| Shodan InternetDB | IP exposure context (free tier) | None |
| GreyNoise Community | Noise/scanner IP classification | Free key |
| HaveIBeenPwned | Domain breach history | Free key |
| CISA KEV | Known Exploited Vulnerabilities catalog | None |
| Lab Port Scanner | TCP scan of localhost/Docker services | None |
| Synthetic Enterprise | Realistic mock asset inventory | N/A |

### Intelligence Engine
- **8 correlation rules** — link signals across source types to find compounding risks
- **CISA KEV cross-reference** — flags CVEs that are actively being exploited in the wild
- **Asset criticality weighting** — risk scores adjust based on asset tier (crown jewel vs. endpoint)
- **Explainable scoring** — every finding shows a full point breakdown
- **Trend tracking** — compare current run vs. previous to see what's new or resolved

### Dashboard
- **Executive View** — KPI cards, risk distribution, top recommendations
- **Data Sources** — configure/connect sources, enable/disable, refresh, provenance, status
- **Upload Evidence** — parse + validate authorized files into the pipeline
- **AI Briefing** — structured CISO briefing generated from current data
- **Threat Feed** — CVEs, news, KEV catalog with filters
- **Exposure & Breach** — scan results, breach hits, IP reputation
- **Correlated Findings** — bar chart + detailed cards with full evidence trails + status tracking + PDF export
- **Methodology / Architecture** — every rule, score, and source documented

### Evidence Ingestion & Configured Sources
- **Upload + connector modes** — manual file upload for every source; API-connector architecture for Tenable, Qualys, HIBP, M365/Entra, STIX/TAXII
- **Supported uploads** — Nmap XML, vulnerability-scanner CSV (Nessus/Tenable/Qualys/OpenVAS), asset-inventory CSV, HIBP breach CSV, M365/Entra sign-in CSV, STIX 2.1 JSON
- **First-run onboarding** — demo vs. real mode, optional sample-data load, workspace setup
- **Saved workspace** — configured sources persist in `data/workspace.json` (gitignored)
- **Secret handling** — API credentials stored in the OS keychain via `keyring`, with a gitignored local-file fallback; masked in the UI, never committed
- **Honest connector status** — upload mode fully works for all sources; live vendor-API fetch is clearly labeled *scaffolded* (config + credential storage + connection-test are real, live fetch is intentionally not faked)

---

## Quickstart

### 1. Clone and set up
```bash
git clone https://github.com/SStevenB/cyberfusion-complete.git
cd cyberfusion-complete
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure (optional — project works without API keys)
```bash
cp config/config.example.yaml config/config.yaml
# Edit config.yaml to add optional free API keys
```

### 3. Run the pipeline
```bash
python run_pipeline.py
```

### 4. Launch a frontend

**Option A — React + FastAPI web app (primary):**
```bash
# terminal 1 — API
uvicorn api.main:app --reload --port 8000
# terminal 2 — React dev server (proxies /api → :8000)
cd frontend && unset NODE_ENV && npm install --include=dev && npm run dev
# open http://localhost:5173
```
For a single-server production build: `./build.sh` then
`uvicorn api.main:app --host 0.0.0.0 --port 8000` (serves API + app on one port).
Or just use `./start.sh` which handles port conflicts + venv automatically.

**For real AI-written briefings** (instead of templates), run `./start_ollama.sh`
in another terminal once — it starts a free local LLM. The "Generate briefing"
button then produces real AI prose; otherwise it falls back to a grounded template.

**Option B — Streamlit dashboard (alternative):**
```bash
streamlit run dashboard/app.py
```

### 5. (Optional) Spin up lab services for scanning
```bash
docker-compose up -d
```

---

## Project Structure

```
cyberfusion-complete/
├── data_collection/          # NVD, KEV, news, breach, IP-reputation, exposure
├── scanning/
│   └── scanner.py            # Lab-only TCP port scanner
├── analysis/
│   ├── normalizer.py         # Unified schema (live API data + uploads)
│   ├── correlator.py         # 8 rule-based correlation rules → MITRE ATT&CK
│   └── risk_scorer.py        # Explainable risk scoring
├── ingestion/                # Upload + configured-source layer
│   ├── file_router.py        # Detect file type → dispatch to parser
│   ├── schema.py             # Shared normalized-record + provenance helper
│   ├── secrets.py            # OS-keychain secret store (+ gitignored fallback)
│   ├── source_registry.py    # Saved source config → data/workspace.json
│   ├── parsers/              # nmap, vuln CSV, asset CSV, HIBP CSV, M365 CSV, STIX
│   └── connectors/           # Tenable/Qualys/HIBP/M365/STIX (scaffolded + base)
├── api/
│   └── main.py               # FastAPI REST backend (wraps the pipeline)
├── frontend/                 # Vite + React SPA (primary web UI)
│   ├── src/mockup/           # design system: components, pages, styles
│   ├── assemble.mjs          # builds src/CyberFusionApp.jsx from mockup
│   └── vite.config.js        # dev proxy /api → :8000
├── dashboard/
│   ├── app.py                # Streamlit multi-page dashboard (alternative UI)
│   ├── sources_page.py       # Onboarding wizard + Data Sources page
│   └── methodology.py        # Rule + data-source documentation
├── samples/                  # Clearly-labeled synthetic evidence files
├── config/                   # config.example.yaml + assets.yaml
├── data/
│   ├── raw/  processed/  outputs/   # pipeline data (gitignored)
│   └── uploads/  workspace.json  secrets.local.json  # local state (gitignored)
├── tests/                    # 63 pytest tests (pipeline + ingestion + platform + API)
├── docker-compose.yml        # Lab service containers
├── run_pipeline.py           # Master pipeline runner
├── build_demo.py             # Static GitHub Pages demo builder
├── build.sh                  # Production build (deps + frontend/dist)
├── Dockerfile                # Multi-stage: build React, run with Python
├── render.yaml               # One-service Render deploy config
├── DEPLOY.md                 # Deployment guide
└── requirements.txt
```

---

## Ethics & Scope

- **No unauthorized scanning.** All TCP scans target `localhost` or Docker lab containers only.
- **No credential harvesting.** The project never stores, displays, or processes real user credentials.
- **No illegal activity.** Every data source used is public, rate-limited, and used per its terms of service.
- **Synthetic data is clearly labeled.** All generated mock data is identified in the UI and in code comments.

---

## Skills Demonstrated

- **Python architecture** — modular pipeline with clean separation of concerns
- **REST API integration** — multiple third-party APIs with graceful error handling
- **Data normalization** — unified schema pattern (mirrors real SIEM design)
- **Security domain knowledge** — CVEs, port scanning, breach monitoring, threat intel workflows
- **Explainability** — every risk score has a documented breakdown (important in real security tooling)
- **Full-stack development** — React (Vite) SPA + FastAPI REST API, plus a Streamlit alternative
- **API design** — clean REST endpoints wrapping the pipeline (data, upload, pipeline-run, source CRUD)
- **Dashboard development** — Streamlit multi-page app with Plotly charts
- **Docker** — lab service orchestration + multi-stage production image
- **Testing** — 63 pytest tests across pipeline, ingestion, platform, and API layers
- **Documentation** — architecture diagrams, ethics statement, setup guide

---

## Roadmap

- [x] **Phase 1**: Public API sources, lab scanning, explainable scoring
- [x] **Phase 2**: Asset inventory integration, MITRE ATT&CK tactic tagging
- [x] **Phase 3**: Historical trend tracking, finding delta detection
- [x] **Phase 4**: Slack/email alerting + PDF reporting + AI briefing
- [x] **Phase 5**: Upload-driven evidence ingestion (6 parsers) + correlation integration
- [x] **Phase 6**: Configured platform — source registry, onboarding, Data Sources page, secret handling, connector scaffolding
- [x] **Phase 7**: React + FastAPI web app (live data, uploads, pipeline runs over HTTP) + deployment config
- [x] **Phase 8**: First real live-API connector — HIBP (free /breaches?domain= endpoint, optional paid /breacheddomain support); local Ollama briefings (free AI); commit + deploy
- [ ] **Next**: Live Tenable/Qualys/Graph/TAXII connector fetch (currently scaffolded)

---

## License

MIT — free to use, modify, and build on. Attribution appreciated.
