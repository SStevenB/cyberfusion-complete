CyberFusion — Threat Intelligence Prioritization Platform

> A cyber risk fusion engine built in Python — designed to mirror real SOC/CTI analyst workflows using public intelligence sources, authorized telemetry, and rule-based signal correlation.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ethics: Lab Safe](https://img.shields.io/badge/Scope-Lab%20Safe-green.svg)](#ethics--scope)

---

## 🔗 Live Demo

**[View the interactive demo →](https://STEVENSCARIA.github.io/cyberfusion-complete/)**

A static, self-contained build of the dashboard hosted on GitHub Pages. The
findings, risk scores, CVEs (NIST NVD), CISA KEV entries, security news, and
lab port-scan results shown are **real output from a pipeline run**. A few
elements are clearly tagged `illustrative` in the UI (30-day trend, peer
benchmark, MTTR, briefing history), and breach/exposure records are
clearly-labeled synthetic. The in-app **Methodology → About This Demo** panel
spells out exactly what is real vs. illustrative.

> Replace `STEVENSCARIA` and `cyberfusion-complete` in the link above with your
> GitHub username and repository name once published.

---

## What This Project Does

CyberFusion is a multi-source threat intelligence aggregation and risk prioritization system. It ingests signals from five categories of public/authorized data sources, normalizes them, applies rule-based correlation logic, scores the resulting findings by business risk, and presents everything in an interactive analyst dashboard.

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
│                      Streamlit Dashboard                        │
│   Executive View │ Threat Feed │ Exposure │ Correlated Findings │
└─────────────────────────────────────────────────────────────────┘
```

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

### Dashboard (4 Pages)
- **Executive View** — KPI cards, risk distribution, top recommendations
- **Threat Feed** — CVEs, news, KEV catalog with filters
- **Exposure View** — scan results, breach hits, IP reputation
- **Correlated Findings** — bar chart + detailed cards with full evidence trails

---

## Quickstart

### 1. Clone and set up
```bash
git clone https://github.com/yourusername/cyber-intel-fusion.git
cd cyber-intel-fusion
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

### 4. Launch the dashboard
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
cyber-intel-fusion/
├── data_collection/
│   ├── cve_collector.py          # NVD CVE ingestion
│   ├── news_collector.py         # RSS feed aggregation
│   ├── breach_monitor.py         # HaveIBeenPwned domain check
│   ├── ip_reputation.py          # GreyNoise + Shodan InternetDB
│   ├── kev_collector.py          # CISA Known Exploited Vulnerabilities
│   └── exposure_simulator.py     # Synthetic enterprise signals
├── scanning/
│   └── scanner.py                # Lab-only TCP port scanner
├── analysis/
│   ├── normalizer.py             # Unified schema converter
│   ├── correlator.py             # Rule-based signal correlation
│   └── risk_scorer.py            # Explainable risk scoring
├── dashboard/
│   └── app.py                    # Streamlit 4-page dashboard
├── config/
│   ├── config.example.yaml       # Template config
│   └── assets.yaml               # Asset inventory + criticality
├── data/
│   ├── raw/                      # Collected source data
│   ├── processed/                # Normalized items
│   └── outputs/                  # Scored findings + history
├── tests/
│   └── test_*.py                 # Unit tests
├── docker-compose.yml            # Lab service containers
├── run_pipeline.py               # Master pipeline runner
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
- **Dashboard development** — Streamlit multi-page app with Plotly charts
- **Docker** — lab service orchestration
- **Testing** — pytest unit coverage on core pipeline logic
- **Documentation** — architecture diagrams, ethics statement, setup guide

---

## Roadmap

- [ ] **Phase 1** (current): Public API sources, lab scanning, explainable scoring
- [ ] **Phase 2**: Asset inventory integration, MITRE ATT&CK tactic tagging
- [ ] **Phase 3**: Historical trend tracking, finding delta detection
- [ ] **Phase 4**: Slack/email alerting for high-severity findings

---

## License

MIT — free to use, modify, and build on. Attribution appreciated.
