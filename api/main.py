# api/main.py
# ─────────────────────────────────────────────────────────────────────────────
# CyberFusion REST API (FastAPI)
#
# This is a THIN wrapper over the existing Python pipeline. It does not contain
# any analysis logic of its own — every endpoint calls functions that already
# live in the project:
#   • GET  /api/data            → build_demo.build_cfdata()+enrich_reference()
#   • POST /api/upload          → ingestion.file_router.parse_upload/save_records
#   • POST /api/pipeline/run    → run_pipeline.run()
#   • GET  /api/sources         → ingestion.source_registry.list_sources()
#   • POST /api/sources         → source_registry.add_source()
#   • PATCH/DELETE /api/sources/{id}
#   • POST /api/sources/{id}/secret, /test
#   • GET  /api/source-types
#   • GET  /api/workspace, POST /api/onboard
#
# Run:  uvicorn api.main:app --reload --port 8000
# ─────────────────────────────────────────────────────────────────────────────

import os
import sys
import json
import importlib.util
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

# ── Reuse existing project modules (no reimplementation) ──────────────────────
from ingestion import file_router
from ingestion import source_registry as reg
from ingestion import secrets as secretstore

# Map a parser's detected file_type to the source-registry source_type so that
# uploaded/sample files automatically appear as Configured Sources.
FILETYPE_TO_SOURCE = {
    "nmap_xml": "nmap",
    "vuln_csv": "vuln_scan",
    "asset_csv": "asset_inventory",
    "hibp_csv": "hibp",
    "m365_csv": "m365_signin",
    "stix_json": "stix",
}


def _register_uploaded_source(file_type: str, filename: str, record_count: int) -> str:
    """Create (or reuse) a Configured Source entry for an uploaded file and mark
    it synced. Returns the source_id, or '' if the type isn't mappable."""
    source_type = FILETYPE_TO_SOURCE.get(file_type)
    if not source_type:
        return ""
    # Reuse an existing upload-mode source of this type if one exists, so we
    # don't create duplicates every time the same kind of file is uploaded.
    existing = next((sv for sv in reg.list_sources()
                     if sv["type"] == source_type and sv["mode"] == "upload"), None)
    if existing:
        sid = existing["id"]
        # accumulate the record count + refresh sync time
        reg.mark_synced(sid, (existing.get("record_count") or 0) + record_count)
        return sid
    label = reg.SOURCE_TYPES.get(source_type, {}).get("label", source_type)
    sid = reg.add_source(source_type, f"{label} (upload)", "upload")
    reg.mark_synced(sid, record_count)
    return sid



def _load_build_demo():
    """build_demo.py isn't a package module; load it by path so we can reuse its
    build_cfdata()/enrich_reference() data-shaping (already battle-tested)."""
    spec = importlib.util.spec_from_file_location("build_demo", os.path.join(BASE, "build_demo.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


app = FastAPI(title="CyberFusion API", version="1.0.0")

# CORS: allow the Vite dev server (5173) during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD DATA
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/api/data")
def get_data() -> Dict[str, Any]:
    """The full dashboard payload (same shape the static demo used as window.CFData)."""
    bd = _load_build_demo()
    data = bd.enrich_reference(bd.build_cfdata())
    # Overlay the real workspace identity (org name / scope are user-set in
    # onboarding, not hardcoded) so the UI header reflects the actual workspace.
    ws = reg.load_workspace()
    data.setdefault("org", {})
    data["org"]["name"] = ws.get("org_name") or "My Organization"
    data["org"]["scope"] = ws.get("scope") or data["org"].get("scope", "")
    data["org"]["mode"] = ws.get("mode", "demo")
    data["org"]["onboarded"] = ws.get("onboarded", False)
    # How many evidence sources are currently staged — lets the UI explain why
    # the finding count changed between runs (more uploads → more correlations).
    try:
        data["org"]["uploadedSourceCount"] = len(file_router.list_uploads())
    except Exception:
        data["org"]["uploadedSourceCount"] = 0
    data["org"]["configuredSourceCount"] = len(ws.get("sources", {}))
    return data


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "secret_backend": secretstore.backend_name()}


# ══════════════════════════════════════════════════════════════════════════════
# UPLOAD EVIDENCE  (reuses ingestion.file_router)
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/api/upload/preview")
async def upload_preview(file: UploadFile = File(...), forced_type: str = Form("auto")):
    """Parse + validate an uploaded file and return a preview WITHOUT saving."""
    raw = await file.read()
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(400, f"Could not read file: {e}")
    result = file_router.parse_upload(file.filename, text, forced_type)
    return {
        "ok": result.ok,
        "file_type": result.file_type,
        "summary": result.summary,
        "errors": result.errors,
        "record_count": len(result.records),
        "preview": [
            {"type": r.get("type"), "title": (r.get("title", "") or "")[:80],
             "severity": r.get("severity"), "asset": r.get("asset") or "—"}
            for r in result.records[:30]
        ],
    }


@app.post("/api/upload/commit")
async def upload_commit(file: UploadFile = File(...), forced_type: str = Form("auto")):
    """Parse and SAVE an uploaded file into data/uploads/ for the next run."""
    raw = await file.read()
    text = raw.decode("utf-8", errors="replace")
    result = file_router.parse_upload(file.filename, text, forced_type)
    if not result.ok:
        raise HTTPException(400, "; ".join(result.errors) or "No usable records.")
    saved = file_router.save_records(result, file.filename)
    sid = _register_uploaded_source(result.file_type, file.filename, len(result.records))
    return {"ok": True, "saved_as": os.path.basename(saved),
            "record_count": len(result.records), "summary": result.summary,
            "source_id": sid}


@app.get("/api/uploads")
def list_uploads():
    """All staged uploaded-evidence files."""
    return {"uploads": file_router.list_uploads()}


@app.delete("/api/uploads")
def clear_uploads():
    """Remove all staged uploads (does not touch live API data)."""
    n = file_router.clear_uploads()
    return {"ok": True, "cleared": n}


@app.get("/api/supported-types")
def supported_types():
    return {"types": [{"key": k, "label": v} for k, v in file_router.SUPPORTED_TYPES]}


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE RUN  (reuses run_pipeline.run)
# ══════════════════════════════════════════════════════════════════════════════
class RunOptions(BaseModel):
    quick: bool = True       # default to quick (skip slow collectors) for UI responsiveness
    no_scan: bool = False


@app.post("/api/pipeline/run")
def pipeline_run(opts: RunOptions = RunOptions()):
    """Run the full pipeline. Reuses run_pipeline.run() with an args shim."""
    import argparse
    rp_spec = importlib.util.spec_from_file_location("run_pipeline", os.path.join(BASE, "run_pipeline.py"))
    rp = importlib.util.module_from_spec(rp_spec)
    rp_spec.loader.exec_module(rp)
    args = argparse.Namespace(quick=opts.quick, no_scan=opts.no_scan)
    try:
        rp.run(args)
    except TypeError:
        # run() may take no args in some versions
        rp.run()
    bd = _load_build_demo()
    data = bd.enrich_reference(bd.build_cfdata())
    return {"ok": True, "summary": data.get("summary", {}),
            "finding_count": len(data.get("findings", []))}


# ══════════════════════════════════════════════════════════════════════════════
# SOURCE REGISTRY  (reuses ingestion.source_registry)
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/api/source-types")
def source_types():
    out = []
    for key, meta in reg.SOURCE_TYPES.items():
        out.append({
            "key": key, "label": meta["label"], "category": meta["category"],
            "modes": meta["modes"], "connector_status": reg.connector_status_for(key),
            "description": meta["description"], "authorization_note": meta["authorization_note"],
            "connector_fields": meta.get("connector_fields", []),
        })
    return {"source_types": out}


@app.get("/api/sources")
def get_sources():
    return {"sources": reg.list_sources()}


class AddSource(BaseModel):
    source_type: str
    name: str
    mode: str
    config: Optional[Dict[str, Any]] = None


@app.post("/api/sources")
def add_source(body: AddSource):
    try:
        sid = reg.add_source(body.source_type, body.name, body.mode, body.config or {})
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "id": sid, "source": reg.get_source(sid)}


class UpdateSource(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None


@app.patch("/api/sources/{source_id}")
def update_source(source_id: str, body: UpdateSource):
    if not reg.get_source(source_id):
        raise HTTPException(404, "Source not found")
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    reg.update_source(source_id, **fields)
    return {"ok": True, "source": reg.get_source(source_id)}


@app.delete("/api/sources/{source_id}")
def delete_source(source_id: str):
    if not reg.get_source(source_id):
        raise HTTPException(404, "Source not found")
    reg.remove_source(source_id)
    return {"ok": True}


class SecretBody(BaseModel):
    field: str
    value: str


@app.post("/api/sources/{source_id}/secret")
def set_secret(source_id: str, body: SecretBody):
    if not reg.get_source(source_id):
        raise HTTPException(404, "Source not found")
    reg.set_source_secret(source_id, body.field, body.value)
    return {"ok": True, "field": body.field,
            "masked": secretstore.masked(reg.secret_key_for(source_id, body.field))}


@app.post("/api/sources/{source_id}/test")
def test_source(source_id: str):
    if not reg.get_source(source_id):
        raise HTTPException(404, "Source not found")
    return reg.test_source_connection(source_id)


# ══════════════════════════════════════════════════════════════════════════════
# WORKSPACE / ONBOARDING  (reuses ingestion.source_registry)
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/api/workspace")
def get_workspace():
    return reg.load_workspace()


class OnboardBody(BaseModel):
    org_name: str
    scope: str
    mode: str = "demo"
    load_samples: bool = False


@app.post("/api/onboard")
def onboard(body: OnboardBody):
    ws = reg.load_workspace()
    ws["org_name"] = body.org_name
    ws["scope"] = body.scope
    ws["mode"] = body.mode
    ws["onboarded"] = True
    reg.save_workspace(ws)

    loaded = 0
    if body.load_samples:
        samples = os.path.join(BASE, "samples")
        if os.path.isdir(samples):
            for fn in os.listdir(samples):
                p = os.path.join(samples, fn)
                if not os.path.isfile(p) or fn.lower() == "readme.md":
                    continue
                try:
                    with open(p, encoding="utf-8", errors="replace") as f:
                        text = f.read()
                    result = file_router.parse_upload(fn, text, "auto")
                    if result.ok:
                        file_router.save_records(result, fn)
                        # Auto-register a Configured Source for this evidence.
                        _register_uploaded_source(result.file_type, fn, len(result.records))
                        loaded += 1
                except Exception:
                    continue
    return {"ok": True, "workspace": reg.load_workspace(), "samples_loaded": loaded}


# ══════════════════════════════════════════════════════════════════════════════
# SLACK NOTIFY  (reuses notifier.py — only sends if a webhook is configured)
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/api/notify/slack")
def notify_slack():
    """Send the current findings to Slack IF a webhook is configured in config.
    Returns sent=False with a helpful message when not configured (honest, no fake send)."""
    import importlib.util as _il
    # Load config (yaml) if present.
    config = {}
    cfg_path = os.path.join(BASE, "config", "config.yaml")
    if os.path.exists(cfg_path):
        try:
            import yaml
            with open(cfg_path) as f:
                config = yaml.safe_load(f) or {}
        except Exception:
            config = {}
    webhook = (config.get("slack", {}) or {}).get("webhook_url", "")
    if not webhook:
        return {"sent": False,
                "message": ("No Slack webhook configured. Add slack.webhook_url to "
                            "config/config.yaml to enable alerts (free 5-minute setup).")}
    spec = _il.spec_from_file_location("notifier", os.path.join(BASE, "notifier.py"))
    notifier = _il.module_from_spec(spec)
    spec.loader.exec_module(notifier)
    try:
        ok = notifier.run_notifier(config=config)
        return {"sent": bool(ok), "message": "Alert sent to Slack." if ok else "Slack send failed — check the webhook URL."}
    except Exception as e:
        raise HTTPException(500, f"Slack notify failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# FINDING STATUS  (open / acknowledged / resolved / false_positive)
# ══════════════════════════════════════════════════════════════════════════════
# Statuses are stored separately from pipeline output so they persist across
# pipeline re-runs (which regenerate the findings file).
_STATUS_FILE = os.path.join(BASE, "data", "finding_status.json")
_VALID_STATUSES = {"open", "acknowledged", "resolved", "false_positive"}


def _load_statuses() -> Dict[str, str]:
    try:
        with open(_STATUS_FILE) as f:
            return json.load(f).get("statuses", {})
    except Exception:
        return {}


def _save_statuses(statuses: Dict[str, str]) -> None:
    os.makedirs(os.path.dirname(_STATUS_FILE), exist_ok=True)
    with open(_STATUS_FILE, "w") as f:
        json.dump({"statuses": statuses}, f, indent=2)


class FindingStatus(BaseModel):
    status: str


@app.get("/api/findings/status")
def get_finding_statuses():
    return {"statuses": _load_statuses()}


@app.patch("/api/findings/{rule_id}/status")
def set_finding_status(rule_id: str, body: FindingStatus):
    if body.status not in _VALID_STATUSES:
        raise HTTPException(400, f"Invalid status. Must be one of: {', '.join(sorted(_VALID_STATUSES))}")
    statuses = _load_statuses()
    statuses[rule_id] = body.status
    _save_statuses(statuses)
    return {"ok": True, "rule_id": rule_id, "status": body.status}


# ══════════════════════════════════════════════════════════════════════════════
# PDF REPORT  (reuses reporter.py)
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/api/report/pdf")
def generate_report():
    """Generate a PDF risk report from the latest findings and return it."""
    import importlib.util as _il
    spec = _il.spec_from_file_location("reporter", os.path.join(BASE, "reporter.py"))
    reporter = _il.module_from_spec(spec)
    spec.loader.exec_module(reporter)
    try:
        path = reporter.generate_pdf_report()
    except FileNotFoundError:
        raise HTTPException(400, "No findings yet. Run the pipeline first.")
    except Exception as e:
        raise HTTPException(500, f"Report generation failed: {e}")
    return FileResponse(path, media_type="application/pdf",
                        filename=os.path.basename(path))


# ══════════════════════════════════════════════════════════════════════════════
# AI BRIEFING  (reuses briefing.py — Ollama local/free, falls back to template)
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/api/briefing/status")
def briefing_status():
    """Report which briefing backend is available (Ollama / Anthropic / template)."""
    import importlib.util as _il
    spec = _il.spec_from_file_location("briefing", os.path.join(BASE, "briefing.py"))
    briefing = _il.module_from_spec(spec)
    spec.loader.exec_module(briefing)
    ollama_ok, model = briefing._check_ollama()
    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY"))
    backend = (f"ollama:{model}" if ollama_ok else
               "anthropic" if has_anthropic else "template")
    return {"ollama": ollama_ok, "model": model if ollama_ok else None,
            "anthropic": has_anthropic, "backend": backend}


@app.post("/api/briefing/generate")
def briefing_generate():
    """Generate a fresh briefing from current pipeline data. Uses Ollama if
    running (free, local), else a pipeline-derived template. Returns sections."""
    import importlib.util as _il
    spec = _il.spec_from_file_location("briefing", os.path.join(BASE, "briefing.py"))
    briefing = _il.module_from_spec(spec)
    spec.loader.exec_module(briefing)
    try:
        text, mode = briefing.generate_briefing(save=True)
    except Exception as e:
        raise HTTPException(500, f"Briefing generation failed: {e}")
    # Return the markdown text + the mode so the UI can render and label it.
    return {"ok": True, "backend": mode, "text": text}


@app.get("/api/briefing/history")
def briefing_history():
    """List real saved briefings from data/outputs/briefings/. Returns metadata
    (filename, generated_at, size, summary) — no fake rows."""
    bdir = os.path.join(BASE, "data", "outputs", "briefings")
    if not os.path.isdir(bdir):
        return {"briefings": []}
    import re as _re
    items = []
    for fn in os.listdir(bdir):
        # Real saved briefings follow briefing_YYYYMMDD_HHMMSS.md
        m = _re.match(r"^briefing_(\d{8})_(\d{6})\.md$", fn)
        if not m:
            continue
        path = os.path.join(bdir, fn)
        st = os.stat(path)
        # Parse timestamp from filename → human-readable
        date_str, time_str = m.group(1), m.group(2)
        generated = f"{date_str[0:4]}-{date_str[4:6]}-{date_str[6:8]} {time_str[0:2]}:{time_str[2:4]}:{time_str[4:6]}"
        # First non-empty line of the briefing as a summary peek
        first_line = ""
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip().lstrip("#").strip().strip("*").strip()
                    if line:
                        first_line = line[:80]
                        break
        except Exception:
            pass
        items.append({"filename": fn, "generated_at": generated,
                      "size_bytes": st.st_size, "preview": first_line})
    # newest first
    items.sort(key=lambda x: x["filename"], reverse=True)
    return {"briefings": items}


@app.get("/api/briefing/history/{filename}")
def briefing_get(filename: str):
    """Return the raw markdown of a saved briefing. Safe path check prevents traversal."""
    import re as _re
    if not _re.match(r"^briefing_\d{8}_\d{6}\.md$", filename):
        raise HTTPException(400, "Invalid briefing filename.")
    path = os.path.join(BASE, "data", "outputs", "briefings", filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "Briefing not found.")
    with open(path) as f:
        return {"filename": filename, "text": f.read()}


# ══════════════════════════════════════════════════════════════════════════════
# WORKSPACE UPDATE  (rename org, change scope)
# ══════════════════════════════════════════════════════════════════════════════
class WorkspacePatch(BaseModel):
    org_name: Optional[str] = None
    scope: Optional[str] = None
    mode: Optional[str] = None


@app.patch("/api/workspace")
def patch_workspace(body: WorkspacePatch):
    ws = reg.load_workspace()
    for k, v in body.model_dump().items():
        if v is not None:
            ws[k] = v
    reg.save_workspace(ws)
    return {"ok": True, "workspace": reg.load_workspace()}


# ══════════════════════════════════════════════════════════════════════════════
# STATIC FRONTEND (production)
# ══════════════════════════════════════════════════════════════════════════════
# In production we build the React app (frontend/dist) and serve it from the same
# FastAPI process, so there is ONE server and no CORS/proxy needed. In dev you
# instead run Vite (npm run dev) which proxies /api here — this block is simply
# skipped when dist/ doesn't exist yet.
_DIST = os.path.join(BASE, "frontend", "dist")

if os.path.isdir(_DIST):
    # Serve built assets (JS/CSS/images) under their hashed paths.
    app.mount("/assets", StaticFiles(directory=os.path.join(_DIST, "assets")), name="assets")

    @app.get("/")
    def _spa_root():
        return FileResponse(os.path.join(_DIST, "index.html"))

    # SPA fallback: any non-API path returns index.html so client-side nav works.
    @app.get("/{full_path:path}")
    def _spa_fallback(full_path: str):
        # Never shadow API routes (they're registered above and match first),
        # but guard explicitly in case of unknown /api paths.
        if full_path.startswith("api/"):
            raise HTTPException(404, "Unknown API endpoint")
        candidate = os.path.join(_DIST, full_path)
        if os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(os.path.join(_DIST, "index.html"))
else:
    @app.get("/")
    def _no_build():
        return {
            "message": "CyberFusion API is running. Frontend not built yet.",
            "hint": "Run:  cd frontend && npm run build   (then restart this server)",
            "dev": "Or run the Vite dev server:  cd frontend && npm run dev",
            "api_health": "/api/health",
        }
