# ingestion/source_registry.py
#
# The source registry turns CyberFusion from a one-time upload tool into a
# configured platform a user returns to. It persists the set of data sources a
# user has set up — their type, mode (upload vs connector), enabled state,
# status, last-sync time, and provenance — to data/workspace.json.
#
# Secrets (API keys) are NOT stored here. They live in ingestion/secrets.py
# (OS keychain or a gitignored local file). The registry only stores a
# reference flag (has_secret) so the UI can show "configured" without exposing
# the value.
#
# Design: a SOURCE_TYPES catalog defines what kinds of sources exist and which
# modes each supports. The workspace stores user-configured *instances* of
# those types.

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ingestion import secrets

WORKSPACE_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "workspace.json")

# ── Source type catalog ───────────────────────────────────────────────────────
# mode options: "upload" (manual file), "connector" (API), or both.
# connector_status: "implemented" | "scaffolded" | "none"
SOURCE_TYPES: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "label": "Nmap Scan",
        "category": "Attack Surface",
        "modes": ["upload"],
        "parser_key": "nmap_xml",
        "connector_status": "none",
        "description": "Open-port scan results from authorized targets (nmap -oX).",
        "authorization_note": "Only upload scans of hosts you own or are authorized to scan.",
    },
    "vuln_scan": {
        "label": "Vulnerability Scan (generic)",
        "category": "Vulnerability Management",
        "modes": ["upload"],
        "parser_key": "vuln_csv",
        "connector_status": "none",
        "description": "Generic vulnerability-scanner CSV export (Nessus/OpenVAS/etc.).",
        "authorization_note": "Authorized vulnerability data for systems you manage.",
    },
    "tenable": {
        "label": "Tenable",
        "category": "Vulnerability Management",
        "modes": ["connector", "upload"],
        "parser_key": "vuln_csv",
        "connector_status": "scaffolded",
        "connector_fields": ["base_url", "access_key", "secret_key"],
        "description": "Tenable.io / Tenable.sc vulnerability data.",
        "authorization_note": "Connect only to tenants you are authorized to query.",
    },
    "qualys": {
        "label": "Qualys",
        "category": "Vulnerability Management",
        "modes": ["connector", "upload"],
        "parser_key": "vuln_csv",
        "connector_status": "scaffolded",
        "connector_fields": ["base_url", "username", "password"],
        "description": "Qualys VMDR vulnerability data.",
        "authorization_note": "Connect only to subscriptions you are authorized to query.",
    },
    "hibp": {
        "label": "HaveIBeenPwned (domain exposure)",
        "category": "External Exposure",
        "modes": ["connector", "upload"],
        "parser_key": "hibp_csv",
        "connector_status": "implemented",
        "connector_fields": ["monitored_domain", "api_key"],
        "description": ("Breach exposure for a domain. Uses the FREE /breaches?domain= "
                        "endpoint (no key needed). If a paid HIBP API key is provided, "
                        "the paid /breacheddomain endpoint is used for per-account detail."),
        "authorization_note": "Only query domains you own or are authorized to monitor.",
    },
    "asset_inventory": {
        "label": "Asset Inventory",
        "category": "Asset Management",
        "modes": ["upload"],
        "parser_key": "asset_csv",
        "connector_status": "none",
        "description": "Asset list with criticality tiers (CMDB / ServiceNow / spreadsheet export).",
        "authorization_note": "Your own organization's asset inventory.",
    },
    "m365_signin": {
        "label": "Microsoft 365 / Entra Sign-in Risk",
        "category": "Identity",
        "modes": ["upload", "connector"],
        "parser_key": "m365_csv",
        "connector_status": "scaffolded",
        "connector_fields": ["tenant_id", "client_id", "client_secret"],
        "description": "Risky sign-in events from Azure AD / Entra ID.",
        "authorization_note": "Your own tenant's sign-in logs.",
    },
    "stix": {
        "label": "STIX 2.1 Threat Intel",
        "category": "Threat Intelligence",
        "modes": ["upload", "connector"],
        "parser_key": "stix_json",
        "connector_status": "scaffolded",
        "connector_fields": ["taxii_url", "collection_id", "api_root"],
        "description": "STIX 2.1 bundles from OpenCTI / MISP / TAXII feeds.",
        "authorization_note": "Feeds you are licensed/authorized to consume.",
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_workspace() -> Dict[str, Any]:
    return {
        "version": 1,
        "onboarded": False,
        "mode": "demo",            # "demo" | "real"
        "org_name": "Northstar Analytics",
        "scope": "northstar-analytics.local",
        "created_at": _now(),
        "sources": {},             # source_id → source dict
    }


def load_workspace() -> Dict[str, Any]:
    if not os.path.exists(WORKSPACE_FILE):
        return _default_workspace()
    try:
        with open(WORKSPACE_FILE) as f:
            data = json.load(f)
        # tolerate older/partial files
        base = _default_workspace()
        base.update({k: v for k, v in data.items() if k in base or k == "sources"})
        if "sources" not in base or not isinstance(base["sources"], dict):
            base["sources"] = {}
        return base
    except (json.JSONDecodeError, OSError):
        return _default_workspace()


def save_workspace(ws: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(WORKSPACE_FILE), exist_ok=True)
    ws["updated_at"] = _now()
    with open(WORKSPACE_FILE, "w") as f:
        json.dump(ws, f, indent=2)


# ── Source CRUD ────────────────────────────────────────────────────────────────
def add_source(source_type: str, name: str, mode: str,
               config: Optional[Dict[str, Any]] = None) -> str:
    """Register a new configured source. Returns its source_id."""
    if source_type not in SOURCE_TYPES:
        raise ValueError(f"Unknown source type: {source_type}")
    ws = load_workspace()
    # Stable-ish id: type + count.
    n = sum(1 for s in ws["sources"].values() if s["type"] == source_type) + 1
    source_id = f"{source_type}_{n}"
    while source_id in ws["sources"]:
        n += 1
        source_id = f"{source_type}_{n}"

    ws["sources"][source_id] = {
        "id": source_id,
        "type": source_type,
        "name": name or SOURCE_TYPES[source_type]["label"],
        "mode": mode,                     # "upload" | "connector"
        "enabled": True,
        "config": config or {},           # non-secret config (urls, domains)
        "status": "configured",           # configured|ok|error|never_synced
        "last_sync": "",
        "last_error": "",
        "record_count": 0,
        "created_at": _now(),
        "provenance": {
            "source_type": source_type,
            "mode": mode,
            "ingestion_method": "connector" if mode == "connector" else "file_upload",
        },
    }
    save_workspace(ws)
    return source_id


def update_source(source_id: str, **fields) -> None:
    ws = load_workspace()
    if source_id in ws["sources"]:
        ws["sources"][source_id].update(fields)
        save_workspace(ws)


def set_enabled(source_id: str, enabled: bool) -> None:
    update_source(source_id, enabled=enabled)


def remove_source(source_id: str) -> None:
    ws = load_workspace()
    if source_id in ws["sources"]:
        # also drop any stored secret for this source
        for field in ("api_key", "secret_key", "access_key", "password",
                      "client_secret"):
            secrets.delete_secret(f"{source_id}.{field}")
        del ws["sources"][source_id]
        save_workspace(ws)


def list_sources() -> List[Dict[str, Any]]:
    ws = load_workspace()
    return list(ws["sources"].values())


def get_source(source_id: str) -> Optional[Dict[str, Any]]:
    return load_workspace()["sources"].get(source_id)


def mark_synced(source_id: str, record_count: int, error: str = "") -> None:
    update_source(
        source_id,
        status="error" if error else "ok",
        last_sync=_now(),
        last_error=error,
        record_count=record_count,
    )


# ── Connector + secret helpers ────────────────────────────────────────────────
def secret_key_for(source_id: str, field: str) -> str:
    """Stable key used to store a per-source secret in the secrets backend."""
    return f"{source_id}.{field}"


def set_source_secret(source_id: str, field: str, value: str) -> None:
    secrets.set_secret(secret_key_for(source_id, field), value)


def get_source_secret(source_id: str, field: str):
    return secrets.get_secret(secret_key_for(source_id, field))


def source_secret_status(source_id: str, fields) -> dict:
    """Return {field: bool_is_set} for the UI (never the value)."""
    return {f: secrets.has_secret(secret_key_for(source_id, f)) for f in fields}


def test_source_connection(source_id: str) -> dict:
    """
    Run the connector's test_connection for a configured source.
    Returns {"ok": bool, "message": str}. Safe for sources without a connector.
    """
    src = get_source(source_id)
    if not src:
        return {"ok": False, "message": "Source not found."}
    stype = src["type"]
    try:
        from ingestion.connectors import get_connector
    except Exception as e:
        return {"ok": False, "message": f"Connector layer unavailable: {e}"}
    conn = get_connector(stype)
    if conn is None:
        return {"ok": False, "message": "This source type has no API connector (upload-only)."}
    config = src.get("config", {})
    secret_values = {f: (get_source_secret(source_id, f) or "") for f in conn.secret_fields}
    result = conn.test_connection(config, secret_values)
    return {"ok": result.ok, "message": result.message}


def connector_status_for(source_type: str) -> str:
    """Authoritative connector status, read from the connector class."""
    try:
        from ingestion.connectors import get_connector
        conn = get_connector(source_type)
        return conn.STATUS if conn else "none"
    except Exception:
        return SOURCE_TYPES.get(source_type, {}).get("connector_status", "none")
