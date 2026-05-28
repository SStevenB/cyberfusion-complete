# ingestion/file_router.py
#
# The single entry point for uploaded evidence. It:
#   1. detects the file type (or accepts a user-forced type),
#   2. dispatches to the right parser,
#   3. persists accepted records to data/uploads/ so the next pipeline run
#      includes them (uploads SUPPLEMENT the live API data, never replace it),
#   4. returns a clean ParseResult for the UI to show.
#
# Adding a new file type = write a parser module and register it in PARSERS.

import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from ingestion.schema import ParseResult
from ingestion.parsers import (nmap_parser, vuln_csv_parser,
                               asset_csv_parser, hibp_csv_parser,
                               stix_parser, m365_csv_parser)

UPLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "uploads")

# Registry: key → (label, module). Order matters for auto-detect (most specific
# first). asset_csv before vuln_csv before hibp_csv so the tighter detectors win.
PARSERS = {
    "nmap_xml":  ("Nmap XML scan",                  nmap_parser),
    "stix_json": ("STIX 2.1 JSON bundle",           stix_parser),
    "asset_csv": ("Asset inventory CSV",            asset_csv_parser),
    "m365_csv":  ("Microsoft 365 / Entra sign-ins", m365_csv_parser),
    "vuln_csv":  ("Vulnerability scanner CSV",      vuln_csv_parser),
    "hibp_csv":  ("Breach export CSV (HIBP)",       hibp_csv_parser),
}

# Human-friendly list for the UI dropdown.
SUPPORTED_TYPES = [("auto", "Auto-detect")] + [(k, v[0]) for k, v in PARSERS.items()]


def detect_type(filename: str, text: str) -> Optional[str]:
    """Return the first parser key whose detect() claims the file, else None."""
    for key, (_label, mod) in PARSERS.items():
        try:
            if mod.detect(filename, text):
                return key
        except Exception:
            continue
    return None


def parse_upload(filename: str, text: str, forced_type: str = "auto") -> ParseResult:
    """
    Parse an uploaded file. If forced_type is 'auto', detect it; otherwise use
    the user's chosen parser. Never raises — returns a ParseResult with errors.
    """
    if forced_type and forced_type != "auto":
        key = forced_type
    else:
        key = detect_type(filename, text)

    if not key or key not in PARSERS:
        res = ParseResult(file_type="unknown")
        res._fatal = True
        res.errors.append(
            "Could not determine the file type automatically. "
            "Please pick the file type manually from the dropdown.")
        res.summary = "Unrecognized file type."
        return res

    _label, mod = PARSERS[key]
    try:
        return mod.parse(text, filename)
    except Exception as e:
        res = ParseResult(file_type=key)
        res._fatal = True
        res.errors.append(f"Parser error: {e}")
        res.summary = "Parsing failed unexpectedly."
        return res


def save_records(result: ParseResult, original_filename: str) -> str:
    """
    Persist accepted records to data/uploads/ as a normalized JSON file the
    normalizer will pick up on the next run. Returns the saved path.
    """
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in original_filename)[:60]
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    out = os.path.join(UPLOADS_DIR, f"upload_{result.file_type}_{ts}_{safe}.json")

    payload = {
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "file_type": result.file_type,
        "original_filename": original_filename,
        "record_count": len(result.records),
        "items": result.records,
    }
    # Carry asset criticality map if the asset parser produced one.
    meta = getattr(result, "records_meta", None)
    if meta:
        payload["meta"] = meta
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)
    return out


def list_uploads() -> List[Dict]:
    """Return metadata for all currently-saved uploads (for the UI table)."""
    if not os.path.exists(UPLOADS_DIR):
        return []
    rows = []
    for fn in sorted(os.listdir(UPLOADS_DIR)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(UPLOADS_DIR, fn)) as f:
                d = json.load(f)
            rows.append({
                "filename": d.get("original_filename", fn),
                "file_type": d.get("file_type", "?"),
                "record_count": d.get("record_count", 0),
                "ingested_at": d.get("ingested_at", "")[:19].replace("T", " "),
                "stored_as": fn,
            })
        except Exception:
            continue
    return rows


def clear_uploads() -> int:
    """Delete all saved uploads. Returns count removed. (User-initiated only.)"""
    if not os.path.exists(UPLOADS_DIR):
        return 0
    n = 0
    for fn in os.listdir(UPLOADS_DIR):
        if fn.endswith(".json"):
            os.remove(os.path.join(UPLOADS_DIR, fn))
            n += 1
    return n
