# ingestion/schema.py
#
# Shared helpers for all upload parsers.
#
# make_uploaded_item() produces a record in the SAME unified schema as
# analysis/normalizer.py's _make_normalized_item(), plus extra provenance
# fields that record where an uploaded record came from. Because the shape
# matches, uploaded records flow into the existing correlator + scorer
# unchanged.
#
# ParseResult is the standard return type for every parser: it carries the
# successfully parsed records, any per-row errors (shown cleanly in the UI),
# and a short human-readable summary.

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Import the canonical asset-context lookup so uploaded assets get the same
# criticality tiers/multipliers as pipeline-collected assets.
try:
    from analysis.normalizer import get_asset_context
except Exception:  # pragma: no cover - fallback if run in isolation
    def get_asset_context(hostname: str) -> Dict[str, Any]:
        return {"tier": 3, "label": "Unknown Asset", "multiplier": 1.0}


@dataclass
class ParseResult:
    """Standard return type for every parser."""
    records: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    file_type: str = "unknown"
    summary: str = ""

    @property
    def ok(self) -> bool:
        return len(self.records) > 0 and not self._fatal

    _fatal: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "file_type": self.file_type,
            "record_count": len(self.records),
            "error_count": len(self.errors),
            "errors": self.errors,
            "summary": self.summary,
            "records": self.records,
        }


def make_uploaded_item(
    *,
    source: str,
    source_type: str,          # e.g. "nmap", "tenable_csv", "asset_inventory", "hibp_csv"
    item_type: str,            # "scan_finding" | "vulnerability" | "breach" | "exposure" | "asset"
    title: str,
    description: str,
    severity: str,
    timestamp: str = "",
    asset: Optional[str] = None,
    entity: Optional[str] = None,
    tags: Optional[List[str]] = None,
    confidence: str = "MEDIUM",
    filename: str = "",
    raw_data: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build one normalized record from uploaded evidence.

    Matches analysis/normalizer.py's schema (source, type, title, description,
    severity, timestamp, asset, asset_tier/label/multiplier, tags, raw_data,
    extra, normalized_at) and ADDS upload-provenance fields:
        source_type, ingestion_method, entity, confidence, provenance
    """
    asset_context = get_asset_context(asset or "")
    now = datetime.now(timezone.utc).isoformat()
    return {
        # ── canonical schema (consumed by correlator + scorer) ──
        "source": source,
        "type": item_type,
        "title": title,
        "description": description,
        "severity": (severity or "UNKNOWN").upper(),
        "timestamp": timestamp or now,
        "asset": asset,
        "asset_tier": asset_context["tier"],
        "asset_label": asset_context["label"],
        "asset_multiplier": asset_context["multiplier"],
        "tags": tags or [],
        "raw_data": raw_data or {},
        "extra": extra or {},
        "normalized_at": now,
        # ── upload provenance (extra fields, ignored by old code) ──
        "source_type": source_type,
        "ingestion_method": "file_upload",
        "entity": entity or asset or "",
        "confidence": confidence.upper(),
        "provenance": {
            "ingestion_method": "file_upload",
            "source_type": source_type,
            "filename": filename,
            "ingested_at": now,
        },
    }


# Map common severity strings/scores to our canonical labels.
def severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0:
        return "LOW"
    return "UNKNOWN"


def normalize_severity_label(raw: str) -> str:
    if not raw:
        return "UNKNOWN"
    r = raw.strip().upper()
    aliases = {
        "CRIT": "CRITICAL", "CRITICAL": "CRITICAL",
        "HIGH": "HIGH", "IMPORTANT": "HIGH",
        "MED": "MEDIUM", "MEDIUM": "MEDIUM", "MODERATE": "MEDIUM",
        "LOW": "LOW", "MINOR": "LOW",
        "INFO": "LOW", "INFORMATIONAL": "LOW", "NONE": "LOW",
    }
    return aliases.get(r, r if r in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN")
