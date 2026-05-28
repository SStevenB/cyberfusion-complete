# ingestion/parsers/asset_csv_parser.py
#
# Parses an asset-inventory CSV (CMDB export / spreadsheet) into `asset`
# records AND returns a criticality map. The criticality map lets uploaded
# assets influence scoring the same way the built-in ASSET_CRITICALITY dict
# does — so a finding on an uploaded "Tier 1" asset gets the 1.5x multiplier.
#
# Expected (flexible) columns: hostname/asset, ip, tier/criticality,
# role/label, internet_facing.

import csv
import io
from typing import Dict, List

from ingestion.schema import ParseResult, make_uploaded_item

COLUMN_ALIASES = {
    "hostname":         ["hostname", "host", "asset", "asset name", "name", "fqdn"],
    "ip":               ["ip", "ip address", "address"],
    "tier":             ["tier", "criticality", "criticality tier", "importance"],
    "label":            ["role", "label", "type", "function", "description"],
    "internet_facing":  ["internet_facing", "internet facing", "public", "exposed"],
}

TIER_MULTIPLIER = {1: 1.5, 2: 1.2, 3: 1.0}


def detect(filename: str, text: str) -> bool:
    name = (filename or "").lower()
    if not (name.endswith(".csv") or "," in text[:1000]):
        return False
    head = text[:1000].lower()
    has_asset = any(k in head for k in ["hostname", "asset", "fqdn"])
    has_tier = any(k in head for k in ["tier", "criticality", "role", "internet"])
    # Avoid colliding with vuln CSVs (which have cve/cvss/plugin columns).
    looks_like_vuln = any(k in head for k in ["cve", "cvss", "plugin"])
    return has_asset and has_tier and not looks_like_vuln


def _build_index(header: List[str]) -> Dict[str, int]:
    idx, low = {}, [h.strip().lower() for h in header]
    for canon, aliases in COLUMN_ALIASES.items():
        for a in aliases:
            if a in low:
                idx[canon] = low.index(a)
                break
    return idx


def _coerce_tier(raw: str) -> int:
    r = (raw or "").strip().lower()
    if r in ("1", "tier 1", "tier1", "critical", "crown jewel"):
        return 1
    if r in ("2", "tier 2", "tier2", "high", "core"):
        return 2
    return 3


def parse(text: str, filename: str = "") -> ParseResult:
    res = ParseResult(file_type="asset_csv")
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except Exception as e:
        res._fatal = True
        res.errors.append(f"Could not read CSV: {e}")
        return res
    if not rows:
        res._fatal = True
        res.errors.append("CSV is empty.")
        return res

    header, data_rows = rows[0], rows[1:]
    idx = _build_index(header)
    if "hostname" not in idx:
        res._fatal = True
        res.errors.append(
            f"No hostname/asset column found. Headers: {', '.join(header[:12])}")
        res.summary = "Unrecognized asset inventory schema."
        return res

    def cell(row, key):
        i = idx.get(key)
        return row[i].strip() if i is not None and i < len(row) else ""

    criticality_map: Dict[str, Dict] = {}
    for row in data_rows:
        if not any(c.strip() for c in row):
            continue
        host = cell(row, "hostname")
        if not host:
            continue
        tier = _coerce_tier(cell(row, "tier"))
        label = cell(row, "label") or "Asset"
        ip = cell(row, "ip")
        inet = cell(row, "internet_facing").lower() in ("yes", "true", "1", "y")
        mult = TIER_MULTIPLIER[tier]

        criticality_map[host] = {"tier": tier, "label": label, "multiplier": mult,
                                 "internet_facing": inet, "ip": ip}

        res.records.append(make_uploaded_item(
            source="uploaded_asset_inventory",
            source_type="asset_inventory",
            item_type="asset",
            title=f"Asset: {host} (Tier {tier} — {label})",
            description=f"{label}. Internet-facing: {'yes' if inet else 'no'}.",
            severity="LOW",  # assets aren't risks themselves
            asset=host,
            entity=host,
            tags=["asset", f"tier{tier}", "uploaded"] + (["internet_facing"] if inet else []),
            confidence="HIGH",
            filename=filename,
            extra={"tier": tier, "label": label, "ip": ip, "internet_facing": inet},
            raw_data={k: cell(row, k) for k in idx},
        ))

    # Stash the criticality map so the caller can merge it into scoring.
    res.summary = f"Parsed {len(criticality_map)} asset(s) with criticality tiers."
    res.records_meta = {"criticality_map": criticality_map}  # type: ignore[attr-defined]
    return res
