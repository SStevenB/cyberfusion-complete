# analysis/normalizer.py
#
# Converts raw collected data from all sources into a unified schema.
# This is a fundamental pattern in real SIEM and CTI platforms:
# every data source speaks a different format, and the normalizer acts
# as a translator that makes all sources comparable.
#
# After normalization, the correlation engine and risk scorer
# never need to know where data came from — they just see items
# with consistent fields: source, type, severity, asset, tags, etc.
#
# This is the same design used in systems like Splunk, Microsoft Sentinel,
# and Elastic SIEM.

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional, List, Dict

RAW_DIR       = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "processed")
UPLOADS_DIR   = os.path.join(os.path.dirname(__file__), "..", "data", "uploads")

# Asset criticality — drives score multipliers in the risk scorer.
# Tier 1 = most critical (identity infra, VPN, domain controllers)
# Tier 2 = important (web servers, core apps)
# Tier 3 = standard (endpoints, dev boxes)
ASSET_CRITICALITY = {
    "vpn01.northstar-analytics.local":  {"tier": 1, "label": "VPN Gateway",          "multiplier": 1.5},
    "dc01.northstar-analytics.local":   {"tier": 1, "label": "Domain Controller",     "multiplier": 1.5},
    "web01.northstar-analytics.local":  {"tier": 2, "label": "Public Web Server",     "multiplier": 1.2},
    "web02.northstar-analytics.local":  {"tier": 2, "label": "Web Application",       "multiplier": 1.2},
    "ssh01.northstar-analytics.local":  {"tier": 3, "label": "SSH Access Host",       "multiplier": 1.0},
    "northstar-web01":                  {"tier": 2, "label": "Lab Web Server",        "multiplier": 1.2},
    "northstar-web02":                  {"tier": 2, "label": "Lab Web Server",        "multiplier": 1.2},
    "northstar-ssh01":                  {"tier": 3, "label": "Lab SSH Host",          "multiplier": 1.0},
}


def get_asset_context(hostname: str) -> Dict[str, Any]:
    """Return asset criticality metadata for a given hostname."""
    return ASSET_CRITICALITY.get(hostname, {"tier": 3, "label": "Unknown Asset", "multiplier": 1.0})


def _make_normalized_item(
    source: str,
    item_type: str,      # "vulnerability" | "news" | "exposure" | "scan_finding" | "breach" | "ip_reputation"
    title: str,
    description: str,
    severity: str,       # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
    timestamp: str,
    asset: Optional[str] = None,
    tags: Optional[List[str]] = None,
    raw_data: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Creates a normalized intelligence item in the standard schema.
    All downstream modules work with this format only — never raw source data.
    Adding a new source means adding a normalize_* function below, not
    changing the correlation or scoring logic.
    """
    asset_context = get_asset_context(asset or "")
    return {
        "source": source,
        "type": item_type,
        "title": title,
        "description": description,
        "severity": severity.upper() if severity else "UNKNOWN",
        "timestamp": timestamp,
        "asset": asset,
        "asset_tier": asset_context["tier"],
        "asset_label": asset_context["label"],
        "asset_multiplier": asset_context["multiplier"],
        "tags": tags or [],
        "raw_data": raw_data or {},
        "extra": extra or {},
        "normalized_at": datetime.now(timezone.utc).isoformat()
    }


# ── Source-specific normalizers ───────────────────────────────────────────────

def normalize_cves(cve_file: str, kev_ids: set | None = None) -> List[Dict[str, Any]]:
    """
    Convert raw NVD CVE JSON into normalized items.
    Cross-references against the CISA KEV catalog if provided.
    KEV-flagged CVEs get a 'kev_confirmed' tag and elevated severity context.
    """
    with open(cve_file) as f:
        data = json.load(f)

    kev_ids = kev_ids or set()
    normalized = []

    for cve in data.get("cves", []):
        cve_id = cve["cve_id"]
        in_kev = cve_id in kev_ids
        tags = ["cve", f"score:{cve.get('score', 'n/a')}"]
        if in_kev:
            tags.append("kev_confirmed")  # Actively exploited — highest priority signal
            tags.append("actively_exploited")

        normalized.append(_make_normalized_item(
            source=cve.get("source", "NVD"),
            item_type="vulnerability",
            title=cve_id,
            description=cve["description"],
            severity=cve.get("severity", "UNKNOWN"),
            timestamp=cve.get("published", ""),
            tags=tags,
            extra={
                "score": cve.get("score"),
                "references": cve.get("references", []),
                "in_kev": in_kev,
            },
            raw_data=cve
        ))

    kev_count = sum(1 for i in normalized if "kev_confirmed" in i["tags"])
    print(f"[Normalizer] CVEs: {len(normalized)} items ({kev_count} in CISA KEV)")
    return normalized


def normalize_news(news_file: str) -> List[Dict[str, Any]]:
    """Convert raw RSS news JSON into normalized items."""
    with open(news_file) as f:
        data = json.load(f)

    normalized = []
    for item in data.get("items", []):
        severity = "HIGH" if item.get("is_priority") else "LOW"
        normalized.append(_make_normalized_item(
            source=item.get("source", "RSS"),
            item_type="news",
            title=item["title"],
            description=item.get("summary", ""),
            severity=severity,
            timestamp=item.get("published", ""),
            tags=item.get("priority_keywords", []),
            extra={"link": item.get("link", "")},
            raw_data=item
        ))

    print(f"[Normalizer] News: {len(normalized)} items")
    return normalized


def normalize_exposure(exposure_file: str) -> List[Dict[str, Any]]:
    """Convert raw exposure alerts into normalized items."""
    with open(exposure_file) as f:
        data = json.load(f)

    normalized = []
    for alert in data.get("alerts", []):
        groups = [g["group"] for g in alert.get("matched_groups", [])]
        normalized.append(_make_normalized_item(
            source=alert.get("platform", "simulated"),
            item_type="exposure",
            title=f"Exposure signal: {', '.join(groups) if groups else 'unknown'} [{alert['alert_id']}]",
            description=alert.get("raw_text_preview", ""),
            severity=alert.get("severity", "MEDIUM"),
            timestamp=alert.get("date", ""),
            tags=alert.get("tags", []),
            extra={
                "alert_id": alert["alert_id"],
                "matched_groups": groups,
                "emails_found": alert.get("emails_found", [])
            },
            raw_data=alert
        ))

    print(f"[Normalizer] Exposure alerts: {len(normalized)} items")
    return normalized


def normalize_breaches(breach_file: str) -> List[Dict[str, Any]]:
    """
    Convert breach monitoring results into normalized items.
    These come from HaveIBeenPwned domain checks (or synthetic equivalents).
    """
    with open(breach_file) as f:
        data = json.load(f)

    normalized = []
    for breach in data.get("breaches", []):
        is_synthetic = breach.get("is_synthetic", False)
        source_label = "synthetic" if is_synthetic else "HaveIBeenPwned"
        data_classes = breach.get("data_classes", [])
        tags = ["breach"] + [dc.lower().replace(" ", "_") for dc in data_classes]
        if is_synthetic:
            tags.append("synthetic")

        normalized.append(_make_normalized_item(
            source=source_label,
            item_type="breach",
            title=f"Breach: {breach.get('breach_name', 'Unknown')} ({breach.get('domain', '')})",
            description=breach.get("description", ""),
            severity=breach.get("severity", "MEDIUM"),
            timestamp=breach.get("breach_date", ""),
            tags=tags,
            extra={
                "breach_name": breach.get("breach_name"),
                "pwn_count": breach.get("pwn_count", 0),
                "data_classes": data_classes,
                "is_verified": breach.get("is_verified", False),
                "is_synthetic": is_synthetic,
            },
            raw_data=breach
        ))

    synthetic_count = sum(1 for i in normalized if "synthetic" in i["tags"])
    print(f"[Normalizer] Breaches: {len(normalized)} items ({synthetic_count} synthetic)")
    return normalized


def normalize_scan(scan_file: str) -> List[Dict[str, Any]]:
    """Convert raw port scan JSON into one normalized item per open port."""
    with open(scan_file) as f:
        data = json.load(f)

    normalized = []
    for host in data.get("hosts", []):
        for port in host.get("open_ports", []):
            normalized.append(_make_normalized_item(
                source="port_scanner",
                item_type="scan_finding",
                title=f"Open port {port['port']}/{port['service']} on {host['hostname']}",
                description=port.get("risk_note", ""),
                severity=port.get("risk_level", "LOW"),
                timestamp=host.get("scanned_at", ""),
                asset=host["hostname"],
                tags=["open_port", port["service"].lower()],
                extra={"port": port["port"], "service": port["service"], "ip": host["ip"]},
                raw_data={**port, "hostname": host["hostname"]}
            ))

    print(f"[Normalizer] Scan findings: {len(normalized)} items")
    return normalized


def normalize_ip_reputation(ip_rep_file: str) -> List[Dict[str, Any]]:
    """
    Convert IP reputation data into normalized items.
    Only creates items for IPs with meaningful signals (malicious classification
    or known CVEs associated with them).
    """
    with open(ip_rep_file) as f:
        data = json.load(f)

    normalized = []
    for result in data.get("results", []):
        if result.get("source") == "skipped":
            continue  # Private IP, skip

        ip = result["ip"]
        shodan = result.get("shodan", {})
        greynoise = result.get("greynoise", {})

        vulns = shodan.get("vulns", [])
        classification = greynoise.get("classification", "unknown") if greynoise else "unknown"

        # Only normalize if there's something worth reporting
        if not vulns and classification not in ("malicious",):
            continue

        severity = "HIGH" if classification == "malicious" else ("MEDIUM" if vulns else "LOW")
        tags = ["ip_reputation", f"greynoise:{classification}"]
        if vulns:
            tags.append("shodan_vulns")
            tags.extend(vulns[:3])  # Tag with CVE IDs

        normalized.append(_make_normalized_item(
            source="ip_reputation",
            item_type="ip_reputation",
            title=f"IP {ip} — {classification} ({len(vulns)} associated CVEs)",
            description=(
                f"IP {ip} classified as '{classification}' by GreyNoise. "
                f"Shodan reports {len(vulns)} associated CVE(s) and "
                f"{len(shodan.get('ports', []))} open port(s)."
            ),
            severity=severity,
            timestamp=result.get("enriched_at", ""),
            asset=ip,
            tags=tags,
            extra={
                "classification": classification,
                "associated_cves": vulns,
                "open_ports": shodan.get("ports", []),
                "hostnames": shodan.get("hostnames", []),
                "greynoise_name": greynoise.get("name", "") if greynoise else "",
            },
            raw_data=result
        ))

    print(f"[Normalizer] IP reputation: {len(normalized)} noteworthy items")
    return normalized


# ── Master normalization runner ───────────────────────────────────────────────

def _merge_uploaded_asset_criticality() -> int:
    """
    If any uploaded asset-inventory file carried a criticality map, merge it
    into ASSET_CRITICALITY so uploaded assets get correct score multipliers.
    Returns the number of assets merged. User-provided data takes precedence.
    """
    if not os.path.exists(UPLOADS_DIR):
        return 0
    merged = 0
    for fn in os.listdir(UPLOADS_DIR):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(UPLOADS_DIR, fn)) as f:
                payload = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        cmap = (payload.get("meta") or {}).get("criticality_map") or {}
        for host, ctx in cmap.items():
            ASSET_CRITICALITY[host] = {
                "tier": ctx.get("tier", 3),
                "label": ctx.get("label", "Asset"),
                "multiplier": ctx.get("multiplier", 1.0),
            }
            merged += 1
    if merged:
        print(f"[Normalizer] Merged {merged} uploaded asset criticality entr(ies)")
    return merged


def load_uploaded_items() -> List[Dict[str, Any]]:
    """
    Load all records from data/uploads/*.json. These were already written in
    the normalized schema by the ingestion parsers, so they need no further
    transformation — uploads SUPPLEMENT the live API data.

    We re-apply asset context here in case an uploaded asset inventory changed
    the criticality of a host referenced by an uploaded scan/vuln record.
    'asset' records themselves are inventory metadata, not findings, so we keep
    them out of the correlation stream (the correlator ignores unknown types,
    but excluding them keeps counts honest).
    """
    if not os.path.exists(UPLOADS_DIR):
        return []
    items: List[Dict[str, Any]] = []
    for fn in sorted(os.listdir(UPLOADS_DIR)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(UPLOADS_DIR, fn)) as f:
                payload = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[Normalizer] Skipping unreadable upload {fn}: {e}")
            continue
        for it in payload.get("items", []):
            # Re-apply asset context (criticality may have been updated above).
            ctx = get_asset_context(it.get("asset") or "")
            it["asset_tier"] = ctx["tier"]
            it["asset_label"] = ctx["label"]
            it["asset_multiplier"] = ctx["multiplier"]
            items.append(it)
    findings = [i for i in items if i.get("type") != "asset"]
    asset_meta = [i for i in items if i.get("type") == "asset"]
    print(f"[Normalizer] Uploaded evidence: {len(findings)} finding record(s), "
          f"{len(asset_meta)} asset inventory record(s)")
    return items


def run_normalization() -> List[Dict[str, Any]]:
    """
    Load all available raw files and normalize them into a single unified list.
    Gracefully skips sources where data files don't exist yet.
    Returns all normalized items sorted by timestamp descending.
    """
    all_items = []

    # Merge any uploaded asset-inventory criticality FIRST so multipliers are
    # correct when we re-apply asset context to all items below.
    _merge_uploaded_asset_criticality()

    # Load KEV IDs for CVE cross-referencing
    kev_ids = set()
    kev_file = os.path.join(RAW_DIR, "cisa_kev.json")
    if os.path.exists(kev_file):
        with open(kev_file) as f:
            kev_data = json.load(f)
        kev_ids = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}
        print(f"[Normalizer] Loaded {len(kev_ids)} KEV CVE IDs for cross-reference")

    # Map: data key → (file path, normalizer function, extra kwargs)
    file_map = {
        "cve":           (os.path.join(RAW_DIR, "latest_vulnerabilities.json"), normalize_cves,       {"kev_ids": kev_ids}),
        "news":          (os.path.join(RAW_DIR, "threat_news.json"),            normalize_news,       {}),
        "exposure":      (os.path.join(RAW_DIR, "simulated_exposure_alerts.json"), normalize_exposure, {}),
        "breach":        (os.path.join(RAW_DIR, "breach_signals.json"),         normalize_breaches,   {}),
        "scan":          (os.path.join(RAW_DIR, "open_ports.json"),             normalize_scan,       {}),
        "ip_reputation": (os.path.join(RAW_DIR, "ip_reputation.json"),          normalize_ip_reputation, {}),
    }

    for key, (filepath, fn, kwargs) in file_map.items():
        if os.path.exists(filepath):
            try:
                items = fn(filepath, **kwargs)
                all_items.extend(items)
            except Exception as e:
                print(f"[Normalizer] Error normalizing {key}: {e}")
        else:
            print(f"[Normalizer] Skipping {key} — file not found: {filepath}")

    # ── Uploaded evidence (supplements live API data) ──
    uploaded = load_uploaded_items()
    all_items.extend(uploaded)

    all_items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    os.makedirs(PROCESSED_DIR, exist_ok=True)
    out = os.path.join(PROCESSED_DIR, "normalized_intel.json")
    with open(out, "w") as f:
        json.dump({
            "normalized_at": datetime.now(timezone.utc).isoformat(),
            "total_items": len(all_items),
            "source_breakdown": _count_by_type(all_items),
            "items": all_items
        }, f, indent=2)

    print(f"[Normalizer] Total: {len(all_items)} items → {out}")
    return all_items


def _count_by_type(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {}
    for item in items:
        t = item.get("type", "unknown")
        counts[t] = counts.get(t, 0) + 1
    return counts


if __name__ == "__main__":
    run_normalization()
