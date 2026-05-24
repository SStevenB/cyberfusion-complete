# data_collection/kev_collector.py
#
# Fetches the CISA Known Exploited Vulnerabilities (KEV) catalog.
#
# What the KEV catalog is:
#   CISA (Cybersecurity and Infrastructure Security Agency) maintains a public
#   catalog of CVEs that have been confirmed as actively exploited in real
#   attacks. This is crucial for prioritization — a CVE in the KEV catalog
#   is dramatically more urgent than one that's just theoretically dangerous.
#
#   Real security teams cross-reference their vulnerability scans against
#   the KEV catalog to identify which patches are truly urgent.
#
# Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# Data: Publicly available JSON feed — no API key required
# License: Public domain (U.S. government publication)

import json
import os
import requests
from datetime import datetime, timezone
from typing import List, Dict, Any, Set

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_catalog() -> Dict[str, Any]:
    """
    Download the full CISA KEV catalog.
    Returns a dict with the catalog metadata and a set of CVE IDs for fast lookup.
    """
    print("[KEV] Fetching CISA Known Exploited Vulnerabilities catalog...")
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        print(f"[KEV] Downloaded {len(vulnerabilities)} KEV entries")
        return {
            "catalog_version": data.get("catalogVersion", "unknown"),
            "date_released": data.get("dateReleased", ""),
            "count": data.get("count", len(vulnerabilities)),
            "vulnerabilities": vulnerabilities,
        }

    except requests.RequestException as e:
        print(f"[KEV] Failed to fetch KEV catalog: {e}")
        return {"vulnerabilities": [], "error": str(e)}


def get_kev_cve_ids(kev_data: Dict[str, Any]) -> Set[str]:
    """
    Extract just the CVE IDs from the catalog for fast O(1) lookup.
    Usage: if cve_id in kev_ids: ... → this CVE is actively exploited
    """
    return {v["cveID"] for v in kev_data.get("vulnerabilities", [])}


def get_kev_details(cve_id: str, kev_data: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Look up full KEV entry for a specific CVE ID.
    Returns None if the CVE is not in the KEV catalog.

    KEV entries include:
    - vendorProject: Who makes the affected product (e.g. "Microsoft", "Apache")
    - product: What product is affected
    - vulnerabilityName: Human-readable name
    - dateAdded: When CISA added it to the catalog
    - shortDescription: What the vulnerability does
    - requiredAction: What CISA says to do about it
    - dueDate: Federal agency remediation deadline (useful context even for non-feds)
    - knownRansomwareCampaignUse: "Known" or "Unknown" — highest priority signal
    """
    for vuln in kev_data.get("vulnerabilities", []):
        if vuln.get("cveID") == cve_id:
            return vuln
    return None


def save_kev_catalog(kev_data: Dict[str, Any]) -> str:
    """Save the KEV catalog to disk and return the file path."""
    os.makedirs(RAW_DIR, exist_ok=True)
    out = os.path.join(RAW_DIR, "cisa_kev.json")

    # Save a lightweight index for fast startup loads
    index = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "catalog_version": kev_data.get("catalog_version", ""),
        "date_released": kev_data.get("date_released", ""),
        "count": kev_data.get("count", 0),
        "vulnerabilities": kev_data.get("vulnerabilities", [])
    }

    with open(out, "w") as f:
        json.dump(index, f, indent=2)

    print(f"[KEV] Saved {kev_data.get('count', 0)} KEV entries → {out}")
    return out


def load_kev_catalog() -> Dict[str, Any]:
    """Load the cached KEV catalog from disk (if it exists)."""
    kev_file = os.path.join(RAW_DIR, "cisa_kev.json")
    if not os.path.exists(kev_file):
        return {"vulnerabilities": []}
    with open(kev_file) as f:
        return json.load(f)


def run_kev_collector() -> Dict[str, Any]:
    """Main entry point — fetch, save, and return the KEV catalog."""
    kev_data = fetch_kev_catalog()
    if kev_data.get("vulnerabilities"):
        save_kev_catalog(kev_data)
    else:
        print("[KEV] No data fetched — check network connection")
    return kev_data


if __name__ == "__main__":
    data = run_kev_collector()
    ids = get_kev_cve_ids(data)
    print(f"\nSample KEV CVE IDs: {list(ids)[:5]}")
