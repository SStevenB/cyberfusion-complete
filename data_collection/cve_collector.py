# data_collection/cve_collector.py
# Fetches recent CVEs from the NIST National Vulnerability Database (NVD).
# Free API — optional key removes rate limits (get one instantly at nvd.nist.gov)
# Docs: https://nvd.nist.gov/developers/vulnerabilities

import json
import os
import time
import requests
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "NONE":     "LOW",
}


def fetch_recent_cves(
    days_back: int = 7,
    max_results: int = 30,
    api_key: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Fetch CVEs published in the last N days from the NVD API.
    api_key: optional NVD API key — removes rate limiting.
             Get one free at: https://nvd.nist.gov/developers/request-an-api-key
    """
    end   = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)

    params = {
        "pubStartDate":   start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":     end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(max_results, 2000),
    }

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    print(f"[CVE Collector] Fetching CVEs from NVD (last {days_back} days)...")

    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)

        # NVD rate-limits unauthenticated requests — wait and retry once
        if resp.status_code == 403:
            print("[CVE Collector] Rate limited by NVD — waiting 6s and retrying...")
            time.sleep(6)
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)

        resp.raise_for_status()
        data = resp.json()

    except requests.RequestException as e:
        print(f"[CVE Collector] NVD request failed: {e} — using empty result")
        print("[CVE Collector] Tip: Add a free NVD API key to config/config.yaml to avoid rate limits")
        return []

    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        cve_id   = cve_data.get("id", "")

        descriptions = cve_data.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        score    = None
        severity = "UNKNOWN"
        metrics  = cve_data.get("metrics", {})

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                score     = cvss_data.get("baseScore")
                sev_raw   = (
                    metric_list[0].get("baseSeverity")
                    or cvss_data.get("baseSeverity", "UNKNOWN")
                )
                severity = SEVERITY_MAP.get(sev_raw.upper(), "UNKNOWN")
                break

        refs      = [r.get("url", "") for r in cve_data.get("references", [])[:3]]
        published = cve_data.get("published", "")

        cves.append({
            "cve_id":      cve_id,
            "description": desc,
            "severity":    severity,
            "score":       score,
            "published":   published,
            "references":  refs,
            "source":      "NVD",
        })

    print(f"[CVE Collector] {len(cves)} CVEs fetched")
    return cves


def save_cves(cves: List[Dict[str, Any]]) -> str:
    os.makedirs(RAW_DIR, exist_ok=True)
    out = os.path.join(RAW_DIR, "latest_vulnerabilities.json")
    with open(out, "w") as f:
        json.dump({
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "total": len(cves),
            "cves": cves,
        }, f, indent=2)
    print(f"[CVE Collector] Saved {len(cves)} CVEs → {out}")
    return out


if __name__ == "__main__":
    cves = fetch_recent_cves(days_back=7, max_results=20)
    save_cves(cves)
