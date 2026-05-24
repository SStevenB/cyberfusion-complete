# data_collection/ip_reputation.py
#
# Queries two free public services for IP reputation context:
#
# 1. Shodan InternetDB (no key required)
#    Returns open ports, tags, hostnames, and known CVEs for an IP.
#    Docs: https://internetdb.shodan.io/
#    Rate limit: ~1 req/sec, no auth needed.
#
# 2. GreyNoise Community API (free key required)
#    Classifies IPs as: benign scanner, malicious, or unknown.
#    "Benign" = known internet-wide scanners like Shodan itself.
#    "Malicious" = seen conducting attacks.
#    Docs: https://docs.greynoise.io/reference/get_v3-community-ip
#    Free community key: https://www.greynoise.io/
#
# Why this matters for a CTI project:
#   When your scanner finds an IP connecting to your lab, knowing whether
#   that IP is a known benign scanner vs. a malicious actor changes the
#   risk assessment dramatically. This is exactly how real SOC teams use
#   threat intel enrichment.

import json
import os
import time
import requests
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")


# ── Shodan InternetDB ─────────────────────────────────────────────────────────

def query_shodan_internetdb(ip: str) -> Dict[str, Any]:
    """
    Free Shodan API — no key required. Returns known open ports, CPEs, CVEs,
    hostnames, and tags for any public IP.

    Note: This only works for public IPs. Private/RFC1918 IPs return 404.
    For lab use, we handle that case gracefully.
    """
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404:
            return {"ip": ip, "error": "not_found", "source": "shodan_internetdb"}
        resp.raise_for_status()
        data = resp.json()
        return {
            "ip": ip,
            "source": "shodan_internetdb",
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "cpes": data.get("cpes", []),       # Common Platform Enumeration (software IDs)
            "vulns": data.get("vulns", []),      # CVEs Shodan has associated with this IP
            "tags": data.get("tags", []),
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }
    except requests.RequestException as e:
        return {"ip": ip, "error": str(e), "source": "shodan_internetdb"}


# ── GreyNoise ─────────────────────────────────────────────────────────────────

def query_greynoise(ip: str, api_key: str) -> Dict[str, Any]:
    """
    GreyNoise Community API. Classifies an IP as:
    - "benign": Known internet scanner (Shodan, Censys, security researchers)
    - "malicious": Seen conducting actual attacks
    - "unknown": Not enough data

    Classification: "noise" means it's doing internet-wide scanning (usually benign).
    "riot" means it's from a known-good source (Google DNS, Cloudflare, etc).
    """
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 404:
            return {"ip": ip, "classification": "unknown", "source": "greynoise", "noise": False}
        resp.raise_for_status()
        data = resp.json()
        return {
            "ip": ip,
            "source": "greynoise",
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name": data.get("name", ""),
            "link": data.get("link", ""),
            "last_seen": data.get("last_seen", ""),
            "message": data.get("message", ""),
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }
    except requests.RequestException as e:
        return {"ip": ip, "error": str(e), "source": "greynoise", "classification": "unknown"}


def enrich_ips(ip_list: List[str], greynoise_api_key: str = "") -> List[Dict[str, Any]]:
    """
    Enrich a list of IP addresses with Shodan and GreyNoise data.
    Filters out private/RFC1918 IPs (can't query those on public APIs).

    Private IP ranges (these are lab/internal — skip public API calls):
    - 10.x.x.x
    - 172.16-31.x.x
    - 192.168.x.x
    - 127.x.x.x
    """
    import ipaddress

    results = []
    for ip in ip_list:
        try:
            ip_obj = ipaddress.ip_address(ip)
            is_private = ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            is_private = False

        if is_private:
            print(f"[IPReputation] Skipping private IP: {ip} (lab/internal only)")
            results.append({
                "ip": ip,
                "source": "skipped",
                "reason": "private_ip",
                "note": "Private/lab IP — not queried against public APIs"
            })
            continue

        # Shodan InternetDB (no key needed)
        shodan_result = query_shodan_internetdb(ip)
        time.sleep(1)  # Respect rate limits

        # GreyNoise (optional key)
        greynoise_result = None
        if greynoise_api_key:
            greynoise_result = query_greynoise(ip, greynoise_api_key)
            time.sleep(0.5)

        results.append({
            "ip": ip,
            "shodan": shodan_result,
            "greynoise": greynoise_result,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        })
        print(f"[IPReputation] Enriched {ip}")

    return results


def run_ip_reputation(ips: Optional[List[str]] = None, config: Optional[dict] = None) -> List[Dict[str, Any]]:
    """
    Main entry point. Enriches a list of IPs and saves results.
    If no IPs provided, loads them from the latest scan results.
    """
    if config is None:
        config = {}

    greynoise_key = config.get("greynoise", {}).get("api_key", "")

    if ips is None:
        # Load IPs from scanner output
        scan_file = os.path.join(RAW_DIR, "open_ports.json")
        if os.path.exists(scan_file):
            with open(scan_file) as f:
                scan_data = json.load(f)
            ips = [h["ip"] for h in scan_data.get("hosts", [])]
        else:
            ips = []

    if not ips:
        print("[IPReputation] No IPs to enrich")
        return []

    results = enrich_ips(ips, greynoise_key)

    os.makedirs(RAW_DIR, exist_ok=True)
    out = os.path.join(RAW_DIR, "ip_reputation.json")
    with open(out, "w") as f:
        json.dump({
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "total_ips": len(results),
            "results": results,
        }, f, indent=2)

    print(f"[IPReputation] {len(results)} IP(s) enriched → {out}")
    return results


if __name__ == "__main__":
    # Example — enrich a test IP (public IP only)
    test_results = enrich_ips(["8.8.8.8"])
    print(json.dumps(test_results, indent=2))
