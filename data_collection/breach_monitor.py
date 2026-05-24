# data_collection/breach_monitor.py
#
# Checks whether a domain appears in known public data breaches.
# Uses the HaveIBeenPwned (HIBP) domain search API — a legitimate,
# widely-used public service for breach exposure monitoring.
#
# What HIBP is:
#   Have I Been Pwned is a free public service created by security researcher
#   Troy Hunt. Organizations use it to check whether their email domains have
#   appeared in published data breach datasets. It does NOT return passwords
#   or personal data — only breach metadata (name, date, what type of data
#   was exposed). This is 100% legal, ethical, and publicly documented.
#
# API docs: https://haveibeenpwned.com/API/v3
# Rate limits: 1 request/1500ms on the free tier (we handle this below)
#
# If no API key is configured, this module returns realistic synthetic
# breach signals so the rest of the pipeline still works for demos.

import json
import os
import time
import requests
from datetime import datetime, timezone
from typing import List, Dict, Any

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")

# Breach data classes returned by HIBP — explains what was leaked
BREACH_CLASS_SEVERITY = {
    "Passwords":           "CRITICAL",
    "Email addresses":     "MEDIUM",
    "Usernames":           "MEDIUM",
    "Phone numbers":       "MEDIUM",
    "Physical addresses":  "LOW",
    "IP addresses":        "LOW",
    "Names":               "LOW",
    "Dates of birth":      "LOW",
    "Credit cards":        "HIGH",
    "Banking details":     "CRITICAL",
    "Social security numbers": "CRITICAL",
    "Auth tokens":         "CRITICAL",
    "API keys":            "CRITICAL",
    "Private messages":    "HIGH",
    "Security questions":  "HIGH",
}


def _severity_from_data_classes(data_classes: List[str]) -> str:
    """Determine worst severity from what was exposed in a breach."""
    levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    worst = "LOW"
    for dc in data_classes:
        sev = BREACH_CLASS_SEVERITY.get(dc, "LOW")
        if levels[sev] > levels[worst]:
            worst = sev
    return worst


def fetch_domain_breaches(domain: str, api_key: str, delay_ms: int = 1600) -> List[Dict[str, Any]]:
    """
    Query HIBP API for all breaches that exposed accounts at this domain.

    Args:
        domain: The email domain to check (e.g. "example.com")
        api_key: Your HIBP API key
        delay_ms: Milliseconds between requests to respect rate limiting

    Returns:
        List of breach dicts with normalized fields
    """
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "CyberFusion-Portfolio-Project/1.0"
    }

    try:
        time.sleep(delay_ms / 1000)
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 404:
            print(f"[BreachMonitor] No breaches found for domain: {domain}")
            return []
        elif resp.status_code == 401:
            print("[BreachMonitor] Invalid API key — falling back to synthetic data")
            return _synthetic_breach_signals(domain)
        elif resp.status_code == 429:
            print("[BreachMonitor] Rate limited — waiting 2s and retrying once")
            time.sleep(2)
            resp = requests.get(url, headers=headers, timeout=10)

        resp.raise_for_status()
        raw_breaches = resp.json()

        results = []
        # HIBP returns a dict: { "account@domain.com": [breach_name, ...], ... }
        # We aggregate across all accounts to get unique breach names
        all_breach_names = set()
        account_count = len(raw_breaches)
        for account_breaches in raw_breaches.values():
            all_breach_names.update(account_breaches)

        # Now fetch details for each unique breach
        for breach_name in list(all_breach_names)[:20]:  # cap at 20
            breach_detail = _fetch_breach_detail(breach_name, api_key)
            if breach_detail:
                results.append(breach_detail)
            time.sleep(delay_ms / 1000)

        print(f"[BreachMonitor] {domain}: {account_count} accounts in {len(results)} breaches")
        return results

    except requests.RequestException as e:
        print(f"[BreachMonitor] Request failed: {e} — using synthetic data")
        return _synthetic_breach_signals(domain)


def _fetch_breach_detail(breach_name: str, api_key: str) -> Dict[str, Any] | None:
    """Fetch metadata for a specific breach by name."""
    url = f"https://haveibeenpwned.com/api/v3/breach/{breach_name}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "CyberFusion-Portfolio-Project/1.0"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        b = resp.json()
        data_classes = b.get("DataClasses", [])
        return {
            "source": "HaveIBeenPwned",
            "breach_name": b.get("Name", breach_name),
            "domain": b.get("Domain", ""),
            "breach_date": b.get("BreachDate", ""),
            "added_date": b.get("AddedDate", ""),
            "pwn_count": b.get("PwnCount", 0),
            "data_classes": data_classes,
            "severity": _severity_from_data_classes(data_classes),
            "is_verified": b.get("IsVerified", False),
            "description": _strip_html(b.get("Description", "")),
        }
    except Exception:
        return None


def _strip_html(text: str) -> str:
    """Remove HTML tags from HIBP breach descriptions."""
    import re
    return re.sub(r"<[^>]+>", "", text)


def _synthetic_breach_signals(domain: str) -> List[Dict[str, Any]]:
    """
    Returns realistic synthetic breach signals when no API key is configured.
    These are clearly marked as synthetic — used for demo/lab purposes only.
    The structure mirrors real HIBP responses so the pipeline works identically.
    """
    print(f"[BreachMonitor] Using synthetic breach data for: {domain} (no API key)")
    return [
        {
            "source": "synthetic",
            "breach_name": "SimulatedCorpBreach2023",
            "domain": domain,
            "breach_date": "2023-08-15",
            "added_date": "2023-09-01",
            "pwn_count": 4821,
            "data_classes": ["Email addresses", "Passwords", "Usernames"],
            "severity": "CRITICAL",
            "is_verified": False,
            "description": (
                "[SYNTHETIC DATA — for demo purposes only] "
                "Simulated breach affecting corporate email accounts. "
                "Credentials and usernames were included in the exposed dataset."
            ),
            "is_synthetic": True,
        },
        {
            "source": "synthetic",
            "breach_name": "SimulatedSaasBreach2024",
            "domain": domain,
            "breach_date": "2024-02-20",
            "added_date": "2024-03-05",
            "pwn_count": 1200,
            "data_classes": ["Email addresses", "IP addresses"],
            "severity": "MEDIUM",
            "is_verified": False,
            "description": (
                "[SYNTHETIC DATA — for demo purposes only] "
                "Simulated SaaS vendor breach affecting organization email addresses."
            ),
            "is_synthetic": True,
        }
    ]


def run_breach_monitor(config: dict | None = None) -> List[Dict[str, Any]]:
    """
    Main entry point. Loads config, checks configured domains, saves results.
    Falls back to synthetic data if no API key is set.
    """
    if config is None:
        config = {}

    hibp_config = config.get("hibp", {})
    api_key = hibp_config.get("api_key", "")
    domains = hibp_config.get("monitored_domains", ["example.com"])

    all_breaches = []

    if not api_key:
        print("[BreachMonitor] No API key configured — using synthetic breach data")
        for domain in domains:
            all_breaches.extend(_synthetic_breach_signals(domain))
    else:
        for domain in domains:
            all_breaches.extend(fetch_domain_breaches(domain, api_key))

    os.makedirs(RAW_DIR, exist_ok=True)
    out = os.path.join(RAW_DIR, "breach_signals.json")
    with open(out, "w") as f:
        json.dump({
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "domains_checked": domains,
            "total_breaches": len(all_breaches),
            "breaches": all_breaches,
        }, f, indent=2)

    print(f"[BreachMonitor] {len(all_breaches)} breach signal(s) → {out}")
    return all_breaches


if __name__ == "__main__":
    run_breach_monitor()
