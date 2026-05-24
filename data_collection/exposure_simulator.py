# data_collection/exposure_simulator.py
#
# Generates realistic synthetic exposure signals for demo/lab use.
# These simulate the kind of alerts a real exposure monitoring service
# (like Recorded Future, Digital Shadows, or Flare) might generate.
#
# ALL data here is clearly synthetic — fictional org, fictional credentials.
# Purpose: let the correlation engine and dashboard work without real breach data.
# When a real HaveIBeenPwned key is configured, breach_monitor.py supplements this.

import json
import os
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
import random

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")

ORG_DOMAIN  = "northstar-analytics.local"
ORG_NAME    = "Northstar Analytics"

SYNTHETIC_ALERTS = [
    {
        "alert_id":   "SIM-EXP-001",
        "platform":   "synthetic",
        "severity":   "CRITICAL",
        "tags":       ["vpn", "credentials", "remote_access"],
        "date":       (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%d"),
        "raw_text_preview": (
            "[SYNTHETIC — demo data only] Alleged VPN credentials for "
            f"{ORG_NAME} posted. Includes username/password pairs for "
            "vpn01.northstar-analytics.local."
        ),
        "matched_groups": [{"group": "vpn"}, {"group": "remote_access"}],
        "emails_found": [],
    },
    {
        "alert_id":   "SIM-EXP-002",
        "platform":   "synthetic",
        "severity":   "HIGH",
        "tags":       ["rdp", "remote_access", "credentials"],
        "date":       (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d"),
        "raw_text_preview": (
            "[SYNTHETIC — demo data only] RDP access listing mentioning "
            f"{ORG_NAME}. Claims access to internal Windows hosts."
        ),
        "matched_groups": [{"group": "rdp"}, {"group": "remote_access"}],
        "emails_found": [],
    },
    {
        "alert_id":   "SIM-EXP-003",
        "platform":   "synthetic",
        "severity":   "MEDIUM",
        "tags":       ["email", "corporate", "phishing_target"],
        "date":       (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d"),
        "raw_text_preview": (
            f"[SYNTHETIC — demo data only] Corporate email list for {ORG_NAME} "
            "identified in combolists. Multiple @northstar-analytics.local addresses."
        ),
        "matched_groups": [{"group": "email"}, {"group": "corporate"}],
        "emails_found": [
            f"j.smith@{ORG_DOMAIN}",
            f"admin@{ORG_DOMAIN}",
            f"it-support@{ORG_DOMAIN}",
        ],
    },
    {
        "alert_id":   "SIM-EXP-004",
        "platform":   "synthetic",
        "severity":   "HIGH",
        "tags":       ["ssh", "keys", "linux"],
        "date":       (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%d"),
        "raw_text_preview": (
            f"[SYNTHETIC — demo data only] SSH private key material attributed to "
            f"{ORG_NAME} Linux infrastructure. Keys may grant passwordless access."
        ),
        "matched_groups": [{"group": "ssh"}, {"group": "linux"}],
        "emails_found": [],
    },
]


def scan_exposure_signals() -> List[Dict[str, Any]]:
    print(f"[Exposure Simulator] Generating {len(SYNTHETIC_ALERTS)} synthetic signals")
    return SYNTHETIC_ALERTS


def save_alerts(alerts: List[Dict[str, Any]]) -> str:
    os.makedirs(RAW_DIR, exist_ok=True)
    out = os.path.join(RAW_DIR, "simulated_exposure_alerts.json")
    with open(out, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "note": "All data is synthetic — for demo and lab use only",
            "total": len(alerts),
            "alerts": alerts,
        }, f, indent=2)
    print(f"[Exposure Simulator] Saved {len(alerts)} alerts → {out}")
    return out


if __name__ == "__main__":
    alerts = scan_exposure_signals()
    save_alerts(alerts)
