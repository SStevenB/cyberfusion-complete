# notifier.py
#
# Sends Slack alerts when new CRITICAL or HIGH findings are detected.
# Uses Slack incoming webhooks — free, no bot token needed, 5-minute setup.
#
# Setup:
#   1. Go to https://api.slack.com/apps → Create New App → From Scratch
#   2. Add "Incoming Webhooks" → Activate → Add to Workspace → pick a channel
#   3. Copy the webhook URL into config/config.yaml under slack.webhook_url
#
# This is exactly how real security teams get paged — Slack/PagerDuty
# webhooks firing when a SIEM or CTI platform detects something urgent.

import json
import os
import requests
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), "data", "outputs")

SEVERITY_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "⚠️",
    "MEDIUM":   "🔵",
    "LOW":      "🟢",
}


def _build_slack_message(new_findings: List[Dict], escalated: List[str], all_findings: List[Dict]) -> dict:
    """Build a rich Slack Block Kit message from new/escalated findings."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    critical = [f for f in new_findings if f.get("risk_label") == "CRITICAL"]
    high     = [f for f in new_findings if f.get("risk_label") == "HIGH"]

    # Header
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡️ CyberFusion — Security Alert", "emoji": True}
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{len(new_findings)} new finding(s)* detected at {now}\n"
                    f"🚨 {len(critical)} CRITICAL  ·  ⚠️ {len(high)} HIGH"
                    + (f"  ·  ⬆️ {len(escalated)} escalated" if escalated else "")
                )
            }
        },
        {"type": "divider"}
    ]

    # One block per critical/high finding
    for f in (new_findings)[:5]:
        emoji = SEVERITY_EMOJI.get(f.get("risk_label", "LOW"), "•")
        score = f.get("risk_score", 0)
        mitre = f.get("mitre_technique", "")
        rec_lines = f.get("recommendation", "").split(". ")
        first_rec = rec_lines[0].strip() if rec_lines else ""

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *[{f['rule_id']}] {f['rule_name']}*  —  Score: `{score}`\n"
                    f"_{f.get('description','')[:200]}..._\n"
                    + (f"🎯 MITRE: `{mitre}`\n" if mitre else "")
                    + (f"✅ *Action:* {first_rec}" if first_rec else "")
                )
            }
        })

    if len(new_findings) > 5:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"_...and {len(new_findings) - 5} more finding(s). Run the dashboard for full details._"}
        })

    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": "CyberFusion CTI Platform · northstar-analytics.local · Lab/Demo"}]
    })

    return {"blocks": blocks}


def send_slack_alert(
    webhook_url: str,
    new_findings: List[Dict],
    escalated_ids: List[str],
    all_findings: List[Dict]
) -> bool:
    """
    POST a Slack alert. Returns True on success.
    Only fires for CRITICAL or HIGH new findings.
    """
    # Filter to only CRITICAL + HIGH — don't spam on MEDIUM/LOW
    urgent = [f for f in new_findings if f.get("risk_label") in ("CRITICAL", "HIGH")]
    if not urgent and not escalated_ids:
        print("[Notifier] No urgent findings to alert on")
        return False

    payload = _build_slack_message(urgent, escalated_ids, all_findings)
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.status_code == 200:
            print(f"[Notifier] ✅ Slack alert sent ({len(urgent)} urgent finding(s))")
            return True
        else:
            print(f"[Notifier] Slack returned {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
        print(f"[Notifier] Slack alert failed: {e}")
        return False


def run_notifier(config: Optional[dict] = None, scored: Optional[List[Dict]] = None) -> bool:
    """
    Main entry point. Loads findings + delta, sends alert if warranted.
    Called at the end of run_pipeline.py automatically.
    """
    if config is None:
        config = {}

    webhook_url = config.get("slack", {}).get("webhook_url", "")
    if not webhook_url:
        print("[Notifier] No Slack webhook configured — skipping alert")
        print("[Notifier] Add slack.webhook_url to config/config.yaml to enable")
        return False

    # Load current findings and delta
    findings_file = os.path.join(OUTPUTS_DIR, "final_risk_findings.json")
    if not os.path.exists(findings_file):
        return False

    with open(findings_file) as f:
        data = json.load(f)

    all_findings = data.get("findings", [])
    delta        = data.get("delta", {})
    new_ids      = set(delta.get("new", []))
    escalated    = delta.get("escalated", [])

    new_findings = [f for f in all_findings if f.get("rule_id") in new_ids]

    return send_slack_alert(webhook_url, new_findings, escalated, all_findings)


if __name__ == "__main__":
    import yaml
    cfg_path = os.path.join(os.path.dirname(__file__), "config", "config.yaml")
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f) or {}
    run_notifier(cfg)
