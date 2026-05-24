# analysis/risk_scorer.py
#
# Assigns a numeric risk score and risk label to each correlated finding.
# Every score is fully explainable — we show exactly which factors drove
# the number. This is an important real-world requirement: security teams
# and executives need to understand WHY something is high-risk, not just
# that it is.
#
# Scoring factors:
# 1. Base severity      — CRITICAL/HIGH/MEDIUM/LOW from the correlation rule
# 2. Confidence bonus   — how certain we are the signal is real
# 3. Rule weight bonus  — some rules are inherently higher priority
# 4. Evidence count     — more corroborating signals = higher score
# 5. Asset criticality  — Tier 1 assets get a multiplier (VPN, DC, etc.)
# 6. KEV bonus          — CISA Known Exploited Vulnerabilities get +20
#
# This produces scores from ~5 (low confidence, low severity) to ~100+
# (critical severity, KEV confirmed, high-tier asset, multiple signals)

import json
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "outputs")

# ── Scoring tables ────────────────────────────────────────────────────────────

SEVERITY_BASE = {
    "CRITICAL": 40,
    "HIGH":     30,
    "MEDIUM":   15,
    "LOW":       5,
}

CONFIDENCE_BONUS = {
    "HIGH":   10,
    "MEDIUM":  5,
    "LOW":     0,
}

# Rules with more direct business impact get a higher inherent weight
RULE_WEIGHT_BONUS = {
    "CORR-003": 25,   # VPN credential leak — direct network access
    "CORR-007": 22,   # Password breach + login services
    "CORR-006": 20,   # CISA KEV — actively exploited right now
    "CORR-001": 15,   # RDP exposure
    "CORR-002": 12,   # SSH exposure
    "CORR-004": 10,   # Critical web CVEs
    "CORR-008":  8,   # Multiple breach signals
    "CORR-005":  8,   # Email in breach data
}

# Asset tier multipliers — Tier 1 assets amplify the score
# This reflects real-world risk: the same finding on a crown-jewel
# asset is more urgent than on a test machine
ASSET_TIER_MULTIPLIER = {
    1: 1.5,   # VPN, Domain Controllers, Identity infra
    2: 1.2,   # Web servers, core applications
    3: 1.0,   # Standard endpoints, dev boxes
}


def score_to_label(score: float) -> str:
    """Convert a numeric score to a human-readable risk label."""
    if score >= 65:
        return "CRITICAL"
    elif score >= 45:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


def _get_asset_tier(finding: Dict[str, Any], normalized_items: List[Dict[str, Any]]) -> int:
    """
    Look up the highest asset tier among affected assets in this finding.
    Higher tier number = lower criticality (Tier 1 is most critical).
    Returns the most critical (lowest) tier found.
    """
    affected = finding.get("affected_assets", [])
    if not affected:
        return 3

    # Check normalized items for asset tier data
    asset_tiers = []
    for asset in affected:
        for item in normalized_items:
            if item.get("asset") == asset and "asset_tier" in item:
                asset_tiers.append(item["asset_tier"])

    if not asset_tiers:
        return 3  # Default to standard tier

    return min(asset_tiers)  # Return the most critical tier found


def score_finding(finding: Dict[str, Any], normalized_items: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Calculate a risk score for a single correlated finding.
    Returns the finding dict with risk_score, risk_label, and score_breakdown added.
    """
    if normalized_items is None:
        normalized_items = []

    score = 0.0
    score_breakdown = []

    # Factor 1: Base severity
    sev = finding.get("severity", "LOW")
    base = SEVERITY_BASE.get(sev, 5)
    score += base
    score_breakdown.append(f"Base severity ({sev}): +{base}")

    # Factor 2: Confidence bonus
    conf = finding.get("confidence", "LOW")
    bonus = CONFIDENCE_BONUS.get(conf, 0)
    score += bonus
    if bonus:
        score_breakdown.append(f"Confidence ({conf}): +{bonus}")

    # Factor 3: Rule importance weight
    rule_id = finding.get("rule_id", "")
    rule_bonus = RULE_WEIGHT_BONUS.get(rule_id, 0)
    score += rule_bonus
    if rule_bonus:
        score_breakdown.append(f"Rule importance ({rule_id}): +{rule_bonus}")

    # Factor 4: Supporting evidence count
    evidence_count = (
        len(finding.get("matched_scan", [])) +
        len(finding.get("matched_exposure", [])) +
        len(finding.get("matched_cves", []))
    )
    evidence_bonus = min(evidence_count * 2, 12)
    score += evidence_bonus
    if evidence_bonus:
        score_breakdown.append(f"Corroborating evidence ({evidence_count} signals): +{evidence_bonus}")

    # Factor 5: Asset criticality multiplier
    asset_tier = _get_asset_tier(finding, normalized_items)
    multiplier = ASSET_TIER_MULTIPLIER.get(asset_tier, 1.0)
    if multiplier > 1.0:
        pre_mult = score
        score = score * multiplier
        score_breakdown.append(
            f"Asset criticality (Tier {asset_tier}, ×{multiplier}): "
            f"+{score - pre_mult:.0f}"
        )

    # Factor 6: KEV bonus — actively exploited = urgent
    kev_cves = finding.get("kev_confirmed_cves", [])
    if kev_cves or finding.get("rule_id") == "CORR-006":
        score += 20
        score_breakdown.append(f"CISA KEV confirmed (active exploitation): +20")

    # Cap score at 100 for clean display
    score = min(round(score), 100)
    risk_label = score_to_label(score)

    return {
        **finding,
        "risk_score": score,
        "risk_label": risk_label,
        "score_breakdown": score_breakdown,
        "asset_tier": asset_tier,
        "scored_at": datetime.now(timezone.utc).isoformat()
    }


def _load_normalized_items() -> List[Dict[str, Any]]:
    """Load normalized items for asset tier lookups during scoring."""
    norm_file = os.path.join(
        os.path.dirname(__file__), "..", "data", "processed", "normalized_intel.json"
    )
    if not os.path.exists(norm_file):
        return []
    with open(norm_file) as f:
        return json.load(f).get("items", [])


def _compute_delta(scored: List[Dict], history_file: str) -> Dict[str, Any]:
    """
    Compare current findings against the previous run to show what's new,
    resolved, or changed in severity. This is how real SOC tools track
    whether your risk posture is improving or degrading over time.
    """
    if not os.path.exists(history_file):
        return {"new": [], "resolved": [], "escalated": [], "deescalated": []}

    with open(history_file) as f:
        prev_data = json.load(f)
    prev_findings = {f["rule_id"]: f for f in prev_data.get("findings", [])}
    curr_findings = {f["rule_id"]: f for f in scored}

    delta = {
        "new":          [rid for rid in curr_findings if rid not in prev_findings],
        "resolved":     [rid for rid in prev_findings if rid not in curr_findings],
        "escalated":    [],
        "deescalated":  [],
    }

    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for rid in curr_findings:
        if rid in prev_findings:
            curr_sev = sev_order.get(curr_findings[rid].get("risk_label", "LOW"), 1)
            prev_sev = sev_order.get(prev_findings[rid].get("risk_label", "LOW"), 1)
            if curr_sev > prev_sev:
                delta["escalated"].append(rid)
            elif curr_sev < prev_sev:
                delta["deescalated"].append(rid)

    return delta


def run_scoring(
    findings: Optional[List[Dict]] = None,
    save_history: bool = True
) -> List[Dict]:
    """
    Main entry point. Score all findings and save results.
    Optionally compares with previous run to produce a delta report.
    """
    if findings is None:
        findings_file = os.path.join(OUTPUTS_DIR, "correlated_findings.json")
        with open(findings_file) as f:
            data = json.load(f)
        findings = data["findings"]

    normalized_items = _load_normalized_items()
    scored = [score_finding(f, normalized_items) for f in findings]
    scored.sort(key=lambda x: x["risk_score"], reverse=True)

    os.makedirs(OUTPUTS_DIR, exist_ok=True)

    # Compare with history
    history_file = os.path.join(OUTPUTS_DIR, "final_risk_findings.json")
    delta = _compute_delta(scored, history_file)

    if delta["new"]:
        print(f"[Risk Scorer] 🆕 {len(delta['new'])} new finding(s) since last run")
    if delta["resolved"]:
        print(f"[Risk Scorer] ✅ {len(delta['resolved'])} finding(s) resolved since last run")

    summary = {
        "critical": sum(1 for s in scored if s["risk_label"] == "CRITICAL"),
        "high":     sum(1 for s in scored if s["risk_label"] == "HIGH"),
        "medium":   sum(1 for s in scored if s["risk_label"] == "MEDIUM"),
        "low":      sum(1 for s in scored if s["risk_label"] == "LOW"),
    }

    output = {
        "scored_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(scored),
        "summary": summary,
        "delta": delta,
        "findings": scored,
    }

    out = os.path.join(OUTPUTS_DIR, "final_risk_findings.json")
    with open(out, "w") as f:
        json.dump(output, f, indent=2)

    # Archive this run for historical comparison
    if save_history:
        archive_dir = os.path.join(OUTPUTS_DIR, "history")
        os.makedirs(archive_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        archive_file = os.path.join(archive_dir, f"findings_{ts}.json")
        with open(archive_file, "w") as f:
            json.dump(output, f, indent=2)

    print(f"[Risk Scorer] Scored {len(scored)} findings → {out}")
    print(f"[Risk Scorer] Summary: {summary}")
    return scored


if __name__ == "__main__":
    run_scoring()
