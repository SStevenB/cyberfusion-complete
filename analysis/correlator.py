# analysis/correlator.py
#
# The correlation engine: links signals from different data sources to find
# compounding risks that no single source would reveal on its own.
#
# Design philosophy (matches real CTI platforms):
# - Rule-based: every finding is explainable — no "the AI thinks this is bad"
# - Single responsibility: each rule checks one specific signal combination
# - Composable: rules are just functions, easy to add or remove
# - Auditable: each finding documents exactly which data items triggered it
#
# Correlation is where this project earns its value. A CVE alone is just
# a database entry. An open port alone is just a scan result. But a
# critical web CVE + an open web port + a confirmed breach of the same
# domain = a finding worth paging someone at 2am.

import json
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "processed")
OUTPUTS_DIR   = os.path.join(os.path.dirname(__file__), "..", "data", "outputs")


# ── Helper filters ────────────────────────────────────────────────────────────

def _by_type(items: List[Dict], type_: str) -> List[Dict]:
    return [i for i in items if i["type"] == type_]

def _has_tag(item: Dict, tag: str) -> bool:
    return tag in item.get("tags", [])

def _has_any_tag(item: Dict, tags: List[str]) -> bool:
    return any(t in item.get("tags", []) for t in tags)

def _in_title_or_desc(item: Dict, keywords: List[str]) -> bool:
    text = (item.get("title", "") + " " + item.get("description", "")).lower()
    return any(kw.lower() in text for kw in keywords)


# ── Correlation Rules ─────────────────────────────────────────────────────────

def rule_rdp_exposure_plus_leak(items: List[Dict]) -> List[Dict]:
    """
    CORR-001: RDP port open + dark web or breach reference to RDP/remote access.
    RDP is the #1 initial access vector in ransomware attacks.
    """
    findings = []
    rdp_ports = [i for i in items if i["type"] == "scan_finding" and "3389" in i["title"]]
    rdp_exposures = [i for i in items if i["type"] in ("exposure", "breach") and
                     _has_any_tag(i, ["rdp", "remote_access"]) or
                     (i["type"] in ("exposure", "breach") and _in_title_or_desc(i, ["rdp", "remote access"]))]

    if rdp_ports and rdp_exposures:
        findings.append({
            "rule_id": "CORR-001",
            "rule_name": "RDP Exposed with Credential Leak Signal",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1133 — External Remote Services",
            "description": (
                "Port 3389 (RDP) is open on a lab host AND exposure/breach data contains "
                "a signal for RDP access or remote credentials for this organization. "
                "RDP is the leading initial access vector in ransomware campaigns. "
                "This combination significantly increases likelihood of unauthorized access."
            ),
            "severity": "HIGH",
            "confidence": "HIGH",
            "matched_scan": [i["title"] for i in rdp_ports],
            "matched_exposure": [i["title"] for i in rdp_exposures],
            "affected_assets": list({i.get("asset", "unknown") for i in rdp_ports}),
            "recommendation": (
                "1. Immediately disable public RDP access if not required. "
                "2. Enforce Network Level Authentication (NLA). "
                "3. Rotate all domain credentials. "
                "4. Review RDP logs for suspicious login attempts. "
                "5. Consider moving RDP behind VPN."
            )
        })
    return findings


def rule_ssh_open_plus_key_exfil(items: List[Dict]) -> List[Dict]:
    """
    CORR-002: SSH port open + exposure signal referencing SSH keys or credentials.
    """
    findings = []
    ssh_ports = [i for i in items if i["type"] == "scan_finding" and "22/" in i["title"]]
    ssh_exposures = [i for i in items if i["type"] in ("exposure", "breach") and
                     _has_tag(i, "ssh")]

    if ssh_ports and ssh_exposures:
        findings.append({
            "rule_id": "CORR-002",
            "rule_name": "SSH Port Exposed with Credential Leak Signal",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1078 — Valid Accounts",
            "description": (
                "Port 22 (SSH) is open AND exposure data references SSH key material "
                "or credentials for this organization's hosts. SSH private key theft "
                "enables passwordless remote access with no password to crack."
            ),
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "matched_scan": [i["title"] for i in ssh_ports],
            "matched_exposure": [i["title"] for i in ssh_exposures],
            "affected_assets": list({i.get("asset", "unknown") for i in ssh_ports}),
            "recommendation": (
                "1. Rotate all SSH key pairs immediately. "
                "2. Audit ~/.ssh/authorized_keys on all hosts. "
                "3. Enable SSH key revocation if using a certificate authority. "
                "4. Restrict SSH to VPN-only access."
            )
        })
    return findings


def rule_vpn_credential_leak(items: List[Dict]) -> List[Dict]:
    """
    CORR-003: Any exposure or breach signal referencing VPN credentials.
    VPN access = trusted network foothold. Highest severity class.
    """
    findings = []
    vpn_signals = [i for i in items if i["type"] in ("exposure", "breach") and
                   _has_any_tag(i, ["vpn"]) or
                   (i["type"] in ("exposure", "breach") and _in_title_or_desc(i, ["vpn"]))]

    if vpn_signals:
        findings.append({
            "rule_id": "CORR-003",
            "rule_name": "VPN Credential Exposure",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1133 — External Remote Services",
            "description": (
                "Exposure or breach data contains VPN credentials for this organization. "
                "VPN access grants an attacker a trusted network foothold, bypassing "
                "perimeter defenses entirely. This is the highest-priority initial access vector."
            ),
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "matched_exposure": [i["title"] for i in vpn_signals],
            "affected_assets": ["vpn01.northstar-analytics.local"],
            "recommendation": (
                "1. Force-reset ALL VPN user credentials immediately. "
                "2. Enable MFA on VPN access. "
                "3. Review VPN access logs for the past 30 days. "
                "4. Consider temporary VPN lockdown while investigating."
            )
        })
    return findings


def rule_critical_cve_plus_exposed_service(items: List[Dict]) -> List[Dict]:
    """
    CORR-004: Critical/high web CVEs + web ports open.
    Upgraded: prioritizes KEV-confirmed CVEs if any match web services.
    """
    findings = []
    critical_cves = [i for i in items if i["type"] == "vulnerability"
                     and i["severity"] in ("CRITICAL", "HIGH")]

    web_ports = [i for i in items if i["type"] == "scan_finding"
                 and any(svc in i["title"] for svc in ["80/", "443/", "8080/", "8443/"])]

    web_cves = [c for c in critical_cves if _in_title_or_desc(c, ["http", "apache", "nginx", "web", "ssl", "tls"])]
    kev_web_cves = [c for c in web_cves if _has_tag(c, "kev_confirmed")]

    if web_cves and web_ports:
        # Escalate to CRITICAL if any matching CVE is in CISA KEV
        severity = "CRITICAL" if kev_web_cves else "HIGH"
        kev_note = (
            f" {len(kev_web_cves)} of these CVEs are confirmed in the CISA Known Exploited "
            f"Vulnerabilities catalog — meaning they are being actively exploited in the wild."
            if kev_web_cves else ""
        )

        findings.append({
            "rule_id": "CORR-004",
            "rule_name": "Critical Web CVEs with Exposed Web Service",
            "mitre_tactic": "Initial Access / Exploitation",
            "mitre_technique": "T1190 — Exploit Public-Facing Application",
            "description": (
                f"{len(web_cves)} critical/high web-related CVEs detected while web ports "
                f"are open on lab hosts.{kev_note} If running an affected version, "
                f"these hosts may be directly exploitable."
            ),
            "severity": severity,
            "confidence": "MEDIUM",
            "matched_cves": [c["title"] for c in web_cves[:5]],
            "kev_confirmed_cves": [c["title"] for c in kev_web_cves],
            "matched_scan": [i["title"] for i in web_ports],
            "affected_assets": list({i.get("asset", "unknown") for i in web_ports}),
            "recommendation": (
                "1. Verify web server versions against CVE affected ranges. "
                "2. Apply available patches — prioritize any CISA KEV entries immediately. "
                "3. Check WAF rules for exploit signatures. "
                "4. Review web access logs for exploitation attempts."
            )
        })
    return findings


def rule_credential_leak_with_email_targets(items: List[Dict]) -> List[Dict]:
    """
    CORR-005: Breach/exposure data containing corporate email addresses.
    These enable spear-phishing and credential stuffing attacks.
    """
    findings = []
    email_exposures = [i for i in items if i["type"] in ("exposure", "breach")
                       and len(i.get("extra", {}).get("emails_found", [])) > 0]

    if email_exposures:
        all_emails = []
        for e in email_exposures:
            all_emails.extend(e["extra"].get("emails_found", []))
        all_emails = list(set(all_emails))

        findings.append({
            "rule_id": "CORR-005",
            "rule_name": "Corporate Email Addresses in Breach Data",
            "mitre_tactic": "Reconnaissance",
            "mitre_technique": "T1589.002 — Email Addresses",
            "description": (
                f"{len(all_emails)} corporate email address(es) identified in exposure/breach "
                f"data. These may be used for spear-phishing, credential stuffing, "
                f"or social engineering attacks against specific individuals."
            ),
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "affected_emails": all_emails,
            "affected_assets": ["email infrastructure"],
            "recommendation": (
                "1. Alert affected users to increase phishing vigilance. "
                "2. Enable MFA on all identified accounts immediately. "
                "3. Monitor login activity for affected accounts. "
                "4. Implement DMARC/DKIM/SPF if not already done."
            )
        })
    return findings


def rule_kev_cve_with_matching_scan_service(items: List[Dict]) -> List[Dict]:
    """
    CORR-006: CVE in CISA KEV catalog + matching open service on the network.
    KEV entries are confirmed as actively exploited — treat as urgent.
    This rule is new and is the main upgrade from the original project.
    """
    findings = []
    kev_cves = [i for i in items if i["type"] == "vulnerability" and _has_tag(i, "kev_confirmed")]

    if not kev_cves:
        return findings

    # Map service names to what might show up in scan titles
    scan_findings = _by_type(items, "scan_finding")

    # For now: flag any KEV CVE + any open port combination as noteworthy
    # A real implementation would map CVE product names to service banners
    if kev_cves and scan_findings:
        findings.append({
            "rule_id": "CORR-006",
            "rule_name": "CISA KEV CVEs Detected — Active Exploitation Confirmed",
            "mitre_tactic": "Exploitation",
            "mitre_technique": "T1190 — Exploit Public-Facing Application",
            "description": (
                f"{len(kev_cves)} CVE(s) from the current NVD feed are listed in the "
                f"CISA Known Exploited Vulnerabilities catalog. This means threat actors "
                f"are actively using these vulnerabilities in real attacks right now. "
                f"Open services detected on lab hosts may be affected."
            ),
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "matched_cves": [c["title"] for c in kev_cves[:10]],
            "matched_scan": [i["title"] for i in scan_findings[:5]],
            "affected_assets": list({i.get("asset", "unknown") for i in scan_findings}),
            "recommendation": (
                "1. Cross-reference KEV CVE IDs against your software inventory immediately. "
                "2. Patch or mitigate any confirmed matches — CISA mandates federal agencies "
                "remediate KEV entries within 2-3 weeks. "
                "3. Check for vendor advisories and available patches. "
                "4. Consider temporary service isolation if patching is delayed."
            )
        })
    return findings


def rule_breach_with_password_data(items: List[Dict]) -> List[Dict]:
    """
    CORR-007: Domain breach that exposed passwords + any login-facing service open.
    Passwords in breach data = direct credential stuffing risk.
    """
    findings = []
    password_breaches = [i for i in items if i["type"] == "breach"
                         and _has_tag(i, "passwords")]
    login_services = [i for i in items if i["type"] == "scan_finding"
                      and any(svc in i["title"] for svc in ["22/", "3389", "80/", "443/", "8080/"])]

    if password_breaches and login_services:
        total_pwned = sum(b.get("extra", {}).get("pwn_count", 0) for b in password_breaches)
        findings.append({
            "rule_id": "CORR-007",
            "rule_name": "Password Breach + Login Services Exposed",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110.004 — Credential Stuffing",
            "description": (
                f"{len(password_breaches)} breach(es) exposing passwords were found for this "
                f"domain (~{total_pwned:,} accounts affected). Login-facing services are "
                f"accessible on the network. Breached passwords are commonly reused, "
                f"enabling credential stuffing attacks against these services."
            ),
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "matched_exposure": [i["title"] for i in password_breaches],
            "matched_scan": [i["title"] for i in login_services],
            "affected_assets": list({i.get("asset", "unknown") for i in login_services}),
            "recommendation": (
                "1. Force password reset for ALL users — assume credentials are compromised. "
                "2. Enable MFA on all login-facing services immediately. "
                "3. Implement account lockout and rate limiting. "
                "4. Monitor authentication logs for stuffing patterns."
            )
        })
    return findings


def rule_multiple_breach_signals(items: List[Dict]) -> List[Dict]:
    """
    CORR-008: Multiple independent breach/exposure signals for the same domain.
    Repeated exposure = sustained attacker interest, not a one-off event.
    """
    findings = []
    breach_items = [i for i in items if i["type"] in ("breach", "exposure")]

    if len(breach_items) >= 3:
        sources = list({i.get("source", "unknown") for i in breach_items})
        findings.append({
            "rule_id": "CORR-008",
            "rule_name": "Multiple Breach/Exposure Signals Detected",
            "mitre_tactic": "Reconnaissance",
            "mitre_technique": "T1594 — Search Victim-Owned Websites",
            "description": (
                f"{len(breach_items)} separate breach or exposure signals detected across "
                f"{len(sources)} source(s). Multiple signals indicate sustained attacker "
                f"interest or long-term exposure. Each individual signal compounds the risk."
            ),
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "matched_exposure": [i["title"] for i in breach_items[:8]],
            "affected_assets": ["organizational email infrastructure"],
            "recommendation": (
                "1. Conduct a full exposure review across all breach sources. "
                "2. Prioritize response for signals that include passwords or API keys. "
                "3. Brief security awareness training for all employees. "
                "4. Consider engaging a breach response service."
            )
        })
    return findings


# ── Master correlation runner ─────────────────────────────────────────────────

ALL_RULES = [
    rule_rdp_exposure_plus_leak,
    rule_ssh_open_plus_key_exfil,
    rule_vpn_credential_leak,
    rule_critical_cve_plus_exposed_service,
    rule_credential_leak_with_email_targets,
    rule_kev_cve_with_matching_scan_service,    # NEW
    rule_breach_with_password_data,              # NEW
    rule_multiple_breach_signals,               # NEW
]


def run_correlation(normalized_items: Optional[List[Dict]] = None) -> List[Dict]:
    """
    Run all correlation rules against the normalized item set.
    Returns a sorted list of findings (CRITICAL first).
    Saves results to outputs/correlated_findings.json.
    """
    if normalized_items is None:
        norm_file = os.path.join(PROCESSED_DIR, "normalized_intel.json")
        with open(norm_file) as f:
            data = json.load(f)
        normalized_items = data["items"]

    findings = []
    for rule_fn in ALL_RULES:
        rule_findings = rule_fn(normalized_items)
        findings.extend(rule_findings)
        if rule_findings:
            print(f"[Correlator] {rule_fn.__name__}: {len(rule_findings)} finding(s)")

    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 0), reverse=True)

    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    out = os.path.join(OUTPUTS_DIR, "correlated_findings.json")
    with open(out, "w") as f:
        json.dump({
            "correlated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings": findings
        }, f, indent=2)

    print(f"[Correlator] {len(findings)} correlated findings → {out}")
    return findings


if __name__ == "__main__":
    run_correlation()
