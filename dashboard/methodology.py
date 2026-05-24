# dashboard/methodology.py
#
# Structured documentation for every correlation rule + every data source.
# This is what powers the Finding Detail page — turns opaque rule IDs into
# auditable, explainable security findings.
#
# Beginner note: each entry below is just a Python dictionary with strings.
# The detail page reads from these dicts to render the explanation. To add
# documentation for a new rule, just add a new entry to RULE_DOCS.

# ══════════════════════════════════════════════════════════════════════════════
# DATA SOURCES — provenance for every external feed CyberFusion pulls
# ══════════════════════════════════════════════════════════════════════════════
DATA_SOURCES = {
    "NVD": {
        "name":        "NIST National Vulnerability Database",
        "url":         "https://nvd.nist.gov/developers/vulnerabilities",
        "type":        "Public API (no auth required)",
        "license":     "Public domain (U.S. Government)",
        "description": "Authoritative U.S. government database of every publicly known software vulnerability. Each entry has a CVE ID, CVSS severity score, and a description of the affected software.",
        "refresh":     "Pulled on every pipeline run (last 7 days)",
    },
    "CISA_KEV": {
        "name":        "CISA Known Exploited Vulnerabilities Catalog",
        "url":         "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "type":        "Public JSON feed (no auth required)",
        "license":     "Public domain (U.S. Government)",
        "description": "CISA's authoritative list of CVEs that have been confirmed as actively exploited in real attacks. Federal agencies are required to remediate KEV entries within 2–3 weeks.",
        "refresh":     "Full catalog downloaded on every pipeline run",
    },
    "HaveIBeenPwned": {
        "name":        "HaveIBeenPwned (HIBP)",
        "url":         "https://haveibeenpwned.com/API/v3",
        "type":        "Public API (free key required for domain queries)",
        "license":     "Used per HIBP Terms of Service",
        "description": "Public service maintained by Troy Hunt. Tells you whether email addresses or domains have appeared in published breach datasets. Returns breach metadata only — never actual passwords or PII.",
        "refresh":     "Queried per configured monitored domain",
    },
    "Shodan_InternetDB": {
        "name":        "Shodan InternetDB",
        "url":         "https://internetdb.shodan.io/",
        "type":        "Public API (no auth required)",
        "license":     "Used per Shodan Terms of Service",
        "description": "Free Shodan endpoint that returns known open ports, software (CPEs), associated CVEs, and hostnames for any public IP address. Skipped for private/RFC1918 addresses.",
        "refresh":     "Queried per IP discovered by lab port scanner",
    },
    "GreyNoise": {
        "name":        "GreyNoise Community API",
        "url":         "https://docs.greynoise.io/reference/get_v3-community-ip",
        "type":        "Public API (free community key required)",
        "license":     "Used per GreyNoise Terms of Service",
        "description": "GreyNoise classifies IPs as benign (known scanners), malicious (observed attackers), or unknown. Used to enrich scan results with real-world reputation context.",
        "refresh":     "Queried per IP discovered by lab port scanner",
    },
    "RSS_Feeds": {
        "name":        "Security News RSS Feeds",
        "url":         "https://feeds.feedburner.com/TheHackersNews",
        "type":        "Public RSS feeds",
        "license":     "Public news content",
        "description": "Aggregates from The Hacker News, BleepingComputer, Krebs on Security, Dark Reading, and SecurityWeek. Used for situational awareness and to flag priority items based on keyword matching.",
        "refresh":     "Pulled on every pipeline run",
    },
    "Lab_Scanner": {
        "name":        "CyberFusion Lab Port Scanner",
        "url":         "internal — scanning/scanner.py",
        "type":        "Internal — TCP socket scan of localhost + Docker lab containers only",
        "license":     "Lab-safe by design",
        "description": "Pure-Python TCP scanner that probes a fixed set of ports against pre-defined lab targets (localhost + 172.29.0.0/24 Docker subnet). Never targets external systems.",
        "refresh":     "Runs on every pipeline execution unless --no-scan flag set",
    },
    "Synthetic": {
        "name":        "Synthetic Lab Data",
        "url":         "internal — data_collection/exposure_simulator.py",
        "type":        "Generated locally for demo/lab",
        "license":     "N/A — fictional data",
        "description": "Realistic synthetic exposure signals generated locally when no breach API key is configured. Every record is clearly tagged as synthetic in both code and UI.",
        "refresh":     "Generated each pipeline run",
    },
}

# ══════════════════════════════════════════════════════════════════════════════
# RULE DOCS — full documentation for every correlation rule
# ══════════════════════════════════════════════════════════════════════════════
# Each rule maps the same fields the Finding Detail page renders:
#   purpose, data_sources, detection_logic, why_it_matters, false_positives
#
# When you add a new correlation rule in analysis/correlator.py, add a matching
# entry here so the detail page can explain it. If a rule has no entry,
# the detail page will fall back to the base finding fields.

RULE_DOCS = {
    "CORR-001": {
        "purpose": (
            "Detect when an organization's RDP infrastructure is both publicly reachable "
            "and referenced in external exposure data — a combination that strongly suggests "
            "credential-based intrusion risk."
        ),
        "data_sources": ["Lab_Scanner", "Synthetic", "HaveIBeenPwned"],
        "detection_logic": (
            "Triggers when: (1) port 3389 is observed open on any monitored host AND "
            "(2) any normalized exposure or breach item is tagged with 'rdp' or 'remote_access'. "
            "Both conditions must be present in the same pipeline run."
        ),
        "why_it_matters": (
            "RDP is consistently the leading initial-access vector in ransomware campaigns "
            "(Microsoft DART, Sophos State of Ransomware reports). When RDP is exposed AND "
            "matching credential leaks exist, attacker effort drops to near-zero."
        ),
        "false_positives": (
            "May fire if RDP is intentionally exposed behind MFA/jump-host controls AND "
            "unrelated RDP credentials surface in breach data. Validate with authentication logs."
        ),
    },
    "CORR-002": {
        "purpose": (
            "Detect when SSH services are reachable AND external signals reference SSH "
            "credentials or key material for the organization."
        ),
        "data_sources": ["Lab_Scanner", "Synthetic", "HaveIBeenPwned"],
        "detection_logic": (
            "Triggers when: (1) port 22 is open on any host AND (2) any normalized "
            "exposure or breach item is tagged with 'ssh'. SSH key compromise enables "
            "passwordless authentication, which makes this combination especially severe."
        ),
        "why_it_matters": (
            "Stolen SSH keys grant durable, passwordless access. Unlike password compromise, "
            "key compromise often persists because keys are rarely rotated and are not "
            "subject to MFA challenges."
        ),
        "false_positives": (
            "May fire if SSH is locked down with key-only auth + bastion controls and the "
            "leaked credentials are stale. Audit ~/.ssh/authorized_keys to confirm."
        ),
    },
    "CORR-003": {
        "purpose": (
            "Detect VPN credential exposure — the highest-impact initial access vector "
            "because VPN auth grants trusted-network status."
        ),
        "data_sources": ["Synthetic", "HaveIBeenPwned"],
        "detection_logic": (
            "Triggers on any normalized exposure or breach item tagged with 'vpn' OR "
            "containing 'vpn' in title/description text. Single-source signal — but the "
            "asset class makes this CRITICAL by default."
        ),
        "why_it_matters": (
            "VPN access bypasses every perimeter control. Once authenticated, an attacker is "
            "treated as an internal user with full Layer-3 access to the network. Recent "
            "examples: Colonial Pipeline (2021), Cisco (2022), LastPass (2022)."
        ),
        "false_positives": (
            "Generic password reuse incidents may surface VPN credentials that have already "
            "been rotated. Always cross-check against VPN authentication logs for the past 30 days."
        ),
    },
    "CORR-004": {
        "purpose": (
            "Identify exploitable web infrastructure — when web-relevant CVEs exist alongside "
            "open web ports on monitored hosts."
        ),
        "data_sources": ["NVD", "CISA_KEV", "Lab_Scanner"],
        "detection_logic": (
            "Triggers when: (1) one or more CRITICAL/HIGH CVEs in the current feed mention "
            "'http', 'apache', 'nginx', 'web', 'ssl', or 'tls' AND (2) any web port "
            "(80/443/8080/8443) is observed open. Severity escalates to CRITICAL if any "
            "matching CVE is also in the CISA KEV catalog."
        ),
        "why_it_matters": (
            "Public-facing web applications are MITRE ATT&CK technique T1190 (Exploit Public-Facing "
            "Application) — the leading initial access vector for state-aligned threat actors per "
            "Mandiant M-Trends 2024."
        ),
        "false_positives": (
            "Without software-version inventory, this rule cannot confirm the web server is "
            "running an affected version. Requires manual verification against vendor advisories."
        ),
    },
    "CORR-005": {
        "purpose": (
            "Identify corporate email addresses surfaced in breach data — high-value targets "
            "for spear phishing, credential stuffing, and social engineering."
        ),
        "data_sources": ["HaveIBeenPwned", "Synthetic"],
        "detection_logic": (
            "Triggers when any normalized breach/exposure item contains one or more email "
            "addresses in its 'emails_found' field. Aggregates unique addresses across all "
            "matching items."
        ),
        "why_it_matters": (
            "MITRE ATT&CK T1589.002 — adversaries collect email addresses during reconnaissance "
            "to enable phishing, BEC, and credential stuffing. Once published in a breach, "
            "an address remains a valid attack target indefinitely."
        ),
        "false_positives": (
            "Includes role-based addresses (info@, admin@) which may already have aggressive "
            "filtering applied. Treat individual mailboxes as higher priority."
        ),
    },
    "CORR-006": {
        "purpose": (
            "Surface CVEs confirmed as actively exploited in the wild (CISA KEV) AND "
            "linked to running services on monitored hosts."
        ),
        "data_sources": ["NVD", "CISA_KEV", "Lab_Scanner"],
        "detection_logic": (
            "Triggers when: (1) one or more CVEs from the current NVD feed are present in "
            "the CISA KEV catalog AND (2) any service is observed open on any host. "
            "KEV entries reflect confirmed exploitation, not theoretical risk."
        ),
        "why_it_matters": (
            "CISA KEV is the single highest-priority signal in vulnerability management. "
            "If a CVE is in KEV, threat actors are exploiting it right now. Federal agencies "
            "are mandated to remediate within 2-3 weeks under BOD 22-01."
        ),
        "false_positives": (
            "This rule does not perform per-host software-version matching. A KEV CVE in the "
            "feed does not guarantee the monitored host is running the affected version. "
            "Use as a prioritization signal, not a definitive vulnerability assessment."
        ),
    },
    "CORR-007": {
        "purpose": (
            "Detect the credential stuffing prerequisite condition: passwords leaked in "
            "breaches AND login-facing services exposed to attackers."
        ),
        "data_sources": ["HaveIBeenPwned", "Synthetic", "Lab_Scanner"],
        "detection_logic": (
            "Triggers when: (1) one or more breach items are tagged with 'passwords' AND "
            "(2) any login-facing service (SSH/22, RDP/3389, HTTP/80, HTTPS/443, alt-HTTP/8080) "
            "is observed open. Aggregates total affected account count across all matching breaches."
        ),
        "why_it_matters": (
            "MITRE ATT&CK T1110.004 — credential stuffing is mathematically inevitable when "
            "passwords are reused across services. Industry data shows ~65% password reuse "
            "rates, meaning leaked credentials are often valid against the victim organization."
        ),
        "false_positives": (
            "If MFA is enforced on all login services, stuffing attempts will fail. Validate "
            "MFA coverage before treating this as a confirmed risk."
        ),
    },
    "CORR-008": {
        "purpose": (
            "Detect sustained adversary interest by counting the number of independent "
            "breach/exposure signals affecting the same organization."
        ),
        "data_sources": ["HaveIBeenPwned", "Synthetic"],
        "detection_logic": (
            "Triggers when 3 or more independent breach or exposure items are observed in "
            "the same pipeline run. Multiple sources converging on the same target indicates "
            "either repeat compromise or sustained reconnaissance."
        ),
        "why_it_matters": (
            "MITRE ATT&CK T1594 — adversaries perform persistent reconnaissance against "
            "high-value targets. Multiple breach signals over time often precede targeted "
            "intrusion campaigns."
        ),
        "false_positives": (
            "Large organizations may surface multiple unrelated breach signals organically. "
            "The rule does not distinguish between coordinated and coincidental exposure."
        ),
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# Helper functions used by the Finding Detail page
# ══════════════════════════════════════════════════════════════════════════════

def get_rule_docs(rule_id: str) -> dict:
    """Return the documentation entry for a rule, or empty dict if not documented."""
    return RULE_DOCS.get(rule_id, {})


def get_data_source(source_key: str) -> dict:
    """Return the metadata for a data source, or a fallback if unknown."""
    return DATA_SOURCES.get(source_key, {
        "name": source_key,
        "url": "",
        "type": "Unknown source",
        "license": "Unknown",
        "description": "Source documentation pending.",
        "refresh": "Unknown",
    })
