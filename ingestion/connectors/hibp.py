# ingestion/connectors/hibp.py
# HaveIBeenPwned connector — IMPLEMENTED for the free public endpoints.
#
# Two endpoints we use, both free and public:
#   GET /api/v3/breaches?domain={domain}     — known breaches AT a service domain
#     (e.g. domain=linkedin.com returns the 2012 + 2021 LinkedIn breach records).
#     No API key required for this endpoint as of HIBP v3.
#   GET /api/pwnedpasswords/range/{5char}    — k-anonymity password check (not used here).
#
# The PAID endpoints (/breacheddomain — list emails on a domain you own, stealer logs)
# require HIBP Pwned 5 ($275/year). If the user provides an api_key, we attempt the
# authenticated /breacheddomain call and use the result; if it fails we fall back to
# the free /breaches?domain= call, so the connector works with or without a key.
#
# What this produces: exposure-type records the correlator already understands.

import time
from typing import Any, Dict, List, Optional

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

from ingestion.connectors.base import BaseConnector, ConnectorResult

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
USER_AGENT = "CyberFusion-CTI/1.0 (portfolio project; contact: github.com/SStevenB)"


class HIBPConnector(BaseConnector):
    source_type = "hibp"
    label = "HaveIBeenPwned"
    STATUS = "implemented"
    config_fields = ["monitored_domain"]
    secret_fields = []   # api_key is OPTIONAL — used only for paid /breacheddomain endpoint
    optional_secret_fields = ["api_key"]

    # ── test_connection ──────────────────────────────────────────────────────
    def test_connection(self, config, secret_values):
        if not REQUESTS_OK:
            return ConnectorResult(ok=False, message="`requests` library not installed.")
        missing = self.required_present({"monitored_domain": (config or {}).get("monitored_domain")}, {})
        if missing:
            return ConnectorResult(ok=False, message=f"Missing required field(s): {', '.join(missing)}.")
        domain = (config or {}).get("monitored_domain", "")
        if "." not in domain:
            return ConnectorResult(ok=False, message="monitored_domain should look like example.com")

        # The free /breaches?domain= endpoint is the cheapest "are we reachable" test.
        try:
            r = requests.get(f"{HIBP_BASE}/breaches",
                             params={"domain": domain},
                             headers={"User-Agent": USER_AGENT},
                             timeout=10)
        except requests.RequestException as e:
            return ConnectorResult(ok=False, message=f"HIBP unreachable: {e}")

        if r.status_code == 200:
            n = len(r.json() or [])
            api_key = (secret_values or {}).get("api_key") or ""
            extra = ""
            if api_key:
                # Optionally validate the key against the subscription-status endpoint.
                try:
                    sub = requests.get(f"{HIBP_BASE}/subscription/status",
                                       headers={"hibp-api-key": api_key, "User-Agent": USER_AGENT},
                                       timeout=10)
                    if sub.status_code == 200:
                        extra = " API key valid (paid /breacheddomain endpoint available)."
                    elif sub.status_code in (401, 403):
                        extra = " ⚠ API key invalid — free endpoints still usable."
                    else:
                        extra = f" (subscription check returned {sub.status_code})"
                except requests.RequestException:
                    extra = " (subscription check failed — free endpoints still work)"
            return ConnectorResult(
                ok=True,
                message=f"Connected. HIBP knows of {n} breach(es) involving {domain}.{extra}")
        if r.status_code == 404:
            return ConnectorResult(ok=True, message=f"Connected. HIBP has no known breaches for {domain}.")
        if r.status_code == 429:
            return ConnectorResult(ok=False, message="HIBP rate-limit hit. Wait a few seconds and retry.")
        return ConnectorResult(ok=False, message=f"HIBP returned HTTP {r.status_code}.")

    # ── fetch (real records) ─────────────────────────────────────────────────
    def fetch(self, config, secret_values):
        if not REQUESTS_OK:
            return ConnectorResult(ok=False, message="`requests` library not installed.")
        domain = (config or {}).get("monitored_domain", "")
        if "." not in domain:
            return ConnectorResult(ok=False, message="monitored_domain should look like example.com")
        api_key = (secret_values or {}).get("api_key") or ""

        # If the user has a paid API key, try the authenticated /breacheddomain
        # endpoint first (lists addresses on a domain you own).
        records: List[Dict[str, Any]] = []
        used_endpoint = "free:/breaches?domain="
        breached_domain_count = None

        if api_key:
            try:
                r = requests.get(f"{HIBP_BASE}/breacheddomain/{domain}",
                                 headers={"hibp-api-key": api_key, "User-Agent": USER_AGENT},
                                 timeout=15)
                if r.status_code == 200:
                    # paid response: {"alice": ["LinkedIn"], "bob": ["Adobe","LinkedIn"]}
                    body = r.json() or {}
                    breached_domain_count = sum(len(v) for v in body.values())
                    for local_part, breach_names in body.items():
                        for bname in breach_names:
                            records.append(_to_record(
                                title=f"{local_part}@{domain} appeared in '{bname}' breach",
                                description=f"HIBP /breacheddomain: account {local_part}@{domain} "
                                            f"was exposed in the {bname} breach.",
                                severity="HIGH",
                                source="hibp_breacheddomain",
                                domain=domain,
                                tags=["hibp", "breach", "credential_exposure"],
                                extra={"email": f"{local_part}@{domain}", "breach_name": bname}))
                    used_endpoint = "paid:/breacheddomain"
                elif r.status_code in (401, 403):
                    pass  # fall through to free endpoint
            except requests.RequestException:
                pass  # fall through

        # Free endpoint (always run as a baseline — lists breaches AT this domain)
        try:
            r2 = requests.get(f"{HIBP_BASE}/breaches",
                              params={"domain": domain},
                              headers={"User-Agent": USER_AGENT},
                              timeout=15)
        except requests.RequestException as e:
            return ConnectorResult(ok=False, message=f"HIBP unreachable: {e}",
                                   records=records, records_meta={"endpoint": used_endpoint})

        if r2.status_code == 200:
            for b in r2.json() or []:
                pwn_count = b.get("PwnCount", 0)
                severity = "HIGH" if pwn_count >= 1_000_000 else "MEDIUM" if pwn_count >= 10_000 else "LOW"
                records.append(_to_record(
                    title=f"{b.get('Name','Unknown')} breach affected {domain}",
                    description=(f"{b.get('Title', b.get('Name',''))} ({b.get('BreachDate','unknown date')}) — "
                                 f"{pwn_count:,} accounts exposed. "
                                 f"Data classes: {', '.join(b.get('DataClasses', []) or [])[:200]}"),
                    severity=severity,
                    source="hibp_breaches",
                    domain=domain,
                    tags=["hibp", "breach"] + ([t for t in ["verified"] if b.get("IsVerified")]),
                    extra={
                        "breach_name": b.get("Name"),
                        "breach_date": b.get("BreachDate"),
                        "pwn_count": pwn_count,
                        "data_classes": b.get("DataClasses", []),
                        "is_verified": b.get("IsVerified"),
                        "is_sensitive": b.get("IsSensitive"),
                    }))
        elif r2.status_code == 404:
            pass  # no breaches for this domain
        elif r2.status_code == 429:
            return ConnectorResult(ok=False, message="HIBP rate-limit hit. Wait and retry.",
                                   records=records, records_meta={"endpoint": used_endpoint})
        else:
            return ConnectorResult(ok=False, message=f"HIBP returned HTTP {r2.status_code}.",
                                   records=records, records_meta={"endpoint": used_endpoint})

        return ConnectorResult(
            ok=True,
            message=(f"Pulled {len(records)} HIBP record(s) for {domain} "
                     f"(via {used_endpoint})."),
            records=records,
            records_meta={"endpoint": used_endpoint, "domain": domain,
                          "breached_domain_count": breached_domain_count})


def _to_record(title: str, description: str, severity: str, source: str,
               domain: str, tags: List[str], extra: Dict[str, Any]) -> Dict[str, Any]:
    """Map a HIBP API response to the normalized 'exposure' record shape the
    correlator already understands. Mirrors what the hibp_csv parser produces."""
    return {
        "type": "exposure",
        "title": title,
        "description": description,
        "severity": severity,
        "asset": domain,
        "source": source,
        "tags": tags,
        "extra": extra,
        "ingested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
