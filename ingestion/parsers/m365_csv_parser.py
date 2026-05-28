# ingestion/parsers/m365_csv_parser.py
#
# Parses a Microsoft 365 / Azure AD (Entra ID) "risky sign-ins" CSV export into
# exposure records. This is the manual-upload path; a live Microsoft Graph
# connector is scaffolded separately (ingestion/connectors/) for a future phase.
#
# Entra exports vary, so we match flexibly on common column names:
#   User / UserPrincipalName, Risk level / riskLevel, Risk state, IP address,
#   Location, Sign-in time / Date (UTC), Status.

import csv
import io
from typing import Dict, List

from ingestion.schema import ParseResult, make_uploaded_item, normalize_severity_label

COLUMN_ALIASES = {
    "user":       ["user", "username", "userprincipalname", "user principal name", "display name"],
    "risk_level": ["risk level", "risklevel", "risk", "sign-in risk", "signin risk"],
    "risk_state": ["risk state", "riskstate", "state"],
    "ip":         ["ip address", "ip", "ipaddress"],
    "location":   ["location", "city", "country/region", "country"],
    "time":       ["sign-in time", "date (utc)", "date", "signin time", "timestamp"],
    "status":     ["status", "sign-in status", "result"],
}


def detect(filename: str, text: str) -> bool:
    name = (filename or "").lower()
    if not (name.endswith(".csv") or "," in text[:1000]):
        return False
    head = text[:1500].lower()
    # Entra risky sign-in exports mention risk + a user/principal column.
    has_risk = any(k in head for k in ["risk level", "risklevel", "risk state", "sign-in risk"])
    has_user = any(k in head for k in ["userprincipalname", "user principal", "username", "user"])
    looks_like_other = any(k in head for k in ["cve", "cvss", "plugin", "breach", "pwn"])
    return has_risk and has_user and not looks_like_other


def _build_index(header: List[str]) -> Dict[str, int]:
    idx, low = {}, [h.strip().lower() for h in header]
    for canon, aliases in COLUMN_ALIASES.items():
        for a in aliases:
            if a in low:
                idx[canon] = low.index(a)
                break
    return idx


def parse(text: str, filename: str = "") -> ParseResult:
    res = ParseResult(file_type="m365_csv")
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except Exception as e:
        res._fatal = True
        res.errors.append(f"Could not read CSV: {e}")
        return res
    if not rows:
        res._fatal = True
        res.errors.append("CSV is empty.")
        return res

    header, data_rows = rows[0], rows[1:]
    idx = _build_index(header)
    if "user" not in idx or "risk_level" not in idx:
        res._fatal = True
        res.errors.append(
            "Could not find user and risk-level columns. "
            f"Headers seen: {', '.join(header[:12])}")
        res.summary = "Unrecognized Entra/M365 sign-in export schema."
        return res

    def cell(row, key):
        i = idx.get(key)
        return row[i].strip() if i is not None and i < len(row) else ""

    kept = 0
    for row in data_rows:
        if not any(c.strip() for c in row):
            continue
        user = cell(row, "user")
        risk = cell(row, "risk_level")
        sev = normalize_severity_label(risk)
        if sev == "UNKNOWN":
            # Map Entra's "none/low/medium/high" if alias missed it.
            sev = {"none": "LOW"}.get(risk.lower(), "MEDIUM")
        # Only keep elevated-risk sign-ins; ignore "none".
        if risk.lower() in ("none", "") and sev == "LOW":
            continue

        ip = cell(row, "ip")
        loc = cell(row, "location")
        tags = ["m365", "identity", "risky_signin", "uploaded"]
        # Tag for correlation with remote-access exposure.
        if sev in ("HIGH", "CRITICAL"):
            tags.append("remote_access")

        kept += 1
        res.records.append(make_uploaded_item(
            source="uploaded_m365_signin",
            source_type="m365_csv",
            item_type="exposure",
            title=f"Risky sign-in: {user} ({risk} risk)",
            description=(f"Azure AD/Entra flagged a {risk}-risk sign-in for {user}"
                         + (f" from {loc}" if loc else "")
                         + (f" (IP {ip})" if ip else "") + "."),
            severity=sev,
            timestamp=cell(row, "time"),
            entity=user,
            tags=tags,
            confidence="MEDIUM",
            filename=filename,
            extra={"user": user, "risk_level": risk, "risk_state": cell(row, "risk_state"),
                   "ip": ip, "location": loc, "status": cell(row, "status"),
                   "emails_found": [user] if "@" in user else []},
            raw_data={k: cell(row, k) for k in idx},
        ))

    if not res.records:
        res.summary = f"Parsed {len(data_rows)} row(s) but none were elevated-risk sign-ins."
        return res
    res.summary = f"Parsed {kept} risky sign-in(s) from M365/Entra export."
    return res
