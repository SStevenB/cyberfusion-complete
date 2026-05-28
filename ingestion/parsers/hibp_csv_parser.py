# ingestion/parsers/hibp_csv_parser.py
#
# Parses a HaveIBeenPwned domain-search CSV export (the kind you can download
# for a domain you own/verify) into `breach` records. These feed CORR-005
# (corporate emails in breach data), CORR-007 (password breach + login service)
# and CORR-008 (multiple breach signals).
#
# Typical columns: Email/Alias, Breach Name, Domain, Breach Date, Data Classes,
# Pwn Count. We match flexibly.

import csv
import io
from typing import Dict, List

from ingestion.schema import ParseResult, make_uploaded_item

COLUMN_ALIASES = {
    "email":       ["email", "alias", "account", "email address"],
    "breach_name": ["breach", "breach name", "name", "title"],
    "domain":      ["domain", "breach domain", "site"],
    "date":        ["breach date", "date", "added date"],
    "classes":     ["data classes", "dataclasses", "compromised data", "exposed data"],
    "pwn_count":   ["pwn count", "pwncount", "accounts", "affected"],
}

# Data classes that escalate severity.
PASSWORD_CLASSES = {"passwords", "password", "password hashes"}
SENSITIVE_CLASSES = {"credit cards", "bank account numbers", "social security numbers"}


def detect(filename: str, text: str) -> bool:
    name = (filename or "").lower()
    if not (name.endswith(".csv") or "," in text[:1000]):
        return False
    head = text[:1500].lower()
    has_breach = any(k in head for k in ["breach", "pwn", "data classes", "compromised data"])
    # Distinguish from vuln CSV.
    looks_like_vuln = any(k in head for k in ["cve", "cvss", "plugin"])
    return has_breach and not looks_like_vuln


def _build_index(header: List[str]) -> Dict[str, int]:
    idx, low = {}, [h.strip().lower() for h in header]
    for canon, aliases in COLUMN_ALIASES.items():
        for a in aliases:
            if a in low:
                idx[canon] = low.index(a)
                break
    return idx


def _severity_for_classes(classes: List[str]) -> str:
    lc = {c.strip().lower() for c in classes}
    if lc & SENSITIVE_CLASSES or lc & PASSWORD_CLASSES:
        return "CRITICAL" if lc & SENSITIVE_CLASSES else "HIGH"
    if "email addresses" in lc:
        return "MEDIUM"
    return "MEDIUM"


def parse(text: str, filename: str = "") -> ParseResult:
    res = ParseResult(file_type="hibp_csv")
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
    if "breach_name" not in idx and "classes" not in idx:
        res._fatal = True
        res.errors.append(
            f"No breach-name or data-classes column found. Headers: {', '.join(header[:12])}")
        res.summary = "Unrecognized breach export schema."
        return res

    def cell(row, key):
        i = idx.get(key)
        return row[i].strip() if i is not None and i < len(row) else ""

    # Aggregate emails per breach so CORR-005 sees affected addresses.
    for row in data_rows:
        if not any(c.strip() for c in row):
            continue
        breach_name = cell(row, "breach_name") or "Unnamed breach"
        domain = cell(row, "domain")
        email = cell(row, "email")
        classes_raw = cell(row, "classes")
        classes = [c.strip() for c in classes_raw.replace(";", ",").split(",") if c.strip()]
        severity = _severity_for_classes(classes)

        tags = ["breach", "uploaded"] + [c.lower().replace(" ", "_") for c in classes]
        if {c.lower() for c in classes} & PASSWORD_CLASSES:
            tags.append("passwords")

        emails_found = [email] if email and "@" in email else []

        # Coerce pwn_count to int — the correlator sums these numerically.
        pwn_raw = cell(row, "pwn_count").replace(",", "").strip()
        try:
            pwn_count = int(pwn_raw) if pwn_raw else 0
        except ValueError:
            pwn_count = 0

        res.records.append(make_uploaded_item(
            source="uploaded_breach_export",
            source_type="hibp_csv",
            item_type="breach",
            title=f"Breach: {breach_name}" + (f" ({domain})" if domain else ""),
            description=(f"Breach '{breach_name}' exposed data classes: "
                         f"{', '.join(classes) or 'unspecified'}."),
            severity=severity,
            timestamp=cell(row, "date"),
            asset=domain or None,
            entity=email or domain or breach_name,
            tags=tags,
            confidence="HIGH",
            filename=filename,
            extra={"breach_name": breach_name, "domain": domain,
                   "data_classes": classes, "emails_found": emails_found,
                   "pwn_count": pwn_count},
            raw_data={k: cell(row, k) for k in idx},
        ))

    if not res.records:
        res.summary = "No breach rows parsed."
        return res
    res.summary = f"Parsed {len(res.records)} breach record(s) from export."
    return res
