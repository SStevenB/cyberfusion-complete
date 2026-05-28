# ingestion/parsers/vuln_csv_parser.py
#
# Parses vulnerability-scanner CSV exports (Nessus / Tenable / Qualys / OpenVAS
# style) into `vulnerability` records. These feed CORR-004 (web CVE + exposed
# web service) and CORR-006 (KEV CVE + open service).
#
# Scanner CSVs vary in column names, so we match flexibly on lowercased header
# aliases rather than requiring an exact schema.

import csv
import io
from typing import Dict, List, Optional

from ingestion.schema import (ParseResult, make_uploaded_item,
                              severity_from_cvss, normalize_severity_label)

# Header aliases → canonical field. Lowercased, stripped on lookup.
COLUMN_ALIASES = {
    "cve":        ["cve", "cve id", "cve_id", "cves"],
    "name":       ["name", "plugin name", "vulnerability", "title", "synopsis"],
    "severity":   ["severity", "risk", "risk factor", "threat"],
    "cvss":       ["cvss", "cvss score", "cvss3 base score", "cvss v3.0 base score",
                   "cvss_base_score", "cvss3_base_score"],
    "host":       ["host", "asset", "ip", "ip address", "dns name", "hostname", "target"],
    "description":["description", "synopsis", "summary"],
    "solution":   ["solution", "remediation", "fix"],
}


def detect(filename: str, text: str) -> bool:
    name = (filename or "").lower()
    if not (name.endswith(".csv") or "," in text[:2000]):
        return False
    head = text[:2000].lower()
    # Must look like a vuln scanner export: has a CVE or plugin/severity column.
    has_vuln_signal = any(k in head for k in
                          ["cve", "plugin", "cvss", "risk factor", "vulnerability"])
    has_host = any(k in head for k in ["host", "ip", "asset", "dns name"])
    return has_vuln_signal and has_host


def _build_index(header: List[str]) -> Dict[str, int]:
    idx = {}
    low = [h.strip().lower() for h in header]
    for canonical, aliases in COLUMN_ALIASES.items():
        for a in aliases:
            if a in low:
                idx[canonical] = low.index(a)
                break
    return idx


def parse(text: str, filename: str = "") -> ParseResult:
    res = ParseResult(file_type="vuln_csv")
    try:
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
    except Exception as e:
        res._fatal = True
        res.errors.append(f"Could not read CSV: {e}")
        res.summary = "Failed to parse CSV."
        return res

    if not rows:
        res._fatal = True
        res.errors.append("CSV is empty.")
        res.summary = "Empty file."
        return res

    header, data_rows = rows[0], rows[1:]
    idx = _build_index(header)

    if "severity" not in idx and "cvss" not in idx and "cve" not in idx:
        res._fatal = True
        res.errors.append(
            "Could not find a CVE, severity, or CVSS column. "
            f"Headers seen: {', '.join(header[:12])}"
        )
        res.summary = "Unrecognized vulnerability CSV schema."
        return res

    def cell(row, key):
        i = idx.get(key)
        return row[i].strip() if i is not None and i < len(row) else ""

    kept = 0
    for n, row in enumerate(data_rows, start=2):
        if not any(c.strip() for c in row):
            continue
        cve = cell(row, "cve")
        name = cell(row, "name") or cve or "Unnamed finding"
        host = cell(row, "host")
        sev_raw = cell(row, "severity")
        cvss_raw = cell(row, "cvss")

        # Prefer explicit severity, else derive from CVSS.
        severity = normalize_severity_label(sev_raw)
        if severity == "UNKNOWN" and cvss_raw:
            try:
                severity = severity_from_cvss(float(cvss_raw))
            except ValueError:
                pass

        # Skip pure-informational rows with no CVE and LOW/UNKNOWN severity to
        # avoid flooding the pipeline.
        if not cve and severity in ("UNKNOWN", "LOW"):
            continue

        desc = cell(row, "description") or name
        tags = ["cve", "uploaded", "vuln_scan"]
        # Web-related tag so CORR-004 can match it.
        if any(w in (name + desc).lower() for w in
               ["http", "apache", "nginx", "web", "ssl", "tls", "iis"]):
            tags.append("web")

        kept += 1
        res.records.append(make_uploaded_item(
            source="uploaded_vuln_scan",
            source_type="vuln_csv",
            item_type="vulnerability",
            title=cve or name,
            description=desc,
            severity=severity,
            asset=host or None,
            entity=cve or name,
            tags=tags,
            confidence="HIGH",
            filename=filename,
            extra={"cve": cve, "cvss": cvss_raw, "scanner_name": name,
                   "solution": cell(row, "solution")},
            raw_data={k: cell(row, k) for k in idx},
        ))

    if not res.records:
        res.summary = f"Parsed {len(data_rows)} row(s) but none were actionable vulnerabilities."
        return res
    res.summary = f"Parsed {kept} vulnerability finding(s) from scanner CSV."
    return res
