# ingestion/parsers/stix_parser.py
#
# Parses STIX 2.1 JSON bundles (the format OpenCTI, MISP, and ISAC feeds export)
# into normalized records. STIX is just JSON, so this is fully implemented —
# no external dependency, uses the stdlib json module.
#
# We map the most common STIX Domain Objects (SDOs) to our schema:
#   - "indicator"        → exposure record (IOC: domain/ip/hash/url pattern)
#   - "vulnerability"    → vulnerability record (often carries a CVE name)
#   - "malware"/"threat-actor"/"campaign" → exposure record (context signal)

import json
from typing import Any, Dict, List

from ingestion.schema import ParseResult, make_uploaded_item, normalize_severity_label


def detect(filename: str, text: str) -> bool:
    name = (filename or "").lower()
    head = text[:1500].lower()
    if not (name.endswith(".json") or head.lstrip().startswith("{")):
        return False
    # A STIX 2.1 bundle declares type:bundle and/or spec_version, and contains
    # "objects": [ ... ] with STIX SDOs.
    return ('"type": "bundle"' in head or '"type":"bundle"' in head
            or '"spec_version"' in head or '"objects"' in head and "stix" in head)


def _severity_from_labels(labels: List[str], confidence: int) -> str:
    lc = " ".join(labels).lower()
    if any(w in lc for w in ["critical", "high-severity", "malicious-activity"]):
        return "HIGH"
    if confidence and confidence >= 80:
        return "HIGH"
    if confidence and confidence >= 50:
        return "MEDIUM"
    return "MEDIUM"


def parse(text: str, filename: str = "") -> ParseResult:
    res = ParseResult(file_type="stix_json")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        res._fatal = True
        res.errors.append(f"Invalid JSON — could not parse STIX bundle: {e}")
        res.summary = "File is not valid JSON."
        return res

    # Accept either a full bundle or a bare list of objects.
    if isinstance(data, dict) and data.get("type") == "bundle":
        objects = data.get("objects", [])
    elif isinstance(data, dict) and "objects" in data:
        objects = data["objects"]
    elif isinstance(data, list):
        objects = data
    else:
        res._fatal = True
        res.errors.append("Not a STIX bundle — expected a 'bundle' with an 'objects' array.")
        res.summary = "Unrecognized STIX structure."
        return res

    kept = 0
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        otype = obj.get("type", "")
        labels = obj.get("labels", []) or obj.get("indicator_types", []) or []
        confidence = obj.get("confidence", 0) or 0

        if otype == "indicator":
            pattern = obj.get("pattern", "")
            name = obj.get("name", "") or pattern[:60] or "STIX indicator"
            res.records.append(make_uploaded_item(
                source="uploaded_stix",
                source_type="stix_json",
                item_type="exposure",
                title=f"Threat indicator: {name}",
                description=obj.get("description", "") or f"STIX indicator pattern: {pattern}",
                severity=_severity_from_labels(labels, confidence),
                timestamp=obj.get("valid_from", "") or obj.get("created", ""),
                entity=pattern or name,
                tags=["stix", "indicator", "uploaded"] + [str(l).lower() for l in labels[:4]],
                confidence="HIGH" if confidence >= 80 else "MEDIUM",
                filename=filename,
                extra={"pattern": pattern, "stix_id": obj.get("id", ""),
                       "indicator_types": labels, "stix_confidence": confidence},
                raw_data=obj,
            ))
            kept += 1

        elif otype == "vulnerability":
            # STIX vulnerabilities usually carry a CVE in external_references.
            cve = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name", "").lower() == "cve":
                    cve = ref.get("external_id", "")
                    break
            name = obj.get("name", "") or cve or "STIX vulnerability"
            res.records.append(make_uploaded_item(
                source="uploaded_stix",
                source_type="stix_json",
                item_type="vulnerability",
                title=cve or name,
                description=obj.get("description", "") or name,
                severity=normalize_severity_label(
                    next((l for l in labels if l), "")) or "MEDIUM",
                timestamp=obj.get("created", ""),
                entity=cve or name,
                tags=["stix", "cve", "uploaded"] if cve else ["stix", "vulnerability", "uploaded"],
                confidence="MEDIUM",
                filename=filename,
                extra={"cve": cve, "stix_id": obj.get("id", "")},
                raw_data=obj,
            ))
            kept += 1

        elif otype in ("malware", "threat-actor", "campaign", "intrusion-set"):
            name = obj.get("name", otype)
            res.records.append(make_uploaded_item(
                source="uploaded_stix",
                source_type="stix_json",
                item_type="exposure",
                title=f"{otype.replace('-', ' ').title()}: {name}",
                description=obj.get("description", "") or f"STIX {otype} object.",
                severity="MEDIUM",
                timestamp=obj.get("created", ""),
                entity=name,
                tags=["stix", otype, "uploaded"],
                confidence="MEDIUM",
                filename=filename,
                extra={"stix_id": obj.get("id", ""), "stix_type": otype},
                raw_data=obj,
            ))
            kept += 1

    if not res.records:
        res.summary = f"Parsed STIX bundle ({len(objects)} object(s)) but found no mappable indicators/vulnerabilities."
        return res
    res.summary = f"Parsed {kept} STIX object(s) into normalized signals."
    return res
