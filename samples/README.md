# Sample Evidence Files

These files let you test and demo CyberFusion's **Upload Evidence** ingestion
without needing real exports. They all describe the fictional
`northstar-analytics.local` lab environment.

| File | Type | Demo source |
|------|------|-------------|
| `sample_nmap_scan.xml` | Nmap XML | Lab scan of the Docker test hosts (localhost/172.29.x) |
| `sample_vuln_scan.csv` | Vulnerability scanner CSV | Nessus-style export, synthetic rows referencing real CVE IDs |
| `sample_asset_inventory.csv` | Asset inventory CSV | Synthetic CMDB-style inventory with criticality tiers |
| `sample_breach_export.csv` | Breach export CSV | HaveIBeenPwned-style schema, synthetic accounts on a fictional domain |
| `sample_m365_signins.csv` | M365 / Entra sign-in CSV | Azure AD risky sign-in export schema, synthetic users |
| `sample_stix_bundle.json` | STIX 2.1 JSON | Public-format threat-intel bundle (indicator + vulnerability + threat-actor), synthetic |

## How to demo honestly

> "CyberFusion ingests authorized company exports — scan results, asset
> inventories, vulnerability exports, and exposure records. For this demo I use
> these clearly-labeled synthetic enterprise-style sample files. In real use, a
> user uploads their own authorized exports (e.g. `nmap -oX` output for a host
> they own, or a HaveIBeenPwned search for a domain they control)."

## Ethics

- All sample data is **synthetic** and describes a **fictional** organization.
- Real-world use is for **authorized targets only** — systems/domains you own or
  are permitted to assess.
- CyberFusion **never scans external infrastructure itself**. It only interprets
  evidence that a user provides.
