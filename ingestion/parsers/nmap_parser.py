# ingestion/parsers/nmap_parser.py
#
# Parses nmap XML output (`nmap -oX scan.xml <authorized-target>`) into
# scan_finding records — the same type the lab scanner produces, so uploaded
# scans feed straight into the port-based correlation rules (CORR-001/002/004/
# 006/007).
#
# We use Python's built-in xml.etree (no extra dependency). One record is
# emitted per open port per host.

import xml.etree.ElementTree as ET
from typing import Optional

from ingestion.schema import ParseResult, make_uploaded_item

# Ports we treat as elevated risk when found open (drives the severity hint).
HIGH_RISK_PORTS = {3389: "RDP", 23: "Telnet", 445: "SMB", 135: "RPC", 21: "FTP"}
MED_RISK_PORTS = {22: "SSH", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
                  6379: "Redis", 27017: "MongoDB"}


def detect(filename: str, text: str) -> bool:
    name = (filename or "").lower()
    head = text[:600].lower()
    return (name.endswith(".xml") and ("nmaprun" in head or "<nmap" in head)) or "<nmaprun" in head


def _risk_for_port(port: int) -> str:
    if port in HIGH_RISK_PORTS:
        return "HIGH"
    if port in MED_RISK_PORTS:
        return "MEDIUM"
    return "LOW"


def parse(text: str, filename: str = "") -> ParseResult:
    res = ParseResult(file_type="nmap_xml")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        res._fatal = True
        res.errors.append(f"Invalid XML — could not parse nmap output: {e}")
        res.summary = "Failed to parse: file is not valid XML."
        return res

    if root.tag != "nmaprun":
        res._fatal = True
        res.errors.append("Root element is not <nmaprun> — this does not look like nmap XML output.")
        res.summary = "Not an nmap XML file."
        return res

    hosts_seen = 0
    open_ports = 0
    for host in root.findall("host"):
        # Resolve a hostname/IP for the asset field.
        addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else ""
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        asset = hostname or ip or "unknown-host"

        scanned_at = ""  # nmap host has @starttime epoch; keep simple/optional

        ports_el = host.find("ports")
        if ports_el is None:
            continue
        hosts_seen += 1

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            try:
                portnum = int(port_el.get("portid"))
            except (TypeError, ValueError):
                res.errors.append(f"Skipped a port with invalid portid on {asset}.")
                continue
            proto = port_el.get("protocol", "tcp")
            svc_el = port_el.find("service")
            service = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""

            risk = _risk_for_port(portnum)
            svc_label = HIGH_RISK_PORTS.get(portnum) or MED_RISK_PORTS.get(portnum) or service
            note_bits = [f"{svc_label} exposed on port {portnum}/{proto}."]
            if product:
                note_bits.append(f"Service banner: {product} {version}".strip())
            risk_note = " ".join(note_bits)

            open_ports += 1
            res.records.append(make_uploaded_item(
                source="uploaded_nmap_scan",
                source_type="nmap",
                item_type="scan_finding",
                # Title format mirrors the lab scanner so existing rules match
                # (they look for substrings like "22/" and "3389").
                title=f"Open port {portnum}/{service} on {asset}",
                description=risk_note,
                severity=risk,
                timestamp=scanned_at,
                asset=asset,
                entity=asset,
                tags=["open_port", service.lower(), "uploaded"],
                confidence="HIGH",
                filename=filename,
                extra={
                    "port": portnum, "service": service, "protocol": proto,
                    "ip": ip, "product": product, "version": version,
                },
                raw_data={"hostname": asset, "ip": ip, "port": portnum,
                          "service": service, "product": product, "version": version},
            ))

    if not res.records:
        res.summary = f"Parsed nmap XML but found no open ports across {hosts_seen} host(s)."
        return res

    res.summary = f"Parsed {open_ports} open port(s) across {hosts_seen} host(s) from nmap scan."
    return res
