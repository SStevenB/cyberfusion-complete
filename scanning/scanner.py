# scanning/scanner.py
#
# Lab-safe TCP port scanner. Targets localhost and Docker lab containers ONLY.
# Does NOT use nmap by default — pure Python socket scanning so it works
# anywhere without root privileges.
#
# IMPORTANT: Only ever scan hosts you own or have explicit permission to scan.
# The targets list in this file is hardcoded to localhost and lab Docker IPs.

import json
import os
import socket
from datetime import datetime, timezone
from typing import List, Dict, Any

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")

# Lab-only targets — Docker containers from docker-compose.yml
LAB_HOSTS = [
    {"hostname": "northstar-web01", "ip": "172.29.0.10"},
    {"hostname": "northstar-web02", "ip": "172.29.0.11"},
    {"hostname": "northstar-ssh01", "ip": "172.29.0.12"},
    {"hostname": "localhost",        "ip": "127.0.0.1"},
]

# Ports to check and their metadata
PORTS_TO_SCAN = [
    {"port": 22,   "service": "SSH",   "risk_level": "MEDIUM", "risk_note": "SSH remote access. Ensure key-only auth and restrict to VPN."},
    {"port": 80,   "service": "HTTP",  "risk_level": "MEDIUM", "risk_note": "Unencrypted web traffic. Should redirect to HTTPS."},
    {"port": 443,  "service": "HTTPS", "risk_level": "LOW",    "risk_note": "Encrypted web traffic. Verify TLS config and cert validity."},
    {"port": 3389, "service": "RDP",   "risk_level": "HIGH",   "risk_note": "RDP remote desktop. High-value ransomware target. Restrict aggressively."},
    {"port": 8080, "service": "HTTP-alt", "risk_level": "MEDIUM", "risk_note": "Alternate HTTP port. Often used for dev/admin interfaces."},
    {"port": 8443, "service": "HTTPS-alt", "risk_level": "MEDIUM", "risk_note": "Alternate HTTPS port."},
    {"port": 2222, "service": "SSH-alt",   "risk_level": "MEDIUM", "risk_note": "Non-standard SSH port (Docker lab mapping)."},
    {"port": 5432, "service": "PostgreSQL","risk_level": "HIGH",   "risk_note": "Database port exposed. Should never be internet-facing."},
    {"port": 3306, "service": "MySQL",     "risk_level": "HIGH",   "risk_note": "Database port exposed. Should never be internet-facing."},
    {"port": 6379, "service": "Redis",     "risk_level": "HIGH",   "risk_note": "Redis often unauthenticated. Critical exposure if reachable."},
]


def _tcp_connect(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Returns True if a TCP connection to ip:port succeeds."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_host(hostname: str, ip: str) -> Dict[str, Any]:
    """Scan a single host for open ports. Returns host result dict."""
    open_ports = []
    scanned_at = datetime.now(timezone.utc).isoformat()

    for port_info in PORTS_TO_SCAN:
        if _tcp_connect(ip, port_info["port"]):
            open_ports.append({**port_info})

    return {
        "hostname":    hostname,
        "ip":          ip,
        "scanned_at":  scanned_at,
        "total_open":  len(open_ports),
        "open_ports":  open_ports,
    }


def run_scan(use_nmap: bool = False) -> Dict[str, Any]:
    """
    Scan all lab hosts. Returns full scan results.
    use_nmap=True requires nmap installed and may need sudo on some systems.
    """
    print(f"[Scanner] Scanning {len(LAB_HOSTS)} lab host(s)...")
    results = []

    for host in LAB_HOSTS:
        print(f"[Scanner]   → {host['hostname']} ({host['ip']})")
        result = scan_host(host["hostname"], host["ip"])
        results.append(result)
        print(f"[Scanner]     {result['total_open']} open port(s)")

    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "scope":      "localhost and Docker lab containers only",
        "total_hosts": len(results),
        "hosts":      results,
    }


def save_scan_results(scan_data: Dict[str, Any]) -> str:
    os.makedirs(RAW_DIR, exist_ok=True)
    out = os.path.join(RAW_DIR, "open_ports.json")
    with open(out, "w") as f:
        json.dump(scan_data, f, indent=2)
    total_ports = sum(h["total_open"] for h in scan_data.get("hosts", []))
    print(f"[Scanner] {total_ports} open port(s) across {scan_data['total_hosts']} host(s) → {out}")
    return out


if __name__ == "__main__":
    results = run_scan()
    save_scan_results(results)
