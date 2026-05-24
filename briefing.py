# briefing.py
#
# Generates a structured daily security briefing from current pipeline data.
#
# This module has three modes, in order of preference:
#
# Mode 1 — Ollama (free, fully local, no internet required)
#   Install: https://ollama.com → then: ollama pull llama3
#   Run:     ollama serve  (starts the local API on port 11434)
#   Cost:    Free. Runs on your Mac. No account needed.
#
# Mode 2 — Anthropic API (paid, ~$0.01 per briefing with claude-haiku)
#   Set:  ANTHROPIC_API_KEY environment variable
#   Or:   anthropic.api_key in config/config.yaml
#
# Mode 3 — Export prompt (always works, always free)
#   Exports a ready-to-paste prompt to data/outputs/briefings/prompt_export.txt
#   Paste it into Claude.ai, ChatGPT, Gemini, or any free AI chat.
#   The dashboard shows the exported prompt and lets you paste the response back in.
#
# Output: markdown saved to data/outputs/briefings/

import json
import os
from datetime import datetime, timezone
from typing import Optional, Tuple

BASE_DIR      = os.path.dirname(__file__)
RAW_DIR       = os.path.join(BASE_DIR, "data", "raw")
OUTPUTS_DIR   = os.path.join(BASE_DIR, "data", "outputs")
BRIEFINGS_DIR = os.path.join(OUTPUTS_DIR, "briefings")


def _load_context() -> dict:
    """Load all current pipeline data to build the briefing context."""

    def _read(path):
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return {}

    findings_data = _read(os.path.join(OUTPUTS_DIR, "final_risk_findings.json"))
    cve_data      = _read(os.path.join(RAW_DIR, "latest_vulnerabilities.json"))
    kev_data      = _read(os.path.join(RAW_DIR, "cisa_kev.json"))
    news_data     = _read(os.path.join(RAW_DIR, "threat_news.json"))
    scan_data     = _read(os.path.join(RAW_DIR, "open_ports.json"))
    breach_data   = _read(os.path.join(RAW_DIR, "breach_signals.json"))

    findings  = findings_data.get("findings", [])
    summary   = findings_data.get("summary", {})
    cves      = cve_data.get("cves", [])
    kev_vulns = kev_data.get("vulnerabilities", [])
    news      = news_data.get("items", [])
    hosts     = scan_data.get("hosts", [])
    breaches  = breach_data.get("breaches", [])

    kev_ids = {v.get("cveID") for v in kev_vulns}

    port_summary = []
    for host in hosts:
        ports = host.get("open_ports", [])
        if ports:
            port_list = ", ".join(f"{p['port']}/{p['service']}" for p in ports)
            port_summary.append(f"{host['hostname']} ({host['ip']}): {port_list}")

    top_cves = []
    for c in sorted(cves, key=lambda x: x.get("score") or 0, reverse=True)[:10]:
        top_cves.append({
            "id":       c["cve_id"],
            "severity": c.get("severity", "UNKNOWN"),
            "score":    c.get("score"),
            "desc":     c.get("description", "")[:200],
            "in_kev":   c["cve_id"] in kev_ids,
        })

    cutoff = datetime.now(timezone.utc).strftime("%Y-%m")
    recent_kev = [v for v in kev_vulns if v.get("dateAdded", "").startswith(cutoff)][:5]
    priority_news = [n for n in news if n.get("is_priority")][:8]

    findings_summary = []
    for f in findings[:8]:
        rec = f.get("recommendation", "")
        first_action = next((l.strip() for l in rec.split(". ") if l.strip()), "")
        findings_summary.append({
            "rule":   f.get("rule_name"),
            "risk":   f.get("risk_label"),
            "score":  f.get("risk_score"),
            "mitre":  f.get("mitre_technique", ""),
            "assets": f.get("affected_assets", []),
            "action": first_action,
        })

    return {
        "date":             datetime.now(timezone.utc).strftime("%B %d, %Y"),
        "summary":          summary,
        "total_findings":   len(findings),
        "findings_summary": findings_summary,
        "top_cves":         top_cves,
        "kev_total":        len(kev_vulns),
        "recent_kev":       recent_kev,
        "priority_news":    [{"title": n["title"], "source": n["source"]} for n in priority_news],
        "open_ports":       port_summary,
        "breach_count":     len(breaches),
        "breach_types":     list({dc for b in breaches for dc in b.get("data_classes", [])}),
    }


def _build_prompt(ctx: dict) -> str:
    """Build the briefing prompt from context data."""
    return f"""You are a senior threat intelligence analyst. Today is {ctx['date']}.
Write a daily security briefing for the leadership team at Northstar Analytics.

Use only the following live intelligence data — do not add external information:

CORRELATED FINDINGS ({ctx['total_findings']} total — Critical: {ctx['summary'].get('critical',0)}, High: {ctx['summary'].get('high',0)}, Medium: {ctx['summary'].get('medium',0)}):
{json.dumps(ctx['findings_summary'], indent=2)}

TOP CVEs THIS WEEK:
{json.dumps(ctx['top_cves'], indent=2)}

CISA KNOWN EXPLOITED VULNERABILITIES: {ctx['kev_total']} total in catalog.
Recent additions this month: {json.dumps(ctx['recent_kev'][:3], indent=2) if ctx['recent_kev'] else 'None'}

OPEN NETWORK SERVICES:
{chr(10).join(ctx['open_ports']) if ctx['open_ports'] else 'No scan data available'}

BREACH EXPOSURE: {ctx['breach_count']} signal(s) — data types: {', '.join(ctx['breach_types']) if ctx['breach_types'] else 'none'}

PRIORITY SECURITY NEWS:
{json.dumps(ctx['priority_news'], indent=2)}

---
Write the briefing using exactly these sections:

## Threat Posture — {ctx['date']}

### Overall Risk Level
One sentence stating the current risk level and the primary reason.

### What Requires Attention
2-3 bullet points on the most urgent items. Reference specific CVE IDs, finding names, or news items. Be precise.

### Active Exploitation Activity
Any CVEs confirmed as actively exploited (CISA KEV) and what an attacker would do with them in plain English.

### Exposed Services
Which ports and services are reachable, and the specific risk each one represents given current findings.

### Recommended Actions
Numbered list, highest priority first. Each action should name the specific finding, CVE, or service it addresses.

Tone: professional, direct, no jargon. Length: 400-550 words."""


def _check_ollama() -> Tuple[bool, str]:
    """Check if Ollama is running locally and which model is available."""
    try:
        import requests
        resp = requests.get("http://localhost:11434/api/tags", timeout=2)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            # Prefer llama3, mistral, phi3 in that order
            for preferred in ["llama3", "llama3.2", "mistral", "phi3", "phi"]:
                for m in models:
                    if m.startswith(preferred):
                        return True, m
            if models:
                return True, models[0]
        return False, ""
    except Exception:
        return False, ""


def _generate_via_ollama(prompt: str, model: str) -> str:
    """Call local Ollama API."""
    import requests
    resp = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": model, "prompt": prompt, "stream": False},
        timeout=120
    )
    resp.raise_for_status()
    return resp.json().get("response", "")


def _generate_via_anthropic(prompt: str, config: dict) -> str:
    """Call Anthropic API using SDK."""
    api_key = os.environ.get("ANTHROPIC_API_KEY") or config.get("anthropic", {}).get("api_key", "")
    if not api_key:
        raise ValueError("No API key")
    from anthropic import Anthropic
    client = Anthropic(api_key=api_key)
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",  # cheapest model ~$0.001 per briefing
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}]
    )
    return msg.content[0].text


def export_prompt(ctx: dict = None) -> str:
    """
    Export the briefing prompt as a plain text file.
    Returns the prompt string so it can be displayed in the dashboard.
    The user can paste this into any free AI chat to get a briefing.
    """
    if ctx is None:
        ctx = _load_context()
    prompt = _build_prompt(ctx)
    os.makedirs(BRIEFINGS_DIR, exist_ok=True)
    export_path = os.path.join(BRIEFINGS_DIR, "prompt_export.txt")
    with open(export_path, "w") as f:
        f.write(prompt)
    return prompt


def save_manual_briefing(text: str) -> str:
    """Save a briefing that was manually generated (pasted in from an external AI)."""
    os.makedirs(BRIEFINGS_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(BRIEFINGS_DIR, f"briefing_{ts}.md")
    with open(path, "w") as f:
        f.write(text)
    with open(os.path.join(BRIEFINGS_DIR, "latest.md"), "w") as f:
        f.write(text)
    print(f"[Briefing] Saved → {path}")
    return path


def generate_briefing(save: bool = True, config: dict = None) -> Tuple[str, str]:
    """
    Generate the security briefing. Tries methods in this order:
      1. Ollama (local, free) — if running
      2. Anthropic API (paid) — if API key configured
      3. Returns the prompt for manual use (always works)

    Returns: (briefing_text_or_prompt, mode_used)
      mode_used is one of: "ollama", "anthropic", "export"
    """
    if config is None:
        try:
            import yaml
            cfg_path = os.path.join(BASE_DIR, "config", "config.yaml")
            if os.path.exists(cfg_path):
                with open(cfg_path) as f:
                    config = yaml.safe_load(f) or {}
        except Exception:
            config = {}

    ctx = _load_context()
    prompt = _build_prompt(ctx)

    # Mode 1: Ollama
    ollama_available, ollama_model = _check_ollama()
    if ollama_available:
        try:
            text = _generate_via_ollama(prompt, ollama_model)
            if save and text:
                os.makedirs(BRIEFINGS_DIR, exist_ok=True)
                ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                for path in [
                    os.path.join(BRIEFINGS_DIR, f"briefing_{ts}.md"),
                    os.path.join(BRIEFINGS_DIR, "latest.md"),
                ]:
                    with open(path, "w") as f:
                        f.write(text)
            return text, f"ollama:{ollama_model}"
        except Exception as e:
            print(f"[Briefing] Ollama failed: {e}")

    # Mode 2: Anthropic API
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY") or (config or {}).get("anthropic", {}).get("api_key"))
    if has_key:
        try:
            text = _generate_via_anthropic(prompt, config or {})
            if save and text:
                os.makedirs(BRIEFINGS_DIR, exist_ok=True)
                ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                for path in [
                    os.path.join(BRIEFINGS_DIR, f"briefing_{ts}.md"),
                    os.path.join(BRIEFINGS_DIR, "latest.md"),
                ]:
                    with open(path, "w") as f:
                        f.write(text)
            return text, "anthropic"
        except Exception as e:
            print(f"[Briefing] Anthropic API failed: {e}")

    # Mode 3: Export prompt for manual use
    exported_prompt = export_prompt(ctx)
    return exported_prompt, "export"


def load_latest_briefing() -> Optional[str]:
    """Return the most recently saved briefing, or None if none exists."""
    latest = os.path.join(BRIEFINGS_DIR, "latest.md")
    if os.path.exists(latest):
        with open(latest) as f:
            return f.read()
    return None


def get_ollama_status() -> dict:
    """Return Ollama availability info for the dashboard to display."""
    available, model = _check_ollama()
    return {"available": available, "model": model}
