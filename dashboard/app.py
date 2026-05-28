# dashboard/app.py  — CyberFusion CTI Platform
# Pages:
#   1. Executive View       — KPIs, risk distribution, delta alerts
#   2. Threat Feed          — CVEs, KEV catalog, security news
#   3. Exposure & Breach    — Ports, breach signals, IP reputation
#   4. Correlated Findings  — Full analysis + status tracking + PDF export
#   5. AI Briefing          — Live AI-generated CISO briefing from real data
#   6. Architecture         — How it works

import streamlit as st
import json, os, sys
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(
    page_title="CyberFusion — CTI Platform",
    page_icon="🛡️", layout="wide",
    initial_sidebar_state="expanded"
)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW  = os.path.join(BASE, "data", "raw")
PROC = os.path.join(BASE, "data", "processed")
OUT  = os.path.join(BASE, "data", "outputs")
sys.path.insert(0, BASE)

# ── Loaders ────────────────────────────────────────────────────────────────────
@st.cache_data(ttl=60)
def load_json(path):
    if not os.path.exists(path): return {}
    with open(path) as f: return json.load(f)

def load_findings():    return load_json(os.path.join(OUT, "final_risk_findings.json")).get("findings", [])
def load_summary():     return load_json(os.path.join(OUT, "final_risk_findings.json")).get("summary", {})
def load_delta():       return load_json(os.path.join(OUT, "final_risk_findings.json")).get("delta", {})
def load_cves():        return load_json(os.path.join(RAW, "latest_vulnerabilities.json")).get("cves", [])
def load_kev():         return load_json(os.path.join(RAW, "cisa_kev.json")).get("vulnerabilities", [])
def load_news():        return load_json(os.path.join(RAW, "threat_news.json")).get("items", [])
def load_scan():        return load_json(os.path.join(RAW, "open_ports.json"))
def load_breaches():    return load_json(os.path.join(RAW, "breach_signals.json")).get("breaches", [])
def load_ip_rep():      return load_json(os.path.join(RAW, "ip_reputation.json")).get("results", [])

def load_status():
    """Load finding status data. Resilient to missing or corrupt files —
    returns a safe default dict if the JSON can't be parsed."""
    p = os.path.join(BASE, "data", "finding_status.json")
    if not os.path.exists(p):
        return {"statuses": {}, "last_updated": ""}
    try:
        with open(p) as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        # File is empty or corrupt — return safe default
        return {"statuses": {}, "last_updated": ""}

def save_status(data):
    data["last_updated"] = datetime.utcnow().isoformat()
    with open(os.path.join(BASE, "data", "finding_status.json"), "w") as f:
        json.dump(data, f, indent=2)

def load_scored_at():
    ts = load_json(os.path.join(OUT, "final_risk_findings.json")).get("scored_at", "")
    if ts:
        try: return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
        except: return ts
    return "Not yet run"

# ── Design ─────────────────────────────────────────────────────────────────────
SEV_COLOR = {"CRITICAL":"#E24B4A","HIGH":"#EF9F27","MEDIUM":"#378ADD","LOW":"#1D9E75","UNKNOWN":"#888780"}

def badge(level, text=None):
    c = SEV_COLOR.get((level or "").upper(), "#888780")
    t = text or level
    return f'<span style="background:{c};color:white;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:600">{t}</span>'

def kev_badge():
    return '<span style="background:#7B2FBE;color:white;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:600">🔥 ACTIVELY EXPLOITED</span>'

import re as _re
def parse_recommendation(text):
    """Split a recommendation string into individual action items.

    Handles two formats:
      "1. Foo. 2. Bar. 3. Baz."           → ["Foo", "Bar", "Baz"]
      "Foo. Bar. Baz."                    → ["Foo", "Bar", "Baz"]

    Beginner note: the regex `\\s*\\d+\\.\\s+` matches things like "1. ",
    " 2. ", " 3. " — i.e. a number followed by a dot and a space. We use
    this to split numbered lists cleanly so the numbers don't get treated
    as separate items.
    """
    if not text:
        return []
    text = text.strip()
    # If the text contains a numbered-list pattern like "1. ... 2. ...",
    # split on that pattern. Otherwise fall back to sentence splitting.
    if _re.search(r"\d+\.\s+", text):
        parts = _re.split(r"\s*\d+\.\s+", text)
    else:
        parts = text.split(". ")
    return [p.strip().rstrip(".") for p in parts if p.strip()]

# ── Sidebar ────────────────────────────────────────────────────────────────────
st.sidebar.markdown("## 🛡️ CyberFusion")
st.sidebar.markdown("**Threat Intelligence Platform**")
st.sidebar.caption("northstar-analytics.local · Lab / Demo")
st.sidebar.markdown("---")

# ── First-run onboarding gate ─────────────────────────────────────────────────
# If the workspace hasn't been set up yet, show the onboarding wizard and stop.
# This makes CyberFusion feel like a configured product you return to.
from ingestion import source_registry as _reg
_ws = _reg.load_workspace()
if not _ws.get("onboarded", False):
    from dashboard.sources_page import render_onboarding
    render_onboarding()
    st.stop()

# ── Detect URL routing for finding detail view ────────────────────────────────
# When the URL has ?finding=CORR-001 we show the Finding Detail page in the
# main content area while keeping the sidebar navigation visible.
selected_finding_id = st.query_params.get("finding", None)
if isinstance(selected_finding_id, list):  # older Streamlit returns list; normalize
    selected_finding_id = selected_finding_id[0] if selected_finding_id else None

# Sidebar nav: always rendered. Clicking a different page clears the URL param.
def _on_nav_change():
    """When user picks a sidebar item, clear the ?finding= URL parameter
    so the main content reverts to the chosen page."""
    if "finding" in st.query_params:
        del st.query_params["finding"]

sidebar_page = st.sidebar.radio("Navigate", [
    "🏠 Executive View",
    "🔌 Data Sources",
    "📥 Upload Evidence",
    "🤖 AI Briefing",
    "📡 Threat Feed",
    "🔭 Exposure & Breach",
    "🔗 Correlated Findings",
    "🧪 Methodology",
    "ℹ️ Architecture",
], label_visibility="collapsed", key="nav_radio", on_change=_on_nav_change)

# If a finding is selected via URL, render detail view; otherwise render the
# page picked in the sidebar.
if selected_finding_id:
    page = "__detail__"
else:
    page = sidebar_page

st.sidebar.markdown("---")
st.sidebar.caption(f"Last run: {load_scored_at()}")
st.sidebar.markdown("⚠️ **Lab scope only.**")
if st.sidebar.button("🔄 Refresh"): st.cache_data.clear(); st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# PAGE 1 — EXECUTIVE VIEW
# ══════════════════════════════════════════════════════════════════════════════
if page == "🏠 Executive View":
    st.title("Executive Security Summary")
    st.caption("Organization: Northstar Analytics · Scope: northstar-analytics.local")

    # ── Objective statement ──────────────────────────────────────────────────
    st.info(
        "**Objective.** Provide a real-time view of the organization's security posture "
        "by correlating threat intelligence, vulnerability data, and exposure signals from "
        "five public sources. Each finding below is fully traceable — click any card to view "
        "its evidence, methodology, and recommended mitigation."
    )
    st.markdown("---")

    summary = load_summary(); findings = load_findings(); delta = load_delta()
    total = sum(summary.values())

    if delta:
        n, r, e = len(delta.get("new",[])), len(delta.get("resolved",[])), len(delta.get("escalated",[]))
        if n or r or e:
            cols = st.columns(3)
            if n: cols[0].error(f"🆕 {n} new finding(s)")
            if r: cols[1].success(f"✅ {r} resolved")
            if e: cols[2].warning(f"⬆️ {e} escalated")

    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("Total Findings", total)
    c2.metric("🔴 Critical", summary.get("critical",0))
    c3.metric("🟠 High",     summary.get("high",0))
    c4.metric("🔵 Medium",   summary.get("medium",0))
    c5.metric("🟢 Low",      summary.get("low",0))
    st.markdown("---")

    cl, cr = st.columns(2)
    with cl:
        st.subheader("Risk Distribution")
        if total > 0:
            fig = px.pie(
                values=[summary.get(k,0) for k in ["critical","high","medium","low"]],
                names=["Critical","High","Medium","Low"],
                color_discrete_sequence=["#E24B4A","#EF9F27","#378ADD","#1D9E75"], hole=0.48
            )
            fig.update_layout(margin=dict(t=10,b=10,l=0,r=0), height=260)
            fig.update_traces(textposition="inside", textinfo="percent+label")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Run `python run_pipeline.py` first")

    with cr:
        st.subheader("Highest Risk Findings")
        st.caption("Click any finding for full evidence, methodology, and mitigation plan.")
        for f in findings[:5]:
            rid = f.get("rule_id", "")
            risk = f.get("risk_label","LOW"); color = SEV_COLOR.get(risk,"#888")
            kev = " &nbsp; " + kev_badge() if f.get("kev_confirmed_cves") else ""
            # The card visual (HTML)
            st.markdown(
                f'<div style="border-left:4px solid {color};padding:8px 12px;margin-bottom:4px;'
                f'background:var(--secondary-background-color);border-radius:4px">'
                f'<strong>{f["rule_name"]}</strong>{kev}<br>'
                f'<small>{badge(risk)} &nbsp; Score: {f.get("risk_score",0)} &nbsp; · &nbsp; {rid}</small><br>'
                f'<small style="color:gray">{f.get("mitre_technique","—")}</small></div>',
                unsafe_allow_html=True
            )
            # The clickable navigation link
            if st.button(f"View Details →", key=f"detail_{rid}", use_container_width=True):
                st.query_params["finding"] = rid
                st.rerun()
            st.markdown("<div style='margin-bottom:6px'></div>", unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("Details & Mitigation Plans")
    st.caption("Top critical/high findings with recommended remediation steps. Click 'Open full detail page' for evidence, data provenance, and the detection rule logic.")
    for i, f in enumerate([x for x in findings if x.get("risk_label") in ("CRITICAL","HIGH")][:4], 1):
        rid = f.get("rule_id","")
        with st.expander(f"{i}. [{f.get('risk_label')}] {f['rule_name']}"):
            st.markdown(f"**Description.** {f.get('description','')}")
            mitre = f.get("mitre_technique","")
            if mitre:
                st.markdown(f"**MITRE ATT&CK.** {f.get('mitre_tactic','')} · {mitre}")
            st.markdown("**Recommended Mitigation.**")
            for i_step, step in enumerate(parse_recommendation(f.get("recommendation","")), 1):
                st.markdown(f"{i_step}. {step}")
            if st.button("Open full detail page →", key=f"action_{rid}_{i}"):
                st.query_params["finding"] = rid
                st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE — UPLOAD EVIDENCE (ingestion layer)
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📥 Upload Evidence":
    from ingestion.file_router import (parse_upload, save_records, list_uploads,
                                       clear_uploads, SUPPORTED_TYPES)

    st.title("Upload Security Evidence")
    st.caption("Ingest authorized security exports — scans, vulnerability reports, asset inventories, breach exports.")

    st.info(
        "**Objective.** CyberFusion interprets uploaded evidence the same way it "
        "interprets its live API feeds: every file is parsed, validated, normalized "
        "into the unified schema, and fed into the correlation + scoring engine. "
        "Uploads **supplement** the live data — they don't replace it."
    )

    st.warning(
        "⚠️ **Authorized use only.** Upload data only for systems and domains you own or are "
        "authorized to assess. CyberFusion never scans external infrastructure itself — it "
        "only interprets evidence you provide. Breach exports should be for domains you control."
    )

    # ── Supported formats + sample files ─────────────────────────────────────
    with st.expander("📋 Supported file types & sample files", expanded=False):
        st.markdown("""
| File type | Real-world source | What it produces |
|-----------|-------------------|------------------|
| **Nmap XML** | `nmap -oX scan.xml <authorized-target>` | Open-port scan findings |
| **Vulnerability CSV** | Nessus / Tenable / Qualys / OpenVAS export | CVE / vulnerability findings |
| **Asset inventory CSV** | CMDB export, asset spreadsheet | Asset criticality tiers |
| **Breach export CSV** | HaveIBeenPwned domain search (domain you own) | Breach / exposure signals |

Sample files for testing live in the **`samples/`** folder of the project:
`sample_nmap_scan.xml`, `sample_vuln_scan.csv`, `sample_asset_inventory.csv`, `sample_breach_export.csv`.
All sample data is for the fictional `northstar-analytics.local` lab environment.
        """)

    st.markdown("---")

    # ── Uploader ──────────────────────────────────────────────────────────────
    col_up, col_type = st.columns([2, 1])
    with col_up:
        uploaded = st.file_uploader(
            "Upload an evidence file",
            type=["xml", "csv"],
            help="Nmap XML, or CSV from a vulnerability scanner / asset inventory / breach export."
        )
    with col_type:
        type_labels = {k: v for k, v in SUPPORTED_TYPES}
        forced = st.selectbox(
            "File type",
            options=[k for k, _ in SUPPORTED_TYPES],
            format_func=lambda k: type_labels[k],
            help="Leave on Auto-detect unless detection picks the wrong parser."
        )

    if uploaded is not None:
        try:
            text = uploaded.getvalue().decode("utf-8", errors="replace")
        except Exception as e:
            st.error(f"Could not read file: {e}")
            text = ""

        if text:
            result = parse_upload(uploaded.name, text, forced)

            # ── Parse result feedback ─────────────────────────────────────────
            if result.errors:
                st.error("**Parsing issues:**")
                for err in result.errors[:10]:
                    st.markdown(f"- {err}")

            if result.ok:
                st.success(f"✅ {result.summary}")

                # Preview the parsed records before committing them.
                st.markdown(f"**Preview — {len(result.records)} record(s) parsed as `{result.file_type}`:**")
                preview_rows = []
                for r in result.records[:25]:
                    preview_rows.append({
                        "Type": r.get("type", ""),
                        "Title": (r.get("title", "") or "")[:60],
                        "Severity": r.get("severity", ""),
                        "Asset": r.get("asset", "") or "—",
                    })
                st.dataframe(pd.DataFrame(preview_rows), use_container_width=True, hide_index=True)

                st.caption("Review the parsed records above. Confirm to add them to the evidence store; "
                           "they'll be included the next time you run the pipeline.")

                if st.button("✅ Confirm & add to evidence store", type="primary"):
                    saved = save_records(result, uploaded.name)
                    st.success(f"Saved {len(result.records)} record(s). Run the pipeline to correlate them.")
                    st.cache_data.clear()
            elif not result.errors:
                st.warning(result.summary or "No usable records found in this file.")

    st.markdown("---")

    # ── Currently stored uploads ──────────────────────────────────────────────
    st.subheader("Stored Evidence")
    uploads = list_uploads()
    if not uploads:
        st.info("No uploaded evidence yet. Upload a file above, or try a file from `samples/`.")
    else:
        total_records = sum(u["record_count"] for u in uploads)
        st.caption(f"{len(uploads)} file(s) · {total_records} record(s) staged for the pipeline.")
        st.dataframe(pd.DataFrame([{
            "File": u["filename"],
            "Type": u["file_type"],
            "Records": u["record_count"],
            "Ingested": u["ingested_at"],
        } for u in uploads]), use_container_width=True, hide_index=True)

        col_a, col_b = st.columns([1, 1])
        with col_a:
            st.markdown("**Re-run pipeline** to correlate uploaded evidence:")
            st.code("python run_pipeline.py", language="bash")
        with col_b:
            st.markdown("**Remove all uploaded evidence** (does not touch live API data):")
            if st.button("🗑️ Clear uploaded evidence"):
                n = clear_uploads()
                st.success(f"Cleared {n} uploaded file(s). Re-run the pipeline to update findings.")
                st.cache_data.clear()
                st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE — DATA SOURCES (configured platform)
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🔌 Data Sources":
    from dashboard.sources_page import render_data_sources
    render_data_sources()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 2 — AI BRIEFING (THE REAL-WORLD FEATURE)
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🤖 AI Briefing":
    st.title("Daily Security Briefing")
    st.caption("Structured threat summary generated from current pipeline data.")
    st.markdown("---")

    from briefing import generate_briefing, load_latest_briefing, save_manual_briefing, get_ollama_status, export_prompt
    import yaml as _yaml

    _cfg_path = os.path.join(BASE, "config", "config.yaml")
    _cfg = {}
    if os.path.exists(_cfg_path):
        with open(_cfg_path) as _f: _cfg = _yaml.safe_load(_f) or {}

    # ── Status bar ────────────────────────────────────────────────────────────
    ollama = get_ollama_status()
    has_api_key = bool(os.environ.get("ANTHROPIC_API_KEY") or _cfg.get("anthropic", {}).get("api_key"))

    if ollama["available"]:
        st.success(f"✅ Ollama running — using `{ollama['model']}` (local, free)")
    elif has_api_key:
        st.info("🔑 Anthropic API key detected")
    else:
        st.info(
            "**No AI backend configured.** Use the free Export option below, or set up "
            "[Ollama](https://ollama.com) for fully local generation."
        )

    st.markdown("""
Reads current findings, CVEs, CISA KEV entries, open ports, breach signals, and news,
then produces a structured briefing with these sections: Overall Risk Level · What Requires Attention ·
Active Exploitation Activity · Exposed Services · Recommended Actions.
Each briefing is saved to `data/outputs/briefings/` and downloadable as markdown.
    """)
    st.markdown("---")

    # ── Three tabs: Auto-generate / Export prompt / Paste response ────────────
    tab_gen, tab_export, tab_paste = st.tabs([
        "⚡ Auto-Generate",
        "📋 Export Prompt",
        "✏️ Paste Response"
    ])

    # Tab 1: Auto-generate (Ollama or Anthropic)
    with tab_gen:
        if ollama["available"] or has_api_key:
            method = "Ollama (local)" if ollama["available"] else "Anthropic API"
            if st.button(f"Generate via {method}", type="primary"):
                with st.spinner("Generating briefing..."):
                    text, mode = generate_briefing(save=True, config=_cfg)
                if mode == "export":
                    st.warning("Fell back to prompt export — check Ollama/API key.")
                else:
                    st.success(f"Generated via {mode}")
                st.cache_data.clear()
                st.rerun()
        else:
            st.info("No auto-generate backend available. Use the **Export Prompt** tab instead.")

        briefing_text = load_latest_briefing()
        briefing_dir  = os.path.join(BASE, "data", "outputs", "briefings")
        if briefing_text and not briefing_text.strip().startswith("You are"):
            latest_file = os.path.join(briefing_dir, "latest.md")
            if os.path.exists(latest_file):
                mtime = os.path.getmtime(latest_file)
                st.caption(f"Last generated: {datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')} · Data from: {load_scored_at()}")
            st.markdown(briefing_text)
            st.markdown("---")
            st.download_button("⬇️ Download (.md)", data=briefing_text,
                               file_name=f"briefing_{datetime.now().strftime('%Y%m%d')}.md",
                               mime="text/markdown", key="dl_auto")
            if os.path.exists(briefing_dir):
                past = sorted([f for f in os.listdir(briefing_dir)
                               if f.startswith("briefing_") and f.endswith(".md")], reverse=True)
                if len(past) > 1:
                    with st.expander(f"Past briefings ({len(past)} saved)"):
                        for fname in past[:10]:
                            ts_str = fname.replace("briefing_","").replace(".md","")
                            try: label = datetime.strptime(ts_str, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M")
                            except: label = ts_str
                            with open(os.path.join(briefing_dir, fname)) as _f2: _c2 = _f2.read()
                            st.download_button(f"⬇️ {label}", data=_c2, file_name=fname,
                                               mime="text/markdown", key=f"dl_{fname}")
        else:
            st.info("No briefing saved yet. Generate one above, or use Export Prompt.")

    # Tab 2: Export the prompt (works with any free AI chat — Claude.ai, ChatGPT, Gemini)
    with tab_export:
        st.markdown("""
**How it works:**
1. Click **Export Prompt** to generate the prompt from your current data
2. Copy the prompt text
3. Paste it into any free AI chat — Claude.ai, ChatGPT, Gemini, etc.
4. Copy the response and paste it into the **Paste Response** tab to save it
        """)
        if st.button("Export Prompt", type="primary"):
            prompt_text = export_prompt()
            st.session_state["exported_prompt"] = prompt_text

        if "exported_prompt" in st.session_state:
            prompt_text = st.session_state["exported_prompt"]
            st.success("Prompt ready — copy everything below and paste into any free AI chat.")
            st.code(prompt_text, language=None)
            st.download_button("⬇️ Download prompt (.txt)", data=prompt_text,
                               file_name="briefing_prompt.txt", mime="text/plain", key="dl_prompt")

    # Tab 3: Paste response back in to save it
    with tab_paste:
        st.markdown("Paste the AI-generated briefing response here to save it to `data/outputs/briefings/`.")
        pasted = st.text_area("Paste briefing text here", height=300,
                              placeholder="Paste the response from Claude.ai / ChatGPT / etc...")
        if st.button("Save Briefing", type="primary"):
            if pasted.strip():
                save_manual_briefing(pasted.strip())
                st.success("Briefing saved. Switch to the Auto-Generate tab to view it.")
                st.cache_data.clear()
            else:
                st.warning("Nothing to save — paste the briefing text first.")

    # ── Ollama setup instructions ─────────────────────────────────────────────
    if not ollama["available"]:
        with st.expander("Set up Ollama for free local generation"):
            st.markdown("""
**Ollama** runs AI models locally on your Mac — no internet, no account, no cost.

```bash
# 1. Install Ollama
brew install ollama

# 2. Pull a model (llama3 is a good balance of speed and quality)
ollama pull llama3

# 3. Start the server
ollama serve

# 4. Refresh this page — the Auto-Generate tab will detect it automatically
```

Once Ollama is running, click **Generate via Ollama (local)** in the Auto-Generate tab.
Models available: `llama3`, `mistral`, `phi3`. All free, all run on your machine.
            """)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 3 — THREAT FEED
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📡 Threat Feed":
    st.title("Threat Intelligence Feed")
    st.markdown("---")
    tab_cve, tab_kev, tab_news = st.tabs(["🐛 Recent CVEs", "🔥 CISA KEV Catalog", "📰 Security News"])

    with tab_cve:
        cves = load_cves(); kev_items = load_kev()
        kev_ids = {v.get("cveID") for v in kev_items}
        if not cves:
            st.warning("No CVE data. Run the pipeline.")
        else:
            kev_count = sum(1 for c in cves if c.get("cve_id") in kev_ids)
            c1, c2 = st.columns([1,3])
            c1.metric("CVEs Loaded", len(cves))
            if kev_count: c1.metric("🔥 In KEV", kev_count)
            sev_f = st.multiselect("Severity", ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"],
                                   default=["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"])
            ca, cb = st.columns(2)
            kev_only = ca.checkbox("KEV only"); search = cb.text_input("Search CVEs")
            filtered = [c for c in cves if c.get("severity","UNKNOWN") in sev_f]
            if kev_only: filtered = [c for c in filtered if c.get("cve_id") in kev_ids]
            if search:   filtered = [c for c in filtered if search.lower() in c["description"].lower()]
            for c in filtered:
                in_kev = c.get("cve_id") in kev_ids
                with st.expander(f"{c['cve_id']} — {c.get('severity','?')} (CVSS {c.get('score','N/A')})"):
                    st.markdown(badge(c.get("severity","UNKNOWN")) + (" &nbsp; " + kev_badge() if in_kev else ""), unsafe_allow_html=True)
                    st.markdown(c["description"])
                    if in_kev:
                        kd = next((v for v in kev_items if v.get("cveID")==c["cve_id"]), None)
                        if kd: st.warning(f"**Actively Exploited** · Added: {kd.get('dateAdded','')} · {kd.get('requiredAction','')[:120]}")
                    st.caption(f"Published: {c.get('published','')[:10]}")

    with tab_kev:
        kev_items = load_kev()
        if not kev_items:
            st.warning("No KEV data.")
        else:
            st.info(f"**CISA KEV** — {len(kev_items)} actively-exploited CVEs. Federal agencies must patch these on deadline.")
            sk = st.text_input("Search KEV"); rw = st.checkbox("Ransomware-linked only")
            fk = kev_items
            if sk: fk = [v for v in fk if sk.lower() in (v.get("vendorProject","") + v.get("product","") + v.get("vulnerabilityName","")).lower()]
            if rw: fk = [v for v in fk if v.get("knownRansomwareCampaignUse") == "Known"]
            st.caption(f"Showing {len(fk)} of {len(kev_items)}")
            if fk:
                df = pd.DataFrame([{"CVE ID": v.get("cveID",""), "Vendor": v.get("vendorProject",""),
                    "Product": v.get("product",""), "Name": v.get("vulnerabilityName","")[:55],
                    "Date Added": v.get("dateAdded",""), "Due Date": v.get("dueDate",""),
                    "Ransomware": v.get("knownRansomwareCampaignUse","")} for v in fk[:100]])
                st.dataframe(df, use_container_width=True, hide_index=True)

    with tab_news:
        news = load_news()
        if not news:
            st.warning("No news data.")
        else:
            ca, cb = st.columns(2)
            p_only = ca.checkbox("Priority only"); sn = cb.text_input("Search news")
            fn = news
            if p_only: fn = [n for n in fn if n.get("is_priority")]
            if sn: fn = [n for n in fn if sn.lower() in n["title"].lower() or sn.lower() in n.get("summary","").lower()]
            for item in fn[:20]:
                with st.expander(f"{'🔴 ' if item.get('is_priority') else ''}{item['title']} — {item['source']}"):
                    st.markdown(item.get("summary",""))
                    if item.get("priority_keywords"): st.caption(f"Keywords: {', '.join(item['priority_keywords'])}")
                    st.caption(f"Published: {item.get('published','')[:10]}")
                    if item.get("link"): st.markdown(f"[Read more ↗]({item['link']})")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 4 — EXPOSURE & BREACH
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🔭 Exposure & Breach":
    st.title("Exposure & Attack Surface")
    st.markdown("---")
    tab_scan, tab_breach, tab_ip = st.tabs(["🔌 Open Ports", "🔓 Breach Signals", "🌐 IP Reputation"])

    with tab_scan:
        hosts = load_scan().get("hosts", [])
        if not hosts:
            st.warning("No scan data.")
        else:
            st.info("⚠️ All scans target localhost/lab Docker containers only.")
            for host in hosts:
                ports = host.get("open_ports", [])
                st.subheader(f"🖥️ {host['hostname']} ({host['ip']})")
                st.caption(f"Scanned: {host.get('scanned_at','')[:16]} · {host.get('total_open',0)} open port(s)")
                if not ports: st.success("No open ports detected.")
                else:
                    df = pd.DataFrame(ports)
                    if "port" in df.columns:
                        st.dataframe(df[["port","service","risk_level","risk_note"]], use_container_width=True, hide_index=True)

    with tab_breach:
        breaches = load_breaches()
        if not breaches:
            st.warning("No breach data.")
        else:
            if any(b.get("is_synthetic") or b.get("source")=="synthetic" for b in breaches):
                st.warning("⚠️ Synthetic data included. Add a HaveIBeenPwned API key in config.yaml for real data.")
            for b in breaches:
                sev = b.get("severity","MEDIUM"); is_synth = b.get("is_synthetic") or b.get("source")=="synthetic"
                synth_tag = ' <span style="background:#6B7280;color:white;padding:1px 6px;border-radius:3px;font-size:10px">SYNTHETIC</span>' if is_synth else ""
                with st.expander(f"[{sev}] {b.get('breach_name','Unknown')} · {b.get('domain','')}"):
                    st.markdown(badge(sev) + synth_tag, unsafe_allow_html=True)
                    st.markdown(f"**Breach date:** {b.get('breach_date','Unknown')}")
                    st.markdown(f"**Accounts affected:** {b.get('pwn_count',0):,}")
                    if b.get("data_classes"): st.markdown(f"**Data exposed:** {', '.join(b['data_classes'])}")
                    if b.get("description"):  st.markdown(b["description"])

    with tab_ip:
        ip_data = load_ip_rep()
        if not ip_data:
            st.info("No IP reputation data. Runs automatically after port scanning.")
        else:
            for r in ip_data:
                if r.get("source") == "skipped": continue
                ip = r.get("ip",""); shodan = r.get("shodan",{}); gn = r.get("greynoise")
                cls = gn.get("classification","unknown") if gn else "not queried"
                ports = shodan.get("ports",[]); vulns = shodan.get("vulns",[])
                c_map = {"malicious":"#E24B4A","benign":"#1D9E75","unknown":"#888780"}
                with st.expander(f"IP: {ip} · {cls.upper()} · {len(ports)} port(s)"):
                    st.markdown(f'<span style="background:{c_map.get(cls,"#888")};color:white;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:600">{cls.upper()}</span>', unsafe_allow_html=True)
                    if ports: st.markdown(f"**Shodan ports:** {', '.join(str(p) for p in ports)}")
                    if vulns: st.warning(f"**Associated CVEs:** {', '.join(vulns[:5])}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 5 — CORRELATED FINDINGS (with status tracking + PDF export)
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🔗 Correlated Findings":
    st.title("Correlated Intelligence Findings")
    st.caption("Multi-source signal correlation with MITRE ATT&CK mapping, status tracking, and PDF export.")
    st.markdown("---")

    findings = load_findings()
    if not findings:
        st.warning("No findings yet. Run: `python run_pipeline.py`")
    else:
        # PDF Export button
        col_export, col_spacer = st.columns([1, 4])
        with col_export:
            if st.button("📄 Export PDF Report", type="primary"):
                with st.spinner("Generating PDF..."):
                    try:
                        from reporter import generate_pdf_report
                        pdf_path = generate_pdf_report()
                        with open(pdf_path, "rb") as f: pdf_bytes = f.read()
                        st.download_button(
                            "⬇️ Download Report",
                            data=pdf_bytes,
                            file_name=f"cyberfusion_report_{datetime.now().strftime('%Y%m%d')}.pdf",
                            mime="application/pdf"
                        )
                    except Exception as e:
                        st.error(f"PDF generation failed: {e}")

        # Score chart
        fig = go.Figure(go.Bar(
            x=[f["risk_score"] for f in findings],
            y=[f["rule_name"][:45] for f in findings],
            orientation="h",
            marker_color=[SEV_COLOR.get(f["risk_label"],"#888") for f in findings],
            text=[f'{f["risk_label"]} · {f["risk_score"]}' for f in findings],
            textposition="outside"
        ))
        fig.update_layout(height=max(240, len(findings)*65), margin=dict(l=0,r=80,t=10,b=0),
                          xaxis_title="Risk Score (0–100)", yaxis={"categoryorder":"total ascending"},
                          xaxis={"range":[0,115]})
        st.plotly_chart(fig, use_container_width=True)
        st.markdown("---")

        sev_filter = st.multiselect("Filter", ["CRITICAL","HIGH","MEDIUM","LOW"],
                                    default=["CRITICAL","HIGH","MEDIUM","LOW"])
        status_data = load_status()

        for f in findings:
            if f.get("risk_label") not in sev_filter: continue
            rule_id = f.get("rule_id","")
            risk    = f.get("risk_label","LOW")
            score   = f.get("risk_score",0)
            color   = SEV_COLOR.get(risk,"#888")
            kev     = f.get("kev_confirmed_cves",[])
            kev_html = " &nbsp; " + kev_badge() if kev else ""

            # Current status
            status_entry = status_data["statuses"].get(rule_id, {"status":"open","note":"","updated":""})
            current_status = status_entry.get("status","open")
            status_icon = {"open":"🔴","acknowledged":"🟡","resolved":"✅","false_positive":"⬜"}.get(current_status,"🔴")

            with st.expander(f"{status_icon} [{rule_id}] {f['rule_name']} — {risk} · Score: {score}"):
                col1, col2 = st.columns([2, 1])

                with col1:
                    st.markdown(badge(risk) + kev_html, unsafe_allow_html=True)
                    st.markdown("")
                    st.markdown(f"**Description:** {f['description']}")
                    mitre = f.get("mitre_technique","")
                    if mitre:
                        st.markdown(
                            f'<div style="background:#1a1a2e;color:#9b8ff5;padding:6px 10px;border-radius:4px;font-size:12px;margin:8px 0">'
                            f'🎯 <strong>MITRE ATT&CK</strong>: {f.get("mitre_tactic","")} · {mitre}</div>',
                            unsafe_allow_html=True
                        )
                    st.markdown(f"**Recommendation:** {f.get('recommendation','')}")
                    for field, label, icon in [
                        ("matched_scan","Scan Signals","🔌"),
                        ("matched_exposure","Exposure Signals","🕳️"),
                        ("matched_cves","CVEs","🐛"),
                        ("kev_confirmed_cves","KEV CVEs","🔥"),
                    ]:
                        ev = f.get(field,[])
                        if ev: st.markdown(f"**{icon} {label}:** " + ", ".join(f"`{e}`" for e in ev[:5]))

                with col2:
                    st.markdown("**Score Breakdown:**")
                    for line in f.get("score_breakdown",[]): st.markdown(f"- {line}")
                    st.markdown("**Affected Assets:**")
                    for a in f.get("affected_assets",[]): st.markdown(f"- `{a}`")
                    tier = f.get("asset_tier")
                    if tier:
                        st.caption({1:"Tier 1 — Crown Jewel",2:"Tier 2 — Core Infra",3:"Tier 3 — Standard"}.get(tier,""))

                    # ── Status tracking ───────────────────────────────────────
                    st.markdown("---")
                    st.markdown("**📋 Finding Status**")
                    new_status = st.selectbox(
                        "Status", ["open","acknowledged","resolved","false_positive"],
                        index=["open","acknowledged","resolved","false_positive"].index(current_status),
                        key=f"status_{rule_id}"
                    )
                    note = st.text_input("Note (optional)", value=status_entry.get("note",""), key=f"note_{rule_id}")
                    if st.button("Save Status", key=f"save_{rule_id}"):
                        status_data["statuses"][rule_id] = {
                            "status":  new_status,
                            "note":    note,
                            "updated": datetime.utcnow().isoformat(),
                            "finding": f.get("rule_name","")
                        }
                        save_status(status_data)
                        st.success(f"Status updated → {new_status}")
                        st.rerun()

                    if status_entry.get("updated"):
                        st.caption(f"Last updated: {status_entry['updated'][:16]}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 6 — ARCHITECTURE
# ══════════════════════════════════════════════════════════════════════════════
elif page == "ℹ️ Architecture":
    st.title("System Architecture")
    st.caption("How CyberFusion works — for demos, interviews, and portfolio reviewers.")
    st.markdown("---")
    st.markdown("""
## Pipeline: Collect → Normalize → Correlate → Score → Visualize

| Module | What It Does |
|--------|-------------|
| `cve_collector.py` | Fetches real CVEs from NIST NVD API |
| `kev_collector.py` | Downloads CISA's 1,500+ actively-exploited CVE catalog |
| `news_collector.py` | Aggregates security news from 5 RSS feeds |
| `breach_monitor.py` | Checks domain breach history via HaveIBeenPwned |
| `ip_reputation.py` | Enriches IPs with Shodan + GreyNoise classification |
| `scanner.py` | TCP port scan of lab Docker containers |
| `ingestion/file_router.py` | **Upload ingestion** — routes uploaded files to the right parser |
| `ingestion/parsers/*` | Parse nmap XML, vuln CSV, asset inventory, breach exports |
| `normalizer.py` | Converts all sources (incl. uploads) into a unified schema |
| `correlator.py` | 8 detection rules linking signals across sources |
| `risk_scorer.py` | Explainable scoring with asset criticality multipliers |
| `briefing.py` | **AI briefing** — Claude generates a CISO-ready summary from live data |
| `notifier.py` | Slack alerts for new CRITICAL/HIGH findings |
| `reporter.py` | PDF report export with full findings + recommendations |

## The AI Briefing (Real-World Feature)

Every morning, SOC analysts spend 30-60 minutes manually writing a threat briefing 
for their CISO. This tool does it in seconds, grounded in live data:

- Today's real CVEs from NVD (not templates)
- CISA KEV entries confirmed as actively exploited right now
- Your actual open ports from the scanner
- Breach exposure signals for your domain
- Correlated findings with MITRE ATT&CK context

The output is a structured briefing that prioritizes what matters today, 
explains it in plain English, and gives concrete action items.

## Upload-Driven Evidence Ingestion

Beyond its live API feeds, CyberFusion ingests **authorized security evidence**
that a user uploads — turning it into the same normalized records the rest of
the pipeline already understands:

| Upload type | Becomes | Feeds rules |
|-------------|---------|-------------|
| Nmap XML | `scan_finding` records | RDP/SSH/web/login exposure rules |
| Vulnerability CSV (Nessus/Tenable/Qualys) | `vulnerability` records | Web-CVE + KEV rules |
| Asset inventory CSV | asset criticality tiers | Score multipliers (×1.0–1.5) |
| Breach export CSV (HIBP) | `breach` records | Credential-stuffing + email-exposure rules |

Uploaded evidence **supplements** the live data — it never replaces the public
API feeds. Because parsers emit the unified schema directly, the correlation
engine and risk scorer consume uploads with zero special-casing.

## Configured Platform: Source Registry & Connectors

CyberFusion isn't just a one-shot uploader — it's a **configured platform you
return to**. A first-run onboarding wizard sets up your workspace; configured
sources persist locally so you never re-enter everything.

| Module | What It Does |
|--------|-------------|
| `ingestion/source_registry.py` | Saved registry of configured sources (type, mode, status, last-sync, provenance) → `data/workspace.json` |
| `ingestion/secrets.py` | API credentials in your OS keychain (via `keyring`), with a gitignored local-file fallback |
| `ingestion/connectors/` | Connector interface + Tenable/Qualys/HIBP/M365/STIX stubs |
| `dashboard/sources_page.py` | Onboarding wizard + Data Sources management page |

**Two ways to connect, mirroring a real Threat Intelligence Platform:**
1. **API connector** — for supported vendors (Tenable, Qualys, HIBP, M365/Entra, STIX/TAXII)
2. **Manual file upload** — a universal fallback, fully implemented for every source

**Honest status:** upload mode is fully working for all source types. Live API
connectors are **scaffolded** — the configuration, credential storage, and
connection-test paths are real, but live vendor-API fetch is intentionally not
wired (a student project can't verify calls against real Tenable/Qualys/Entra
tenants). Each connector clearly labels itself as scaffolded and points to the
working upload path. Nothing fakes a live integration.

## Risk Scoring Formula
```
Score = (base_severity + confidence + rule_weight + evidence_count)
        × asset_criticality_multiplier  [1.0 – 1.5×]
        + kev_bonus  [+20 if actively exploited]
```
Capped at 100. Every point is documented in the score breakdown.

## Ethics & Safety
- All TCP scans: localhost + Docker lab only — never external
- Breach data: HaveIBeenPwned public API per ToS, or clearly-labeled synthetic
- No credentials stored or displayed
- AI briefing uses only your own local intelligence data as context
    """)
    st.markdown("---")
    st.markdown("### Cron Scheduler")
    st.markdown("Auto-run the pipeline hourly so the dashboard always has fresh data:")
    st.code('crontab -e\n# Add this line:\n0 * * * * cd ~/Desktop/cyberfusion-complete && source venv/bin/activate && python run_pipeline.py --quick >> data/pipeline.log 2>&1', language="bash")


# ══════════════════════════════════════════════════════════════════════════════
# FINDING DETAIL VIEW (triggered by ?finding=CORR-XXX URL parameter)
# ══════════════════════════════════════════════════════════════════════════════
if page == "__detail__":
    try:
        from methodology import get_rule_docs, get_data_source
    except ModuleNotFoundError:
        from dashboard.methodology import get_rule_docs, get_data_source

    findings = load_findings()
    finding = next((f for f in findings if f.get("rule_id") == selected_finding_id), None)

    # ── Back navigation (top of page) ─────────────────────────────────────────
    col_back, _ = st.columns([1, 5])
    with col_back:
        if st.button("← Back to Executive View", use_container_width=True):
            st.query_params.clear()
            st.rerun()

    if finding is None:
        st.error(f"Finding `{selected_finding_id}` not found. It may have been resolved or the data has been refreshed.")
        st.stop()

    # ── Header ───────────────────────────────────────────────────────────────
    risk      = finding.get("risk_label", "LOW")
    score     = finding.get("risk_score", 0)
    rule_id   = finding.get("rule_id", "")
    color     = SEV_COLOR.get(risk, "#888")
    kev_cves  = finding.get("kev_confirmed_cves", [])

    st.markdown(
        f'<div style="border-left:6px solid {color};padding:14px 18px;margin:8px 0 18px;'
        f'background:var(--secondary-background-color);border-radius:6px">'
        f'<div style="font-size:11px;color:#888;font-weight:600;letter-spacing:1px">FINDING · {rule_id}</div>'
        f'<h2 style="margin:4px 0 8px">{finding.get("rule_name","")}</h2>'
        f'<div>{badge(risk)} &nbsp; <strong>Risk Score: {score}/100</strong>'
        + (f' &nbsp; {kev_badge()}' if kev_cves else '')
        + '</div></div>',
        unsafe_allow_html=True
    )

    docs = get_rule_docs(rule_id)

    # ── Section 1: Objective / Purpose ───────────────────────────────────────
    st.subheader("🎯 Objective")
    if docs.get("purpose"):
        st.markdown(docs["purpose"])
    else:
        st.markdown(finding.get("description", "_No documented purpose for this rule yet._"))

    # ── Section 2: MITRE ATT&CK ──────────────────────────────────────────────
    mitre_t = finding.get("mitre_technique", "")
    mitre_x = finding.get("mitre_tactic", "")
    if mitre_t or mitre_x:
        st.subheader("🗺️ MITRE ATT&CK Mapping")
        st.markdown(
            f'<div style="background:#1a1a2e;color:#9b8ff5;padding:10px 14px;border-radius:4px;font-size:13px">'
            f'<strong>Tactic:</strong> {mitre_x or "—"}<br>'
            f'<strong>Technique:</strong> {mitre_t or "—"}</div>',
            unsafe_allow_html=True
        )
        st.caption("Reference: [attack.mitre.org](https://attack.mitre.org/)")

    # ── Section 3: Evidence Summary ──────────────────────────────────────────
    st.subheader("🧾 Evidence Summary")
    has_evidence = False
    for field, label, icon in [
        ("matched_scan",        "Open Ports / Scan Findings",  "🔌"),
        ("matched_exposure",    "Exposure / Breach Signals",   "🕳️"),
        ("matched_cves",        "Related CVEs",                "🐛"),
        ("kev_confirmed_cves",  "Actively Exploited (KEV)",    "🔥"),
        ("affected_emails",     "Affected Email Addresses",    "📧"),
    ]:
        items = finding.get(field, [])
        if items:
            has_evidence = True
            st.markdown(f"**{icon} {label}** ({len(items)})")
            with st.container():
                for item in items[:8]:
                    st.markdown(f"- `{item}`")
                if len(items) > 8:
                    st.caption(f"...and {len(items)-8} more")
    if not has_evidence:
        st.markdown("_No structured evidence items recorded for this finding._")

    # ── Section 4: Data Provenance ───────────────────────────────────────────
    st.subheader("📡 Data Provenance")
    st.caption("Every signal in this finding can be traced back to its source. Sources used:")
    for src_key in docs.get("data_sources", []):
        src = get_data_source(src_key)
        with st.expander(f"📄 {src['name']}"):
            c1, c2 = st.columns([1, 2])
            with c1:
                st.markdown(f"**Type:** {src.get('type','—')}")
                st.markdown(f"**License:** {src.get('license','—')}")
                st.markdown(f"**Refresh:** {src.get('refresh','—')}")
            with c2:
                st.markdown(src.get("description", ""))
                if src.get("url"):
                    st.markdown(f"🔗 [{src['url']}]({src['url']})")
    if not docs.get("data_sources"):
        st.markdown("_Data source documentation pending for this rule._")

    # ── Section 5: Detection Methodology ─────────────────────────────────────
    st.subheader("⚙️ Detection Methodology")
    if docs.get("detection_logic"):
        st.markdown(docs["detection_logic"])
    else:
        st.markdown("_Detection logic documentation pending. See `analysis/correlator.py` for the implementation._")
    st.caption(f"Source code: `analysis/correlator.py` → rule `{rule_id}`")

    # ── Section 6: Why This Matters ──────────────────────────────────────────
    if docs.get("why_it_matters"):
        st.subheader("💡 Why This Matters")
        st.markdown(docs["why_it_matters"])

    # ── Section 7: Score Breakdown ───────────────────────────────────────────
    st.subheader("📊 Score Breakdown")
    st.caption("Every point in the risk score is documented. No black boxes.")
    breakdown = finding.get("score_breakdown", [])
    if breakdown:
        for line in breakdown:
            st.markdown(f"- {line}")
        st.markdown(f"**Final score: {score} / 100** &nbsp; → &nbsp; **{risk}**", unsafe_allow_html=False)
    else:
        st.markdown("_No score breakdown recorded._")

    # ── Section 8: Affected Assets ───────────────────────────────────────────
    st.subheader("🖥️ Affected Assets")
    assets = finding.get("affected_assets", [])
    tier   = finding.get("asset_tier")
    tier_label = {1:"Tier 1 — Crown Jewel (×1.5 score multiplier)",
                  2:"Tier 2 — Core Infrastructure (×1.2 score multiplier)",
                  3:"Tier 3 — Standard Asset (×1.0 score multiplier)"}.get(tier, "")
    if assets:
        for a in assets:
            st.markdown(f"- `{a}`")
        if tier_label:
            st.caption(tier_label)
    else:
        st.markdown("_No specific assets recorded — finding is organization-wide._")

    # ── Section 9: Recommended Mitigation ────────────────────────────────────
    st.subheader("🛠️ Recommended Mitigation")
    rec_steps = parse_recommendation(finding.get("recommendation", ""))
    if rec_steps:
        for i_step, step in enumerate(rec_steps, 1):
            st.markdown(f"{i_step}. {step}")
    else:
        st.markdown("_No mitigation recommendations available._")

    # ── Section 10: False Positives / Caveats ────────────────────────────────
    if docs.get("false_positives"):
        st.subheader("⚠️ Known False-Positive Conditions")
        st.markdown(docs["false_positives"])

    # ── Section 11: Confidence ────────────────────────────────────────────────
    confidence = finding.get("confidence", "")
    if confidence:
        st.subheader("🎚️ Confidence")
        c_color = {"HIGH":"#1D9E75","MEDIUM":"#EF9F27","LOW":"#888780"}.get(confidence, "#888")
        st.markdown(
            f'<span style="background:{c_color};color:white;padding:3px 10px;border-radius:4px;font-weight:600">{confidence}</span>',
            unsafe_allow_html=True
        )
        st.caption("Confidence reflects how certain the correlation engine is that this finding represents a real risk vs. a coincidence. Driven by the number of independent signals and source reliability.")

    st.markdown("---")
    if st.button("← Back to Executive View ", key="back_bottom"):
        st.query_params.clear()
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# METHODOLOGY PAGE — explains how the platform works end-to-end
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🧪 Methodology":
    try:
        from methodology import RULE_DOCS, DATA_SOURCES
    except ModuleNotFoundError:
        from dashboard.methodology import RULE_DOCS, DATA_SOURCES

    st.title("Methodology & Transparency")
    st.caption("Every score, every signal, every data source — fully documented.")

    st.info(
        "**Objective.** CyberFusion is built on the principle that every security finding "
        "must be auditable. This page documents exactly how data is collected, how "
        "correlation rules fire, and how risk scores are calculated."
    )

    st.markdown("---")

    # ── Pipeline overview ────────────────────────────────────────────────────
    st.subheader("Pipeline Overview")
    st.markdown("""
```
Collect    →    Normalize    →    Correlate    →    Score    →    Visualize
   ↓                ↓                  ↓             ↓                ↓
5 public         Unified         8 rule-based     Weighted         Streamlit
APIs +           schema          detection        formula          dashboard
lab scan         (one shape      across data      with full        + PDF
                 for all)        sources          breakdown        + Slack + AI
```
    """)

    # ── Data sources catalog ─────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("Data Sources")
    st.caption("All sources are public APIs or internal lab data. No unauthorized scanning, no scraped data, no purchased intel.")

    for src_key, src in DATA_SOURCES.items():
        with st.expander(f"📄 {src['name']}"):
            c1, c2 = st.columns([1, 2])
            with c1:
                st.markdown(f"**Type:** {src.get('type','—')}")
                st.markdown(f"**License:** {src.get('license','—')}")
                st.markdown(f"**Refresh:** {src.get('refresh','—')}")
            with c2:
                st.markdown(src.get("description",""))
                if src.get("url"):
                    st.markdown(f"🔗 [{src['url']}]({src['url']})")

    # ── Risk scoring formula ─────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("Risk Scoring Formula")
    st.markdown("""
Every score is the sum of documented factors, with no hidden weights:

```
Score = (base_severity + confidence_bonus + rule_weight_bonus + evidence_bonus)
        × asset_criticality_multiplier      [1.0 – 1.5×]
        + kev_bonus                         [+20 if actively exploited]
```

| Factor | Range | Drives |
|--------|-------|--------|
| Base severity | 5–40 | CRITICAL / HIGH / MEDIUM / LOW from the rule |
| Confidence bonus | 0–10 | How certain the correlation rule is |
| Rule importance | 0–25 | Some rules are inherently higher priority |
| Evidence count | 0–12 | More corroborating signals → higher score |
| Asset multiplier | 1.0–1.5 | Tier 1 assets (VPN/DC) amplify the score |
| KEV bonus | +20 | Active CISA exploitation overrides everything |

Scores are capped at 100 and mapped to risk labels: ≥65 CRITICAL, ≥45 HIGH, ≥25 MEDIUM, <25 LOW.
    """)

    # ── Correlation rule catalog ─────────────────────────────────────────────
    st.markdown("---")
    st.subheader("Correlation Rule Catalog")
    st.caption("Eight rules covering the highest-impact signal combinations. Click any rule to see its full documentation.")

    for rid, doc in RULE_DOCS.items():
        with st.expander(f"**{rid}** — {doc.get('purpose','')[:70]}..."):
            st.markdown(f"**Purpose.** {doc.get('purpose','—')}")
            st.markdown(f"**Detection logic.** {doc.get('detection_logic','—')}")
            st.markdown(f"**Why it matters.** {doc.get('why_it_matters','—')}")
            if doc.get("false_positives"):
                st.markdown(f"**Known false-positive conditions.** {doc['false_positives']}")
            srcs = doc.get("data_sources", [])
            if srcs:
                st.markdown(f"**Data sources used:** {', '.join(srcs)}")

    # ── Differentiation ──────────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("How CyberFusion Differs from Commercial Platforms")
    st.markdown("""
Most commercial cyber-risk platforms (CyberSaint, RiskLens, BitSight) provide a number you can't audit. CyberFusion takes the opposite approach:

- **Every correlation rule is open Python code** — readable, modifiable, testable
- **Every data source is publicly verifiable** — no proprietary feeds, no vendor lock-in
- **Every risk score has a published breakdown** — no opaque ML models
- **Every finding lists its data provenance** — you see exactly where each signal came from

The trade-off is that CyberFusion has fewer integrations and no enterprise support. The benefit is that nothing happens in the system that you cannot inspect, modify, or override.
    """)
