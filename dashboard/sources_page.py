# dashboard/sources_page.py
#
# Two product surfaces for the configured-platform phase, kept out of app.py so
# that file stays readable:
#   render_onboarding()    — first-run setup wizard (shown until workspace is
#                            marked onboarded)
#   render_data_sources()  — the Data Sources management page
#
# Both use the source_registry + secrets + connectors modules built in
# ingestion/. Nothing here re-implements parsing — uploads still go through the
# existing file_router.

import os
import streamlit as st
import pandas as pd

from ingestion import source_registry as reg
from ingestion import secrets as secretstore
from ingestion.file_router import parse_upload, save_records


# ── shared bits ────────────────────────────────────────────────────────────────
STATUS_BADGE = {
    "ok":            ("🟢", "Synced"),
    "configured":   ("🔵", "Configured"),
    "never_synced": ("⚪", "Never synced"),
    "error":        ("🔴", "Error"),
}


def _mode_badge(mode):
    return "🔌 Connector" if mode == "connector" else "📤 Upload"


def _category_for(stype):
    return reg.SOURCE_TYPES.get(stype, {}).get("category", "Other")


# ══════════════════════════════════════════════════════════════════════════════
# FIRST-RUN ONBOARDING
# ══════════════════════════════════════════════════════════════════════════════
def render_onboarding():
    """Shown until the workspace is marked onboarded. Returns nothing; writes
    workspace state and triggers a rerun when finished."""
    ws = reg.load_workspace()

    st.title("👋 Welcome to CyberFusion")
    st.caption("Let's set up your workspace. This takes about a minute and is saved locally.")
    st.markdown("---")

    st.markdown(
        "CyberFusion fuses **authorized security evidence** — vulnerability scans, "
        "asset inventories, breach exposure, identity risk, and threat intel — into "
        "correlated, scored, explainable findings. You can connect sources via API "
        "(where supported) or upload files. Everything you configure here is saved so "
        "you don't start from scratch next time."
    )

    with st.form("onboarding_form"):
        st.subheader("1. Workspace")
        org = st.text_input("Organization name", value=ws.get("org_name", "Northstar Analytics"))
        scope = st.text_input("Primary scope (domain / environment)",
                              value=ws.get("scope", "northstar-analytics.local"))

        st.subheader("2. Mode")
        mode = st.radio(
            "How do you want to start?",
            ["demo", "real"],
            format_func=lambda m: ("🧪 Demo mode — load clearly-labeled sample evidence so I can "
                                   "explore the platform" if m == "demo"
                                   else "🔐 Real mode — I'll configure my own authorized sources"),
        )

        st.subheader("3. Sample data (optional)")
        load_samples = st.checkbox(
            "Pre-load the sample evidence files (nmap, vuln, asset, breach, M365, STIX)",
            value=(mode == "demo"),
            help="Parses the files in samples/ and stages them so you can run the pipeline immediately."
        )

        submitted = st.form_submit_button("✅ Finish setup", type="primary")

    if submitted:
        ws["org_name"] = org
        ws["scope"] = scope
        ws["mode"] = mode
        ws["onboarded"] = True

        # Register the upload-only sources that ship with the project so the
        # Data Sources page isn't empty on first open.
        existing_types = {s["type"] for s in ws["sources"].values()}
        for stype, name in [("asset_inventory", "Asset Inventory (upload)"),
                            ("nmap", "Nmap Scan (upload)")]:
            if stype not in existing_types:
                reg.add_source(stype, name, "upload")
        ws = reg.load_workspace()  # reload after add_source writes
        ws["org_name"] = org; ws["scope"] = scope; ws["mode"] = mode; ws["onboarded"] = True
        reg.save_workspace(ws)

        loaded_msg = ""
        if load_samples:
            n = _load_sample_evidence()
            loaded_msg = f" Loaded {n} sample evidence file(s)."

        st.success(f"Setup complete!{loaded_msg} Opening your workspace…")
        st.cache_data.clear()
        st.rerun()

    st.markdown("---")
    st.caption("You can change any of this later on the Data Sources page.")


def _load_sample_evidence():
    """Parse + stage every file in samples/ via the existing router. Returns count."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    samples = os.path.join(base, "samples")
    n = 0
    if not os.path.isdir(samples):
        return 0
    for fn in os.listdir(samples):
        path = os.path.join(samples, fn)
        if not os.path.isfile(path) or fn.lower() == "readme.md":
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            result = parse_upload(fn, text, "auto")
            if result.ok:
                save_records(result, fn)
                n += 1
        except Exception:
            continue
    return n


# ══════════════════════════════════════════════════════════════════════════════
# DATA SOURCES PAGE
# ══════════════════════════════════════════════════════════════════════════════
def render_data_sources():
    ws = reg.load_workspace()
    st.title("🔌 Data Sources")
    st.caption(f"Workspace: {ws.get('org_name','')} · Scope: {ws.get('scope','')} · "
               f"Mode: {ws.get('mode','demo').upper()}")

    # Secret backend honesty banner
    if secretstore.is_secure():
        st.success(f"🔐 Secrets stored in your {secretstore.backend_name()}.")
    else:
        st.warning(
            f"🔓 Secrets are stored in **{secretstore.backend_name()}**. This file is "
            "gitignored and chmod 600, but for full security install the `keyring` "
            "package so credentials go to your OS keychain instead."
        )

    st.info(
        "**Two ways to connect**, mirroring a real TIP: (1) **API connector** for "
        "supported vendors, or (2) **manual file upload** as a universal fallback. "
        "Upload mode is fully implemented for every source; live API connectors are "
        "clearly labeled where scaffolded."
    )

    tab_manage, tab_add = st.tabs(["📋 Configured Sources", "➕ Add Source"])

    with tab_add:
        _render_add_source()

    with tab_manage:
        _render_manage_sources()


def _render_add_source():
    st.subheader("Add a data source")

    # Group the type picker by category, like the design's source columns.
    types = list(reg.SOURCE_TYPES.items())
    labels = {k: f"{v['label']}  ·  {v['category']}" for k, v in types}
    stype = st.selectbox("Source type", [k for k, _ in types],
                         format_func=lambda k: labels[k])
    meta = reg.SOURCE_TYPES[stype]

    st.caption(meta["description"])
    st.caption(f"🔒 Authorization: {meta['authorization_note']}")

    modes = meta["modes"]
    mode = st.radio("Connection mode", modes,
                   format_func=lambda m: ("🔌 API connector" if m == "connector" else "📤 File upload"),
                   horizontal=True)

    if mode == "connector":
        cstatus = reg.connector_status_for(stype)
        if cstatus == "scaffolded":
            st.warning("This connector is **scaffolded** — the configuration and "
                       "connection-test work, but live API fetch isn't enabled in this "
                       "build. Upload mode for this source is fully working.")
        elif cstatus == "implemented":
            st.success("This connector is fully implemented.")

    name = st.text_input("Display name", value=meta["label"])

    if st.button("Add source", type="primary"):
        sid = reg.add_source(stype, name, mode)
        st.session_state["just_added"] = sid
        st.success(f"Added **{name}**. Configure it under *Configured Sources*.")
        st.cache_data.clear()
        st.rerun()


def _render_manage_sources():
    sources = reg.list_sources()
    if not sources:
        st.info("No sources configured yet. Use the **Add Source** tab to create one.")
        return

    # Refresh-all action
    top1, top2 = st.columns([1, 3])
    with top1:
        if st.button("🔄 Refresh all"):
            _refresh_all()
            st.cache_data.clear()
            st.rerun()
    with top2:
        st.caption(f"{len(sources)} source(s) configured. Toggle, refresh, test, or remove each below.")

    # Group by category for a product-like layout.
    by_cat = {}
    for s in sources:
        by_cat.setdefault(_category_for(s["type"]), []).append(s)

    for cat, items in by_cat.items():
        st.markdown(f"#### {cat}")
        for s in items:
            _render_source_card(s)


def _render_source_card(s):
    sid = s["id"]
    meta = reg.SOURCE_TYPES.get(s["type"], {})
    icon, status_label = STATUS_BADGE.get(s.get("status", "configured"), ("🔵", "Configured"))
    enabled = s.get("enabled", True)

    with st.expander(
        f"{icon} {s['name']}  ·  {_mode_badge(s['mode'])}  ·  "
        f"{'enabled' if enabled else 'disabled'}",
        expanded=False,
    ):
        c1, c2 = st.columns([2, 1])

        with c1:
            st.markdown(f"**Type:** {meta.get('label', s['type'])}")
            st.markdown(f"**Mode:** {_mode_badge(s['mode'])}")
            st.markdown(f"**Status:** {icon} {status_label}")
            st.markdown(f"**Last sync:** {s.get('last_sync','—')[:19].replace('T',' ') or '—'}")
            st.markdown(f"**Records last sync:** {s.get('record_count', 0)}")
            if s.get("last_error"):
                st.error(f"Last error: {s['last_error']}")

            # Provenance block
            prov = s.get("provenance", {})
            st.caption(
                f"Provenance — source_type: `{prov.get('source_type','')}` · "
                f"ingestion_method: `{prov.get('ingestion_method','')}` · "
                f"id: `{sid}`"
            )

        with c2:
            new_enabled = st.toggle("Enabled", value=enabled, key=f"en_{sid}")
            if new_enabled != enabled:
                reg.set_enabled(sid, new_enabled)
                st.cache_data.clear()
                st.rerun()

            if st.button("🗑️ Remove", key=f"rm_{sid}"):
                reg.remove_source(sid)
                st.cache_data.clear()
                st.rerun()

        st.markdown("---")

        if s["mode"] == "connector":
            _render_connector_config(s)
        else:
            _render_upload_config(s)


def _render_connector_config(s):
    sid = s["id"]
    stype = s["type"]
    from ingestion.connectors import get_connector
    conn = get_connector(stype)
    if conn is None:
        st.info("This source type has no API connector — switch to upload mode.")
        return

    st.markdown("**Connector configuration**")
    config = dict(s.get("config", {}))

    # Non-secret config fields
    changed = False
    for f in conn.config_fields:
        val = st.text_input(f, value=config.get(f, ""), key=f"cfg_{sid}_{f}")
        if val != config.get(f, ""):
            config[f] = val
            changed = True
    if changed:
        reg.update_source(sid, config=config)

    # Secret fields (masked)
    st.markdown("**Credentials** (stored in your secret backend, never in git)")
    for f in conn.secret_fields:
        is_set = secretstore.has_secret(reg.secret_key_for(sid, f))
        st.caption(f"{f}: {'✅ set — ' + secretstore.masked(reg.secret_key_for(sid, f)) if is_set else '— not set —'}")
        new_val = st.text_input(f"Set/replace {f}", value="", type="password", key=f"sec_{sid}_{f}")
        if new_val:
            reg.set_source_secret(sid, f, new_val)
            st.success(f"{f} saved.")
            st.rerun()

    cc1, cc2 = st.columns(2)
    with cc1:
        if st.button("🔍 Test connection", key=f"test_{sid}"):
            result = reg.test_source_connection(sid)
            if result["ok"]:
                st.success(result["message"])
            else:
                st.error(result["message"])
    with cc2:
        st.caption("Live fetch is enabled only for fully-implemented connectors. "
                   "Scaffolded connectors: use upload mode to ingest real data.")


def _render_upload_config(s):
    sid = s["id"]
    stype = s["type"]
    meta = reg.SOURCE_TYPES.get(stype, {})
    parser_key = meta.get("parser_key", "auto")

    st.markdown("**Upload a file for this source**")
    st.caption(meta.get("authorization_note", ""))

    up = st.file_uploader("Choose file", type=["xml", "csv", "json"], key=f"up_{sid}")
    if up is not None:
        try:
            text = up.getvalue().decode("utf-8", errors="replace")
        except Exception as e:
            st.error(f"Could not read file: {e}")
            return
        # Force the parser tied to this source type for predictability.
        result = parse_upload(up.name, text, parser_key)
        if result.errors:
            for err in result.errors[:6]:
                st.error(err)
        if result.ok:
            st.success(f"✅ {result.summary}")
            st.dataframe(pd.DataFrame([{
                "Type": r.get("type"), "Title": (r.get("title","") or "")[:55],
                "Severity": r.get("severity"), "Asset": r.get("asset") or "—",
            } for r in result.records[:20]]), use_container_width=True, hide_index=True)
            if st.button("Confirm & attach to source", key=f"conf_{sid}", type="primary"):
                save_records(result, up.name)
                reg.mark_synced(sid, len(result.records))
                st.success(f"Attached {len(result.records)} record(s). Run the pipeline to correlate.")
                st.cache_data.clear()
                st.rerun()


def _refresh_all():
    """For connector sources, run test_connection; for upload sources, this is a
    no-op (their data is already staged). Scaffolded connectors will report they
    need upload mode — that's the honest behavior."""
    for s in reg.list_sources():
        if not s.get("enabled", True):
            continue
        if s["mode"] == "connector":
            res = reg.test_source_connection(s["id"])
            reg.mark_synced(s["id"], s.get("record_count", 0),
                           error="" if res["ok"] else res["message"])
