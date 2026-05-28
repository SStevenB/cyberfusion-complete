# run_pipeline.py
# Master pipeline runner.
#
# Usage:
#   python run_pipeline.py              # Full pipeline
#   python run_pipeline.py --no-scan   # Skip port scanning
#   python run_pipeline.py --quick     # Skip slow collectors (news)

import sys
import os
import argparse
import yaml
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load_config() -> dict:
    config_file = os.path.join(os.path.dirname(__file__), "config", "config.yaml")
    if os.path.exists(config_file):
        with open(config_file) as f:
            return yaml.safe_load(f) or {}
    return {}


def run(args):
    config  = load_config()
    started = datetime.now()

    print("\n" + "=" * 65)
    print("  CyberFusion — Threat Intelligence Pipeline")
    print("  Target: northstar-analytics.local (LAB / DEMO ONLY)")
    print(f"  Started: {started.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65 + "\n")

    # ── Phase 1: Data Collection ──────────────────────────────────────────────
    print("[PHASE 1] Data Collection")
    print("-" * 45)

    nvd_key = config.get("nvd", {}).get("api_key", "") or ""

    print("  → Fetching CVEs from NIST NVD...")
    from data_collection.cve_collector import fetch_recent_cves, save_cves
    cve_days = config.get("pipeline", {}).get("cve_days_back", 7)
    cve_max  = config.get("pipeline", {}).get("cve_max_results", 30)
    cves = fetch_recent_cves(days_back=cve_days, max_results=cve_max, api_key=nvd_key or None)
    save_cves(cves)

    print("  → Fetching CISA KEV catalog...")
    from data_collection.kev_collector import run_kev_collector
    run_kev_collector()

    if not args.quick:
        print("  → Fetching security news...")
        from data_collection.news_collector import fetch_security_news, save_news
        max_news = config.get("pipeline", {}).get("news_max_per_feed", 10)
        news = fetch_security_news(max_per_feed=max_news)
        save_news(news)

    print("  → Checking breach exposure...")
    from data_collection.breach_monitor import run_breach_monitor
    run_breach_monitor(config)

    print("  → Loading exposure signals...")
    from data_collection.exposure_simulator import scan_exposure_signals, save_alerts
    alerts = scan_exposure_signals()
    save_alerts(alerts)

    if not args.no_scan:
        print("  → Scanning lab hosts...")
        from scanning.scanner import run_scan, save_scan_results
        scan_results = run_scan(use_nmap=False)
        save_scan_results(scan_results)

        print("  → Enriching IPs with reputation data...")
        from data_collection.ip_reputation import run_ip_reputation
        run_ip_reputation(config=config)

    # ── Phase 2: Normalization ────────────────────────────────────────────────
    print("\n[PHASE 2] Normalization")
    print("-" * 45)
    from analysis.normalizer import run_normalization
    normalized = run_normalization()

    # ── Phase 3: Correlation ──────────────────────────────────────────────────
    print("\n[PHASE 3] Correlation")
    print("-" * 45)
    from analysis.correlator import run_correlation
    findings = run_correlation(normalized)

    # ── Phase 4: Risk Scoring ─────────────────────────────────────────────────
    print("\n[PHASE 4] Risk Scoring")
    print("-" * 45)
    from analysis.risk_scorer import run_scoring
    scored = run_scoring(findings)

    # ── Record a history snapshot for the real trend chart ────────────────────
    try:
        from analysis.history import record_snapshot
        snap = record_snapshot(scored)
        print(f"[History] snapshot saved → {snap}")
    except Exception as e:
        print(f"[History] could not save snapshot: {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed  = (datetime.now() - started).total_seconds()
    critical = sum(1 for s in scored if s["risk_label"] == "CRITICAL")
    high     = sum(1 for s in scored if s["risk_label"] == "HIGH")

    print("\n" + "=" * 65)
    print("  Pipeline Complete!")
    print(f"  Duration:  {elapsed:.1f}s")
    print(f"  Findings:  {len(scored)} total  |  {critical} CRITICAL  |  {high} HIGH")
    print("  Dashboard: streamlit run dashboard/app.py")
    print("=" * 65 + "\n")

    if critical > 0:
        print("  ⚠️  CRITICAL findings require immediate attention.")
        for s in scored:
            if s["risk_label"] == "CRITICAL":
                print(f"     • [{s['rule_id']}] {s['rule_name']} (score: {s['risk_score']})")
        print()


    # ── Phase 5: Notify ───────────────────────────────────────────────────────
    from notifier import run_notifier
    run_notifier(config, scored)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberFusion pipeline runner")
    parser.add_argument("--no-scan", action="store_true", help="Skip port scanning and IP enrichment")
    parser.add_argument("--quick",   action="store_true", help="Skip slower collectors (news)")
    args = parser.parse_args()
    run(args)
