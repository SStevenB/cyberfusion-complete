# analysis/history.py
# ─────────────────────────────────────────────────────────────────────────────
# Records a small snapshot of each pipeline run so the dashboard can show a
# REAL trend over time (instead of a synthetic ramp). Each snapshot captures
# the timestamp, severity counts, aggregate risk score, and finding count.
#
# Snapshots accumulate in data/history/ as one JSON file per run. The trend
# chart reads them back in chronological order. With <2 runs there isn't enough
# data to draw a trend yet — the UI says so honestly rather than inventing one.
# ─────────────────────────────────────────────────────────────────────────────

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY_DIR = os.path.join(BASE, "data", "history")


def _agg_score(findings: List[Dict[str, Any]]) -> int:
    """Same aggregate-score logic build_cfdata uses, kept consistent here."""
    if not findings:
        return 0
    scores = [f.get("risk_score", 0) for f in findings]
    agg = round(sum(scores) / len(scores))
    agg = max(agg, max(scores) - 5)   # bias toward the worst finding
    return min(100, agg)


def record_snapshot(scored_findings: List[Dict[str, Any]]) -> str:
    """Save a snapshot of the current run. Returns the file path written.

    `scored_findings` is the list returned by risk_scorer.run_scoring().
    """
    os.makedirs(HISTORY_DIR, exist_ok=True)
    now = datetime.now(timezone.utc)

    def _count(label: str) -> int:
        return sum(1 for f in scored_findings if f.get("risk_label") == label)

    snapshot = {
        "timestamp": now.isoformat(),
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "summary": {
            "critical": _count("CRITICAL"),
            "high": _count("HIGH"),
            "medium": _count("MEDIUM"),
            "low": _count("LOW"),
        },
        "total": len(scored_findings),
        "agg_score": _agg_score(scored_findings),
    }

    fname = f"run_{now.strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join(HISTORY_DIR, fname)
    with open(path, "w") as f:
        json.dump(snapshot, f, indent=2)
    return path


def load_history(limit: int = 60) -> List[Dict[str, Any]]:
    """Return run snapshots in chronological order (oldest → newest).

    `limit` caps how many of the most-recent runs are returned (default 60,
    ~2 months of daily runs)."""
    if not os.path.isdir(HISTORY_DIR):
        return []
    files = sorted(f for f in os.listdir(HISTORY_DIR)
                   if f.startswith("run_") and f.endswith(".json"))
    snapshots = []
    for fn in files[-limit:]:
        try:
            with open(os.path.join(HISTORY_DIR, fn)) as f:
                snapshots.append(json.load(f))
        except Exception:
            continue
    return snapshots


def build_trend() -> Dict[str, Any]:
    """Build the trend payload for the dashboard from REAL history.

    Returns {"points": [...], "real": bool, "runs": int}. When there are fewer
    than 2 runs we return real=False so the UI can show an honest
    'not enough history yet' state instead of a fabricated line."""
    history = load_history()
    points = [{
        "d": h.get("date", "")[5:] or h.get("timestamp", "")[:10],  # MM-DD
        "ts": h.get("timestamp", ""),
        "crit": h["summary"].get("critical", 0),
        "high": h["summary"].get("high", 0),
        "med": h["summary"].get("medium", 0),
        "low": h["summary"].get("low", 0),
        "score": h.get("agg_score", 0),
    } for h in history]
    return {"points": points, "real": len(points) >= 2, "runs": len(points)}


if __name__ == "__main__":
    # Quick manual check
    t = build_trend()
    print(f"history runs: {t['runs']} · real trend: {t['real']}")
    for p in t["points"][-5:]:
        print(f"  {p['d']}  score={p['score']}  C{p['crit']} H{p['high']} M{p['med']} L{p['low']}")
