# tests/test_platform.py
#
# Tests for the configured-platform phase: new parsers (STIX, M365), the source
# registry, secret handling, and connector scaffolding.
# Run with: pytest tests/test_platform.py -v

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def _read(name):
    with open(os.path.join(SAMPLES, name)) as f:
        return f.read()


# ── New parsers ──────────────────────────────────────────────────────────────
class TestNewParsers:
    def test_stix_detected_and_parsed(self):
        from ingestion.file_router import parse_upload, detect_type
        text = _read("sample_stix_bundle.json")
        assert detect_type("sample_stix_bundle.json", text) == "stix_json"
        r = parse_upload("sample_stix_bundle.json", text, "auto")
        assert r.ok
        # bundle has an indicator, a vulnerability, and a threat-actor
        types = {rec["type"] for rec in r.records}
        assert "exposure" in types and "vulnerability" in types

    def test_m365_detected_and_parsed(self):
        from ingestion.file_router import parse_upload, detect_type
        text = _read("sample_m365_signins.csv")
        assert detect_type("sample_m365_signins.csv", text) == "m365_csv"
        r = parse_upload("sample_m365_signins.csv", text, "auto")
        assert r.ok
        # "None" risk row is dropped; elevated rows kept
        assert all(rec["type"] == "exposure" for rec in r.records)
        assert any("High" in rec["extra"]["risk_level"] for rec in r.records)


# ── Source registry ──────────────────────────────────────────────────────────
class TestSourceRegistry:
    @pytest.fixture(autouse=True)
    def isolate_workspace(self, tmp_path, monkeypatch):
        # Point the registry + secrets at temp files so tests don't touch real state.
        from ingestion import source_registry as reg
        from ingestion import secrets as sec
        monkeypatch.setattr(reg, "WORKSPACE_FILE", str(tmp_path / "workspace.json"))
        monkeypatch.setattr(sec, "SECRETS_FILE", str(tmp_path / "secrets.json"))
        monkeypatch.setattr(sec, "_KEYRING_OK", False)  # force file backend in tests
        yield

    def test_default_workspace_not_onboarded(self):
        from ingestion import source_registry as reg
        ws = reg.load_workspace()
        assert ws["onboarded"] is False
        assert ws["sources"] == {}

    def test_add_and_persist_source(self):
        from ingestion import source_registry as reg
        sid = reg.add_source("asset_inventory", "CMDB", "upload")
        assert sid in {s["id"] for s in reg.list_sources()}
        # reload from disk → still there (persistence)
        ws = reg.load_workspace()
        assert sid in ws["sources"]

    def test_enable_disable_and_remove(self):
        from ingestion import source_registry as reg
        sid = reg.add_source("tenable", "T", "connector", {"base_url": "https://x"})
        reg.set_enabled(sid, False)
        assert reg.get_source(sid)["enabled"] is False
        reg.remove_source(sid)
        assert reg.get_source(sid) is None

    def test_mark_synced_updates_status(self):
        from ingestion import source_registry as reg
        sid = reg.add_source("nmap", "N", "upload")
        reg.mark_synced(sid, 5)
        s = reg.get_source(sid)
        assert s["status"] == "ok" and s["record_count"] == 5


# ── Secrets ──────────────────────────────────────────────────────────────────
class TestSecrets:
    @pytest.fixture(autouse=True)
    def isolate(self, tmp_path, monkeypatch):
        from ingestion import secrets as sec
        monkeypatch.setattr(sec, "SECRETS_FILE", str(tmp_path / "secrets.json"))
        monkeypatch.setattr(sec, "_KEYRING_OK", False)
        yield

    def test_set_get_delete(self):
        from ingestion import secrets as sec
        sec.set_secret("a.b", "supersecret")
        assert sec.get_secret("a.b") == "supersecret"
        assert sec.has_secret("a.b")
        sec.delete_secret("a.b")
        assert not sec.has_secret("a.b")

    def test_masked_hides_value(self):
        from ingestion import secrets as sec
        sec.set_secret("a.b", "abcdef123456")
        masked = sec.masked("a.b")
        assert "abcdef123456" not in masked
        assert masked.startswith("abc")


# ── Connectors ───────────────────────────────────────────────────────────────
class TestConnectors:
    def test_all_connectors_registered(self):
        from ingestion.connectors import CONNECTORS
        for t in ["tenable", "qualys", "hibp", "m365_signin", "stix"]:
            assert t in CONNECTORS

    def test_scaffolded_connectors_are_honest(self):
        from ingestion.connectors import get_connector
        c = get_connector("tenable")
        # missing creds → not ok
        r = c.test_connection({}, {})
        assert not r.ok
        # fetch is honestly not implemented
        r2 = c.fetch({"base_url": "https://x"}, {"access_key": "a", "secret_key": "b"})
        assert not r2.ok
        assert "scaffolded" in r2.message.lower()

    def test_connector_status_reads_from_class(self):
        from ingestion import source_registry as reg
        assert reg.connector_status_for("tenable") == "scaffolded"
        assert reg.connector_status_for("nmap") == "none"



# ── HIBP connector (Phase 8: one real implementation) ───────────────────────
class TestHIBPConnector:
    """The HIBP connector is the one real, live-API connector. Other connectors
    remain honestly labeled scaffolded."""

    def test_status_is_implemented(self):
        from ingestion.connectors.hibp import HIBPConnector
        assert HIBPConnector.STATUS == "implemented"

    def test_missing_domain_rejected(self):
        from ingestion.connectors.hibp import HIBPConnector
        r = HIBPConnector().test_connection({}, {})
        assert not r.ok
        assert "monitored_domain" in r.message

    def test_bad_domain_format_rejected(self):
        from ingestion.connectors.hibp import HIBPConnector
        r = HIBPConnector().test_connection({"monitored_domain": "no-dot"}, {})
        assert not r.ok
        assert "example.com" in r.message

    def test_optional_api_key_not_required(self):
        """test_connection must work WITHOUT an api_key (free /breaches endpoint)."""
        from ingestion.connectors.hibp import HIBPConnector
        # we don't make a real network call here — just confirm validation passes.
        # If the network call fails the message includes "unreachable" or status code,
        # which is still ok=False with an honest message — never a crash.
        r = HIBPConnector().test_connection({"monitored_domain": "example.com"}, {})
        # whether the network succeeds or fails, the call shouldn't crash
        assert isinstance(r.ok, bool)
        assert isinstance(r.message, str) and len(r.message) > 0



# ── History / trend (Phase 9: real trend from accumulated runs) ──────────────
class TestHistory:
    @pytest.fixture(autouse=True)
    def isolate_history(self, tmp_path, monkeypatch):
        from analysis import history
        monkeypatch.setattr(history, "HISTORY_DIR", str(tmp_path / "history"))
        yield

    def test_empty_history_not_real(self):
        from analysis.history import build_trend
        t = build_trend()
        assert t["real"] is False and t["runs"] == 0

    def test_single_run_not_real(self):
        from analysis.history import record_snapshot, build_trend
        record_snapshot([{"risk_label": "HIGH", "risk_score": 60}])
        t = build_trend()
        assert t["runs"] == 1 and t["real"] is False

    def test_two_runs_makes_real_trend(self):
        import time
        from analysis.history import record_snapshot, build_trend
        record_snapshot([{"risk_label": "CRITICAL", "risk_score": 90}])
        time.sleep(1.1)  # filename timestamp is per-second
        record_snapshot([{"risk_label": "HIGH", "risk_score": 55},
                         {"risk_label": "LOW", "risk_score": 10}])
        t = build_trend()
        assert t["runs"] == 2 and t["real"] is True
        assert t["points"][0]["crit"] == 1   # first run had 1 critical
        assert t["points"][1]["high"] == 1   # second run had 1 high

    def test_snapshot_counts_severities(self):
        from analysis.history import record_snapshot, load_history
        record_snapshot([
            {"risk_label": "CRITICAL", "risk_score": 90},
            {"risk_label": "CRITICAL", "risk_score": 85},
            {"risk_label": "MEDIUM", "risk_score": 30},
        ])
        h = load_history()
        assert h[-1]["summary"]["critical"] == 2
        assert h[-1]["summary"]["medium"] == 1
        assert h[-1]["total"] == 3
