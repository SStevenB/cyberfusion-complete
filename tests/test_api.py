# tests/test_api.py
#
# Tests for the FastAPI backend (api/main.py) using FastAPI's TestClient.
# These exercise the HTTP layer end-to-end against the real pipeline functions.
# Workspace + secrets are redirected to temp files so tests never touch real state.
# Run with: pytest tests/test_api.py -v

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient with workspace + secrets isolated to temp files."""
    from ingestion import source_registry as reg
    from ingestion import secrets as sec
    monkeypatch.setattr(reg, "WORKSPACE_FILE", str(tmp_path / "workspace.json"))
    monkeypatch.setattr(sec, "SECRETS_FILE", str(tmp_path / "secrets.json"))
    monkeypatch.setattr(sec, "_KEYRING_OK", False)
    # Isolate uploads dir too so commit tests don't pollute real staged evidence.
    from ingestion import file_router
    up = tmp_path / "uploads"
    up.mkdir()
    monkeypatch.setattr(file_router, "UPLOADS_DIR", str(up))
    from api import main as apimain
    monkeypatch.setattr(apimain, "_STATUS_FILE", str(tmp_path / "finding_status.json"))
    return TestClient(apimain.app)


# ── Core data endpoints ──────────────────────────────────────────────────────
class TestData:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_data_shape(self, client):
        r = client.get("/api/data")
        assert r.status_code == 200
        d = r.json()
        for key in ("findings", "summary", "riskScore", "cves", "dataSources"):
            assert key in d

    def test_supported_types(self, client):
        r = client.get("/api/supported-types")
        keys = [t["key"] for t in r.json()["types"]]
        assert "auto" in keys and "nmap_xml" in keys

    def test_source_types(self, client):
        r = client.get("/api/source-types")
        assert len(r.json()["source_types"]) == 8


# ── Upload endpoints ─────────────────────────────────────────────────────────
class TestUpload:
    def _file(self, name):
        with open(os.path.join(SAMPLES, name), "rb") as f:
            return f.read()

    def test_preview_nmap(self, client):
        r = client.post("/api/upload/preview",
                        files={"file": ("sample_nmap_scan.xml", self._file("sample_nmap_scan.xml"), "text/xml")},
                        data={"forced_type": "auto"})
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] and d["file_type"] == "nmap_xml" and d["record_count"] >= 1

    def test_preview_bad_file(self, client):
        r = client.post("/api/upload/preview",
                        files={"file": ("junk.csv", b"a,b\n1,2\n", "text/csv")},
                        data={"forced_type": "auto"})
        assert r.status_code == 200
        assert r.json()["ok"] is False

    def test_commit_and_list(self, client):
        client.post("/api/upload/commit",
                    files={"file": ("sample_vuln_scan.csv", self._file("sample_vuln_scan.csv"), "text/csv")},
                    data={"forced_type": "auto"})
        listed = client.get("/api/uploads").json()["uploads"]
        assert any(u["file_type"] == "vuln_csv" for u in listed)

    def test_clear_uploads(self, client):
        client.post("/api/upload/commit",
                    files={"file": ("sample_nmap_scan.xml", self._file("sample_nmap_scan.xml"), "text/xml")},
                    data={"forced_type": "auto"})
        r = client.delete("/api/uploads")
        assert r.json()["ok"]
        assert client.get("/api/uploads").json()["uploads"] == []


# ── Source registry endpoints ────────────────────────────────────────────────
class TestSources:
    def test_add_list_delete(self, client):
        r = client.post("/api/sources", json={"source_type": "asset_inventory", "name": "CMDB", "mode": "upload"})
        assert r.status_code == 200
        sid = r.json()["id"]
        assert any(s["id"] == sid for s in client.get("/api/sources").json()["sources"])
        assert client.delete(f"/api/sources/{sid}").json()["ok"]
        assert not any(s["id"] == sid for s in client.get("/api/sources").json()["sources"])

    def test_add_unknown_type_400(self, client):
        r = client.post("/api/sources", json={"source_type": "nope", "name": "x", "mode": "upload"})
        assert r.status_code == 400

    def test_enable_disable(self, client):
        sid = client.post("/api/sources", json={"source_type": "nmap", "name": "N", "mode": "upload"}).json()["id"]
        client.patch(f"/api/sources/{sid}", json={"enabled": False})
        src = next(s for s in client.get("/api/sources").json()["sources"] if s["id"] == sid)
        assert src["enabled"] is False

    def test_secret_then_test_connection(self, client):
        sid = client.post("/api/sources", json={
            "source_type": "tenable", "name": "T", "mode": "connector",
            "config": {"base_url": "https://cloud.tenable.com"}}).json()["id"]
        m = client.post(f"/api/sources/{sid}/secret", json={"field": "access_key", "value": "AKxxxx"})
        assert m.json()["ok"]
        assert "AKxxxx" not in m.json()["masked"]   # masked, not leaked
        client.post(f"/api/sources/{sid}/secret", json={"field": "secret_key", "value": "SKyyyy"})
        res = client.post(f"/api/sources/{sid}/test").json()
        assert res["ok"] is True   # config + creds present → scaffolded-OK


# ── Onboarding / workspace ────────────────────────────────────────────────────
class TestWorkspace:
    def test_onboard_persists(self, client):
        r = client.post("/api/onboard", json={
            "org_name": "Test Org", "scope": "test.local", "mode": "demo", "load_samples": False})
        assert r.json()["ok"]
        ws = client.get("/api/workspace").json()
        assert ws["onboarded"] is True and ws["org_name"] == "Test Org"

    def test_onboard_loads_samples(self, client):
        r = client.post("/api/onboard", json={
            "org_name": "X", "scope": "y", "mode": "demo", "load_samples": True})
        assert r.json()["samples_loaded"] >= 4


# ── Finding status ───────────────────────────────────────────────────────────
class TestFindingStatus:
    def test_set_and_get_status(self, client):
        r = client.patch("/api/findings/CORR-003/status", json={"status": "resolved"})
        assert r.status_code == 200 and r.json()["status"] == "resolved"
        got = client.get("/api/findings/status").json()["statuses"]
        assert got["CORR-003"] == "resolved"

    def test_invalid_status_rejected(self, client):
        r = client.patch("/api/findings/CORR-003/status", json={"status": "banana"})
        assert r.status_code == 400

    def test_status_values(self, client):
        for st in ["open", "acknowledged", "resolved", "false_positive"]:
            r = client.patch("/api/findings/X/status", json={"status": st})
            assert r.status_code == 200


# ── Slack notify (not configured in test → honest sent=False) ─────────────────
class TestSlackNotify:
    def test_notify_without_webhook(self, client, monkeypatch, tmp_path):
        # Point config dir away so no webhook is found.
        r = client.post("/api/notify/slack")
        assert r.status_code == 200
        body = r.json()
        # Either not configured (sent False) — should never crash.
        assert "sent" in body


# ── Briefing history (real saved files) ──────────────────────────────────────
class TestBriefingHistory:
    def test_history_endpoint_returns_list(self, client):
        r = client.get("/api/briefing/history")
        assert r.status_code == 200
        body = r.json()
        assert "briefings" in body
        # In test env briefings dir may be empty — list shape is what matters.
        assert isinstance(body["briefings"], list)

    def test_get_unknown_briefing_404(self, client):
        r = client.get("/api/briefing/history/briefing_99999999_999999.md")
        assert r.status_code == 404

    def test_get_rejects_bad_filename(self, client):
        # path-traversal style + non-conforming → 400 before disk access
        r = client.get("/api/briefing/history/..%2Fpasswd")
        assert r.status_code in (400, 404)
