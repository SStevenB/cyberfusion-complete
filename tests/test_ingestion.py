# tests/test_ingestion.py
#
# Unit tests for the upload ingestion layer.
# Run with: pytest tests/test_ingestion.py -v
#
# These tests parse the sample files in samples/ and confirm each parser
# produces records in the unified schema that the correlator/scorer consume.

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingestion.file_router import parse_upload, detect_type, SUPPORTED_TYPES
from ingestion.schema import severity_from_cvss, normalize_severity_label

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def _read(name):
    with open(os.path.join(SAMPLES, name)) as f:
        return f.read()


# ── detection ──────────────────────────────────────────────────────────────────

class TestDetection:
    def test_nmap_detected(self):
        assert detect_type("sample_nmap_scan.xml", _read("sample_nmap_scan.xml")) == "nmap_xml"

    def test_vuln_csv_detected(self):
        assert detect_type("sample_vuln_scan.csv", _read("sample_vuln_scan.csv")) == "vuln_csv"

    def test_asset_csv_detected(self):
        assert detect_type("sample_asset_inventory.csv", _read("sample_asset_inventory.csv")) == "asset_csv"

    def test_breach_csv_detected(self):
        assert detect_type("sample_breach_export.csv", _read("sample_breach_export.csv")) == "hibp_csv"

    def test_garbage_not_detected(self):
        assert detect_type("x.csv", "foo,bar\n1,2\n") is None


# ── parsing produces unified schema ──────────────────────────────────────────────

class TestParsing:
    REQUIRED_FIELDS = ["source", "type", "title", "description", "severity",
                       "asset_tier", "asset_multiplier", "tags", "source_type",
                       "ingestion_method", "provenance"]

    def _check_schema(self, records):
        for r in records:
            for field in self.REQUIRED_FIELDS:
                assert field in r, f"missing field {field}"
            assert r["ingestion_method"] == "file_upload"

    def test_nmap_parses_open_ports(self):
        r = parse_upload("sample_nmap_scan.xml", _read("sample_nmap_scan.xml"), "auto")
        assert r.ok
        assert all(rec["type"] == "scan_finding" for rec in r.records)
        assert any("3389" in rec["title"] for rec in r.records)  # RDP present
        self._check_schema(r.records)

    def test_vuln_csv_parses_cves(self):
        r = parse_upload("sample_vuln_scan.csv", _read("sample_vuln_scan.csv"), "auto")
        assert r.ok
        assert all(rec["type"] == "vulnerability" for rec in r.records)
        # CVE-2024-38476 has CVSS 9.8 → must be CRITICAL
        crit = [rec for rec in r.records if rec["title"] == "CVE-2024-38476"]
        assert crit and crit[0]["severity"] == "CRITICAL"
        self._check_schema(r.records)

    def test_asset_csv_parses_tiers(self):
        r = parse_upload("sample_asset_inventory.csv", _read("sample_asset_inventory.csv"), "auto")
        assert r.ok
        assert all(rec["type"] == "asset" for rec in r.records)
        # carries a criticality map for scoring
        assert hasattr(r, "records_meta")
        assert "criticality_map" in r.records_meta

    def test_breach_csv_parses(self):
        r = parse_upload("sample_breach_export.csv", _read("sample_breach_export.csv"), "auto")
        assert r.ok
        assert all(rec["type"] == "breach" for rec in r.records)
        # pwn_count must be int (correlator sums it numerically)
        for rec in r.records:
            assert isinstance(rec["extra"]["pwn_count"], int)
        self._check_schema(r.records)


# ── error handling ───────────────────────────────────────────────────────────────

class TestErrorHandling:
    def test_invalid_xml_fails_cleanly(self):
        r = parse_upload("broken.xml", "<nmaprun><not closed", "nmap_xml")
        assert not r.ok
        assert r.errors

    def test_unknown_file_gives_guidance(self):
        r = parse_upload("x.csv", "a,b\n1,2\n", "auto")
        assert not r.ok
        assert any("file type" in e.lower() for e in r.errors)

    def test_forced_type_overrides_detection(self):
        # Force a breach CSV to be read as vuln CSV — should fail gracefully, not crash.
        r = parse_upload("sample_breach_export.csv", _read("sample_breach_export.csv"), "vuln_csv")
        assert isinstance(r.errors, list)  # no exception raised


# ── schema helpers ───────────────────────────────────────────────────────────────

class TestSchemaHelpers:
    def test_cvss_to_severity(self):
        assert severity_from_cvss(9.8) == "CRITICAL"
        assert severity_from_cvss(7.5) == "HIGH"
        assert severity_from_cvss(5.0) == "MEDIUM"
        assert severity_from_cvss(2.0) == "LOW"
        assert severity_from_cvss(None) == "UNKNOWN"

    def test_severity_label_aliases(self):
        assert normalize_severity_label("Critical") == "CRITICAL"
        assert normalize_severity_label("informational") == "LOW"
        assert normalize_severity_label("moderate") == "MEDIUM"

    def test_supported_types_includes_auto(self):
        keys = [k for k, _ in SUPPORTED_TYPES]
        assert "auto" in keys
        assert "nmap_xml" in keys
