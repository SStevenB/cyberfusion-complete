# tests/test_pipeline.py
#
# Unit tests for the core pipeline logic.
# Run with: pytest tests/ -v
#
# Testing philosophy: focus on the logic that could silently break
# (scoring, correlation, normalization) rather than API calls.
# API calls should be tested with mocks in a real project.

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.risk_scorer import score_finding, score_to_label, SEVERITY_BASE
from analysis.normalizer import _make_normalized_item, get_asset_context
from analysis.correlator import (
    rule_kev_cve_with_matching_scan_service,
    rule_breach_with_password_data,
    rule_vpn_credential_leak,
    rule_critical_cve_plus_exposed_service,
    rule_multiple_breach_signals,
)


# ── score_to_label ─────────────────────────────────────────────────────────────

class TestScoreToLabel:
    def test_critical_threshold(self):
        assert score_to_label(65) == "CRITICAL"
        assert score_to_label(100) == "CRITICAL"

    def test_high_threshold(self):
        assert score_to_label(45) == "HIGH"
        assert score_to_label(64) == "HIGH"

    def test_medium_threshold(self):
        assert score_to_label(25) == "MEDIUM"
        assert score_to_label(44) == "MEDIUM"

    def test_low_threshold(self):
        assert score_to_label(0) == "LOW"
        assert score_to_label(24) == "LOW"


# ── score_finding ──────────────────────────────────────────────────────────────

class TestScoreFinding:
    def _make_finding(self, severity="HIGH", confidence="HIGH", rule_id="CORR-001"):
        return {
            "rule_id": rule_id,
            "rule_name": "Test Rule",
            "severity": severity,
            "confidence": confidence,
            "description": "Test",
            "matched_scan": ["port 22/ssh on host01"],
            "matched_exposure": ["exposure signal 1"],
            "affected_assets": [],
        }

    def test_score_increases_with_severity(self):
        low  = score_finding(self._make_finding(severity="LOW"))
        high = score_finding(self._make_finding(severity="HIGH"))
        crit = score_finding(self._make_finding(severity="CRITICAL"))
        assert low["risk_score"] < high["risk_score"] < crit["risk_score"]

    def test_kev_bonus_applied(self):
        without_kev = score_finding(self._make_finding(rule_id="CORR-004"))
        finding_with_kev = {**self._make_finding(rule_id="CORR-004"), "kev_confirmed_cves": ["CVE-2024-1234"]}
        with_kev = score_finding(finding_with_kev)
        assert with_kev["risk_score"] > without_kev["risk_score"]

    def test_score_capped_at_100(self):
        finding = {
            "rule_id": "CORR-003",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "kev_confirmed_cves": ["CVE-1", "CVE-2", "CVE-3"],
            "matched_scan": ["s1", "s2", "s3", "s4", "s5"],
            "matched_exposure": ["e1", "e2", "e3"],
            "matched_cves": ["c1", "c2"],
            "affected_assets": [],
        }
        result = score_finding(finding)
        assert result["risk_score"] <= 100

    def test_score_breakdown_populated(self):
        result = score_finding(self._make_finding())
        assert len(result["score_breakdown"]) > 0
        assert any("severity" in line.lower() for line in result["score_breakdown"])

    def test_risk_label_in_result(self):
        result = score_finding(self._make_finding(severity="CRITICAL", confidence="HIGH"))
        assert result["risk_label"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


# ── normalizer ─────────────────────────────────────────────────────────────────

class TestNormalizer:
    def test_make_normalized_item_required_fields(self):
        item = _make_normalized_item(
            source="test", item_type="vulnerability",
            title="CVE-2024-0001", description="Test desc",
            severity="HIGH", timestamp="2024-01-01"
        )
        required = ["source", "type", "title", "description", "severity",
                    "timestamp", "asset", "tags", "extra", "normalized_at"]
        for field in required:
            assert field in item, f"Missing field: {field}"

    def test_severity_is_uppercased(self):
        item = _make_normalized_item(
            source="test", item_type="vulnerability",
            title="T", description="D", severity="critical", timestamp=""
        )
        assert item["severity"] == "CRITICAL"

    def test_unknown_severity_fallback(self):
        item = _make_normalized_item(
            source="test", item_type="vulnerability",
            title="T", description="D", severity="", timestamp=""
        )
        assert item["severity"] == "UNKNOWN"

    def test_asset_context_tier1(self):
        ctx = get_asset_context("vpn01.northstar-analytics.local")
        assert ctx["tier"] == 1
        assert ctx["multiplier"] > 1.0

    def test_asset_context_unknown(self):
        ctx = get_asset_context("unknown-host.local")
        assert ctx["tier"] == 3
        assert ctx["multiplier"] == 1.0

    def test_tags_default_empty_list(self):
        item = _make_normalized_item(
            source="test", item_type="vulnerability",
            title="T", description="D", severity="LOW", timestamp=""
        )
        assert item["tags"] == []


# ── correlator ─────────────────────────────────────────────────────────────────

def _make_item(type_, title, tags=None, severity="MEDIUM", extra=None):
    return {
        "type": type_,
        "title": title,
        "description": title,
        "tags": tags or [],
        "severity": severity,
        "extra": extra or {},
        "asset": "test-host",
    }


class TestCorrelationRules:
    def test_vpn_rule_triggers_on_vpn_tag(self):
        items = [_make_item("exposure", "VPN credentials found", tags=["vpn"])]
        findings = rule_vpn_credential_leak(items)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "CORR-003"

    def test_vpn_rule_no_trigger_without_vpn(self):
        items = [_make_item("exposure", "Some other signal", tags=["ssh"])]
        findings = rule_vpn_credential_leak(items)
        assert len(findings) == 0

    def test_kev_rule_triggers_with_kev_tag_and_scan(self):
        items = [
            _make_item("vulnerability", "CVE-2024-1234", tags=["kev_confirmed"], severity="CRITICAL"),
            _make_item("scan_finding", "Open port 80/http on web01"),
        ]
        findings = rule_kev_cve_with_matching_scan_service(items)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "CORR-006"

    def test_kev_rule_no_trigger_without_scan(self):
        items = [
            _make_item("vulnerability", "CVE-2024-1234", tags=["kev_confirmed"]),
        ]
        findings = rule_kev_cve_with_matching_scan_service(items)
        assert len(findings) == 0

    def test_breach_rule_triggers_with_passwords_and_service(self):
        items = [
            _make_item("breach", "Corp breach", tags=["passwords"], severity="CRITICAL"),
            _make_item("scan_finding", "Open port 22/ssh on host01"),
        ]
        findings = rule_breach_with_password_data(items)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "CORR-007"
        assert findings[0]["severity"] == "CRITICAL"

    def test_multiple_breach_signals_rule(self):
        items = [
            _make_item("breach", "Breach 1", tags=["passwords"]),
            _make_item("exposure", "Exposure 1", tags=["rdp"]),
            _make_item("breach", "Breach 2", tags=["emails"]),
        ]
        findings = rule_multiple_breach_signals(items)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "CORR-008"

    def test_multiple_breach_rule_no_trigger_below_threshold(self):
        items = [
            _make_item("breach", "Breach 1"),
            _make_item("exposure", "Exposure 1"),
        ]
        findings = rule_multiple_breach_signals(items)
        assert len(findings) == 0  # Need >= 3 signals

    def test_web_cve_rule_requires_both_cve_and_scan(self):
        items = [
            _make_item("vulnerability", "CVE-2024-nginx-rce", tags=["cve"], severity="CRITICAL"),
        ]
        findings = rule_critical_cve_plus_exposed_service(items)
        assert len(findings) == 0  # No scan finding → no correlation

        items.append(_make_item("scan_finding", "Open port 80/http on web01"))
        findings = rule_critical_cve_plus_exposed_service(items)
        assert len(findings) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
