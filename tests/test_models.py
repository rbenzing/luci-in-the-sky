"""
Unit tests for luci_sky.models — Finding, ScanResult, Severity, ScanMode.

These tests define the data contract for the models module.
All tests will fail with ImportError until luci_sky/models.py is implemented.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from luci_sky.models import (
    Category,
    Confidence,
    Finding,
    ScanMode,
    ScanResult,
    Severity,
    Target,
)


# ---------------------------------------------------------------------------
# Severity tests
# ---------------------------------------------------------------------------


class TestSeverityNumericRank:
    def test_severity_numeric_rank_ordering(self):
        """CRITICAL must outrank HIGH which outranks MEDIUM, LOW, INFO in strict order."""
        assert Severity.CRITICAL.numeric_rank > Severity.HIGH.numeric_rank
        assert Severity.HIGH.numeric_rank > Severity.MEDIUM.numeric_rank
        assert Severity.MEDIUM.numeric_rank > Severity.LOW.numeric_rank
        assert Severity.LOW.numeric_rank > Severity.INFO.numeric_rank

    def test_severity_numeric_rank_exact_values(self):
        """Exact numeric rank values must match the architecture specification."""
        assert Severity.CRITICAL.numeric_rank == 5
        assert Severity.HIGH.numeric_rank == 4
        assert Severity.MEDIUM.numeric_rank == 3
        assert Severity.LOW.numeric_rank == 2
        assert Severity.INFO.numeric_rank == 1


class TestSeverityFromCvss:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0.0, Severity.INFO),
            (0.1, Severity.LOW),
            (3.9, Severity.LOW),
            (4.0, Severity.MEDIUM),
            (6.9, Severity.MEDIUM),
            (7.0, Severity.HIGH),
            (8.9, Severity.HIGH),
            (9.0, Severity.CRITICAL),
            (10.0, Severity.CRITICAL),
        ],
    )
    def test_severity_from_cvss_boundary_values(self, score: float, expected: Severity):
        """from_cvss must map CVSS 3.1 boundary scores to the correct qualitative rating."""
        assert Severity.from_cvss(score) == expected


# ---------------------------------------------------------------------------
# ScanMode tests
# ---------------------------------------------------------------------------


class TestScanModeAllows:
    def test_scan_mode_allows_full_allows_all(self):
        """FULL mode must allow checks that require FULL, ACTIVE, or PASSIVE."""
        assert ScanMode.FULL.allows(ScanMode.FULL) is True
        assert ScanMode.FULL.allows(ScanMode.ACTIVE) is True
        assert ScanMode.FULL.allows(ScanMode.PASSIVE) is True

    def test_scan_mode_allows_active_allows_active_and_passive(self):
        """ACTIVE mode allows ACTIVE and PASSIVE but not FULL."""
        assert ScanMode.ACTIVE.allows(ScanMode.ACTIVE) is True
        assert ScanMode.ACTIVE.allows(ScanMode.PASSIVE) is True
        assert ScanMode.ACTIVE.allows(ScanMode.FULL) is False

    def test_scan_mode_allows_passive_allows_only_passive(self):
        """PASSIVE mode allows only PASSIVE checks."""
        assert ScanMode.PASSIVE.allows(ScanMode.PASSIVE) is True
        assert ScanMode.PASSIVE.allows(ScanMode.ACTIVE) is False
        assert ScanMode.PASSIVE.allows(ScanMode.FULL) is False


# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------


def _make_sample_finding(**overrides) -> Finding:
    """Helper that constructs a valid Finding with sensible defaults."""
    defaults = dict(
        id="LUCI-TEST-001",
        check_id="test_check",
        title="Test finding title",
        severity=Severity.HIGH,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        category=Category.TLS,
        confidence=Confidence.HIGH,
        description="A test vulnerability description.",
        evidence="GET /test returned 200 with sensitive data",
        affected_url="https://192.168.1.1/test",
        remediation="Apply the recommended patch.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2011-0001"],
        cve_ids=["CVE-2011-0001"],
        scan_mode=ScanMode.PASSIVE,
        timestamp=datetime(2026, 4, 23, 10, 0, 0),
        raw_response=None,
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestFindingToDict:
    def test_finding_to_dict_round_trips_all_fields(self):
        """to_dict() must return a dict containing all Finding fields with correct types."""
        finding = _make_sample_finding()
        d = finding.to_dict()

        assert isinstance(d, dict)
        assert d["id"] == "LUCI-TEST-001"
        assert d["check_id"] == "test_check"
        assert d["title"] == "Test finding title"
        assert d["cvss_score"] == 7.5
        assert isinstance(d["timestamp"], str)
        assert d["references"] == ["https://nvd.nist.gov/vuln/detail/CVE-2011-0001"]
        assert d["cve_ids"] == ["CVE-2011-0001"]
        assert d["raw_response"] is None

    def test_finding_to_dict_severity_is_string(self):
        """Serialized severity must be a plain string, not the Severity enum instance."""
        finding = _make_sample_finding()
        d = finding.to_dict()
        assert isinstance(d["severity"], str)
        assert d["severity"] == "high"

    def test_finding_to_dict_category_is_string(self):
        """Serialized category must be a plain string."""
        finding = _make_sample_finding()
        d = finding.to_dict()
        assert isinstance(d["category"], str)

    def test_finding_to_dict_scan_mode_is_string(self):
        """Serialized scan_mode must be a plain string."""
        finding = _make_sample_finding()
        d = finding.to_dict()
        assert isinstance(d["scan_mode"], str)
        assert d["scan_mode"] == "passive"

    def test_finding_to_dict_confidence_is_string(self):
        """Serialized confidence must be a plain string."""
        finding = _make_sample_finding()
        d = finding.to_dict()
        assert isinstance(d["confidence"], str)


# ---------------------------------------------------------------------------
# ScanResult tests
# ---------------------------------------------------------------------------


def _make_target() -> Target:
    return Target(
        url="https://192.168.1.1",
        host="192.168.1.1",
        port=443,
        scheme="https",
        detected_version="21.02.3",
        detected_luci_version=None,
        open_ports=[],
        accessible_paths=[],
        is_authenticated=False,
    )


class TestScanResultMethods:
    def test_scan_result_findings_by_severity(self):
        """findings_by_severity() must correctly bucket findings into per-severity lists."""
        critical_f = _make_sample_finding(id="C1", severity=Severity.CRITICAL, cvss_score=9.8)
        high_f = _make_sample_finding(id="H1", severity=Severity.HIGH, cvss_score=7.5)
        medium_f = _make_sample_finding(id="M1", severity=Severity.MEDIUM, cvss_score=5.0)

        result = ScanResult(
            target=_make_target(),
            findings=[critical_f, high_f, medium_f],
        )
        by_sev = result.findings_by_severity()

        assert critical_f in by_sev[Severity.CRITICAL]
        assert high_f in by_sev[Severity.HIGH]
        assert medium_f in by_sev[Severity.MEDIUM]
        assert by_sev[Severity.LOW] == []
        assert by_sev[Severity.INFO] == []

    def test_scan_result_findings_above_threshold(self):
        """findings_above(HIGH) must return only CRITICAL and HIGH findings."""
        critical_f = _make_sample_finding(id="C1", severity=Severity.CRITICAL, cvss_score=9.8)
        high_f = _make_sample_finding(id="H1", severity=Severity.HIGH, cvss_score=7.5)
        medium_f = _make_sample_finding(id="M1", severity=Severity.MEDIUM, cvss_score=5.0)

        result = ScanResult(
            target=_make_target(),
            findings=[critical_f, high_f, medium_f],
        )
        above_high = result.findings_above(Severity.HIGH)

        assert critical_f in above_high
        assert high_f in above_high
        assert medium_f not in above_high

    def test_scan_result_findings_above_includes_equal_threshold(self):
        """findings_above must include findings AT the threshold level (inclusive)."""
        medium_f = _make_sample_finding(id="M1", severity=Severity.MEDIUM, cvss_score=5.0)
        result = ScanResult(target=_make_target(), findings=[medium_f])

        # MEDIUM threshold must include the MEDIUM finding itself
        above_medium = result.findings_above(Severity.MEDIUM)
        assert medium_f in above_medium

    def test_scan_result_duration_seconds(self):
        """duration_seconds must equal finished_at minus started_at in seconds."""
        started = datetime(2026, 4, 23, 12, 0, 0)
        finished = started + timedelta(seconds=90)
        result = ScanResult(
            target=_make_target(),
            started_at=started,
            finished_at=finished,
        )
        assert abs(result.duration_seconds - 90.0) < 0.001

    def test_scan_result_duration_seconds_none_when_not_finished(self):
        """duration_seconds must be None when finished_at has not been set."""
        result = ScanResult(target=_make_target(), finished_at=None)
        assert result.duration_seconds is None

    def test_scan_result_to_dict_summary_counts(self):
        """to_dict()['summary'] must contain accurate counts per severity level."""
        critical_f = _make_sample_finding(id="C1", severity=Severity.CRITICAL, cvss_score=9.8)
        high_f = _make_sample_finding(id="H1", severity=Severity.HIGH, cvss_score=7.5)
        high_f2 = _make_sample_finding(id="H2", severity=Severity.HIGH, cvss_score=7.0)

        started = datetime(2026, 4, 23, 12, 0, 0)
        finished = started + timedelta(seconds=60)
        result = ScanResult(
            target=_make_target(),
            findings=[critical_f, high_f, high_f2],
            started_at=started,
            finished_at=finished,
        )
        d = result.to_dict()
        summary = d["summary"]

        assert summary["critical"] == 1
        assert summary["high"] == 2
        assert summary["medium"] == 0
        assert summary["low"] == 0
        assert summary["info"] == 0

    def test_scan_result_to_dict_contains_findings_list(self):
        """to_dict() must include a 'findings' key with serialized finding dicts."""
        f = _make_sample_finding()
        started = datetime(2026, 4, 23, 12, 0, 0)
        finished = started + timedelta(seconds=10)
        result = ScanResult(
            target=_make_target(),
            findings=[f],
            started_at=started,
            finished_at=finished,
        )
        d = result.to_dict()
        assert "findings" in d
        assert len(d["findings"]) == 1
        assert d["findings"][0]["id"] == "LUCI-TEST-001"


# ---------------------------------------------------------------------------
# Target tests
# ---------------------------------------------------------------------------


def _minimal_finding(**kw):
    base = dict(
        id="LUCI-X-001", check_id="c", title="t", severity=Severity.LOW,
        cvss_score=1.0, cvss_vector="v", category=Category.CONFIGURATION,
        confidence=Confidence.LOW, description="d", evidence="e",
        affected_url="u", remediation="r",
    )
    base.update(kw)
    return Finding(**base)


def test_finding_contributing_checks_defaults_empty():
    assert _minimal_finding().contributing_checks == []


def test_finding_to_dict_includes_contributing_checks():
    f = _minimal_finding(contributing_checks=["a", "b"])
    assert f.to_dict()["contributing_checks"] == ["a", "b"]


class TestTargetToDict:
    def test_target_to_dict_round_trips(self):
        """Target.to_dict() must serialize all fields to the correct Python types."""
        target = Target(
            url="https://192.168.1.1",
            host="192.168.1.1",
            port=443,
            scheme="https",
            detected_version="23.05.2",
            detected_luci_version="git-23.277.65432",
            open_ports=[22, 80, 443],
            accessible_paths=["/cgi-bin/luci/"],
            is_authenticated=True,
        )
        d = target.to_dict()

        assert d["url"] == "https://192.168.1.1"
        assert d["host"] == "192.168.1.1"
        assert d["port"] == 443
        assert d["scheme"] == "https"
        assert d["detected_version"] == "23.05.2"
        assert d["detected_luci_version"] == "git-23.277.65432"
        assert d["open_ports"] == [22, 80, 443]
        assert d["accessible_paths"] == ["/cgi-bin/luci/"]
        assert d["is_authenticated"] is True

    def test_target_to_dict_none_version_is_preserved(self):
        """Undetected version must serialize as None, not empty string."""
        target = Target(
            url="https://192.168.1.1",
            host="192.168.1.1",
            port=443,
            scheme="https",
            detected_version=None,
            detected_luci_version=None,
        )
        d = target.to_dict()
        assert d["detected_version"] is None
        assert d["detected_luci_version"] is None
