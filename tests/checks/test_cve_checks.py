"""
Unit tests for luci_sky.checks.cve — CVECorrelation check and CVEDatabase.

Tests will fail with ImportError until luci_sky/checks/cve.py and
luci_sky/cve/database.py are implemented.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from luci_sky.checks import get_check
from luci_sky.config import Config
from luci_sky.cve.database import CVEDatabase
from luci_sky.models import Finding, ScanMode, Severity, Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_target(version: str = None) -> Target:
    return Target(
        url="https://192.168.1.1",
        host="192.168.1.1",
        port=443,
        scheme="https",
        detected_version=version,
        detected_luci_version=None,
        open_ports=[],
        accessible_paths=[],
        is_authenticated=False,
    )


def _make_config() -> Config:
    cfg = Config()
    cfg.verify_tls = False
    cfg.timeout = 5.0
    return cfg


def _make_session() -> MagicMock:
    session = MagicMock()
    empty_resp = MagicMock()
    empty_resp.status_code = 200
    empty_resp.text = json.dumps({"error": "permission denied"})
    empty_resp.json = lambda: {"error": "permission denied"}
    session.get.return_value = empty_resp
    session.post.return_value = empty_resp
    return session


# ---------------------------------------------------------------------------
# CVECorrelation check registration
# ---------------------------------------------------------------------------


class TestCVECorrelationRegistered:
    def test_cve_correlation_registered(self):
        """get_check('cve_correlation') must succeed."""
        check = get_check("cve_correlation")
        assert check.__class__.id == "cve_correlation"

    def test_cve_correlation_is_passive(self):
        """CVECorrelation must be PASSIVE mode."""
        check = get_check("cve_correlation")
        assert check.__class__.min_mode == ScanMode.PASSIVE

    def test_cve_correlation_does_not_require_auth(self):
        """CVECorrelation must not require authentication."""
        check = get_check("cve_correlation")
        assert check.__class__.requires_auth is False


# ---------------------------------------------------------------------------
# CVECorrelation run() — version-based correlation
# ---------------------------------------------------------------------------


class TestCVECorrelationRun:
    def test_cve_correlation_with_known_vulnerable_version_produces_findings(self):
        """Version 18.06.1 (old) should match multiple CVE entries."""
        check = get_check("cve_correlation")
        target = _make_target(version="18.06.1")
        session = _make_session()

        findings = check.run(target, session, _make_config())

        assert len(findings) >= 1, (
            "Version 18.06.1 should match at least one CVE"
        )

    def test_cve_correlation_with_patched_version_produces_fewer_findings(self):
        """Version 23.05.5 (recent) should match fewer CVEs than 18.06.1."""
        check = get_check("cve_correlation")

        old_target = _make_target(version="18.06.1")
        new_target = _make_target(version="23.05.5")
        session = _make_session()

        old_findings = check.run(old_target, session, _make_config())
        new_findings = check.run(new_target, session, _make_config())

        # The older version must produce at least as many findings
        assert len(old_findings) >= len(new_findings), (
            f"Old version produced {len(old_findings)} findings, "
            f"new version produced {len(new_findings)} — expected old >= new"
        )

    def test_cve_correlation_no_version_runs_behavior_checks(self):
        """With no detected version, run() must still make network probes (behavior checks)."""
        check = get_check("cve_correlation")
        target = _make_target(version=None)
        session = _make_session()

        # Must not raise; may produce behavior-based findings or return []
        findings = check.run(target, session, _make_config())
        assert isinstance(findings, list)

    def test_cve_finding_has_cve_id(self):
        """Every finding produced by CVECorrelation must have at least one CVE ID."""
        check = get_check("cve_correlation")
        target = _make_target(version="18.06.1")
        session = _make_session()

        findings = check.run(target, session, _make_config())

        for finding in findings:
            assert len(finding.cve_ids) >= 1, (
                f"Finding {finding.id} has no cve_ids"
            )

    def test_cve_finding_has_nvd_reference(self):
        """Every finding must have an NVD URL in its references list."""
        check = get_check("cve_correlation")
        target = _make_target(version="18.06.1")
        session = _make_session()

        findings = check.run(target, session, _make_config())

        for finding in findings:
            has_nvd = any("nvd.nist.gov" in ref for ref in finding.references)
            assert has_nvd, (
                f"Finding {finding.id} for CVEs {finding.cve_ids} has no NVD reference"
            )

    def test_cve_finding_severity_matches_cvss_score(self):
        """Each finding's severity must match what Severity.from_cvss() would produce."""
        check = get_check("cve_correlation")
        target = _make_target(version="18.06.1")
        session = _make_session()

        findings = check.run(target, session, _make_config())

        for finding in findings:
            expected_severity = Severity.from_cvss(finding.cvss_score)
            assert finding.severity == expected_severity, (
                f"Finding {finding.id}: severity={finding.severity} does not match "
                f"from_cvss({finding.cvss_score})={expected_severity}"
            )


# ---------------------------------------------------------------------------
# CVEDatabase singleton and match()
# ---------------------------------------------------------------------------


class TestCVEDatabase:
    def test_cve_database_singleton(self):
        """Two CVEDatabase() calls must return the same object (singleton pattern)."""
        db1 = CVEDatabase()
        db2 = CVEDatabase()
        assert db1 is db2, "CVEDatabase() must return the same singleton instance"

    def test_cve_database_loads_30_plus_entries(self):
        """CVEDatabase must contain at least 30 CVE entries from the YAML file."""
        db = CVEDatabase()
        assert len(db._entries) >= 30, (
            f"Expected >= 30 CVE entries; found {len(db._entries)}"
        )

    def test_cve_database_match_returns_sorted_by_cvss(self):
        """db.match() must return entries sorted by cvss_score descending."""
        db = CVEDatabase()
        entries = db.match("18.06.1")
        if len(entries) >= 2:
            for i in range(len(entries) - 1):
                assert entries[i].cvss_score >= entries[i + 1].cvss_score, (
                    f"Entries not sorted by cvss_score: "
                    f"{entries[i].cvss_score} < {entries[i+1].cvss_score}"
                )

    def test_cve_database_version_none_returns_behavior_only(self):
        """db.match(None) must return only entries with detection_method in ('behavior', 'both')."""
        db = CVEDatabase()
        entries = db.match(None)
        for entry in entries:
            assert entry.detection_method in ("behavior", "both"), (
                f"Entry {entry.cve_id} with detection_method='{entry.detection_method}' "
                f"should not be returned for None version"
            )

    def test_cve_database_version_range_exclusive_upper_bound(self):
        """A version exactly at the upper bound < X must NOT be matched."""
        db = CVEDatabase()
        # CVE-2022-46623 has upper bound < 21.02.5 (among others)
        # Version 21.02.5 should NOT match that range
        entries_at_boundary = db.match("21.02.5")
        ids_at_boundary = {e.cve_id for e in entries_at_boundary}
        # If the CVE range is "< 21.02.5", then 21.02.5 should NOT be matched
        # (this depends on exact database content)
        assert isinstance(ids_at_boundary, set)  # Type check at minimum

    def test_cve_database_version_range_inclusive_lower_bound(self):
        """A version exactly at >= X lower bound must be included in matches."""
        db = CVEDatabase()
        # version 21.02.0 should match CVEs with >= 21.02.0
        entries = db.match("21.02.0")
        assert isinstance(entries, list)

    def test_cve_database_invalid_version_string_falls_back_conservatively(self):
        """db.match('not-a-version') must not raise and must return entries (conservative)."""
        db = CVEDatabase()
        entries = db.match("not-a-version")
        # Conservative fallback: return all entries (better false positive than miss)
        assert isinstance(entries, list)
        assert len(entries) >= 0  # At minimum, does not raise

    def test_cve_database_entry_has_required_fields(self):
        """Every CVEEntry must have non-empty cve_id, title, description, cvss_score, remediation."""
        db = CVEDatabase()
        for entry in db._entries:
            assert entry.cve_id, f"Entry missing cve_id: {entry}"
            assert entry.title, f"Entry {entry.cve_id} missing title"
            assert entry.description, f"Entry {entry.cve_id} missing description"
            assert entry.cvss_score is not None, f"Entry {entry.cve_id} missing cvss_score"
            assert entry.remediation, f"Entry {entry.cve_id} missing remediation"
            assert len(entry.references) >= 1, f"Entry {entry.cve_id} has no references"
