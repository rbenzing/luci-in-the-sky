"""
Unit tests for luci_sky.scanner — ScanEngine orchestration, concurrency, progress.

All HTTP calls and check.run() invocations are mocked.
Tests will fail with ImportError until luci_sky/scanner.py is implemented.
"""
from __future__ import annotations

from datetime import datetime
from typing import List
from unittest.mock import MagicMock, patch, call

import pytest

from luci_sky.config import Config
from luci_sky.models import (
    Category,
    Confidence,
    Finding,
    Phase,
    ScanMode,
    ScanResult,
    Severity,
    Target,
)
from luci_sky.scanner import Scanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**overrides) -> Config:
    cfg = Config()
    cfg.target_url = "https://192.168.1.1"
    cfg.mode = ScanMode.PASSIVE
    cfg.threads = 2
    cfg.timeout = 5.0
    cfg.verify_tls = False
    cfg.confirm = True
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


def _make_finding(
    finding_id: str,
    severity: Severity = Severity.HIGH,
    cvss_score: float = 7.5,
) -> Finding:
    return Finding(
        id=finding_id,
        check_id="mock_check",
        title=f"Mock finding {finding_id}",
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        category=Category.TLS,
        confidence=Confidence.HIGH,
        description="Mock description",
        evidence="Mock evidence",
        affected_url="https://192.168.1.1/test",
        remediation="Mock remediation",
        references=[],
        cve_ids=[],
        scan_mode=ScanMode.PASSIVE,
        timestamp=datetime(2026, 4, 23, 12, 0, 0),
    )


def _make_mock_check(check_id: str, findings: list = None) -> MagicMock:
    """Build a mock Check instance that returns the given findings from run()."""
    check = MagicMock()
    check.__class__ = MagicMock()
    check.__class__.id = check_id
    check.__class__.min_mode = ScanMode.PASSIVE
    check.__class__.severity = Severity.HIGH
    check.__class__.requires_auth = False
    check.run.return_value = findings or []
    return check


# ---------------------------------------------------------------------------
# _build_target
# ---------------------------------------------------------------------------


class TestBuildTarget:
    def test_scanner_build_target_http(self):
        """_build_target must extract scheme=http and port=80 from a plain HTTP URL."""
        cfg = _make_config(target_url="http://192.168.1.1")
        scanner = Scanner(cfg)
        target = scanner._build_target("http://192.168.1.1")
        assert target.scheme == "http"
        assert target.port == 80
        assert target.host == "192.168.1.1"

    def test_scanner_build_target_https_with_path(self):
        """_build_target must handle custom ports and strip the path from the base URL."""
        cfg = _make_config(target_url="https://192.168.1.1:8443/cgi-bin/luci")
        scanner = Scanner(cfg)
        target = scanner._build_target("https://192.168.1.1:8443/cgi-bin/luci")
        assert target.scheme == "https"
        assert target.port == 8443
        assert target.host == "192.168.1.1"

    def test_scanner_build_target_strips_trailing_slash(self):
        """Target URL must have no trailing slash."""
        cfg = _make_config(target_url="https://192.168.1.1/")
        scanner = Scanner(cfg)
        target = scanner._build_target("https://192.168.1.1/")
        assert not target.url.endswith("/")

    def test_scanner_build_target_https_default_port(self):
        """_build_target must default to port 443 for HTTPS URLs without explicit port."""
        cfg = _make_config(target_url="https://192.168.1.1")
        scanner = Scanner(cfg)
        target = scanner._build_target("https://192.168.1.1")
        assert target.port == 443


# ---------------------------------------------------------------------------
# _validate_target
# ---------------------------------------------------------------------------


class TestValidateTarget:
    def test_scanner_validate_target_raises_on_unreachable(self):
        """_validate_target must raise RuntimeError when the HEAD request fails."""
        cfg = _make_config()
        scanner = Scanner(cfg)
        target = Target(
            url="https://192.168.1.1",
            host="192.168.1.1",
            port=443,
            scheme="https",
            detected_version=None,
            detected_luci_version=None,
        )
        mock_session = MagicMock()
        mock_session.head.side_effect = ConnectionError("No route to host")

        with pytest.raises(RuntimeError):
            scanner._validate_target(target, mock_session)

    def test_scanner_validate_target_succeeds_on_200(self):
        """_validate_target must not raise when the HEAD request succeeds."""
        cfg = _make_config()
        scanner = Scanner(cfg)
        target = Target(
            url="https://192.168.1.1",
            host="192.168.1.1",
            port=443,
            scheme="https",
            detected_version=None,
            detected_luci_version=None,
        )
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.head.return_value = mock_response

        # Must not raise
        scanner._validate_target(target, mock_session)


# ---------------------------------------------------------------------------
# Scanner.run() — full lifecycle
# ---------------------------------------------------------------------------


class TestScannerRun:
    def _run_with_mocked_checks(
        self,
        checks: list,
        extra_config: dict = None,
        session_authenticate_return: bool = False,
    ) -> ScanResult:
        """Helper: run scanner with mocked session and mocked filtered_checks()."""
        cfg = _make_config(**(extra_config or {}))
        mock_session = MagicMock()
        mock_session.is_authenticated = False
        mock_session.authenticate.return_value = session_authenticate_return
        mock_session.head.return_value = MagicMock(status_code=200)
        mock_session.clone.return_value = mock_session

        with (
            patch("luci_sky.scanner.SessionManager", return_value=mock_session),
            patch("luci_sky.scanner.filtered_checks", return_value=checks),
        ):
            scanner = Scanner(cfg)
            return scanner.run()

    def test_scanner_run_with_mocked_checks_returns_scan_result(self):
        """scanner.run() must return a ScanResult."""
        check = _make_mock_check("mock_tls", [_make_finding("F1")])
        result = self._run_with_mocked_checks([check])
        assert isinstance(result, ScanResult)

    def test_scanner_run_aggregates_all_findings(self):
        """scanner.run() must collect all findings from all checks into the result."""
        check1 = _make_mock_check("chk1", [_make_finding("F1"), _make_finding("F2")])
        check2 = _make_mock_check("chk2", [_make_finding("F3"), _make_finding("F4")])
        result = self._run_with_mocked_checks([check1, check2])
        assert len(result.findings) == 4

    def test_scanner_findings_sorted_by_severity_then_cvss(self):
        """Findings in ScanResult must be sorted: highest severity first, then highest CVSS."""
        critical_high = _make_finding("C1", Severity.CRITICAL, 9.8)
        critical_low = _make_finding("C2", Severity.CRITICAL, 8.8)
        high_finding = _make_finding("H1", Severity.HIGH, 7.5)

        check = _make_mock_check("chk", [high_finding, critical_low, critical_high])
        result = self._run_with_mocked_checks([check])

        assert result.findings[0].id == "C1"
        assert result.findings[1].id == "C2"
        assert result.findings[2].id == "H1"

    def test_scanner_check_failure_increments_checks_failed(self):
        """A check that raises must increment result.checks_failed."""
        failing_check = _make_mock_check("fail_chk", [])
        failing_check.run.side_effect = RuntimeError("Check exploded")

        good_check = _make_mock_check("good_chk", [_make_finding("F1")])

        result = self._run_with_mocked_checks([failing_check, good_check])

        assert result.checks_failed >= 1

    def test_scanner_check_failure_does_not_abort_scan(self):
        """A failing check must not prevent other checks from running."""
        failing_check = _make_mock_check("fail_chk", [])
        failing_check.run.side_effect = RuntimeError("Check exploded")

        good_check = _make_mock_check("good_chk", [_make_finding("F1")])

        result = self._run_with_mocked_checks([failing_check, good_check])

        # The good check's finding must still appear
        finding_ids = [f.id for f in result.findings]
        assert "F1" in finding_ids

    def test_scanner_calls_authenticate_when_credentials_set(self):
        """Scanner must call session.authenticate() when username is configured."""
        cfg = _make_config(username="root", password="")
        mock_session = MagicMock()
        mock_session.is_authenticated = True
        mock_session.authenticate.return_value = True
        mock_session.head.return_value = MagicMock(status_code=200)
        mock_session.clone.return_value = mock_session

        with (
            patch("luci_sky.scanner.SessionManager", return_value=mock_session),
            patch("luci_sky.scanner.filtered_checks", return_value=[]),
        ):
            Scanner(cfg).run()

        mock_session.authenticate.assert_called_once()

    def test_scanner_calls_logout_after_authenticated_scan(self):
        """Scanner must call session.logout() after an authenticated scan completes."""
        cfg = _make_config(username="root", password="")
        mock_session = MagicMock()
        mock_session.is_authenticated = True
        mock_session.authenticate.return_value = True
        mock_session.head.return_value = MagicMock(status_code=200)
        mock_session.clone.return_value = mock_session

        with (
            patch("luci_sky.scanner.SessionManager", return_value=mock_session),
            patch("luci_sky.scanner.filtered_checks", return_value=[]),
        ):
            Scanner(cfg).run()

        mock_session.logout.assert_called_once()

    def test_scanner_emits_progress_events(self):
        """Scanner must call the progress_callback with 'started' and 'done' events."""
        events: list = []
        callback = lambda event: events.append(event)

        check = _make_mock_check("test_chk", [])

        cfg = _make_config()
        mock_session = MagicMock()
        mock_session.is_authenticated = False
        mock_session.head.return_value = MagicMock(status_code=200)
        mock_session.clone.return_value = mock_session

        with (
            patch("luci_sky.scanner.SessionManager", return_value=mock_session),
            patch("luci_sky.scanner.filtered_checks", return_value=[check]),
        ):
            Scanner(cfg, progress_callback=callback).run()

        statuses = [e["status"] for e in events if isinstance(e, dict)]
        assert "started" in statuses or "done" in statuses

    def test_scanner_run_raises_runtime_error_on_unreachable_target(self):
        """scanner.run() must raise RuntimeError when the target is unreachable."""
        cfg = _make_config()
        mock_session = MagicMock()
        mock_session.head.side_effect = ConnectionError("No route to host")

        with (
            patch("luci_sky.scanner.SessionManager", return_value=mock_session),
            patch("luci_sky.scanner.filtered_checks", return_value=[]),
        ):
            with pytest.raises(RuntimeError):
                Scanner(cfg).run()

    def test_scanner_result_has_finished_at_set(self):
        """ScanResult.finished_at must be set after scanner.run() completes."""
        result = self._run_with_mocked_checks([])
        assert result.finished_at is not None
        assert isinstance(result.finished_at, datetime)

    def test_scanner_result_checks_run_count(self):
        """ScanResult.checks_run must equal the number of checks that were executed."""
        checks = [_make_mock_check(f"chk{i}", []) for i in range(3)]
        result = self._run_with_mocked_checks(checks)
        assert result.checks_run == 3


class _ReconSetsVersion:
    id = "recon_probe"
    phase = Phase.RECON

    def run(self, target, session, config):
        target.detected_version = "21.02.3"
        return []


class _AnalysisReadsVersion:
    id = "analysis_reader"
    phase = Phase.ANALYSIS
    seen = {}

    def run(self, target, session, config):
        type(self).seen["version"] = target.detected_version
        return []


def test_recon_runs_before_analysis():
    recon = _ReconSetsVersion()
    analysis = _AnalysisReadsVersion()
    type(analysis).seen = {}
    cfg = Config()
    cfg.target_url = "https://192.168.1.1"

    # Patch the underlying `filtered_checks`/`SessionManager` names (not the
    # `_get_filtered_checks`/`_make_session_manager` indirections) so this
    # keeps working after tests/test_packaging.py::test_no_circular_imports
    # reloads luci_sky.* mid-session — see the indirections' docstrings.
    with patch("luci_sky.scanner.filtered_checks", return_value=[analysis, recon]), \
         patch("luci_sky.scanner.SessionManager") as MS:
        MS.return_value.clone.return_value = MS.return_value
        MS.return_value.authenticate.return_value = False
        Scanner(cfg).run()

    assert _AnalysisReadsVersion.seen["version"] == "21.02.3"


def test_progress_events_include_totals():
    events = []

    class _C:
        id = "p_check"
        phase = Phase.RECON
        def run(self, target, session, config):
            return []

    cfg = Config()
    cfg.target_url = "https://192.168.1.1"
    # Patch the underlying `filtered_checks`/`SessionManager` names (not the
    # `_get_filtered_checks`/`_make_session_manager` indirections) — see the
    # indirections' docstrings and the comment on test_recon_runs_before_analysis.
    with patch("luci_sky.scanner.filtered_checks", return_value=[_C()]), \
         patch("luci_sky.scanner.SessionManager") as MS:
        MS.return_value.clone.return_value = MS.return_value
        MS.return_value.authenticate.return_value = False
        Scanner(cfg, progress_callback=events.append).run()

    done = [e for e in events if e["status"] == "done"]
    assert done and done[0]["total"] == 1 and done[0]["completed"] == 1
    assert "phase" in done[0]
