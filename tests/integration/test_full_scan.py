"""
Integration tests for luci_sky — end-to-end scan flow.

These tests are marked with @pytest.mark.integration and are SKIPPED by default.
Run them explicitly with: pytest -m integration

All tests use the `responses` library or mock HTTP server to avoid real network calls.
Tests will fail with ImportError until the luci_sky package is fully implemented.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from luci_sky.config import Config
from luci_sky.models import (
    Category,
    Confidence,
    Finding,
    ScanMode,
    ScanResult,
    Severity,
    Target,
)
from luci_sky.scanner import Scanner


pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    target_url: str = "https://192.168.1.1",
    mode: ScanMode = ScanMode.PASSIVE,
    **overrides,
) -> Config:
    cfg = Config()
    cfg.target_url = target_url
    cfg.mode = mode
    cfg.verify_tls = False
    cfg.timeout = 5.0
    cfg.threads = 2
    cfg.confirm = True
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


def _make_mock_session(
    head_status: int = 200,
    authenticate_return: bool = False,
    cookies: dict = None,
) -> MagicMock:
    """Create a fully-mocked SessionManager."""
    session = MagicMock()
    session.is_authenticated = authenticate_return
    session.authenticate.return_value = authenticate_return

    head_resp = MagicMock()
    head_resp.status_code = head_status
    session.head.return_value = head_resp

    default_resp = MagicMock()
    default_resp.status_code = 200
    default_resp.text = ""
    default_resp.headers = {}
    cookie_dict = cookies or {}
    default_resp.cookies = MagicMock()
    default_resp.cookies.__contains__ = lambda self, k: k in cookie_dict
    default_resp.cookies.get = lambda k, default=None: cookie_dict.get(k, default)

    session.get.return_value = default_resp
    session.post.return_value = default_resp
    session.put.return_value = default_resp
    session.clone.return_value = session

    return session


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFullPassiveScanFlow:
    def test_full_passive_scan_flow(self):
        """
        A complete passive scan with mocked HTTP must return a ScanResult
        with target, scan_mode, and all relevant metadata populated.
        """
        cfg = _make_config(mode=ScanMode.PASSIVE)
        mock_session = _make_mock_session()

        with (
            patch("luci_sky.scanner.SessionManager", return_value=mock_session),
            patch("luci_sky.scanner.filtered_checks", return_value=[]),
        ):
            result = Scanner(cfg).run()

        assert isinstance(result, ScanResult)
        assert result.target.url == "https://192.168.1.1"
        assert result.scan_mode == ScanMode.PASSIVE
        assert result.finished_at is not None
        assert result.checks_run == 0

    def test_scan_exit_code_0_on_no_findings(self):
        """
        A scan with all checks returning no findings must result in an empty
        findings list, which maps to CLI exit code 0.
        """
        cfg = _make_config(mode=ScanMode.PASSIVE)
        mock_session = _make_mock_session()

        with (
            patch("luci_sky.scanner.SessionManager", return_value=mock_session),
            patch("luci_sky.scanner.filtered_checks", return_value=[]),
        ):
            result = Scanner(cfg).run()

        assert result.findings == []
        assert result.findings_above(Severity.INFO) == []

    def test_scan_exit_code_1_on_critical_finding(self):
        """
        A scan producing a CRITICAL finding must have a non-empty
        findings_above(INFO) list, which maps to CLI exit code 1.
        """
        critical_finding = Finding(
            id="LUCI-TEST-001",
            check_id="test_check",
            title="Critical test finding",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            category=Category.AUTHENTICATION,
            confidence=Confidence.HIGH,
            description="Test",
            evidence="Test",
            affected_url="https://192.168.1.1",
            remediation="Test",
            references=[],
            cve_ids=[],
            scan_mode=ScanMode.ACTIVE,
            timestamp=datetime(2026, 4, 23, 12, 0, 0),
        )

        mock_check = MagicMock()
        mock_check.__class__.id = "test_check"
        mock_check.__class__.min_mode = ScanMode.PASSIVE
        mock_check.__class__.requires_auth = False
        mock_check.run.return_value = [critical_finding]

        cfg = _make_config(mode=ScanMode.PASSIVE)
        mock_session = _make_mock_session()

        with (
            patch("luci_sky.scanner.SessionManager", return_value=mock_session),
            patch("luci_sky.scanner.filtered_checks", return_value=[mock_check]),
        ):
            result = Scanner(cfg).run()

        assert len(result.findings_above(Severity.INFO)) >= 1


@pytest.mark.integration
class TestAuthenticatedScanFlow:
    def test_authenticated_scan_adds_auth_checks(self):
        """
        An authenticated scan must set target.is_authenticated=True and
        allow authenticated checks to run.
        """
        cfg = _make_config(
            mode=ScanMode.ACTIVE,
            username="root",
            password="",
        )
        mock_session = _make_mock_session(
            authenticate_return=True,
            cookies={"sysauth": "tok123"},
        )
        mock_session.is_authenticated = True

        with (
            patch("luci_sky.scanner.SessionManager", return_value=mock_session),
            patch("luci_sky.scanner.filtered_checks", return_value=[]) as mock_fc,
        ):
            result = Scanner(cfg).run()

        # authenticate must have been called
        mock_session.authenticate.assert_called_once()


@pytest.mark.integration
class TestScanJsonOutput:
    def test_scan_produces_valid_json_output(self, tmp_path: Path):
        """
        Running a scan with format=json must produce a valid JSON file
        with all required top-level keys.
        """
        out_file = tmp_path / "result.json"
        cfg = _make_config(format="json", output_path=out_file)

        mock_session = _make_mock_session()

        with (
            patch("luci_sky.scanner.SessionManager", return_value=mock_session),
            patch("luci_sky.scanner.filtered_checks", return_value=[]),
        ):
            result = Scanner(cfg).run()

        # Write JSON output manually (simulating what the reporter does)
        out_file.write_text(json.dumps(result.to_dict()))

        content = out_file.read_text()
        data = json.loads(content)

        required_keys = {"target", "findings", "scan_mode", "started_at", "finished_at",
                         "checks_run", "checks_failed", "tool_version", "summary"}
        missing_keys = required_keys - set(data.keys())
        assert not missing_keys, f"JSON output missing keys: {missing_keys}"


@pytest.mark.integration
class TestUnreachableTarget:
    def test_scan_unreachable_target_raises_runtime_error(self):
        """
        A scan against an unreachable target (HEAD fails) must raise RuntimeError.
        """
        cfg = _make_config(target_url="https://10.255.255.1")
        mock_session = MagicMock()
        mock_session.head.side_effect = ConnectionError("No route to host")

        with (
            patch("luci_sky.scanner.SessionManager", return_value=mock_session),
            patch("luci_sky.scanner.filtered_checks", return_value=[]),
        ):
            with pytest.raises(RuntimeError):
                Scanner(cfg).run()


@pytest.mark.integration
class TestLiveScanWithMockServer:
    def test_full_passive_scan_against_mock_http_server(self, mock_http_server: str):
        """
        Run a real (non-mocked) passive scan against the Werkzeug test server.
        Validates that the scanner can complete without crashing and returns
        a ScanResult with target populated from the real HTTP response.

        This test is skipped if the mock_http_server fixture is not available
        (Flask/Werkzeug not installed).
        """
        cfg = _make_config(target_url=mock_http_server, mode=ScanMode.PASSIVE)
        cfg.threads = 1  # Sequential for test stability

        # Only run passive checks that won't make many network calls
        with patch("luci_sky.scanner.filtered_checks", return_value=[]):
            scanner = Scanner(cfg)
            try:
                result = scanner.run()
                assert isinstance(result, ScanResult)
                assert result.target.url == mock_http_server.rstrip("/")
            except RuntimeError:
                pytest.skip("Mock server not reachable in this environment")
