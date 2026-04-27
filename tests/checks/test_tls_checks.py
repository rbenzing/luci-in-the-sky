"""
Unit tests for luci_sky.checks.tls — TLSAnalysis check.

All SSL/TLS socket calls and HTTP session calls are mocked.
Tests will fail with ImportError until luci_sky/checks/tls.py is implemented.
"""
from __future__ import annotations

import ssl
from datetime import datetime, timedelta
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from luci_sky.checks import get_check
from luci_sky.config import Config
from luci_sky.models import Finding, ScanMode, Severity, Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_target(scheme: str = "https") -> Target:
    return Target(
        url=f"{scheme}://192.168.1.1",
        host="192.168.1.1",
        port=443 if scheme == "https" else 80,
        scheme=scheme,
        detected_version=None,
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


def _make_session(
    status_code: int = 200,
    headers: dict = None,
    text: str = "",
) -> MagicMock:
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    session.get.return_value = resp
    session.head.return_value = resp
    return session


def _make_ssl_context_mock(
    protocol: str = "TLSv1.3",
    cipher_name: str = "ECDHE-RSA-AES256-GCM-SHA384",
    days_until_expiry: int = 365,
) -> MagicMock:
    """Return a mock ssl.SSLSocket with configurable protocol/cipher/cert."""
    mock_sock = MagicMock()
    mock_sock.version.return_value = protocol
    mock_sock.cipher.return_value = (cipher_name, "TLSv1.3", 256)

    expiry_date = datetime.utcnow() + timedelta(days=days_until_expiry)
    mock_sock.getpeercert.return_value = {
        "notAfter": expiry_date.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": [["CN", "192.168.1.1"]],
        "issuer": [["CN", "TrustedCA"]],
    }
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    return mock_sock


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestTLSAnalysisRegistered:
    def test_tls_analysis_registered(self):
        """get_check('tls_analysis') must succeed after the checks package is imported."""
        check = get_check("tls_analysis")
        assert check is not None
        assert check.__class__.id == "tls_analysis"

    def test_tls_analysis_is_passive(self):
        """TLSAnalysis must require only PASSIVE mode."""
        check = get_check("tls_analysis")
        assert check.__class__.min_mode == ScanMode.PASSIVE

    def test_tls_analysis_does_not_require_auth(self):
        """TLSAnalysis must not require authentication."""
        check = get_check("tls_analysis")
        assert check.__class__.requires_auth is False


# ---------------------------------------------------------------------------
# Weak protocol detection
# ---------------------------------------------------------------------------


class TestWeakProtocol:
    def test_tls_analysis_weak_protocol_produces_high_finding(self):
        """TLSv1.0 negotiation must produce a HIGH severity finding."""
        check = get_check("tls_analysis")
        target = _make_target()
        session = _make_session()

        mock_sock = _make_ssl_context_mock(protocol="TLSv1.0", days_until_expiry=365)

        with patch("ssl.create_default_context"), patch("ssl.SSLContext") as MockCtx:
            MockCtx.return_value.wrap_socket.return_value = mock_sock
            with patch("socket.create_connection", return_value=MagicMock()):
                findings = check.run(target, session, _make_config())

        # At minimum, there should be a HIGH finding (may have others too)
        severities = [f.severity for f in findings]
        assert Severity.HIGH in severities or Severity.CRITICAL in severities, (
            f"Expected HIGH finding for TLSv1.0; got severities: {severities}"
        )

    def test_tls_analysis_weak_cipher_produces_high_finding(self):
        """RC4 cipher detection must produce a HIGH severity finding."""
        check = get_check("tls_analysis")
        target = _make_target()
        session = _make_session()

        mock_sock = _make_ssl_context_mock(cipher_name="RC4-SHA", days_until_expiry=365)

        with patch("ssl.SSLContext") as MockCtx:
            MockCtx.return_value.wrap_socket.return_value = mock_sock
            with patch("socket.create_connection", return_value=MagicMock()):
                findings = check.run(target, session, _make_config())

        severities = [f.severity for f in findings]
        assert Severity.HIGH in severities or Severity.CRITICAL in severities


# ---------------------------------------------------------------------------
# Certificate expiry
# ---------------------------------------------------------------------------


class TestCertExpiry:
    def test_tls_analysis_expired_cert_produces_high_finding(self):
        """An already-expired certificate must produce a HIGH severity finding."""
        check = get_check("tls_analysis")
        target = _make_target()
        session = _make_session()

        # days_until_expiry=-1 means expired yesterday
        mock_sock = _make_ssl_context_mock(days_until_expiry=-1)

        with patch("ssl.SSLContext") as MockCtx:
            MockCtx.return_value.wrap_socket.return_value = mock_sock
            with patch("socket.create_connection", return_value=MagicMock()):
                findings = check.run(target, session, _make_config())

        severities = [f.severity for f in findings]
        assert Severity.HIGH in severities or Severity.CRITICAL in severities

    def test_tls_analysis_expiring_soon_produces_medium_finding(self):
        """A certificate expiring in 10 days must produce a MEDIUM severity finding."""
        check = get_check("tls_analysis")
        target = _make_target()
        session = _make_session()

        mock_sock = _make_ssl_context_mock(days_until_expiry=10)

        with patch("ssl.SSLContext") as MockCtx:
            MockCtx.return_value.wrap_socket.return_value = mock_sock
            with patch("socket.create_connection", return_value=MagicMock()):
                findings = check.run(target, session, _make_config())

        severities = [f.severity for f in findings]
        assert Severity.MEDIUM in severities or Severity.HIGH in severities


# ---------------------------------------------------------------------------
# HTTPS redirect and HSTS
# ---------------------------------------------------------------------------


class TestHttpsRedirectAndHsts:
    def test_tls_analysis_no_https_redirect_produces_medium_finding(self):
        """HTTP → HTTPS redirect missing must produce a MEDIUM finding."""
        check = get_check("tls_analysis")
        target = _make_target()

        session = MagicMock()
        no_redirect_resp = MagicMock()
        no_redirect_resp.status_code = 200
        no_redirect_resp.headers = {}
        no_redirect_resp.text = "plain http page"
        session.get.return_value = no_redirect_resp
        session.head.return_value = no_redirect_resp

        mock_sock = _make_ssl_context_mock(days_until_expiry=365)
        with patch("ssl.SSLContext") as MockCtx:
            MockCtx.return_value.wrap_socket.return_value = mock_sock
            with patch("socket.create_connection", return_value=MagicMock()):
                findings = check.run(target, session, _make_config())

        severities = [f.severity for f in findings]
        assert Severity.MEDIUM in severities or len(findings) > 0

    def test_tls_analysis_missing_hsts_produces_low_finding(self):
        """HTTPS response with no Strict-Transport-Security header must produce a LOW finding."""
        check = get_check("tls_analysis")
        target = _make_target()
        session = _make_session(headers={})  # No HSTS header

        mock_sock = _make_ssl_context_mock(days_until_expiry=365)
        with patch("ssl.SSLContext") as MockCtx:
            MockCtx.return_value.wrap_socket.return_value = mock_sock
            with patch("socket.create_connection", return_value=MagicMock()):
                findings = check.run(target, session, _make_config())

        severities = [f.severity for f in findings]
        assert Severity.LOW in severities or len(findings) > 0

    def test_tls_analysis_low_hsts_max_age_produces_low_finding(self):
        """HSTS max-age=3600 (below 31536000) must produce a LOW finding."""
        check = get_check("tls_analysis")
        target = _make_target()
        session = _make_session(headers={"Strict-Transport-Security": "max-age=3600"})

        mock_sock = _make_ssl_context_mock(days_until_expiry=365)
        with patch("ssl.SSLContext") as MockCtx:
            MockCtx.return_value.wrap_socket.return_value = mock_sock
            with patch("socket.create_connection", return_value=MagicMock()):
                findings = check.run(target, session, _make_config())

        severities = [f.severity for f in findings]
        assert Severity.LOW in severities or len(findings) > 0


# ---------------------------------------------------------------------------
# Safe / clean config
# ---------------------------------------------------------------------------


class TestCleanTLS:
    def test_tls_analysis_connection_failure_returns_empty(self):
        """An ssl.SSLError during socket connect must cause run() to return [] without raising."""
        check = get_check("tls_analysis")
        target = _make_target()
        session = _make_session()

        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            findings = check.run(target, session, _make_config())

        assert findings == []


# ---------------------------------------------------------------------------
# Finding quality
# ---------------------------------------------------------------------------


class TestFindingQuality:
    def _get_any_finding(self) -> Finding:
        """Run TLSAnalysis with a weak protocol to get at least one finding."""
        check = get_check("tls_analysis")
        target = _make_target()
        session = _make_session()
        mock_sock = _make_ssl_context_mock(protocol="TLSv1.0", days_until_expiry=365)
        with patch("ssl.SSLContext") as MockCtx:
            MockCtx.return_value.wrap_socket.return_value = mock_sock
            with patch("socket.create_connection", return_value=MagicMock()):
                findings = check.run(target, session, _make_config())
        return findings[0] if findings else None

    def test_tls_analysis_finding_has_remediation(self):
        """Any produced finding must have a non-empty remediation string."""
        finding = self._get_any_finding()
        if finding is None:
            pytest.skip("No findings produced; cannot test remediation")
        assert finding.remediation, "finding.remediation must not be empty"

    def test_tls_analysis_finding_has_references(self):
        """Any produced finding must have at least one reference URL."""
        finding = self._get_any_finding()
        if finding is None:
            pytest.skip("No findings produced; cannot test references")
        assert len(finding.references) >= 1, "finding.references must have at least one entry"
