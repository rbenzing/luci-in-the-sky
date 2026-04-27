"""
Shared pytest fixtures for the luci-redteam test suite.

All fixtures in this file are available to every test module without an
explicit import — pytest discovers conftest.py automatically.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

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
from luci_sky.config import Config


# ---------------------------------------------------------------------------
# Target fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_target() -> Target:
    """Return a minimal Target with no detected version or authenticated state."""
    return Target(
        url="https://192.168.1.1",
        host="192.168.1.1",
        port=443,
        scheme="https",
        detected_version=None,
        detected_luci_version=None,
        open_ports=[],
        accessible_paths=[],
        is_authenticated=False,
    )


@pytest.fixture()
def mock_target_with_version(mock_target: Target) -> Target:
    """Return a Target with a known OpenWrt version detected."""
    mock_target.detected_version = "21.02.3"
    return mock_target


@pytest.fixture()
def mock_target_http() -> Target:
    """Return an HTTP (non-TLS) Target for HTTP-specific tests."""
    return Target(
        url="http://192.168.1.1",
        host="192.168.1.1",
        port=80,
        scheme="http",
        detected_version=None,
        detected_luci_version=None,
        open_ports=[],
        accessible_paths=[],
        is_authenticated=False,
    )


# ---------------------------------------------------------------------------
# Config fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_config() -> Config:
    """Return a Config suitable for unit tests: TLS verification off, short timeout."""
    cfg = Config()
    cfg.verify_tls = False
    cfg.timeout = 5.0
    return cfg


@pytest.fixture()
def scan_config_safe() -> Config:
    """Return a passive-mode Config with no credentials."""
    cfg = Config()
    cfg.mode = ScanMode.PASSIVE
    cfg.verify_tls = False
    cfg.timeout = 5.0
    return cfg


@pytest.fixture()
def scan_config_active() -> Config:
    """Return an active-mode Config with test credentials."""
    cfg = Config()
    cfg.mode = ScanMode.ACTIVE
    cfg.verify_tls = False
    cfg.timeout = 5.0
    cfg.username = "root"
    cfg.password = ""
    cfg.confirm = True
    return cfg


# ---------------------------------------------------------------------------
# Mock HTTP session fixture
# ---------------------------------------------------------------------------


def _make_mock_response(
    status_code: int = 200,
    text: str = "",
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> MagicMock:
    """Build a MagicMock that behaves like a requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode("utf-8")
    resp.headers = headers or {}
    # cookies is a dict-like object; support __contains__ and .get
    cookie_dict = cookies or {}
    resp.cookies = MagicMock()
    resp.cookies.__contains__ = lambda self, key: key in cookie_dict
    resp.cookies.__getitem__ = lambda self, key: cookie_dict[key]
    resp.cookies.get = lambda key, default=None: cookie_dict.get(key, default)
    resp.json = lambda: json.loads(text) if text else {}
    resp.raise_for_status = MagicMock()
    return resp


@pytest.fixture()
def mock_session() -> MagicMock:
    """
    Return a MagicMock SessionManager.

    All HTTP methods (.get, .post, .head, .put) return a default 200 response
    with empty body.  Individual tests can override the return_value or
    side_effect of each method to simulate specific server behaviour.
    """
    session = MagicMock()
    default_response = _make_mock_response(status_code=200, text="")
    session.get.return_value = default_response
    session.post.return_value = default_response
    session.head.return_value = default_response
    session.put.return_value = default_response
    session.is_authenticated = False
    session.auth_token = None
    session.clone.return_value = session
    return session


@pytest.fixture()
def mock_response_factory():
    """
    Return the ``make_response`` helper so tests can build custom responses.

    Usage::

        def test_something(mock_response_factory, mock_session):
            mock_session.get.return_value = mock_response_factory(
                status_code=403, text="Forbidden"
            )
    """
    return _make_mock_response


# ---------------------------------------------------------------------------
# Finding / ScanResult fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_finding() -> Finding:
    """Return a fully-populated Finding for use in reporter and model tests."""
    return Finding(
        id="LUCI-DEFA-001",
        check_id="default_credentials",
        title="Default credentials accepted: root:(empty)",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        category=Category.AUTHENTICATION,
        confidence=Confidence.HIGH,
        description=(
            "The LuCI interface accepted a commonly-known default credential pair. "
            "An unauthenticated attacker can gain full administrative access."
        ),
        evidence="POST /cgi-bin/luci/;stok=/login\nCredentials: root:(empty)\nHTTP 302\nsysauth: present",
        affected_url="https://192.168.1.1/cgi-bin/luci/;stok=/login",
        remediation="Change the default root password immediately via System > Administration.",
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2019-12272",
            "https://openwrt.org/advisory/2019-12-272",
        ],
        cve_ids=["CVE-2019-12272"],
        scan_mode=ScanMode.ACTIVE,
        timestamp=datetime(2026, 4, 23, 12, 0, 0),
        raw_response=None,
    )


@pytest.fixture()
def sample_scan_result(mock_target: Target, sample_finding: Finding) -> ScanResult:
    """
    Return a completed ScanResult with three findings at different severities:
    one CRITICAL, one HIGH, one MEDIUM.
    """
    high_finding = Finding(
        id="LUCI-TLSA-001",
        check_id="tls_analysis",
        title="Weak TLS protocol version detected: TLSv1.0",
        severity=Severity.HIGH,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        category=Category.TLS,
        confidence=Confidence.HIGH,
        description="The target negotiates TLSv1.0, which is deprecated and vulnerable.",
        evidence="SSL negotiation: TLSv1.0 accepted",
        affected_url="https://192.168.1.1",
        remediation="Disable TLSv1.0 and TLSv1.1; require TLSv1.2 minimum.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2011-3389"],
        cve_ids=[],
        scan_mode=ScanMode.PASSIVE,
        timestamp=datetime(2026, 4, 23, 12, 0, 5),
    )

    medium_finding = Finding(
        id="LUCI-CSFR-001",
        check_id="csrf_validation",
        title="CSRF protection absent on password-change endpoint",
        severity=Severity.MEDIUM,
        cvss_score=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        category=Category.CSRF,
        confidence=Confidence.MEDIUM,
        description="The password-change form does not include a CSRF token.",
        evidence="POST /cgi-bin/luci/admin/system/admin accepted without CSRF token.",
        affected_url="https://192.168.1.1/cgi-bin/luci/admin/system/admin",
        remediation="Implement CSRF token validation on all state-changing endpoints.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-36746"],
        cve_ids=["CVE-2021-36746"],
        scan_mode=ScanMode.ACTIVE,
        timestamp=datetime(2026, 4, 23, 12, 0, 10),
    )

    started = datetime(2026, 4, 23, 12, 0, 0)
    finished = datetime(2026, 4, 23, 12, 1, 30)

    return ScanResult(
        target=mock_target,
        findings=[sample_finding, high_finding, medium_finding],
        scan_mode=ScanMode.ACTIVE,
        tool_version="1.0.0",
        started_at=started,
        finished_at=finished,
        checks_run=10,
        checks_failed=0,
    )


# ---------------------------------------------------------------------------
# Utility helpers (not fixtures — imported directly if needed)
# ---------------------------------------------------------------------------


def make_response(
    status_code: int = 200,
    text: str = "",
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> MagicMock:
    """
    Public alias for _make_mock_response, intended for use in test modules
    that need to build responses outside of a fixture context.
    """
    return _make_mock_response(
        status_code=status_code,
        text=text,
        headers=headers,
        cookies=cookies,
    )


def assert_finding_valid(finding: Finding) -> None:
    """
    Assert that a Finding has all required non-empty fields.

    Call this in check tests to confirm that every Finding produced by a
    check.run() call meets the minimum data contract.
    """
    assert finding.id, "finding.id must not be empty"
    assert finding.check_id, "finding.check_id must not be empty"
    assert finding.title, "finding.title must not be empty"
    assert isinstance(finding.severity, Severity), "finding.severity must be Severity enum"
    assert isinstance(finding.cvss_score, float), "finding.cvss_score must be float"
    assert 0.0 <= finding.cvss_score <= 10.0, "cvss_score must be in [0.0, 10.0]"
    assert finding.description, "finding.description must not be empty"
    assert finding.evidence, "finding.evidence must not be empty"
    assert finding.affected_url, "finding.affected_url must not be empty"
    assert finding.remediation, "finding.remediation must not be empty"


# ---------------------------------------------------------------------------
# Integration-only: mock HTTP server (session-scoped)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def mock_http_server():
    """
    Start a lightweight WSGI test server for integration tests.

    Yields the base URL (e.g. "http://127.0.0.1:PORT").  The server serves
    a minimal set of LuCI-like endpoints sufficient for end-to-end scan flow
    testing.

    Marked as session scope so the server starts once per test session.
    Skip silently if Flask/Werkzeug is unavailable in the test environment.
    """
    try:
        import threading
        from werkzeug.serving import make_server
        from flask import Flask, jsonify, make_response as flask_response

        app = Flask("mock_luci_server")

        @app.route("/cgi-bin/luci/", methods=["GET"])
        def luci_root():
            return flask_response(
                "<html><body>OpenWrt 21.02.3</body></html>",
                200,
                {"Content-Type": "text/html"},
            )

        @app.route("/cgi-bin/luci/;stok=/login", methods=["GET", "POST"])
        def luci_login():
            resp = flask_response("<html>login</html>", 200)
            return resp

        server = make_server("127.0.0.1", 0, app)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        yield f"http://127.0.0.1:{port}"

        server.shutdown()

    except ImportError:
        pytest.skip("Flask/Werkzeug not available — skipping integration server fixture")
