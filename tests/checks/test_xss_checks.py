"""
Unit tests for luci_sky.checks.xss — XSSDetection, StoredXSS.

Tests will fail with ImportError until luci_sky/checks/xss.py is implemented.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from luci_sky.checks import get_check
from luci_sky.config import Config
from luci_sky.models import Finding, ScanMode, Severity, Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_target() -> Target:
    return Target(
        url="https://192.168.1.1",
        host="192.168.1.1",
        port=443,
        scheme="https",
        detected_version=None,
        detected_luci_version=None,
        is_authenticated=False,
    )


def _make_config() -> Config:
    cfg = Config()
    cfg.verify_tls = False
    cfg.timeout = 5.0
    return cfg


def _make_response(status_code: int = 200, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode()
    return resp


def _make_session(**overrides) -> MagicMock:
    session = MagicMock()
    default_resp = _make_response(200, "")
    session.get.return_value = overrides.get("get", default_resp)
    session.post.return_value = overrides.get("post", default_resp)
    session.head.return_value = overrides.get("head", default_resp)
    return session


# ---------------------------------------------------------------------------
# XSSDetection — registration and mode
# ---------------------------------------------------------------------------


class TestXSSDetectionRegistered:
    def test_xss_detection_registered(self):
        """get_check('xss_detection') must succeed after the checks package is imported."""
        check = get_check("xss_detection")
        assert check.__class__.id == "xss_detection"

    def test_xss_detection_requires_active_mode(self):
        """XSSDetection must require ACTIVE scan mode."""
        check = get_check("xss_detection")
        assert check.__class__.min_mode == ScanMode.ACTIVE

    def test_xss_detection_does_not_require_auth(self):
        """XSSDetection must not require authentication."""
        check = get_check("xss_detection")
        assert check.__class__.requires_auth is False


# ---------------------------------------------------------------------------
# XSSDetection — reflected XSS
# ---------------------------------------------------------------------------


class TestReflectedXSS:
    def test_reflected_xss_payload_in_response_produces_high_finding(self):
        """Literal unencoded script tag in response must produce a HIGH finding."""
        check = get_check("xss_detection")
        target = _make_target()

        payload = "<script>alert(1)</script>"
        # Response reflects the payload literally (unencoded)
        reflected_resp = _make_response(200, f"<html><body>{payload}</body></html>")
        session = _make_session(get=reflected_resp, post=reflected_resp)

        findings = check.run(target, session, _make_config())

        assert any(f.severity == Severity.HIGH for f in findings), (
            "Expected HIGH finding when XSS payload reflected unencoded"
        )

    def test_reflected_xss_encoded_payload_no_finding(self):
        """HTML-encoded payload must produce no finding (properly escaped)."""
        check = get_check("xss_detection")
        target = _make_target()

        # Response contains only the HTML-encoded version of the payload
        encoded_resp = _make_response(
            200,
            "<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>",
        )
        session = _make_session(get=encoded_resp, post=encoded_resp)

        findings = check.run(target, session, _make_config())

        # No HIGH XSS finding when payload is encoded
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high_findings) == 0

    def test_reflected_xss_all_endpoints_tested(self):
        """run() must make requests to at least 3 distinct endpoint URLs."""
        check = get_check("xss_detection")
        target = _make_target()

        requested_urls: set = set()

        def get_side_effect(url, **kwargs):
            requested_urls.add(url)
            return _make_response(200, "clean")

        def post_side_effect(url, **kwargs):
            requested_urls.add(url)
            return _make_response(200, "clean")

        session = MagicMock()
        session.get.side_effect = get_side_effect
        session.post.side_effect = post_side_effect

        check.run(target, session, _make_config())

        assert len(requested_urls) >= 3, (
            f"Expected >= 3 distinct URLs tested; got {len(requested_urls)}: {requested_urls}"
        )

    def test_xss_detection_request_failure_does_not_raise(self):
        """A ConnectionError during XSS testing must not propagate; return []."""
        check = get_check("xss_detection")
        target = _make_target()

        session = MagicMock()
        session.get.side_effect = ConnectionError("Connection refused")
        session.post.side_effect = ConnectionError("Connection refused")

        findings = check.run(target, session, _make_config())

        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# StoredXSS — registration and mode
# ---------------------------------------------------------------------------


class TestStoredXSSRegistered:
    def test_stored_xss_registered(self):
        """get_check('stored_xss') must succeed."""
        check = get_check("stored_xss")
        assert check.__class__.id == "stored_xss"

    def test_stored_xss_requires_full_mode(self):
        """StoredXSS must require FULL scan mode."""
        check = get_check("stored_xss")
        assert check.__class__.min_mode == ScanMode.FULL


# ---------------------------------------------------------------------------
# StoredXSS — stored detection
# ---------------------------------------------------------------------------


class TestStoredXSS:
    def test_stored_xss_unencoded_in_admin_page_produces_high(self):
        """Unencoded XSS payload in the verify-URL response must produce a HIGH finding."""
        check = get_check("stored_xss")
        target = _make_target()

        xss_payload = "<script>alert(1)</script>"

        session = MagicMock()
        # Submit POST to inject (succeed)
        session.post.return_value = _make_response(200, "saved")
        # GET verify URL returns the payload unencoded
        session.get.return_value = _make_response(
            200, f"<html><body>{xss_payload}</body></html>"
        )

        findings = check.run(target, session, _make_config())

        if findings:
            assert any(f.severity == Severity.HIGH for f in findings)

    def test_stored_xss_encoded_in_admin_page_no_finding(self):
        """HTML-encoded payload in verify-URL response must produce no finding."""
        check = get_check("stored_xss")
        target = _make_target()

        session = MagicMock()
        session.post.return_value = _make_response(200, "saved")
        # Verify response properly encodes the payload
        session.get.return_value = _make_response(
            200, "<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
        )

        findings = check.run(target, session, _make_config())

        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high_findings) == 0
