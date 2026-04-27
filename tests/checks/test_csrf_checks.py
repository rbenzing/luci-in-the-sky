"""
Unit tests for luci_sky.checks.csrf — CSRFValidation check.

Tests will fail with ImportError until luci_sky/checks/csrf.py is implemented.
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


def _make_response(
    status_code: int = 200,
    text: str = "",
    cookies: dict = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode()
    cookie_dict = cookies or {}
    resp.cookies = MagicMock()
    resp.cookies.__contains__ = lambda self, k: k in cookie_dict
    resp.cookies.get = lambda k, default=None: cookie_dict.get(k, default)
    return resp


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestCSRFValidationRegistered:
    def test_csrf_validation_registered(self):
        """get_check('csrf_validation') must succeed."""
        check = get_check("csrf_validation")
        assert check.__class__.id == "csrf_validation"

    def test_csrf_validation_requires_active_mode(self):
        """CSRFValidation must require ACTIVE scan mode."""
        check = get_check("csrf_validation")
        assert check.__class__.min_mode == ScanMode.ACTIVE

    def test_csrf_validation_does_not_require_auth(self):
        """CSRFValidation must not require authentication."""
        check = get_check("csrf_validation")
        assert check.__class__.requires_auth is False


# ---------------------------------------------------------------------------
# CSRF protection absence
# ---------------------------------------------------------------------------


class TestCSRFNoToken:
    def test_csrf_no_token_in_form_produces_medium_finding(self):
        """A form with no CSRF token patterns must produce a MEDIUM finding."""
        check = get_check("csrf_validation")
        target = _make_target()

        # Form response with no CSRF token field
        form_html = (
            "<html><body>"
            "<form method='POST'>"
            "<input name='password' type='password'>"
            "<button type='submit'>Save</button>"
            "</form>"
            "</body></html>"
        )
        session = MagicMock()
        session.get.return_value = _make_response(200, form_html)
        session.post.return_value = _make_response(200, "saved")

        findings = check.run(target, session, _make_config())

        assert any(f.severity == Severity.MEDIUM for f in findings), (
            "Expected MEDIUM finding when no CSRF token in form"
        )


# ---------------------------------------------------------------------------
# Token submission tests
# ---------------------------------------------------------------------------


class TestCSRFTokenSubmission:
    def test_csrf_submit_without_token_succeeds_produces_medium(self):
        """Server accepting a tokenless POST must produce a MEDIUM finding."""
        check = get_check("csrf_validation")
        target = _make_target()

        # Form has a CSRF token
        form_html = (
            "<html><body>"
            "<form method='POST'>"
            "<input name='token' value='abc123def456abc123def456abc12345'>"
            "<button>Save</button>"
            "</form>"
            "</body></html>"
        )

        session = MagicMock()
        # GET: return form with token; POST without token: 200 (accepted — vulnerable)
        session.get.return_value = _make_response(200, form_html)
        session.post.return_value = _make_response(200, "password changed")

        findings = check.run(target, session, _make_config())

        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_csrf_submit_with_wrong_token_succeeds_produces_medium(self):
        """Server accepting a wrong CSRF token must produce a MEDIUM finding."""
        check = get_check("csrf_validation")
        target = _make_target()

        form_html = (
            "<html><body>"
            "<form>"
            "<input name='token' value='realtoken123'>"
            "</form>"
            "</body></html>"
        )

        session = MagicMock()
        session.get.return_value = _make_response(200, form_html)
        # Wrong token also accepted (200) — vulnerable
        session.post.return_value = _make_response(200, "success")

        findings = check.run(target, session, _make_config())

        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_csrf_rejection_of_wrong_token_returns_empty(self):
        """Server returning 403 for tokenless/wrong-token POST must produce no finding."""
        check = get_check("csrf_validation")
        target = _make_target()

        form_html = (
            "<html><body>"
            "<form>"
            "<input name='token' value='realtoken123'>"
            "</form>"
            "</body></html>"
        )

        session = MagicMock()
        session.get.return_value = _make_response(200, form_html)
        # 403 Forbidden → CSRF protection is working
        session.post.return_value = _make_response(403, "CSRF validation failed")

        findings = check.run(target, session, _make_config())

        medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium_findings) == 0

    def test_csrf_token_present_and_validated_returns_empty(self):
        """A form with a token that the server strictly validates must produce no findings."""
        check = get_check("csrf_validation")
        target = _make_target()

        form_html = (
            "<html><body>"
            "<form>"
            "<input name='token' value='validcsrf00000000000000000000000'>"
            "</form>"
            "</body></html>"
        )

        session = MagicMock()
        session.get.return_value = _make_response(200, form_html)
        # Both tokenless and wrong-token POST are rejected (403)
        session.post.return_value = _make_response(403, "CSRF token mismatch")

        findings = check.run(target, session, _make_config())

        medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium_findings) == 0


# ---------------------------------------------------------------------------
# CVE references
# ---------------------------------------------------------------------------


class TestCSRFReferences:
    def test_csrf_references_include_cve_ids(self):
        """CSRF findings must reference CVE-2021-36746 or CVE-2022-31340."""
        check = get_check("csrf_validation")
        target = _make_target()

        # No token in form → vulnerable
        session = MagicMock()
        session.get.return_value = _make_response(200, "<form><input name='pass'></form>")
        session.post.return_value = _make_response(200, "ok")

        findings = check.run(target, session, _make_config())

        if findings:
            all_cve_refs = []
            for f in findings:
                all_cve_refs.extend(f.cve_ids)
                all_cve_refs.extend(f.references)
            cve_text = " ".join(all_cve_refs)
            assert "CVE-2021-36746" in cve_text or "CVE-2022-31340" in cve_text
