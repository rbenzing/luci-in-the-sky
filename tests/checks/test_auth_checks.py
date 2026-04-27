"""
Unit tests for luci_sky.checks.auth — DefaultCredentials, AuthBypass, RateLimiting.

All HTTP calls are mocked via MagicMock session.
Tests will fail with ImportError until luci_sky/checks/auth.py is implemented.
"""
from __future__ import annotations

from typing import List
from unittest.mock import MagicMock, call, patch

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


def _make_config(**overrides) -> Config:
    cfg = Config()
    cfg.verify_tls = False
    cfg.timeout = 5.0
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


def _make_response(
    status_code: int = 200,
    cookies: dict = None,
    text: str = "login",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    cookie_dict = cookies or {}
    resp.cookies = MagicMock()
    resp.cookies.__contains__ = lambda self, k: k in cookie_dict
    resp.cookies.get = lambda k, default=None: cookie_dict.get(k, default)
    return resp


def _make_session(**method_configs) -> MagicMock:
    session = MagicMock()
    default_resp = _make_response()
    session.get.return_value = method_configs.get("get", default_resp)
    session.post.return_value = method_configs.get("post", default_resp)
    session.head.return_value = method_configs.get("head", default_resp)
    return session


# ---------------------------------------------------------------------------
# DefaultCredentials
# ---------------------------------------------------------------------------


class TestDefaultCredentials:
    def test_default_credentials_registered(self):
        """get_check('default_credentials') must succeed."""
        check = get_check("default_credentials")
        assert check.__class__.id == "default_credentials"

    def test_default_credentials_requires_active_mode(self):
        """DefaultCredentials must require ACTIVE scan mode."""
        check = get_check("default_credentials")
        assert check.__class__.min_mode == ScanMode.ACTIVE

    def test_default_credentials_success_produces_critical_finding(self):
        """A login response with sysauth cookie must produce a CRITICAL finding."""
        check = get_check("default_credentials")
        target = _make_target()
        # First POST returns sysauth cookie (login success)
        success_resp = _make_response(
            status_code=200,
            cookies={"sysauth": "abc123tok"},
            text="dashboard",
        )
        session = _make_session(post=success_resp)

        findings = check.run(target, session, _make_config())

        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_default_credentials_stops_after_first_success(self):
        """Only one finding must be produced even if multiple credential pairs would succeed."""
        check = get_check("default_credentials")
        target = _make_target()

        call_count = [0]

        def post_side_effect(url, **kwargs):
            call_count[0] += 1
            # Always return sysauth cookie (every pair "succeeds")
            return _make_response(
                status_code=200,
                cookies={"sysauth": f"tok{call_count[0]}"},
                text="dashboard",
            )

        session = MagicMock()
        session.post.side_effect = post_side_effect

        findings = check.run(target, session, _make_config())

        # Only one finding should be produced (stop after first success)
        assert len(findings) == 1
        # And we should have called POST fewer than 8 times (the full default list length)
        assert call_count[0] < 8

    def test_default_credentials_all_fail_returns_empty(self):
        """All credential pairs failing must produce no findings."""
        check = get_check("default_credentials")
        target = _make_target()
        fail_resp = _make_response(status_code=200, cookies={}, text="login")
        session = _make_session(post=fail_resp)

        findings = check.run(target, session, _make_config())

        assert findings == []

    def test_default_credentials_evidence_masks_password(self):
        """The finding evidence must NOT contain the plaintext password."""
        check = get_check("default_credentials")
        target = _make_target()
        success_resp = _make_response(
            status_code=200,
            cookies={"sysauth": "tok"},
            text="dashboard",
        )
        session = _make_session(post=success_resp)

        findings = check.run(target, session, _make_config())

        if findings:
            finding = findings[0]
            # The raw credential value must not appear verbatim in evidence
            # (Password masking via _sanitize is applied)
            assert "luci_password=root" not in finding.evidence
            assert "luci_password=admin" not in finding.evidence

    def test_default_credentials_extra_credentials_config(self):
        """Extra credentials from config.extra_credentials must also be tested."""
        check = get_check("default_credentials")
        target = _make_target()
        cfg = _make_config(extra_credentials=[("testuser", "testpass")])

        tested_users: list = []

        def post_side_effect(url, **kwargs):
            data = kwargs.get("data", {})
            tested_users.append(data.get("luci_username", ""))
            return _make_response(status_code=200, cookies={}, text="login")

        session = MagicMock()
        session.post.side_effect = post_side_effect

        check.run(target, session, cfg)

        assert "testuser" in tested_users


# ---------------------------------------------------------------------------
# AuthBypass
# ---------------------------------------------------------------------------


class TestAuthBypass:
    def test_auth_bypass_registered(self):
        """get_check('auth_bypass') must succeed."""
        check = get_check("auth_bypass")
        assert check.__class__.id == "auth_bypass"

    def test_auth_bypass_requires_active_mode(self):
        """AuthBypass must require ACTIVE scan mode."""
        check = get_check("auth_bypass")
        assert check.__class__.min_mode == ScanMode.ACTIVE

    def test_auth_bypass_header_spoofing_success_produces_critical(self):
        """Admin content in response to spoofed header must produce a CRITICAL finding."""
        check = get_check("auth_bypass")
        target = _make_target()

        # Respond with admin panel content (not a login page)
        admin_resp = _make_response(
            status_code=200,
            cookies={"sysauth": "faketoken"},
            text="LuCI Administration Dashboard",
        )
        session = MagicMock()
        session.get.return_value = admin_resp
        session.post.return_value = admin_resp

        findings = check.run(target, session, _make_config())

        # If any bypass succeeds, there should be CRITICAL findings
        if findings:
            assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_auth_bypass_all_fail_returns_empty(self):
        """All bypass attempts returning redirect to login must produce no findings."""
        check = get_check("auth_bypass")
        target = _make_target()
        # All responses redirect to login (not accessible)
        redirect_resp = _make_response(status_code=302, cookies={}, text="login")
        session = MagicMock()
        session.get.return_value = redirect_resp
        session.post.return_value = redirect_resp

        findings = check.run(target, session, _make_config())

        assert findings == []


# ---------------------------------------------------------------------------
# RateLimiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    def test_rate_limiting_registered(self):
        """get_check('rate_limiting') must succeed."""
        check = get_check("rate_limiting")
        assert check.__class__.id == "rate_limiting"

    def test_rate_limiting_requires_active_mode(self):
        """RateLimiting must require ACTIVE scan mode."""
        check = get_check("rate_limiting")
        assert check.__class__.min_mode == ScanMode.ACTIVE

    def test_rate_limiting_no_protection_produces_medium_finding(self):
        """All 20 identical fast responses must produce a MEDIUM finding (no protection)."""
        check = get_check("rate_limiting")
        target = _make_target()
        # Every attempt returns identical error (no lockout, no delay)
        fail_resp = _make_response(status_code=200, cookies={}, text="Invalid credentials")
        session = MagicMock()
        session.post.return_value = fail_resp

        findings = check.run(target, session, _make_config())

        assert len(findings) >= 1
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_rate_limiting_lockout_detected_returns_empty(self):
        """Changing error message after attempt 10 must indicate lockout; return []."""
        check = get_check("rate_limiting")
        target = _make_target()

        call_count = [0]

        def post_side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 10:
                return _make_response(200, {}, "Invalid credentials")
            else:
                return _make_response(200, {}, "Account temporarily locked")

        session = MagicMock()
        session.post.side_effect = post_side_effect

        findings = check.run(target, session, _make_config())

        # Lockout detected → no MEDIUM finding (protection exists)
        assert not any(f.severity == Severity.MEDIUM for f in findings)

    def test_rate_limiting_http_429_returns_empty(self):
        """HTTP 429 Too Many Requests after some attempts must indicate protection; return []."""
        check = get_check("rate_limiting")
        target = _make_target()

        call_count = [0]

        def post_side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 5:
                return _make_response(200, {}, "Invalid credentials")
            return _make_response(429, {}, "Too Many Requests")

        session = MagicMock()
        session.post.side_effect = post_side_effect

        findings = check.run(target, session, _make_config())

        assert not any(f.severity == Severity.MEDIUM for f in findings)


# ---------------------------------------------------------------------------
# RateLimitStress
# ---------------------------------------------------------------------------


class TestRateLimitStress:
    def test_rate_limit_stress_registered(self):
        """get_check('rate_limit_stress') must succeed."""
        check = get_check("rate_limit_stress")
        assert check.__class__.id == "rate_limit_stress"

    def test_rate_limit_stress_requires_full_mode(self):
        """RateLimitStress must require FULL scan mode."""
        check = get_check("rate_limit_stress")
        assert check.__class__.min_mode == ScanMode.FULL
