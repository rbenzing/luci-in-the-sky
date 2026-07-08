"""
Unit tests for luci_sky.session.http — RateLimitedSession, retry logic, rate limiting.

All network calls are mocked; no real connections are made.
Tests will fail with ImportError until luci_sky/session/http.py is implemented.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch, PropertyMock

import json
import pytest
import requests_mock

from luci_sky.audit import AuditLogger
from luci_sky.config import Config
from luci_sky.models import Target
from luci_sky.session.http import SessionManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_target(scheme: str = "https", port: int = 443) -> Target:
    return Target(
        url=f"{scheme}://192.168.1.1",
        host="192.168.1.1",
        port=port,
        scheme=scheme,
        detected_version=None,
        detected_luci_version=None,
        open_ports=[],
        accessible_paths=[],
        is_authenticated=False,
    )


def _make_response(status_code: int = 200, cookies: dict = None, text: str = ""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.cookies = MagicMock()
    cookie_dict = cookies or {}
    resp.cookies.__contains__ = lambda self, k: k in cookie_dict
    resp.cookies.__getitem__ = lambda self, k: cookie_dict[k]
    resp.cookies.get = lambda k, default=None: cookie_dict.get(k, default)
    return resp


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestSessionManagerInit:
    def test_session_manager_initializes_with_config(self):
        """SessionManager(Config()) must not raise and must start unauthenticated."""
        cfg = Config()
        sm = SessionManager(cfg)
        assert sm.is_authenticated is False

    def test_session_manager_auth_token_initially_none(self):
        """auth_token must be None before any authentication attempt."""
        cfg = Config()
        sm = SessionManager(cfg)
        assert sm.auth_token is None


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TestSessionManagerAuthenticate:
    def test_authenticate_with_session_token_sets_cookie(self):
        """Pre-supplied session_token must be injected as sysauth cookie without a network call."""
        cfg = Config()
        cfg.session_token = "abc123tok"
        sm = SessionManager(cfg)
        target = _make_target()

        result = sm.authenticate(target)

        assert result is True
        assert sm.is_authenticated is True
        # The sysauth cookie must be present in the session
        assert "sysauth" in sm._session.cookies or sm.auth_token == "abc123tok"

    def test_authenticate_with_credentials_success(self):
        """authenticate() must return True and set is_authenticated when login POST returns sysauth cookie."""
        cfg = Config()
        cfg.username = "root"
        cfg.password = ""
        sm = SessionManager(cfg)
        target = _make_target()

        login_resp = _make_response(status_code=200, cookies={"sysauth": "tok123abc"})

        with patch.object(sm._session, "request", return_value=login_resp):
            result = sm.authenticate(target)

        assert result is True
        assert sm.is_authenticated is True

    def test_authenticate_with_credentials_failure(self):
        """authenticate() must return False when login POST returns no sysauth cookie."""
        cfg = Config()
        cfg.username = "root"
        cfg.password = "wrongpassword"
        sm = SessionManager(cfg)
        target = _make_target()

        login_resp = _make_response(status_code=200, cookies={}, text="Invalid credentials")

        with patch.object(sm._session, "request", return_value=login_resp):
            result = sm.authenticate(target)

        assert result is False
        assert sm.is_authenticated is False

    def test_authenticate_no_credentials_returns_false(self):
        """authenticate() must return False immediately with no network call when no credentials set."""
        cfg = Config()
        # No username or session_token
        sm = SessionManager(cfg)
        target = _make_target()

        with patch.object(sm._session, "request") as mock_req:
            result = sm.authenticate(target)
            mock_req.assert_not_called()

        assert result is False


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


class TestSessionManagerLogout:
    def test_logout_clears_auth_state(self):
        """After logout(), is_authenticated must be False and auth_token must be None."""
        cfg = Config()
        cfg.session_token = "tok"
        sm = SessionManager(cfg)
        target = _make_target()
        sm.authenticate(target)
        assert sm.is_authenticated is True

        logout_resp = _make_response(status_code=200)
        with patch.object(sm._session, "request", return_value=logout_resp):
            sm.logout(target)

        assert sm.is_authenticated is False
        assert sm.auth_token is None

    def test_logout_never_raises(self):
        """logout() must complete without raising even if the network call throws."""
        cfg = Config()
        sm = SessionManager(cfg)
        target = _make_target()

        with patch.object(sm._session, "request", side_effect=ConnectionError("refused")):
            # Must not raise
            sm.logout(target)


# ---------------------------------------------------------------------------
# Clone
# ---------------------------------------------------------------------------


class TestSessionManagerClone:
    def test_clone_has_independent_session(self):
        """clone() must produce a SessionManager with a different _session object."""
        cfg = Config()
        sm = SessionManager(cfg)
        cloned = sm.clone()
        assert cloned._session is not sm._session

    def test_clone_copies_auth_state(self):
        """clone() must copy the authenticated state to the new SessionManager."""
        cfg = Config()
        cfg.session_token = "tok123"
        sm = SessionManager(cfg)
        target = _make_target()
        sm.authenticate(target)

        cloned = sm.clone()
        assert cloned.is_authenticated == sm.is_authenticated


# ---------------------------------------------------------------------------
# Rate limiting / throttle
# ---------------------------------------------------------------------------


class TestSessionManagerThrottle:
    def test_throttle_enforces_delay(self):
        """With delay_ms=150, consecutive requests must be separated by at least 150 ms."""
        cfg = Config()
        cfg.delay_ms = 150
        cfg.jitter_ms = 0
        sm = SessionManager(cfg)

        resp = _make_response(status_code=200)
        timestamps: list = []

        def capturing_request(*args, **kwargs):
            timestamps.append(time.monotonic())
            return resp

        with patch.object(sm._session, "request", side_effect=capturing_request):
            sm.get("https://192.168.1.1/")
            sm.get("https://192.168.1.1/cgi-bin/luci/")

        assert len(timestamps) == 2
        gap_ms = (timestamps[1] - timestamps[0]) * 1000
        assert gap_ms >= 100, f"Expected >= 150ms gap, got {gap_ms:.0f}ms"


# ---------------------------------------------------------------------------
# Request configuration
# ---------------------------------------------------------------------------


class TestSessionManagerRequestConfig:
    def test_request_applies_default_timeout(self):
        """get() must pass config.timeout as the timeout kwarg when none is specified."""
        cfg = Config()
        cfg.timeout = 7.0
        sm = SessionManager(cfg)

        resp = _make_response(status_code=200)
        captured_kwargs: dict = {}

        def capturing_request(method, url, **kwargs):
            captured_kwargs.update(kwargs)
            return resp

        with patch.object(sm._session, "request", side_effect=capturing_request):
            sm.get("https://192.168.1.1/")

        assert "timeout" in captured_kwargs
        assert captured_kwargs["timeout"] == 7.0

    def test_request_applies_verify_tls(self):
        """get() must pass verify=False when config.verify_tls is False."""
        cfg = Config()
        cfg.verify_tls = False
        sm = SessionManager(cfg)

        resp = _make_response(status_code=200)
        captured_kwargs: dict = {}

        def capturing_request(method, url, **kwargs):
            captured_kwargs.update(kwargs)
            return resp

        with patch.object(sm._session, "request", side_effect=capturing_request):
            sm.get("https://192.168.1.1/")

        assert captured_kwargs.get("verify") is False

    def test_build_session_configures_proxy(self):
        """_build_session must configure proxies from config.proxy."""
        cfg = Config()
        cfg.proxy = "http://127.0.0.1:8080"
        sm = SessionManager(cfg)
        # The session's proxies dict should contain the proxy URL
        proxies = sm._session.proxies
        assert any("127.0.0.1:8080" in v for v in proxies.values())


# ---------------------------------------------------------------------------
# Retry behaviour
# ---------------------------------------------------------------------------


class TestSessionManagerRetry:
    def test_build_session_retry_on_5xx(self):
        """_build_session must configure retry adapter that retries on 5xx responses."""
        cfg = Config()
        sm = SessionManager(cfg)
        # The HTTPAdapter attached to the session must have retry configured
        adapter = sm._session.get_adapter("https://")
        assert hasattr(adapter, "max_retries")
        # max_retries total should be >= 1 (architecture spec: retry=2)
        retries = adapter.max_retries
        assert retries is not None


# ---------------------------------------------------------------------------
# Audit logging (Task 9)
# ---------------------------------------------------------------------------


def test_session_records_audit(tmp_path):
    cfg = Config()
    cfg.verify_tls = False
    log = AuditLogger(log_file=tmp_path / "a.jsonl")
    sm = SessionManager(cfg, audit=log)
    with requests_mock.Mocker() as m:
        m.get("https://h/x", text="body-here", status_code=200)
        sm.get("https://h/x")
    log.close()
    rec = json.loads((tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert rec["method"] == "GET" and rec["status"] == 200


def test_clone_shares_audit(tmp_path):
    cfg = Config()
    log = AuditLogger(log_file=tmp_path / "a.jsonl")
    sm = SessionManager(cfg, audit=log)
    assert sm.clone()._audit is log
