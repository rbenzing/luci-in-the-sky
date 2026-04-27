"""
Unit tests for LuCI authenticator / session auth flow in luci_sky.session.http.

These focus on the authenticate() / logout() flow as a higher-level unit.
Tests will fail with ImportError until luci_sky/session/http.py is implemented.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from luci_sky.config import Config
from luci_sky.models import Target
from luci_sky.session.http import SessionManager


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


def _make_response(status_code: int = 200, cookies: dict = None, text: str = ""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    cookie_dict = cookies or {}
    resp.cookies = MagicMock()
    resp.cookies.__contains__ = lambda self, k: k in cookie_dict
    resp.cookies.get = lambda k, default=None: cookie_dict.get(k, default)
    return resp


class TestLuCIAuthenticator:
    def test_login_flow_posts_to_correct_endpoint(self):
        """authenticate() must POST to /cgi-bin/luci/;stok=/login."""
        cfg = Config()
        cfg.username = "root"
        cfg.password = ""
        sm = SessionManager(cfg)
        target = _make_target()

        captured_urls: list = []
        resp = _make_response(200, cookies={"sysauth": "tok"})

        def capturing_request(method, url, **kwargs):
            captured_urls.append(url)
            return resp

        with patch.object(sm._session, "request", side_effect=capturing_request):
            sm.authenticate(target)

        assert any("/cgi-bin/luci" in url and "login" in url for url in captured_urls), (
            f"Expected login URL; got {captured_urls}"
        )

    def test_login_sends_correct_form_fields(self):
        """authenticate() must send luci_username and luci_password form fields."""
        cfg = Config()
        cfg.username = "admin"
        cfg.password = "secret"
        sm = SessionManager(cfg)
        target = _make_target()

        captured_data: dict = {}
        resp = _make_response(200, cookies={"sysauth": "tok"})

        def capturing_request(method, url, **kwargs):
            data = kwargs.get("data", {})
            captured_data.update(data)
            return resp

        with patch.object(sm._session, "request", side_effect=capturing_request):
            sm.authenticate(target)

        assert "luci_username" in captured_data
        assert "luci_password" in captured_data
        assert captured_data["luci_username"] == "admin"

    def test_token_extraction_sets_is_authenticated(self):
        """A sysauth cookie in the login response must set is_authenticated=True."""
        cfg = Config()
        cfg.username = "root"
        cfg.password = ""
        sm = SessionManager(cfg)
        target = _make_target()

        resp = _make_response(200, cookies={"sysauth": "mytoken123"})
        with patch.object(sm._session, "request", return_value=resp):
            result = sm.authenticate(target)

        assert result is True
        assert sm.is_authenticated is True

    def test_session_token_injection_bypasses_login_post(self):
        """Pre-supplied session_token must skip the login POST entirely."""
        cfg = Config()
        cfg.session_token = "preexisting_token"
        sm = SessionManager(cfg)
        target = _make_target()

        with patch.object(sm._session, "request") as mock_req:
            result = sm.authenticate(target)
            mock_req.assert_not_called()

        assert result is True

    def test_logout_clears_is_authenticated(self):
        """logout() must reset is_authenticated to False."""
        cfg = Config()
        cfg.session_token = "tok"
        sm = SessionManager(cfg)
        target = _make_target()
        sm.authenticate(target)

        with patch.object(sm._session, "request", return_value=_make_response(200)):
            sm.logout(target)

        assert sm.is_authenticated is False

    def test_logout_is_best_effort(self):
        """logout() must not propagate network exceptions."""
        cfg = Config()
        sm = SessionManager(cfg)
        target = _make_target()

        with patch.object(sm._session, "request", side_effect=ConnectionError("refused")):
            try:
                sm.logout(target)
            except Exception as exc:
                pytest.fail(f"logout() raised unexpectedly: {exc}")
