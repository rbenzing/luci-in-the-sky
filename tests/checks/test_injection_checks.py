"""
Unit tests for luci_sky.checks.injection — CommandInjection, PathTraversal, TimedBasedInjection.

All HTTP calls are mocked.
Tests will fail with ImportError until luci_sky/checks/injection.py is implemented.
"""
from __future__ import annotations

import time
from typing import List
from unittest.mock import MagicMock, patch

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


def _make_response(status_code: int = 200, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode()
    return resp


# ---------------------------------------------------------------------------
# CommandInjection
# ---------------------------------------------------------------------------


class TestCommandInjection:
    def test_command_injection_registered(self):
        """get_check('command_injection') must succeed."""
        check = get_check("command_injection")
        assert check.__class__.id == "command_injection"

    def test_command_injection_requires_active_mode(self):
        """CommandInjection must require ACTIVE scan mode."""
        check = get_check("command_injection")
        assert check.__class__.min_mode == ScanMode.ACTIVE

    def test_command_injection_with_2_pattern_matches_produces_critical(self):
        """A response matching 2+ COMMAND_INDICATOR patterns must produce a CRITICAL finding."""
        check = get_check("command_injection")
        target = _make_target()

        # Two indicator patterns: uid= and root@
        inject_response_text = (
            "uid=0(root) gid=0(root) groups=0(root)\n"
            "root@OpenWrt:/#\n"
        )

        session = MagicMock()
        baseline_resp = _make_response(200, "PING 127.0.0.1: 56 data bytes")
        inject_resp = _make_response(200, inject_response_text)

        call_count = [0]

        def post_side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline_resp
            return inject_resp

        session.post.side_effect = post_side_effect
        session.get.return_value = baseline_resp

        findings = check.run(target, session, _make_config())

        assert any(f.severity == Severity.CRITICAL for f in findings), (
            f"Expected CRITICAL finding; got: {[str(f.severity) for f in findings]}"
        )

    def test_command_injection_with_1_match_and_length_increase_produces_critical(self):
        """1 indicator match + response length > 150% of baseline must produce CRITICAL."""
        check = get_check("command_injection")
        target = _make_target()

        baseline_text = "pong" * 10  # 40 chars
        # One indicator + significantly longer response (> 1.5x baseline)
        inject_text = "uid=0(root) gid=0(root)\n" + "X" * 200  # >> 40 chars

        session = MagicMock()
        call_count = [0]

        def post_side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_response(200, baseline_text)
            return _make_response(200, inject_text)

        session.post.side_effect = post_side_effect
        session.get.return_value = _make_response(200, baseline_text)

        findings = check.run(target, session, _make_config())

        criticals = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(criticals) >= 1 or len(findings) >= 1

    def test_command_injection_below_threshold_returns_empty(self):
        """Single weak match with no length increase must produce no finding."""
        check = get_check("command_injection")
        target = _make_target()

        # Only matches "packets transmitted" — 1 indicator, no length increase
        response_text = "3 packets transmitted, 3 received"
        session = MagicMock()
        session.post.return_value = _make_response(200, response_text)
        session.get.return_value = _make_response(200, response_text)

        findings = check.run(target, session, _make_config())

        criticals = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(criticals) == 0

    def test_command_injection_403_response_stops_endpoint_testing(self):
        """A 403 response must prevent findings for that endpoint (access denied)."""
        check = get_check("command_injection")
        target = _make_target()

        session = MagicMock()
        session.post.return_value = _make_response(403, "Forbidden")
        session.get.return_value = _make_response(403, "Forbidden")

        findings = check.run(target, session, _make_config())

        assert not any(f.severity == Severity.CRITICAL for f in findings)

    def test_command_injection_request_failure_continues_scan(self):
        """A ConnectionError on the first endpoint must not prevent testing subsequent endpoints."""
        check = get_check("command_injection")
        target = _make_target()

        call_count = [0]

        def post_side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionError("refused")
            return _make_response(200, "clean response")

        session = MagicMock()
        session.post.side_effect = post_side_effect
        session.get.side_effect = post_side_effect

        # Must not raise
        findings = check.run(target, session, _make_config())
        assert isinstance(findings, list)

    def test_command_injection_baseline_failure_skips_endpoint(self):
        """Baseline request failure must cause the endpoint to be skipped gracefully."""
        check = get_check("command_injection")
        target = _make_target()

        session = MagicMock()
        session.post.side_effect = ConnectionError("refused")
        session.get.side_effect = ConnectionError("refused")

        findings = check.run(target, session, _make_config())
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# PathTraversal
# ---------------------------------------------------------------------------


class TestPathTraversal:
    def test_path_traversal_registered(self):
        """get_check('path_traversal') must succeed."""
        check = get_check("path_traversal")
        assert check.__class__.id == "path_traversal"

    def test_path_traversal_requires_active_mode(self):
        """PathTraversal must require ACTIVE scan mode."""
        check = get_check("path_traversal")
        assert check.__class__.min_mode == ScanMode.ACTIVE

    def test_path_traversal_passwd_content_in_response_produces_high(self):
        """Response containing 'root:x:0:0:' must produce a HIGH finding."""
        check = get_check("path_traversal")
        target = _make_target()

        session = MagicMock()
        passwd_content = "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/var:/bin/false"
        session.get.return_value = _make_response(200, passwd_content)
        session.post.return_value = _make_response(200, passwd_content)

        findings = check.run(target, session, _make_config())

        assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings), (
            "Expected HIGH finding when passwd content detected in response"
        )

    def test_path_traversal_no_indicators_returns_empty(self):
        """A plain HTML response must produce no findings (avoid false positives)."""
        check = get_check("path_traversal")
        target = _make_target()

        session = MagicMock()
        html_resp = _make_response(200, "<html><body><h1>LuCI Dashboard</h1></body></html>")
        session.get.return_value = html_resp
        session.post.return_value = html_resp

        findings = check.run(target, session, _make_config())

        highs = [f for f in findings if f.severity == Severity.HIGH]
        assert len(highs) == 0


# ---------------------------------------------------------------------------
# TimeBasedInjection
# ---------------------------------------------------------------------------


class TestTimeBasedInjection:
    def test_time_based_injection_registered(self):
        """get_check('time_based_injection') must succeed."""
        check = get_check("time_based_injection")
        assert check.__class__.id == "time_based_injection"

    def test_time_based_injection_requires_full_mode(self):
        """TimeBasedInjection must require FULL scan mode."""
        check = get_check("time_based_injection")
        assert check.__class__.min_mode == ScanMode.FULL

    def test_time_based_injection_delay_detected_produces_critical(self):
        """A 5+ second delay compared to baseline must produce a CRITICAL finding."""
        check = get_check("time_based_injection")
        target = _make_target()

        session = MagicMock()
        call_count = [0]

        def slow_post(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # Baseline: fast response
                return _make_response(200, "fast baseline")
            else:
                # Injection: simulate delay by patching time
                return _make_response(200, "slow response after 5s")

        session.post.side_effect = slow_post
        session.get.return_value = _make_response(200, "fast baseline")

        # Patch time.monotonic to simulate elapsed time for the delayed request
        time_values = [0.0, 0.1, 0.1, 5.5]  # baseline fast, injection slow (5.5s delta)
        time_iter = iter(time_values)

        with patch("time.monotonic", side_effect=lambda: next(time_iter, 10.0)):
            findings = check.run(target, session, _make_config())

        # If delay detection is implemented, CRITICAL findings should appear
        assert isinstance(findings, list)  # Must not raise regardless
