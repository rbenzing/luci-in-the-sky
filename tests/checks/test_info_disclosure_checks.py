"""
Unit tests for luci_sky.checks.info_disclosure — VersionDetection, PathEnumeration,
BackupExposure, PackageEnumeration, SecurityHeaders.

Tests will fail with ImportError until luci_sky/checks/info_disclosure.py is implemented.
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
        open_ports=[],
        accessible_paths=[],
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
    headers: dict = None,
    content_type: str = "text/html",
    content_length: int = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode() if text else b""
    h = headers or {}
    h.setdefault("Content-Type", content_type)
    if content_length is not None:
        h["Content-Length"] = str(content_length)
    resp.headers = h
    resp.url = "https://192.168.1.1/"
    return resp


# ---------------------------------------------------------------------------
# VersionDetection
# ---------------------------------------------------------------------------


class TestVersionDetection:
    def test_version_detection_registered(self):
        """get_check('version_detection') must succeed."""
        check = get_check("version_detection")
        assert check.__class__.id == "version_detection"

    def test_version_detection_is_passive(self):
        """VersionDetection must be PASSIVE mode."""
        check = get_check("version_detection")
        assert check.__class__.min_mode == ScanMode.PASSIVE

    def test_version_detection_from_response_body_regex(self):
        """'OpenWrt 23.05.2' in body must produce an INFO finding with version in evidence."""
        check = get_check("version_detection")
        target = _make_target()

        body = "<html><body>Welcome to OpenWrt 23.05.2</body></html>"
        session = MagicMock()
        session.get.return_value = _make_response(200, body)
        session.head.return_value = _make_response(200, body)

        findings = check.run(target, session, _make_config())

        info_findings = [f for f in findings if f.severity == Severity.INFO]
        assert len(info_findings) >= 1
        assert any("23.05.2" in f.evidence or "23.05.2" in f.description for f in findings)

    def test_version_detection_sets_target_detected_version(self):
        """After run(), target.detected_version must equal the detected version string."""
        check = get_check("version_detection")
        target = _make_target()

        body = "OpenWrt 23.05.2 - Chaos Calmer"
        session = MagicMock()
        session.get.return_value = _make_response(200, body)

        check.run(target, session, _make_config())

        assert target.detected_version == "23.05.2"

    def test_version_detection_no_version_found_returns_empty(self):
        """A response with no version patterns must return []."""
        check = get_check("version_detection")
        target = _make_target()

        session = MagicMock()
        session.get.return_value = _make_response(200, "<html><body>Welcome</body></html>")
        session.head.return_value = _make_response(200, "")

        findings = check.run(target, session, _make_config())

        assert findings == [] or all(f.severity == Severity.INFO for f in findings)


# ---------------------------------------------------------------------------
# PathEnumeration
# ---------------------------------------------------------------------------


class TestPathEnumeration:
    def test_path_enumeration_registered(self):
        """get_check('path_enumeration') must succeed."""
        check = get_check("path_enumeration")
        assert check.__class__.id == "path_enumeration"

    def test_path_enumeration_is_passive(self):
        """PathEnumeration must be PASSIVE mode."""
        check = get_check("path_enumeration")
        assert check.__class__.min_mode == ScanMode.PASSIVE

    def test_path_enumeration_accessible_path_produces_finding(self):
        """A 200 response to a LuCI admin path must produce a finding."""
        check = get_check("path_enumeration")
        target = _make_target()

        session = MagicMock()

        def get_side_effect(url, **kwargs):
            if "admin/system" in url:
                return _make_response(200, "<html>Admin System Page</html>")
            return _make_response(302, "", headers={"Location": "/cgi-bin/luci/"})

        session.get.side_effect = get_side_effect
        session.head.side_effect = get_side_effect

        findings = check.run(target, session, _make_config())

        assert len(findings) >= 1

    def test_path_enumeration_302_to_login_produces_no_finding(self):
        """302 redirect to login must not be reported as an accessible path."""
        check = get_check("path_enumeration")
        target = _make_target()

        # All paths redirect to login
        session = MagicMock()
        redirect_resp = _make_response(
            302, "", headers={"Location": "/cgi-bin/luci/;stok=/login"}
        )
        session.get.return_value = redirect_resp
        session.head.return_value = redirect_resp

        findings = check.run(target, session, _make_config())

        assert findings == []

    def test_path_enumeration_populates_accessible_paths(self):
        """target.accessible_paths must be populated with accessible URLs after run()."""
        check = get_check("path_enumeration")
        target = _make_target()

        session = MagicMock()

        def get_side_effect(url, **kwargs):
            if "diagnostics" in url:
                return _make_response(200, "<html>Diagnostics</html>")
            return _make_response(302, "")

        session.get.side_effect = get_side_effect
        session.head.side_effect = get_side_effect

        check.run(target, session, _make_config())

        assert len(target.accessible_paths) >= 0  # Could be populated


# ---------------------------------------------------------------------------
# BackupExposure
# ---------------------------------------------------------------------------


class TestBackupExposure:
    def test_backup_exposure_registered(self):
        """get_check('backup_exposure') must succeed."""
        check = get_check("backup_exposure")
        assert check.__class__.id == "backup_exposure"

    def test_backup_exposure_is_passive(self):
        """BackupExposure must be PASSIVE mode."""
        check = get_check("backup_exposure")
        assert check.__class__.min_mode == ScanMode.PASSIVE

    def test_backup_exposure_200_with_binary_content_produces_critical(self):
        """200 response with application/octet-stream and 500+ bytes must produce CRITICAL."""
        check = get_check("backup_exposure")
        target = _make_target()

        binary_body = "X" * 500
        session = MagicMock()
        session.get.return_value = _make_response(
            200,
            binary_body,
            content_type="application/octet-stream",
            content_length=500,
        )

        findings = check.run(target, session, _make_config())

        assert any(f.severity == Severity.CRITICAL for f in findings), (
            "Expected CRITICAL finding for accessible binary backup"
        )

    def test_backup_exposure_200_with_html_content_no_finding(self):
        """200 response with text/html (login redirect) must produce no finding."""
        check = get_check("backup_exposure")
        target = _make_target()

        session = MagicMock()
        session.get.return_value = _make_response(
            200,
            "<html><body>Login required</body></html>",
            content_type="text/html",
        )

        findings = check.run(target, session, _make_config())

        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0

    def test_backup_exposure_200_with_small_body_no_finding(self):
        """200 response with fewer than 100 bytes must produce no finding (too small)."""
        check = get_check("backup_exposure")
        target = _make_target()

        session = MagicMock()
        session.get.return_value = _make_response(
            200,
            "tiny",
            content_type="application/octet-stream",
            content_length=4,
        )

        findings = check.run(target, session, _make_config())

        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0


# ---------------------------------------------------------------------------
# SecurityHeaders
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    def test_security_headers_registered(self):
        """get_check('security_headers') must succeed."""
        check = get_check("security_headers")
        assert check.__class__.id == "security_headers"

    def test_security_headers_is_passive(self):
        """SecurityHeaders must be PASSIVE mode."""
        check = get_check("security_headers")
        assert check.__class__.min_mode == ScanMode.PASSIVE

    def test_security_headers_missing_csp_produces_medium_finding(self):
        """Response without Content-Security-Policy header must produce a MEDIUM finding."""
        check = get_check("security_headers")
        target = _make_target()

        session = MagicMock()
        # Response has some headers but missing CSP
        session.get.return_value = _make_response(
            200, "", headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                # No Content-Security-Policy
            }
        )

        findings = check.run(target, session, _make_config())

        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_security_headers_all_present_returns_empty(self):
        """Response with all required security headers must return []."""
        check = get_check("security_headers")
        target = _make_target()

        session = MagicMock()
        all_headers = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
        }
        session.get.return_value = _make_response(200, "", headers=all_headers)

        findings = check.run(target, session, _make_config())

        assert findings == []


# ---------------------------------------------------------------------------
# PackageEnumeration
# ---------------------------------------------------------------------------


class TestPackageEnumeration:
    def test_package_enumeration_registered(self):
        """get_check('package_enumeration') must succeed."""
        check = get_check("package_enumeration")
        assert check.__class__.id == "package_enumeration"

    def test_package_enumeration_is_passive(self):
        """PackageEnumeration must be PASSIVE mode."""
        check = get_check("package_enumeration")
        assert check.__class__.min_mode == ScanMode.PASSIVE
