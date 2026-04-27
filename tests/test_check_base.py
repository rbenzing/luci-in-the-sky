"""
Unit tests for luci_sky.checks.base — Check ABC, _make_finding, _sanitize.

Tests will fail with ImportError until luci_sky/checks/base.py is implemented.
"""
from __future__ import annotations

from typing import List
from unittest.mock import MagicMock

import pytest

from luci_sky.checks.base import Check
from luci_sky.config import Config
from luci_sky.models import (
    Category,
    Confidence,
    Finding,
    ScanMode,
    Severity,
    Target,
)


# ---------------------------------------------------------------------------
# Minimal concrete Check subclass for testing the base class
# ---------------------------------------------------------------------------


class _MinimalCheck(Check):
    """Minimal concrete Check with all required ClassVars for testing base behaviour."""

    id = "test_check_minimal"
    name = "Minimal Test Check"
    category = Category.TLS
    severity = Severity.HIGH
    min_mode = ScanMode.PASSIVE
    requires_auth = False
    description = "A minimal check for unit-testing the base class."
    cve_ids: List[str] = []

    def run(
        self,
        target: Target,
        session: object,
        config: Config,
    ) -> List[Finding]:
        return []


class _CVECheck(Check):
    """Check that declares CVE IDs for testing cve_ids defaulting."""

    id = "test_check_with_cves"
    name = "CVE Test Check"
    category = Category.AUTHENTICATION
    severity = Severity.CRITICAL
    min_mode = ScanMode.ACTIVE
    requires_auth = False
    description = "Tests that cve_ids default from class attribute."
    cve_ids: List[str] = ["CVE-2019-12272", "CVE-2022-46623"]

    def run(self, target, session, config) -> List[Finding]:
        return []


# ---------------------------------------------------------------------------
# Abstract class enforcement
# ---------------------------------------------------------------------------


class TestCheckIsAbstract:
    def test_check_is_abstract(self):
        """Instantiating Check directly (without subclassing) must raise TypeError."""
        with pytest.raises(TypeError):
            Check()  # type: ignore[abstract]

    def test_concrete_check_must_implement_run(self):
        """A subclass that skips implementing run() must raise TypeError on instantiation."""

        class IncompleteCheck(Check):
            id = "incomplete"
            name = "Incomplete"
            category = Category.TLS
            severity = Severity.LOW
            min_mode = ScanMode.PASSIVE
            requires_auth = False
            description = "Missing run()."
            cve_ids: List[str] = []
            # run() deliberately NOT defined

        with pytest.raises(TypeError):
            IncompleteCheck()


# ---------------------------------------------------------------------------
# _make_finding helper
# ---------------------------------------------------------------------------


class TestMakeFinding:
    def setup_method(self):
        self.check = _MinimalCheck()
        self.target = Target(
            url="https://192.168.1.1",
            host="192.168.1.1",
            port=443,
            scheme="https",
            detected_version=None,
            detected_luci_version=None,
        )

    def test_make_finding_returns_finding_instance(self):
        """_make_finding() must return a Finding dataclass instance."""
        finding = self.check._make_finding(
            title="Test title",
            description="Test description",
            evidence="Test evidence",
            affected_url="https://192.168.1.1/test",
            remediation="Test remediation",
        )
        assert isinstance(finding, Finding)

    def test_make_finding_id_format(self):
        """Finding ID must follow LUCI-XXXX-001 format where XXXX is id[:4].upper()."""
        finding = self.check._make_finding(
            title="T",
            description="D",
            evidence="E",
            affected_url="https://192.168.1.1",
            remediation="R",
            finding_suffix="001",
        )
        # id = "test_check_minimal" → prefix = "TEST"
        assert finding.id.startswith("LUCI-TEST-")
        assert finding.id.endswith("-001")

    def test_make_finding_defaults_to_class_severity(self):
        """When severity is not supplied, _make_finding must use the class's severity."""
        finding = self.check._make_finding(
            title="T",
            description="D",
            evidence="E",
            affected_url="https://192.168.1.1",
            remediation="R",
        )
        assert finding.severity == _MinimalCheck.severity  # HIGH

    def test_make_finding_override_severity(self):
        """Explicitly passing severity must override the class-level default."""
        finding = self.check._make_finding(
            title="T",
            description="D",
            evidence="E",
            affected_url="https://192.168.1.1",
            remediation="R",
            severity=Severity.CRITICAL,
        )
        assert finding.severity == Severity.CRITICAL

    def test_make_finding_defaults_to_class_cve_ids(self):
        """When cve_ids is not supplied, _make_finding must use the class's cve_ids list."""
        cve_check = _CVECheck()
        finding = cve_check._make_finding(
            title="T",
            description="D",
            evidence="E",
            affected_url="https://192.168.1.1",
            remediation="R",
        )
        assert finding.cve_ids == ["CVE-2019-12272", "CVE-2022-46623"]

    def test_make_finding_defaults_to_class_min_mode(self):
        """When scan_mode is not supplied, _make_finding must use the class's min_mode."""
        finding = self.check._make_finding(
            title="T",
            description="D",
            evidence="E",
            affected_url="https://192.168.1.1",
            remediation="R",
        )
        assert finding.scan_mode == _MinimalCheck.min_mode  # PASSIVE

    def test_make_finding_populates_check_id(self):
        """check_id field must match the check's id attribute."""
        finding = self.check._make_finding(
            title="T",
            description="D",
            evidence="E",
            affected_url="https://192.168.1.1",
            remediation="R",
        )
        assert finding.check_id == "test_check_minimal"

    def test_make_finding_populates_category(self):
        """category field must match the check's category attribute."""
        finding = self.check._make_finding(
            title="T",
            description="D",
            evidence="E",
            affected_url="https://192.168.1.1",
            remediation="R",
        )
        assert finding.category == Category.TLS


# ---------------------------------------------------------------------------
# _sanitize static method
# ---------------------------------------------------------------------------


class TestSanitize:
    def test_sanitize_masks_sysauth_cookie(self):
        """_sanitize must replace sysauth token value (past first 8 chars) with ***."""
        text = "sysauth=abcdefghijklmnop"
        result = Check._sanitize(text)
        assert "abcdefgh" in result
        assert "***" in result
        # The full token must not be present
        assert "ijklmnop" not in result

    def test_sanitize_masks_sysauth_underscore_variant(self):
        """_sanitize must handle sysauth_ prefix variant."""
        text = "Set-Cookie: sysauth_https=abc123456789xyz; Path=/"
        result = Check._sanitize(text)
        assert "abc12345" in result
        # Further token chars must be masked
        assert "6789xyz" not in result

    def test_sanitize_masks_password_field(self):
        """_sanitize must mask the value after luci_password= in form data."""
        text = "luci_password=mysecretpassword"
        result = Check._sanitize(text)
        assert "luci_password=" in result
        assert "mysecretpassword" not in result
        assert "***" in result

    def test_sanitize_masks_password_case_insensitive(self):
        """_sanitize must mask password fields regardless of case."""
        text = "PASSWORD=topsecret"
        result = Check._sanitize(text)
        assert "topsecret" not in result

    def test_sanitize_masks_authorization_header(self):
        """_sanitize must replace the token portion of Authorization headers with ***."""
        text = "Authorization: Bearer mytoken123abc"
        result = Check._sanitize(text)
        assert "Authorization: Bearer" in result
        assert "mytoken123abc" not in result
        assert "***" in result

    def test_sanitize_truncates_to_max_len(self):
        """_sanitize must truncate text longer than max_len characters."""
        long_text = "a" * 3000
        result = Check._sanitize(long_text, max_len=2000)
        assert len(result) == 2000

    def test_sanitize_leaves_clean_text_unchanged(self):
        """_sanitize must not modify text that contains no sensitive patterns."""
        clean = "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 42"
        result = Check._sanitize(clean)
        assert result == clean

    def test_sanitize_default_max_len_is_2000(self):
        """_sanitize without explicit max_len must truncate at 2000 characters."""
        long_text = "b" * 5000
        result = Check._sanitize(long_text)
        assert len(result) <= 2000
