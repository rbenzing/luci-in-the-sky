"""
Unit tests for luci_sky.checks — registry, @register decorator, filtered_checks.

Tests will fail with ImportError until luci_sky/checks/__init__.py is implemented.
Registry-mutation tests use a separate copy of the registry to avoid cross-test pollution.
"""
from __future__ import annotations

import importlib
from typing import List
from unittest.mock import MagicMock

import pytest

from luci_sky.checks import (
    _REGISTRY,
    all_checks,
    filtered_checks,
    get_check,
    register,
)
from luci_sky.checks.base import Check
from luci_sky.config import Config
from luci_sky.models import (
    Category,
    Finding,
    ScanMode,
    Severity,
    Target,
)


# ---------------------------------------------------------------------------
# Helpers: build test Check classes WITHOUT polluting the live registry
# ---------------------------------------------------------------------------


def _build_check_class(
    check_id: str,
    severity: Severity = Severity.HIGH,
    min_mode: ScanMode = ScanMode.PASSIVE,
    requires_auth: bool = False,
) -> type:
    """Return an un-registered Check subclass with the given attributes."""

    class _TestCheck(Check):
        id = check_id
        name = f"Test check {check_id}"
        category = Category.TLS
        severity = severity  # type: ignore[assignment]
        min_mode = min_mode  # type: ignore[assignment]
        requires_auth = requires_auth  # type: ignore[assignment]
        description = f"Auto-generated check {check_id}"
        cve_ids: List[str] = []

        def run(self, target, session, config) -> List[Finding]:
            return []

    _TestCheck.__name__ = f"Check_{check_id}"
    _TestCheck.__qualname__ = f"Check_{check_id}"
    return _TestCheck


# ---------------------------------------------------------------------------
# @register decorator
# ---------------------------------------------------------------------------


class TestRegisterDecorator:
    def test_register_decorator_adds_to_registry(self):
        """@register must add the check class to _REGISTRY keyed by its id."""
        unique_id = "_test_reg_add_001"
        cls = _build_check_class(unique_id)
        try:
            register(cls)
            check = get_check(unique_id)
            assert isinstance(check, cls)
        finally:
            _REGISTRY.pop(unique_id, None)

    def test_register_duplicate_id_raises_value_error(self):
        """Registering a second class with the same id must raise ValueError."""
        unique_id = "_test_reg_dup_001"
        cls1 = _build_check_class(unique_id)
        cls2 = _build_check_class(unique_id)
        try:
            register(cls1)
            with pytest.raises(ValueError, match="Duplicate"):
                register(cls2)
        finally:
            _REGISTRY.pop(unique_id, None)

    def test_register_requires_id_attribute(self):
        """A class with no 'id' attribute must raise ValueError on @register."""

        class NoId(Check):
            name = "no id"
            category = Category.TLS
            severity = Severity.LOW
            min_mode = ScanMode.PASSIVE
            requires_auth = False
            description = "no id"
            cve_ids: List[str] = []

            def run(self, target, session, config) -> List[Finding]:
                return []

        with pytest.raises((ValueError, AttributeError)):
            register(NoId)


# ---------------------------------------------------------------------------
# all_checks() / get_check()
# ---------------------------------------------------------------------------


class TestAllChecksAndGetCheck:
    def test_all_checks_returns_list_of_check_instances(self):
        """all_checks() must return a non-empty list of Check instances."""
        checks = all_checks()
        assert isinstance(checks, list)
        assert len(checks) > 0
        for c in checks:
            assert isinstance(c, Check)

    def test_get_check_raises_key_error_for_unknown_id(self):
        """get_check() with an unknown id must raise KeyError."""
        with pytest.raises(KeyError):
            get_check("definitely_not_registered_xyz_abc")

    def test_get_check_key_error_message_lists_available(self):
        """The KeyError message must include 'Available:' with the known IDs."""
        with pytest.raises(KeyError) as exc_info:
            get_check("nonexistent_check_id")
        error_text = str(exc_info.value)
        assert "Available" in error_text or "available" in error_text

    def test_get_check_returns_instance_of_correct_class(self):
        """get_check(id) must return an instance of the class registered under that id."""
        unique_id = "_test_get_check_001"
        cls = _build_check_class(unique_id)
        try:
            register(cls)
            instance = get_check(unique_id)
            assert isinstance(instance, cls)
        finally:
            _REGISTRY.pop(unique_id, None)


# ---------------------------------------------------------------------------
# filtered_checks()
# ---------------------------------------------------------------------------


class TestFilteredChecks:
    """Tests rely on the real registered checks from checks/__init__.py imports."""

    def test_filtered_checks_mode_filtering_passive_only(self):
        """PASSIVE mode must exclude checks with min_mode=ACTIVE or FULL."""
        checks = filtered_checks(
            mode=ScanMode.PASSIVE,
            severity_threshold=Severity.INFO,
            include_ids=[],
            exclude_ids=[],
            requires_auth=False,
        )
        for c in checks:
            assert ScanMode.PASSIVE.allows(c.__class__.min_mode), (
                f"Check {c.__class__.id} with min_mode={c.__class__.min_mode} "
                f"should not be returned for PASSIVE mode"
            )

    def test_filtered_checks_active_includes_passive(self):
        """ACTIVE mode must include both PASSIVE and ACTIVE min_mode checks."""
        passive_checks = filtered_checks(
            mode=ScanMode.PASSIVE,
            severity_threshold=Severity.INFO,
            include_ids=[],
            exclude_ids=[],
            requires_auth=False,
        )
        active_checks = filtered_checks(
            mode=ScanMode.ACTIVE,
            severity_threshold=Severity.INFO,
            include_ids=[],
            exclude_ids=[],
            requires_auth=False,
        )
        # Active mode must return at least as many checks as passive
        assert len(active_checks) >= len(passive_checks)
        passive_ids = {c.__class__.id for c in passive_checks}
        active_ids = {c.__class__.id for c in active_checks}
        assert passive_ids.issubset(active_ids), (
            "ACTIVE mode must include all PASSIVE mode checks"
        )

    def test_filtered_checks_severity_threshold(self):
        """Checks whose max severity is below the threshold must be excluded."""
        high_threshold_checks = filtered_checks(
            mode=ScanMode.FULL,
            severity_threshold=Severity.HIGH,
            include_ids=[],
            exclude_ids=[],
            requires_auth=True,
        )
        for c in high_threshold_checks:
            assert c.__class__.severity.numeric_rank >= Severity.HIGH.numeric_rank, (
                f"Check {c.__class__.id} with severity={c.__class__.severity} "
                f"should not pass HIGH threshold filter"
            )

    def test_filtered_checks_requires_auth_filtering(self):
        """Checks with requires_auth=True must be excluded when requires_auth=False."""
        checks = filtered_checks(
            mode=ScanMode.FULL,
            severity_threshold=Severity.INFO,
            include_ids=[],
            exclude_ids=[],
            requires_auth=False,
        )
        for c in checks:
            assert c.__class__.requires_auth is False, (
                f"Check {c.__class__.id} requires auth but was returned for unauthenticated scan"
            )

    def test_filtered_checks_requires_auth_included_when_authenticated(self):
        """Auth-requiring checks must appear when requires_auth=True is passed."""
        with_auth = filtered_checks(
            mode=ScanMode.FULL,
            severity_threshold=Severity.INFO,
            include_ids=[],
            exclude_ids=[],
            requires_auth=True,
        )
        without_auth = filtered_checks(
            mode=ScanMode.FULL,
            severity_threshold=Severity.INFO,
            include_ids=[],
            exclude_ids=[],
            requires_auth=False,
        )
        # Authenticated scan should return at least as many checks
        assert len(with_auth) >= len(without_auth)

    def test_filtered_checks_include_ids(self):
        """include_ids non-empty must restrict output to only those IDs."""
        # tls_analysis is a real registered passive check
        checks = filtered_checks(
            mode=ScanMode.PASSIVE,
            severity_threshold=Severity.INFO,
            include_ids=["tls_analysis"],
            exclude_ids=[],
            requires_auth=False,
        )
        ids = [c.__class__.id for c in checks]
        assert ids == ["tls_analysis"] or "tls_analysis" in ids
        for c in checks:
            assert c.__class__.id == "tls_analysis"

    def test_filtered_checks_exclude_ids(self):
        """exclude_ids must remove the specified check IDs from the results."""
        all_passive = filtered_checks(
            mode=ScanMode.PASSIVE,
            severity_threshold=Severity.INFO,
            include_ids=[],
            exclude_ids=[],
            requires_auth=False,
        )
        first_id = all_passive[0].__class__.id if all_passive else None
        if first_id is None:
            pytest.skip("No passive checks registered")

        excluded = filtered_checks(
            mode=ScanMode.PASSIVE,
            severity_threshold=Severity.INFO,
            include_ids=[],
            exclude_ids=[first_id],
            requires_auth=False,
        )
        excluded_ids = [c.__class__.id for c in excluded]
        assert first_id not in excluded_ids

    def test_filtered_checks_returns_instances_not_classes(self):
        """filtered_checks must return instantiated Check objects, not class objects."""
        checks = filtered_checks(
            mode=ScanMode.PASSIVE,
            severity_threshold=Severity.INFO,
            include_ids=[],
            exclude_ids=[],
            requires_auth=False,
        )
        for c in checks:
            assert isinstance(c, Check), f"{c!r} is not a Check instance"


# ---------------------------------------------------------------------------
# Check matrix: verify all 28 expected check IDs are registered
# ---------------------------------------------------------------------------


EXPECTED_CHECK_IDS = {
    "tls_analysis",
    "version_detection",
    "path_enumeration",
    "backup_exposure",
    "package_enumeration",
    "security_headers",
    "port_scan",
    "service_security",
    "cors_misconfiguration",
    "wan_exposure",
    "firewall_audit",
    "wireless_audit",
    "cve_correlation",
    "session_management",
    "default_credentials",
    "auth_bypass",
    "rate_limiting",
    "rate_limit_stress",
    "command_injection",
    "time_based_injection",
    "path_traversal",
    "xss_detection",
    "stored_xss",
    "csrf_validation",
    "rpc_exploitation",
    "upnp_audit",
    "upnp_port_mapping",
    "dns_rebinding",
}


class TestExpectedChecksRegistered:
    def test_all_28_expected_check_ids_are_registered(self):
        """All 28 check IDs from the architecture matrix must be in the registry."""
        registered_ids = set(_REGISTRY.keys())
        missing = EXPECTED_CHECK_IDS - registered_ids
        assert not missing, (
            f"The following expected check IDs are not registered: {sorted(missing)}"
        )
