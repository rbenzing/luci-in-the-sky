"""
Unit tests for luci_sky.exceptions — the typed exception hierarchy.

All tests will fail with ImportError until luci_sky/exceptions.py is implemented.
"""
from __future__ import annotations

import pytest

from luci_sky.exceptions import (
    AuthenticationError,
    CheckRegistrationError,
    ConfigurationError,
    CVEDatabaseError,
    LuciRedTeamError,
    ReportingError,
    TargetUnreachableError,
)

# Collect all concrete exception classes for parametrized tests
ALL_EXCEPTION_CLASSES = [
    TargetUnreachableError,
    AuthenticationError,
    CheckRegistrationError,
    ConfigurationError,
    CVEDatabaseError,
    ReportingError,
]


class TestExceptionHierarchy:
    def test_luci_redteam_error_is_exception(self):
        """LuciRedTeamError must be a subclass of the built-in Exception."""
        assert issubclass(LuciRedTeamError, Exception)

    @pytest.mark.parametrize("exc_cls", ALL_EXCEPTION_CLASSES)
    def test_all_exceptions_inherit_base(self, exc_cls):
        """Every custom exception must be a subclass of LuciRedTeamError."""
        assert issubclass(exc_cls, LuciRedTeamError), (
            f"{exc_cls.__name__} does not inherit from LuciRedTeamError"
        )

    @pytest.mark.parametrize("exc_cls", ALL_EXCEPTION_CLASSES)
    def test_exceptions_can_be_raised_and_caught_by_own_class(self, exc_cls):
        """Each exception must be catchable by its own class."""
        with pytest.raises(exc_cls):
            raise exc_cls("test message")

    @pytest.mark.parametrize("exc_cls", ALL_EXCEPTION_CLASSES)
    def test_exceptions_can_be_caught_by_base_class(self, exc_cls):
        """Each exception must be catchable by LuciRedTeamError (Liskov)."""
        with pytest.raises(LuciRedTeamError):
            raise exc_cls("test message")


class TestTargetUnreachableError:
    def test_target_unreachable_stores_message(self):
        """TargetUnreachableError must preserve the provided message in args[0]."""
        err = TargetUnreachableError("http://192.168.1.1 is not responding")
        assert "192.168.1.1" in str(err)

    def test_target_unreachable_with_cause(self):
        """TargetUnreachableError must support chaining from a causing exception."""
        cause = IOError("Connection timed out")
        try:
            raise TargetUnreachableError("http://x") from cause
        except TargetUnreachableError as e:
            assert e.__cause__ is cause


class TestConfigurationError:
    def test_configuration_error_raised_on_bad_threads(self):
        """ConfigurationError must be raisable with a descriptive message."""
        with pytest.raises(ConfigurationError) as exc_info:
            raise ConfigurationError("threads must be between 1 and 50, got 0")
        assert "threads" in str(exc_info.value)


class TestAuthenticationError:
    def test_authentication_error_message_preserved(self):
        """AuthenticationError must store and expose the message."""
        err = AuthenticationError("Login failed: invalid credentials")
        assert "invalid credentials" in str(err)


class TestCheckRegistrationError:
    def test_check_registration_error_with_duplicate_id(self):
        """CheckRegistrationError must be raisable with a duplicate-ID message."""
        with pytest.raises(CheckRegistrationError):
            raise CheckRegistrationError("Duplicate check id: 'tls_analysis'")


class TestCVEDatabaseError:
    def test_cve_database_error_raisable(self):
        """CVEDatabaseError must be raisable."""
        with pytest.raises(CVEDatabaseError):
            raise CVEDatabaseError("luci_cves.yml not found")


class TestReportingError:
    def test_reporting_error_raisable(self):
        """ReportingError must be raisable."""
        with pytest.raises(ReportingError):
            raise ReportingError("Cannot write report: permission denied")
