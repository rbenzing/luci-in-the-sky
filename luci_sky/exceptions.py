"""
luci_sky.exceptions — typed exception hierarchy for the luci-redteam framework.
"""
from __future__ import annotations


class LuciRedTeamError(Exception):
    """Base exception for all luci-redteam errors."""


class TargetUnreachableError(LuciRedTeamError):
    """Raised when the scan target cannot be reached via HTTP/HTTPS."""


class AuthenticationError(LuciRedTeamError):
    """Raised when authentication to the target fails."""


class CheckRegistrationError(LuciRedTeamError):
    """Raised when a check cannot be registered (e.g., duplicate ID)."""


class ConfigurationError(LuciRedTeamError):
    """Raised when the configuration is invalid or inconsistent."""


class CVEDatabaseError(LuciRedTeamError):
    """Raised when the CVE database cannot be loaded or parsed."""


class ReportingError(LuciRedTeamError):
    """Raised when a reporter fails to write its output."""


# Alias used in some contract descriptions
ScanError = LuciRedTeamError
