"""
luci_sky.checks.base — abstract Check base class.

All check plugins subclass Check and implement run().
"""
from __future__ import annotations

from abc import ABCMeta, abstractmethod
from datetime import datetime
from typing import ClassVar, List, Optional

from luci_sky.config import Config
from luci_sky.models import Category, Confidence, Finding, Phase, ScanMode, Severity, Target
from luci_sky.sanitize import sanitize as _shared_sanitize


class _CheckMeta(ABCMeta):
    """Metaclass for Check that pre-populates the class namespace with default
    attribute values so that ``severity = severity`` style assignments in
    subclass bodies resolve correctly under Python 3.13's scoping rules."""

    @classmethod
    def __prepare__(mcs, name: str, bases: tuple, **kwargs):  # type: ignore[override]
        ns = super().__prepare__(name, bases, **kwargs)
        # Inject default values for ClassVar attributes so that self-referential
        # assignments (e.g. ``severity = severity``) find a value on the RHS.
        ns["severity"] = Severity.HIGH
        ns["min_mode"] = ScanMode.PASSIVE
        ns["requires_auth"] = False
        ns["phase"] = Phase.ANALYSIS
        return ns


class Check(metaclass=_CheckMeta):
    """Abstract base class for all security checks."""

    # --- Required class-level metadata ---
    id: ClassVar[str]
    name: ClassVar[str]
    category: ClassVar[Category]
    severity: ClassVar[Severity]
    min_mode: ClassVar[ScanMode]
    requires_auth: ClassVar[bool]
    phase: ClassVar[Phase]
    description: ClassVar[str]
    cve_ids: ClassVar[List[str]]

    @abstractmethod
    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        """Execute this check against *target* using *session* and return findings."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        title: str,
        description: str,
        evidence: str,
        affected_url: str,
        remediation: str,
        severity: Optional[Severity] = None,
        cvss_score: float = 5.0,
        cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        confidence: Confidence = Confidence.HIGH,
        references: Optional[List[str]] = None,
        cve_ids: Optional[List[str]] = None,
        scan_mode: Optional[ScanMode] = None,
        finding_suffix: str = "001",
    ) -> Finding:
        """Construct a Finding with defaults drawn from the check's class attributes."""
        # Build ID: LUCI-XXXX-NNN where XXXX = first 4 chars of check id, uppercased
        prefix = self.__class__.id[:4].upper()
        finding_id = f"LUCI-{prefix}-{finding_suffix}"

        return Finding(
            id=finding_id,
            check_id=self.__class__.id,
            title=title,
            severity=severity if severity is not None else self.__class__.severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            category=self.__class__.category,
            confidence=confidence,
            description=description,
            evidence=self._sanitize(evidence),
            affected_url=affected_url,
            remediation=remediation,
            references=references or [],
            cve_ids=cve_ids if cve_ids is not None else list(self.__class__.cve_ids),
            scan_mode=scan_mode if scan_mode is not None else self.__class__.min_mode,
            timestamp=datetime.utcnow(),
            raw_response=None,
        )

    @staticmethod
    def _sanitize(text: str, max_len: int = 2000) -> str:
        """Delegate to the shared sanitizer (kept as a method for existing callers)."""
        return _shared_sanitize(text, max_len=max_len)
