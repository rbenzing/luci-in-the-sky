"""
luci_sky.models — all data shapes for the luci-redteam scanning framework.

No I/O, no network calls, no internal package dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Qualitative severity rating for a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def numeric_rank(self) -> int:
        """Return a numeric rank for ordering (higher = more severe)."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Map a CVSS 3.1 base score to a qualitative severity rating."""
        if score == 0.0:
            return cls.INFO
        elif score < 4.0:
            return cls.LOW
        elif score < 7.0:
            return cls.MEDIUM
        elif score < 9.0:
            return cls.HIGH
        else:
            return cls.CRITICAL


class ScanMode(str, Enum):
    """Scan aggressiveness modes, ordered by increasing invasiveness."""

    PASSIVE = "passive"
    ACTIVE = "active"
    FULL = "full"

    def allows(self, required_mode: "ScanMode") -> bool:
        """Return True if this scan mode permits running a check that requires *required_mode*."""
        order = {ScanMode.PASSIVE: 0, ScanMode.ACTIVE: 1, ScanMode.FULL: 2}
        return order[self] >= order[required_mode]


class Phase(IntEnum):
    """Scan phase ordering: recon runs before analysis before exploitation."""

    RECON = 0
    ANALYSIS = 1
    EXPLOIT = 2


class Confidence(str, Enum):
    """Confidence level for a finding detection."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(str, Enum):
    """Vulnerability category for a finding."""

    AUTHENTICATION = "authentication"
    INJECTION = "injection"
    XSS = "xss"
    CSRF = "csrf"
    SESSION = "session"
    TLS = "tls"
    INFORMATION_DISCLOSURE = "information_disclosure"
    NETWORK = "network"
    CVE = "cve"
    CONFIGURATION = "configuration"


@dataclass
class Target:
    """Descriptor for the scan target."""

    url: str
    host: str
    port: int
    scheme: str
    detected_version: Optional[str] = None
    detected_luci_version: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    accessible_paths: List[str] = field(default_factory=list)
    is_authenticated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "detected_version": self.detected_version,
            "detected_luci_version": self.detected_luci_version,
            "open_ports": list(self.open_ports),
            "accessible_paths": list(self.accessible_paths),
            "is_authenticated": self.is_authenticated,
        }


@dataclass
class Finding:
    """A single discovered vulnerability or security issue."""

    id: str
    check_id: str
    title: str
    severity: Severity
    cvss_score: float
    cvss_vector: str
    category: Category
    confidence: Confidence
    description: str
    evidence: str
    affected_url: str
    remediation: str
    references: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    contributing_checks: List[str] = field(default_factory=list)
    scan_mode: ScanMode = ScanMode.PASSIVE
    timestamp: Optional[datetime] = field(default_factory=datetime.utcnow)
    raw_response: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "category": self.category.value,
            "confidence": self.confidence.value,
            "description": self.description,
            "evidence": self.evidence,
            "affected_url": self.affected_url,
            "remediation": self.remediation,
            "references": list(self.references),
            "cve_ids": list(self.cve_ids),
            "contributing_checks": list(self.contributing_checks),
            "scan_mode": self.scan_mode.value,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "raw_response": self.raw_response,
        }


@dataclass
class ScanResult:
    """Aggregated result of a complete scan run."""

    target: Target
    findings: List[Finding] = field(default_factory=list)
    scan_mode: ScanMode = ScanMode.PASSIVE
    tool_version: str = "1.0.0"
    started_at: Optional[datetime] = field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    checks_run: int = 0
    checks_failed: int = 0

    def findings_by_severity(self) -> Dict[Severity, List[Finding]]:
        """Return findings bucketed by severity level."""
        buckets: Dict[Severity, List[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            buckets[f.severity].append(f)
        return buckets

    def findings_above(self, threshold: Severity) -> List[Finding]:
        """Return all findings whose severity is >= the given threshold (inclusive)."""
        return [f for f in self.findings if f.severity.numeric_rank >= threshold.numeric_rank]

    @property
    def duration_seconds(self) -> Optional[float]:
        """Elapsed scan time in seconds, or None if the scan has not finished."""
        if self.finished_at is None or self.started_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        by_sev = self.findings_by_severity()
        summary = {
            "critical": len(by_sev[Severity.CRITICAL]),
            "high": len(by_sev[Severity.HIGH]),
            "medium": len(by_sev[Severity.MEDIUM]),
            "low": len(by_sev[Severity.LOW]),
            "info": len(by_sev[Severity.INFO]),
            "total": len(self.findings),
        }
        return {
            "target": self.target.to_dict(),
            "scan_mode": self.scan_mode.value,
            "tool_version": self.tool_version,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "checks_run": self.checks_run,
            "checks_failed": self.checks_failed,
            "summary": summary,
            "findings": [f.to_dict() for f in self.findings],
        }
