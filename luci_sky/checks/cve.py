"""
luci_sky.checks.cve — CVE correlation check.

Checks: CVECorrelation
"""
from __future__ import annotations

from typing import List

from luci_sky.checks.base import Check
from luci_sky.checks import register
from luci_sky.config import Config
from luci_sky.cve.database import CVEDatabase
from luci_sky.models import Category, Confidence, Finding, Phase, ScanMode, Severity, Target


@register
class CVECorrelation(Check):
    """Correlate detected OpenWrt version with known CVEs."""

    id = "cve_correlation"
    name = "CVE Correlation"
    category = Category.CVE
    severity = Severity.CRITICAL
    min_mode = ScanMode.PASSIVE
    phase = Phase.ANALYSIS
    requires_auth = False
    description = (
        "Matches the detected OpenWrt version against the CVE database and generates "
        "findings for each applicable vulnerability."
    )
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        db = CVEDatabase()

        version = target.detected_version
        matched_entries = db.match(version)

        for entry in matched_entries:
            severity = Severity.from_cvss(entry.cvss_score)
            findings.append(self._make_finding(
                title=f"{entry.cve_id}: {entry.title}",
                description=entry.description,
                evidence=(
                    f"CVE ID: {entry.cve_id}\n"
                    f"Component: {entry.component}\n"
                    f"Detected version: {version or 'unknown'}\n"
                    f"Affected versions: {', '.join(entry.affected_versions) or 'all versions'}\n"
                    f"CVSS: {entry.cvss_score} ({entry.cvss_vector})"
                ),
                affected_url=target.url,
                remediation=entry.remediation,
                severity=severity,
                cvss_score=entry.cvss_score,
                cvss_vector=entry.cvss_vector,
                references=entry.references,
                cve_ids=[entry.cve_id],
                confidence=Confidence.HIGH if version else Confidence.MEDIUM,
            ))

        return findings
