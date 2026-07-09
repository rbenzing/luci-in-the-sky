from luci_sky.dedup import merge_findings
from luci_sky.models import Finding, Severity, Category, Confidence


def _f(check_id, sev, cve=None, url="https://h/x", title="t"):
    return Finding(
        id="LUCI-X-001", check_id=check_id, title=title, severity=sev,
        cvss_score=float(sev.numeric_rank), cvss_vector="v",
        category=Category.CVE, confidence=Confidence.HIGH, description="d",
        evidence="e", affected_url=url, remediation="r",
        references=[f"ref-{check_id}"], cve_ids=[cve] if cve else [],
    )


def test_merge_collapses_shared_cve_same_url():
    findings = [
        _f("default_credentials", Severity.CRITICAL, cve="CVE-2019-12272"),
        _f("service_security", Severity.HIGH, cve="CVE-2019-12272"),
        _f("cve_correlation", Severity.MEDIUM, cve="CVE-2019-12272"),
    ]
    merged = merge_findings(findings)
    assert len(merged) == 1
    m = merged[0]
    assert m.severity == Severity.CRITICAL          # highest wins
    assert set(m.contributing_checks) == {
        "default_credentials", "service_security", "cve_correlation"}
    assert set(m.references) == {"ref-default_credentials", "ref-service_security",
                                 "ref-cve_correlation"}


def test_merge_keeps_distinct_urls_separate():
    findings = [
        _f("a", Severity.HIGH, cve="CVE-1", url="https://h/1"),
        _f("b", Severity.HIGH, cve="CVE-1", url="https://h/2"),
    ]
    assert len(merge_findings(findings)) == 2


def test_merge_empty_returns_empty():
    assert merge_findings([]) == []
