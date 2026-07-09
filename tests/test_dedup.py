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


def test_merge_multi_cve_merges_on_shared_key_regardless_of_order():
    def mk(check_id, cves):
        f = _f(check_id, Severity.HIGH, url="https://h/x")
        f.cve_ids = cves
        return f
    a = mk("a", ["CVE-A", "CVE-B"])
    b = mk("b", ["CVE-B"])  # shares a's NON-first key
    assert len(merge_findings([a, b])) == 1
    assert len(merge_findings([b, a])) == 1


def test_merge_groups_by_normalized_title_when_no_cve():
    a = _f("a", Severity.HIGH, url="https://h/x", title="Weak  TLS")
    b = _f("b", Severity.MEDIUM, url="https://h/x", title="weak tls")
    merged = merge_findings([a, b])
    assert len(merged) == 1
    assert set(merged[0].contributing_checks) == {"a", "b"}
