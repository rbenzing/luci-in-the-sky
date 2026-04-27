"""
luci_sky.checks.xss — cross-site scripting checks.

Checks: XSSDetection, StoredXSS
"""
from __future__ import annotations

from typing import List

from luci_sky.checks.base import Check
from luci_sky.checks import register
from luci_sky.config import Config
from luci_sky.models import Category, Confidence, Finding, ScanMode, Severity, Target

_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'><script>alert(1)</script>",
]

_ENCODED_MARKERS = ["&lt;script&gt;", "&lt;img", "&#60;script", "%3Cscript"]

_XSS_ENDPOINTS = [
    "/cgi-bin/luci/",
    "/cgi-bin/luci/;stok=/login",
    "/cgi-bin/luci/admin/",
    "/cgi-bin/luci/admin/system",
    "/cgi-bin/luci/admin/network",
]

_STORED_XSS_TARGETS = [
    {
        "inject_url": "/cgi-bin/luci/admin/network/interfaces",
        "inject_field": "hostname",
        "verify_url": "/cgi-bin/luci/admin/",
    },
    {
        "inject_url": "/cgi-bin/luci/admin/wireless",
        "inject_field": "ssid",
        "verify_url": "/cgi-bin/luci/admin/wireless",
    },
]


@register
class XSSDetection(Check):
    """Test for reflected XSS in LuCI parameters."""

    id = "xss_detection"
    name = "Reflected XSS Detection"
    category = Category.XSS
    severity = Severity.HIGH
    min_mode = ScanMode.ACTIVE
    requires_auth = False
    description = (
        "Tests LuCI endpoints for reflected XSS by injecting payloads via GET and POST "
        "parameters, checking for unencoded reflection in the response."
    )
    cve_ids: List[str] = ["CVE-2023-28489"]

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []

        for endpoint in _XSS_ENDPOINTS:
            url = f"{target.url}{endpoint}"
            for payload in _XSS_PAYLOADS:
                # Test via GET query parameter
                try:
                    resp = session.get(url, params={"q": payload})
                    body = resp.text or ""
                    if self._is_reflected_unencoded(payload, body):
                        findings.append(self._make_xss_finding(url, payload, "GET", body))
                        break
                except Exception:
                    pass

                # Test via POST parameter
                try:
                    resp = session.post(url, data={"search": payload, "q": payload})
                    body = resp.text or ""
                    if self._is_reflected_unencoded(payload, body):
                        findings.append(self._make_xss_finding(url, payload, "POST", body))
                        break
                except Exception:
                    pass

        return findings

    def _is_reflected_unencoded(self, payload: str, body: str) -> bool:
        """Return True if payload appears literally (not HTML-encoded) in body."""
        if payload not in body:
            return False
        # Check that it's not just the encoded version
        for enc in _ENCODED_MARKERS:
            if enc in body and payload not in body:
                return False
        return True

    def _make_xss_finding(self, url: str, payload: str, method: str, body: str) -> Finding:
        return self._make_finding(
            title=f"Reflected XSS: unencoded payload in response from {method} {url}",
            description=(
                f"The {method} parameter at {url} reflects the XSS payload "
                f"'{payload}' without HTML encoding. Attackers can craft links that "
                "execute JavaScript in a victim's browser."
            ),
            evidence=self._sanitize(
                f"{method} {url}?q={payload}\n"
                f"Response snippet: {body[:200]}"
            ),
            affected_url=url,
            remediation=(
                "HTML-encode all user-supplied input before rendering in responses. "
                "Use Content-Security-Policy to block inline script execution."
            ),
            severity=Severity.HIGH,
            cvss_score=6.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-28489",
                "https://owasp.org/www-community/attacks/xss/",
            ],
            cve_ids=["CVE-2023-28489"],
        )


@register
class StoredXSS(Check):
    """Test for stored XSS in persistent LuCI fields (full mode)."""

    id = "stored_xss"
    name = "Stored XSS Detection"
    category = Category.XSS
    severity = Severity.HIGH
    min_mode = ScanMode.FULL
    requires_auth = False
    description = (
        "Injects XSS payloads into persistent fields (hostname, SSID) and checks "
        "whether the payload appears unencoded in subsequently loaded admin pages."
    )
    cve_ids: List[str] = ["CVE-2018-19629"]

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        payload = "<script>alert(1)</script>"

        for tgt in _STORED_XSS_TARGETS:
            inject_url = f"{target.url}{tgt['inject_url']}"
            verify_url = f"{target.url}{tgt['verify_url']}"
            field = tgt["inject_field"]

            try:
                # Inject
                session.post(inject_url, data={field: payload})

                # Verify
                resp = session.get(verify_url)
                body = resp.text or ""

                if payload in body:
                    findings.append(self._make_finding(
                        title=f"Stored XSS: payload persists in {field} field",
                        description=(
                            f"An XSS payload injected into the '{field}' field at {inject_url} "
                            f"was found unencoded in the admin page at {verify_url}. "
                            "An attacker with partial access can compromise admin sessions."
                        ),
                        evidence=self._sanitize(
                            f"Injected via POST {inject_url} field={field}\n"
                            f"Verified at GET {verify_url}: payload found in response"
                        ),
                        affected_url=inject_url,
                        remediation=(
                            "HTML-encode all stored data before rendering. "
                            "Validate and sanitize input server-side before storage. "
                            "Implement Content-Security-Policy."
                        ),
                        severity=Severity.HIGH,
                        cvss_score=8.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
                        references=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2018-19629",
                            "https://owasp.org/www-community/attacks/xss/",
                        ],
                        cve_ids=["CVE-2018-19629"],
                    ))
                    return findings

            except Exception:
                continue

        return findings
