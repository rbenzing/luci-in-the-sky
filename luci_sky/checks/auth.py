"""
luci_sky.checks.auth — authentication security checks.

Checks: DefaultCredentials, AuthBypass, RateLimiting, RateLimitStress
"""
from __future__ import annotations

import time
from typing import List

from luci_sky.checks.base import Check
from luci_sky.checks import register
from luci_sky.config import Config
from luci_sky.models import Category, Confidence, Finding, Phase, ScanMode, Severity, Target

_DEFAULT_CREDENTIALS = [
    ("root", ""),
    ("root", "root"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("ubnt", "ubnt"),
    ("user", "user"),
    ("guest", "guest"),
]


@register
class DefaultCredentials(Check):
    """Test for default credential pairs on the LuCI login endpoint."""

    id = "default_credentials"
    name = "Default Credentials Check"
    category = Category.AUTHENTICATION
    severity = Severity.CRITICAL
    min_mode = ScanMode.ACTIVE
    phase = Phase.EXPLOIT
    requires_auth = False
    description = "Tests a list of commonly-known default username/password pairs against LuCI."
    cve_ids: List[str] = ["CVE-2019-12272"]

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        login_url = f"{target.url}/cgi-bin/luci/;stok=/login"

        cred_list = list(_DEFAULT_CREDENTIALS)
        extra = getattr(config, "extra_credentials", None) or []
        cred_list.extend(extra)

        for username, password in cred_list:
            payload = {
                "luci_username": username,
                "luci_password": password,
            }
            try:
                resp = session.post(login_url, data=payload)
                if "sysauth" in resp.cookies or (
                    hasattr(resp, "cookies") and resp.cookies.get("sysauth")
                ):
                    # Mask password in evidence
                    evidence = self._sanitize(
                        f"POST {login_url}\n"
                        f"Credentials: {username}:({password if password else 'empty'})\n"
                        f"HTTP {resp.status_code}\nsysauth: present"
                    )
                    findings.append(self._make_finding(
                        title=f"Default credentials accepted: {username}:({'(empty)' if not password else '****'})",
                        description=(
                            f"The LuCI interface accepted the default credential pair "
                            f"'{username}' with {'an empty' if not password else 'a known default'} password. "
                            "An unauthenticated attacker can gain full administrative access."
                        ),
                        evidence=evidence,
                        affected_url=login_url,
                        remediation=(
                            "Change the default root password immediately via "
                            "System > Administration. Set a strong, unique password."
                        ),
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        references=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2019-12272",
                            "https://openwrt.org/docs/guide-user/security/openwrt_security",
                        ],
                        cve_ids=["CVE-2019-12272"],
                    ))
                    return findings  # Stop after first success
            except Exception:
                continue

        return findings


@register
class AuthBypass(Check):
    """Test for authentication bypass via path manipulation and header spoofing."""

    id = "auth_bypass"
    name = "Authentication Bypass Check"
    category = Category.AUTHENTICATION
    severity = Severity.CRITICAL
    min_mode = ScanMode.ACTIVE
    phase = Phase.EXPLOIT
    requires_auth = False
    description = "Tests authentication bypass techniques: path manipulation and X-Forwarded-For spoofing."
    cve_ids: List[str] = ["CVE-2021-33998"]

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []

        bypass_attempts = [
            # Path manipulation
            (f"{target.url}/cgi-bin/luci/admin/", {"X-Forwarded-For": "127.0.0.1"}),
            (f"{target.url}/cgi-bin/luci/;stok=AAAAAAAAAAAAAAAA/admin/", {}),
            (f"{target.url}/cgi-bin/luci/%2F..%2Fadmin/", {}),
            (f"{target.url}/cgi-bin/luci/admin/system", {"X-Original-URL": "/cgi-bin/luci/admin/system"}),
            (f"{target.url}/cgi-bin/luci//admin/", {}),
        ]

        for url, extra_headers in bypass_attempts:
            try:
                resp = session.get(url, headers=extra_headers, allow_redirects=False)
                if resp.status_code == 200:
                    body = resp.text or ""
                    # Check for admin panel indicators
                    if any(kw in body for kw in [
                        "Administration", "dashboard", "System", "Network",
                        "LuCI Administration", "admin-panel"
                    ]):
                        findings.append(self._make_finding(
                            title="Authentication bypass: admin panel accessible without credentials",
                            description=(
                                f"The URL {url} returned HTTP 200 with admin panel content "
                                "without valid authentication. This indicates an authentication "
                                "bypass vulnerability."
                            ),
                            evidence=f"GET {url} headers={extra_headers} → HTTP 200 with admin content",
                            affected_url=url,
                            remediation=(
                                "Ensure all admin paths enforce authentication. "
                                "Update to a version that patches CVE-2021-33998."
                            ),
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            references=[
                                "https://nvd.nist.gov/vuln/detail/CVE-2021-33998",
                            ],
                            cve_ids=["CVE-2021-33998"],
                        ))
            except Exception:
                continue

        return findings


@register
class RateLimiting(Check):
    """Test whether login attempts are rate-limited."""

    id = "rate_limiting"
    name = "Rate Limiting Check"
    category = Category.AUTHENTICATION
    severity = Severity.MEDIUM
    min_mode = ScanMode.ACTIVE
    phase = Phase.EXPLOIT
    requires_auth = False
    description = "Sends 20 rapid failed login attempts to detect absence of brute-force protection."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        login_url = f"{target.url}/cgi-bin/luci/;stok=/login"
        payload = {"luci_username": "root", "luci_password": "wrongpassword_test_xyz"}

        responses = []
        for i in range(20):
            try:
                resp = session.post(login_url, data=payload)
                responses.append((resp.status_code, resp.text or ""))

                # HTTP 429 → rate limiting exists
                if resp.status_code == 429:
                    return []  # Protected

            except Exception:
                continue

        if not responses:
            return []

        # Check for lockout (changing error message or account lockout keywords)
        first_text = responses[0][1] if responses else ""
        later_texts = [r[1] for r in responses[10:]] if len(responses) > 10 else []

        # If later responses differ significantly → lockout detected
        for later_text in later_texts:
            if (
                "locked" in later_text.lower()
                or "account" in later_text.lower()
                or "temporarily" in later_text.lower()
                or (first_text and first_text.strip() != later_text.strip() and len(later_text) > 0
                    and "locked" in later_text.lower())
            ):
                return []  # Lockout detected — protection exists

        # Check if all responses look identical (no protection)
        statuses = [r[0] for r in responses]
        if all(s in (200, 401, 403) for s in statuses):
            # No 429, no lockout → no rate limiting
            findings.append(self._make_finding(
                title="Brute-force protection absent: no rate limiting on login endpoint",
                description=(
                    "The login endpoint accepted 20 rapid failed attempts without rate limiting, "
                    "account lockout, or CAPTCHA challenge. This allows brute-force attacks."
                ),
                evidence=(
                    f"20 POST requests to {login_url} all returned HTTP {statuses[0]} "
                    "with no lockout or rate limit response."
                ),
                affected_url=login_url,
                remediation=(
                    "Implement rate limiting on the login endpoint. "
                    "Use fail2ban or configure uhttpd connection limits."
                ),
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                references=[
                    "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                ],
            ))

        return findings


@register
class RateLimitStress(Check):
    """Full-mode stress test for rate limiting (sends 50 concurrent requests)."""

    id = "rate_limit_stress"
    name = "Rate Limit Stress Test"
    category = Category.AUTHENTICATION
    severity = Severity.MEDIUM
    min_mode = ScanMode.FULL
    phase = Phase.EXPLOIT
    requires_auth = False
    description = "Sends 50 concurrent login requests to stress-test rate limiting defenses."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        from concurrent.futures import ThreadPoolExecutor
        login_url = f"{target.url}/cgi-bin/luci/;stok=/login"
        payload = {"luci_username": "root", "luci_password": "stresstest_xyz_123"}
        responses = []

        def make_request():
            try:
                resp = session.post(login_url, data=payload)
                return resp.status_code
            except Exception:
                return 0

        with ThreadPoolExecutor(max_workers=50) as ex:
            futs = [ex.submit(make_request) for _ in range(50)]
            responses = [f.result() for f in futs]

        rate_limited = any(s == 429 for s in responses)
        if not rate_limited and all(s in (200, 401, 403, 0) for s in responses):
            findings.append(self._make_finding(
                title="Rate limit stress test: no rate limiting under 50 concurrent requests",
                description=(
                    "50 concurrent login requests were processed without any rate limit "
                    "response (no HTTP 429). The server may be vulnerable to credential stuffing."
                ),
                evidence=f"50 concurrent POST to {login_url}: statuses {set(responses)}",
                affected_url=login_url,
                remediation=(
                    "Implement concurrent request rate limiting. "
                    "Use fail2ban with the luci jail to block rapid login attempts."
                ),
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                references=[
                    "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                ],
            ))
        return findings
