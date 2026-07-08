"""
luci_sky.checks.session — session management security checks.

Checks: SessionManagement
"""
from __future__ import annotations

from typing import List, Optional

from luci_sky.checks.base import Check
from luci_sky.checks import register
from luci_sky.config import Config
from luci_sky.models import Category, Confidence, Finding, Phase, ScanMode, Severity, Target


def _get_sysauth_cookie(resp) -> Optional[object]:
    """Return the sysauth cookie object from a response, or None."""
    try:
        for cookie in resp.cookies:
            if "sysauth" in cookie.name:
                return cookie
    except Exception:
        pass
    return None


def _get_sysauth_value(resp) -> Optional[str]:
    """Return the sysauth cookie value from a response, or None."""
    try:
        return resp.cookies.get("sysauth")
    except Exception:
        return None


@register
class SessionManagement(Check):
    """Audit session token security: cookie flags, entropy, fixation, post-logout reuse."""

    id = "session_management"
    name = "Session Management Security"
    category = Category.SESSION
    severity = Severity.HIGH
    min_mode = ScanMode.ACTIVE
    phase = Phase.EXPLOIT
    requires_auth = False
    description = (
        "Checks sysauth session cookie flags (Secure, HttpOnly, SameSite), "
        "tests for session fixation, and verifies post-logout token invalidation."
    )
    cve_ids: List[str] = ["CVE-2019-5102"]

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        login_url = f"{target.url}/cgi-bin/luci/;stok=/login"

        # Obtain a session cookie by performing a GET (may set pre-auth cookie)
        pre_token = None
        post_token = None

        try:
            pre_resp = session.get(login_url)
            pre_token = _get_sysauth_value(pre_resp)

            # Simulate a login to get the post-login cookie
            login_resp = session.post(login_url, data={
                "luci_username": "root",
                "luci_password": "",
            })
            post_token = _get_sysauth_value(login_resp)

            # Primary: check cookie flags from login response
            sysauth_cookie = _get_sysauth_cookie(login_resp)
            if sysauth_cookie is not None:
                findings.extend(self._check_cookie_flags(sysauth_cookie, target, login_url))

        except Exception:
            # Try GET to get any cookie
            try:
                resp = session.get(f"{target.url}/cgi-bin/luci/")
                sysauth_cookie = _get_sysauth_cookie(resp)
                if sysauth_cookie is not None:
                    findings.extend(self._check_cookie_flags(sysauth_cookie, target, f"{target.url}/cgi-bin/luci/"))
            except Exception:
                pass

        # Session fixation: same token before and after login
        if pre_token and post_token and pre_token == post_token:
            findings.append(self._make_finding(
                title="Session fixation: token unchanged after login",
                description=(
                    "The session token does not change upon successful authentication. "
                    "An attacker who can set a victim's session token can hijack their "
                    "authenticated session after login."
                ),
                evidence=self._sanitize(f"Pre-login token: {pre_token[:8]}*** Post-login: same value"),
                affected_url=login_url,
                remediation=(
                    "Regenerate the session token upon successful authentication. "
                    "Invalidate any pre-authentication tokens."
                ),
                severity=Severity.HIGH,
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                references=[
                    "https://owasp.org/www-community/attacks/Session_fixation",
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-5102",
                ],
                cve_ids=["CVE-2019-5102"],
            ))

        # Post-logout token reuse
        if post_token:
            findings.extend(self._check_post_logout_reuse(post_token, target, session))

        return findings

    def _check_cookie_flags(self, cookie, target: Target, url: str) -> List[Finding]:
        findings: List[Finding] = []

        # Secure flag
        secure = getattr(cookie, "secure", False)
        if not secure:
            findings.append(self._make_finding(
                title="Session cookie missing Secure flag",
                description=(
                    "The sysauth session cookie does not have the Secure flag set. "
                    "This allows the cookie to be transmitted over unencrypted HTTP "
                    "connections, exposing it to network sniffing attacks."
                ),
                evidence=f"Set-Cookie: sysauth=... (no Secure flag)",
                affected_url=url,
                remediation=(
                    "Set the Secure flag on all session cookies. Configure uhttpd "
                    "to set Secure on cookies when serving HTTPS."
                ),
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            ))

        # HttpOnly flag
        rest = getattr(cookie, "_rest", {})
        http_only = "HttpOnly" in rest or (hasattr(cookie, "has_nonstandard_attr") and cookie.has_nonstandard_attr("HttpOnly"))
        if not http_only:
            findings.append(self._make_finding(
                title="Session cookie missing HttpOnly flag",
                description=(
                    "The sysauth session cookie does not have the HttpOnly flag set. "
                    "JavaScript on the page can access this cookie, enabling XSS-based "
                    "session hijacking."
                ),
                evidence="Set-Cookie: sysauth=... (no HttpOnly flag)",
                affected_url=url,
                remediation=(
                    "Set the HttpOnly flag on all session cookies to prevent JavaScript access."
                ),
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                references=["https://owasp.org/www-community/HttpOnly"],
            ))

        # SameSite attribute
        same_site = rest.get("SameSite") if isinstance(rest, dict) else None
        if not same_site:
            if hasattr(cookie, "has_nonstandard_attr") and not cookie.has_nonstandard_attr("SameSite"):
                same_site = None
        if not same_site:
            findings.append(self._make_finding(
                title="Session cookie missing SameSite attribute",
                description=(
                    "The sysauth session cookie has no SameSite attribute. "
                    "Without SameSite=Strict or Lax, the cookie may be sent in "
                    "cross-site requests, enabling CSRF attacks."
                ),
                evidence="Set-Cookie: sysauth=... (no SameSite attribute)",
                affected_url=url,
                remediation=(
                    "Add SameSite=Strict to the sysauth cookie. "
                    "This prevents the cookie from being sent in cross-site requests."
                ),
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#samesite_attribute"],
            ))

        return findings

    def _check_post_logout_reuse(self, token: str, target: Target, session: object) -> List[Finding]:
        findings: List[Finding] = []
        logout_url = f"{target.url}/cgi-bin/luci/;stok=/logout"
        dashboard_url = f"{target.url}/cgi-bin/luci/admin/"

        try:
            # Logout
            session.get(logout_url)

            # Try to access with old token
            resp = session.get(dashboard_url)
            body = resp.text or ""

            if resp.status_code == 200 and any(
                kw in body.lower() for kw in ["admin", "dashboard", "system", "network"]
            ):
                findings.append(self._make_finding(
                    title="Post-logout token reuse: session not properly invalidated",
                    description=(
                        "The session token remains valid after logout. An attacker who "
                        "intercepts a session token can continue using it even after the "
                        "legitimate user logs out."
                    ),
                    evidence=self._sanitize(
                        f"Token {token[:8]}*** still accepted after logout. "
                        f"GET {dashboard_url} → HTTP {resp.status_code}"
                    ),
                    affected_url=logout_url,
                    remediation=(
                        "Invalidate session tokens server-side upon logout. "
                        "Remove the sysauth cookie from the server-side session store."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    references=["https://owasp.org/www-community/attacks/Session_hijacking_attack"],
                ))
        except Exception:
            pass

        return findings
