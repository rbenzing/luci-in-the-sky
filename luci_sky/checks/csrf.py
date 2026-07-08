"""
luci_sky.checks.csrf — CSRF protection validation check.

Checks: CSRFValidation
"""
from __future__ import annotations

import re
from typing import List, Optional

from luci_sky.checks.base import Check
from luci_sky.checks import register
from luci_sky.config import Config
from luci_sky.models import Category, Confidence, Finding, Phase, ScanMode, Severity, Target

# Patterns that indicate a CSRF token field in a form
_TOKEN_PATTERNS = [
    # Token-named input with any non-empty value (>= 4 chars)
    re.compile(r'<input[^>]+name=["\'](?:token|csrf|_token|stok|csrfmiddlewaretoken|__RequestVerificationToken|authenticity_token)["\'][^>]*value=["\']([^"\']{4,})["\']', re.IGNORECASE),
    # Or value= first, then name=
    re.compile(r'<input[^>]+value=["\']([^"\']{4,})["\'][^>]*name=["\'](?:token|csrf|_token|stok)["\']', re.IGNORECASE),
    # Hex token value >= 32 chars (heuristic)
    re.compile(r'value=["\']([a-f0-9]{32,})["\']', re.IGNORECASE),
]

_STATE_CHANGE_ENDPOINTS = [
    "/cgi-bin/luci/admin/system/admin",
    "/cgi-bin/luci/admin/system/reboot",
    "/cgi-bin/luci/admin/network/firewall",
    "/cgi-bin/luci/admin/system/",
]


def _extract_token(html: str) -> Optional[str]:
    """Extract a CSRF token from an HTML form."""
    for pattern in _TOKEN_PATTERNS:
        m = pattern.search(html)
        if m:
            return m.group(1)
    return None


@register
class CSRFValidation(Check):
    """Validate CSRF protection on LuCI admin forms."""

    id = "csrf_validation"
    name = "CSRF Token Validation"
    category = Category.CSRF
    severity = Severity.MEDIUM
    min_mode = ScanMode.ACTIVE
    phase = Phase.EXPLOIT
    requires_auth = False
    description = (
        "Checks LuCI admin forms for CSRF token presence and validates that the server "
        "rejects requests without valid tokens."
    )
    cve_ids: List[str] = ["CVE-2021-36746", "CVE-2022-31340"]

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []

        for endpoint in _STATE_CHANGE_ENDPOINTS:
            url = f"{target.url}{endpoint}"

            # Step 1: GET the form
            try:
                get_resp = session.get(url)
                form_html = get_resp.text or ""
            except Exception:
                continue

            token = _extract_token(form_html)

            if token is None:
                # No token in form → no CSRF protection
                findings.append(self._make_finding(
                    title=f"CSRF: no token in form at {endpoint}",
                    description=(
                        f"The admin form at {endpoint} does not include a CSRF token. "
                        "An attacker can forge state-changing requests that the victim's "
                        "browser will submit with their session cookie."
                    ),
                    evidence=f"GET {url} form has no CSRF token field",
                    affected_url=url,
                    remediation=(
                        "Add a unique, unpredictable CSRF token to all state-changing forms. "
                        "Validate the token server-side on every POST request. "
                        "Update to a patched LuCI version."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-36746",
                        "https://nvd.nist.gov/vuln/detail/CVE-2022-31340",
                        "https://owasp.org/www-community/attacks/csrf",
                    ],
                    cve_ids=["CVE-2021-36746", "CVE-2022-31340"],
                ))
                # Check if server still accepts POST without token
                try:
                    post_resp = session.post(url, data={"password": "test"})
                    if post_resp.status_code == 200:
                        pass  # Already reported the no-token finding
                except Exception:
                    pass
                continue

            # Token present — test if server validates it
            # Test 1: POST without token
            try:
                no_token_resp = session.post(url, data={"action": "test"})
                if no_token_resp.status_code == 200:
                    findings.append(self._make_finding(
                        title=f"CSRF: server accepts request without token at {endpoint}",
                        description=(
                            f"The form at {endpoint} has a CSRF token but the server accepts "
                            "POST requests without providing the token. Token validation is absent."
                        ),
                        evidence=(
                            f"POST {url} without token → HTTP {no_token_resp.status_code} (accepted)"
                        ),
                        affected_url=url,
                        remediation=(
                            "Validate the CSRF token on the server for every state-changing request. "
                            "Return 403 for requests missing or with invalid tokens."
                        ),
                        severity=Severity.MEDIUM,
                        cvss_score=6.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                        references=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-36746",
                            "https://nvd.nist.gov/vuln/detail/CVE-2022-31340",
                            "https://owasp.org/www-community/attacks/csrf",
                        ],
                        cve_ids=["CVE-2021-36746", "CVE-2022-31340"],
                    ))
                    return findings
                elif no_token_resp.status_code in (403, 401):
                    # No-token rejected — test wrong token
                    wrong_token_resp = session.post(url, data={"token": "wrongtoken123", "action": "test"})
                    if wrong_token_resp.status_code == 200:
                        findings.append(self._make_finding(
                            title=f"CSRF: server accepts wrong token at {endpoint}",
                            description=(
                                f"The server at {endpoint} accepts a deliberately wrong CSRF token, "
                                "indicating the token value is not validated."
                            ),
                            evidence=(
                                f"POST {url} with wrong token → HTTP {wrong_token_resp.status_code}"
                            ),
                            affected_url=url,
                            remediation=(
                                "Validate the CSRF token value against the session-stored token. "
                                "Ensure constant-time comparison is used to prevent timing attacks."
                            ),
                            severity=Severity.MEDIUM,
                            cvss_score=6.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                            references=[
                                "https://nvd.nist.gov/vuln/detail/CVE-2021-36746",
                                "https://nvd.nist.gov/vuln/detail/CVE-2022-31340",
                            ],
                            cve_ids=["CVE-2021-36746", "CVE-2022-31340"],
                        ))
                        return findings
            except Exception:
                pass

        return findings
