"""
luci_sky.checks.info_disclosure — information disclosure checks.

Checks: VersionDetection, PathEnumeration, BackupExposure,
        PackageEnumeration, SecurityHeaders
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from luci_sky.checks.base import Check
from luci_sky.checks import register
from luci_sky.config import Config
from luci_sky.models import Category, Confidence, Finding, ScanMode, Severity, Target

_VERSION_REGEX = re.compile(
    r"OpenWrt\s+(\d{2}\.\d{2}(?:\.\d+)?(?:-rc\d+)?)",
    re.IGNORECASE,
)

_LUCI_PATHS = [
    "/cgi-bin/luci/",
    "/cgi-bin/luci/admin/",
    "/cgi-bin/luci/admin/system",
    "/cgi-bin/luci/admin/system/admin",
    "/cgi-bin/luci/admin/network",
    "/cgi-bin/luci/admin/network/firewall",
    "/cgi-bin/luci/admin/status",
    "/cgi-bin/luci/admin/status/overview",
    "/cgi-bin/luci/admin/services",
    "/cgi-bin/luci/admin/diagnostics",
    "/cgi-bin/luci/;stok=/login",
    "/cgi-bin/luci/admin/system/packages",
    "/cgi-bin/luci/admin/wireless",
    "/cgi-bin/luci/admin/vpn",
    "/cgi-bin/luci/admin/system/crontab",
    "/cgi-bin/luci/admin/system/flashops",
    "/cgi-bin/luci/admin/system/reboot",
    "/api/v1/",
    "/api/",
    "/.well-known/",
    "/ubus/",
    "/rpc/",
    "/cgi-bin/cgi-backup",
]

_BACKUP_PATHS = [
    "/cgi-bin/luci/admin/system/flashops/backup",
    "/backup.tar.gz",
    "/config.tar.gz",
    "/backup",
    "/sysupgrade.tar.gz",
    "/etc/config.tar.gz",
    "/.backup",
    "/cgi-bin/cgi-backup",
    "/cgi-bin/luci/;stok=/backup",
    "/var/backup.tar.gz",
    "/tmp/backup.tar.gz",
    "/openwrt-backup.tar.gz",
    "/router-config.tar.gz",
    "/luci-backup",
    "/config.bak",
    "/settings.bak",
    "/router.conf.bak",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/config/",
    "/etc/dropbear/authorized_keys",
]

_SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
]


@register
class VersionDetection(Check):
    """Detect OpenWrt firmware version from HTTP responses."""

    id = "version_detection"
    name = "Version Detection"
    category = Category.INFORMATION_DISCLOSURE
    severity = Severity.INFO
    min_mode = ScanMode.PASSIVE
    requires_auth = False
    description = "Detects the OpenWrt version via response body and header fingerprinting."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        urls_to_check = [
            f"{target.url}/cgi-bin/luci/",
            f"{target.url}/",
        ]
        for url in urls_to_check:
            try:
                resp = session.get(url)
                text = resp.text or ""
                m = _VERSION_REGEX.search(text)
                if m:
                    version = m.group(1)
                    target.detected_version = version
                    findings.append(self._make_finding(
                        title=f"OpenWrt version detected: {version}",
                        description=(
                            f"The OpenWrt firmware version {version} was detected in the "
                            "HTTP response body. Version information helps attackers identify "
                            "applicable CVEs."
                        ),
                        evidence=f"Regex match in response from {url}: 'OpenWrt {version}'",
                        affected_url=url,
                        remediation=(
                            "Consider hiding version information from unauthenticated responses. "
                            "Ensure the firmware is kept up to date."
                        ),
                        severity=Severity.INFO,
                        cvss_score=0.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                        references=[
                            "https://openwrt.org/advisory/",
                        ],
                    ))
                    return findings
            except Exception:
                continue
        return findings


@register
class PathEnumeration(Check):
    """Enumerate accessible LuCI admin paths."""

    id = "path_enumeration"
    name = "Path Enumeration"
    category = Category.INFORMATION_DISCLOSURE
    severity = Severity.MEDIUM
    min_mode = ScanMode.PASSIVE
    requires_auth = False
    description = "Probes common LuCI paths to identify accessible endpoints."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []

        def probe_path(path: str) -> tuple:
            url = f"{target.url}{path}"
            try:
                resp = session.get(url, allow_redirects=False)
                return path, url, resp.status_code, resp.headers.get("Location", "")
            except Exception:
                return path, url, 0, ""

        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(probe_path, p): p for p in _LUCI_PATHS}
            for fut in as_completed(futures):
                path, url, status, location = fut.result()
                if status == 200:
                    target.accessible_paths.append(url)
                    # Only report admin paths as findings
                    if "admin" in path or "ubus" in path or "rpc" in path:
                        findings.append(self._make_finding(
                            title=f"Accessible admin path: {path}",
                            description=(
                                f"The path {path} returned HTTP 200 without requiring "
                                "authentication. This may expose administrative functionality."
                            ),
                            evidence=f"GET {url} → HTTP {status}",
                            affected_url=url,
                            remediation=(
                                "Ensure all admin paths require authentication. "
                                "Review LuCI ACL configuration."
                            ),
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            references=[
                                "https://openwrt.org/docs/guide-user/security/openwrt_security",
                            ],
                        ))

        return findings


@register
class BackupExposure(Check):
    """Check for exposed backup/configuration files."""

    id = "backup_exposure"
    name = "Backup File Exposure"
    category = Category.INFORMATION_DISCLOSURE
    severity = Severity.CRITICAL
    min_mode = ScanMode.PASSIVE
    requires_auth = False
    description = (
        "Probes common backup file paths for unprotected configuration archives "
        "that could expose credentials and network settings."
    )
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []

        for path in _BACKUP_PATHS:
            url = f"{target.url}{path}"
            try:
                resp = session.get(url)
                if resp.status_code != 200:
                    continue

                content_type = resp.headers.get("Content-Type", "").lower()
                content_length_hdr = resp.headers.get("Content-Length", "")
                body = resp.content if hasattr(resp, "content") else b""
                body_len = len(body) if body else 0

                # Use Content-Length header if body empty
                if not body_len and content_length_hdr:
                    try:
                        body_len = int(content_length_hdr)
                    except ValueError:
                        pass

                # Skip HTML responses (login redirect)
                if "html" in content_type:
                    continue

                # Skip tiny responses
                if body_len < 100:
                    continue

                findings.append(self._make_finding(
                    title=f"Backup file exposed: {path}",
                    description=(
                        f"The file at {path} is publicly accessible and appears to be a "
                        f"configuration/backup archive ({body_len} bytes, {content_type}). "
                        "This may expose credentials, network topology, and secret keys."
                    ),
                    evidence=(
                        f"GET {url} → HTTP 200\n"
                        f"Content-Type: {content_type}\n"
                        f"Content-Length: {body_len}"
                    ),
                    affected_url=url,
                    remediation=(
                        "Restrict access to backup files. Require authentication for all "
                        "download endpoints. Remove publicly accessible backup archives."
                    ),
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    references=[
                        "https://openwrt.org/docs/guide-user/security/openwrt_security",
                    ],
                ))
            except Exception:
                continue

        return findings


@register
class PackageEnumeration(Check):
    """Enumerate installed packages from LuCI JavaScript includes."""

    id = "package_enumeration"
    name = "Package Enumeration"
    category = Category.INFORMATION_DISCLOSURE
    severity = Severity.INFO
    min_mode = ScanMode.PASSIVE
    requires_auth = False
    description = "Infers installed LuCI packages from JS includes in the admin interface."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        try:
            resp = session.get(f"{target.url}/cgi-bin/luci/")
            text = resp.text or ""
            # Find JS includes that reveal package names
            js_files = re.findall(r'src=["\']([^"\']+luci[^"\']*\.js)["\']', text)
            if js_files:
                packages = list(set(js_files))
                findings.append(self._make_finding(
                    title="Installed LuCI packages detected from JavaScript includes",
                    description=(
                        f"The LuCI interface exposes {len(packages)} JavaScript references "
                        "that reveal installed package names. This aids attackers in targeting "
                        "package-specific vulnerabilities."
                    ),
                    evidence=f"JS files detected: {', '.join(packages[:5])}",
                    affected_url=f"{target.url}/cgi-bin/luci/",
                    remediation=(
                        "Remove unused LuCI packages. Keep all packages updated. "
                        "Consider using LuCI's minimal configuration."
                    ),
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    references=[
                        "https://openwrt.org/docs/guide-user/security/openwrt_security",
                    ],
                ))
        except Exception:
            pass
        return findings


@register
class SecurityHeaders(Check):
    """Check for missing HTTP security headers."""

    id = "security_headers"
    name = "Security Headers Check"
    category = Category.INFORMATION_DISCLOSURE
    severity = Severity.MEDIUM
    min_mode = ScanMode.PASSIVE
    requires_auth = False
    description = "Checks for the presence and correct values of HTTP security response headers."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        try:
            resp = session.get(f"{target.url}/cgi-bin/luci/")
            headers = resp.headers or {}
            for header in _SECURITY_HEADERS:
                if header not in headers:
                    findings.append(self._make_finding(
                        title=f"Missing security header: {header}",
                        description=(
                            f"The HTTP response does not include the {header} security header. "
                            "This header helps protect against common web attacks."
                        ),
                        evidence=f"Response headers: {dict(list(headers.items())[:5])}",
                        affected_url=f"{target.url}/cgi-bin/luci/",
                        remediation=(
                            f"Add the {header} header to all HTTP responses from uhttpd. "
                            "Configure this in /etc/config/uhttpd."
                        ),
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        references=[
                            "https://owasp.org/www-project-secure-headers/",
                            "https://openwrt.org/docs/guide-user/security/openwrt_security",
                        ],
                    ))
        except Exception:
            pass
        return findings
