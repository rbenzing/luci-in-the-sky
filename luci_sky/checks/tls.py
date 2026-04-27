"""
luci_sky.checks.tls — TLS/SSL security checks.

Checks: TLSAnalysis (tls_analysis) — single unified TLS check
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import List

from luci_sky.checks.base import Check
from luci_sky.checks import register
from luci_sky.config import Config
from luci_sky.models import Category, Confidence, Finding, ScanMode, Severity, Target

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
_WEAK_CIPHER_PATTERNS = ("RC4", "DES", "MD5", "NULL", "EXPORT", "ANON", "ADH", "AECDH")
_HSTS_MIN_MAX_AGE = 31_536_000  # 1 year


@register
class TLSAnalysis(Check):
    """Comprehensive TLS/SSL security analysis."""

    id = "tls_analysis"
    name = "TLS/SSL Security Analysis"
    category = Category.TLS
    severity = Severity.HIGH
    min_mode = ScanMode.PASSIVE
    requires_auth = False
    description = (
        "Checks TLS protocol version, cipher strength, certificate validity, "
        "HTTPS redirect presence, and HSTS header configuration."
    )
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []

        if target.scheme != "https":
            # Check for missing HTTPS redirect
            findings.extend(self._check_https_redirect(target, session, config))
            return findings

        # TLS socket checks — track whether connection succeeded
        socket_findings, connected = self._check_tls_socket(target, config)
        findings.extend(socket_findings)

        # Only run HSTS check if we could actually connect to the TLS socket
        if connected:
            findings.extend(self._check_hsts(target, session))

        return findings

    def _check_tls_socket(self, target: Target, config: Config):
        """Returns (findings, connected) where connected=False means socket failed."""
        findings: List[Finding] = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            raw_sock = socket.create_connection((target.host, target.port), timeout=config.timeout)
            with ctx.wrap_socket(raw_sock, server_hostname=target.host) as ssl_sock:
                protocol = ssl_sock.version() or ""
                cipher_info = ssl_sock.cipher() or ("", "", 0)
                cipher_name = cipher_info[0] if cipher_info else ""
                cert = ssl_sock.getpeercert() or {}

                # Weak protocol
                if any(protocol == wp or protocol.replace(".", "") == wp.replace(".", "")
                       for wp in _WEAK_PROTOCOLS):
                    findings.append(self._make_finding(
                        title=f"Weak TLS protocol version detected: {protocol}",
                        description=(
                            f"The target negotiates {protocol}, which is deprecated and vulnerable "
                            "to known attacks (e.g., POODLE, BEAST). Modern clients should require "
                            "TLSv1.2 as a minimum."
                        ),
                        evidence=f"SSL negotiation: {protocol} accepted",
                        affected_url=target.url,
                        remediation=(
                            "Disable TLSv1.0 and TLSv1.1; require TLSv1.2 minimum. "
                            "Configure uhttpd: option tls_ciphers 'HIGH:!aNULL:!MD5'"
                        ),
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        references=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2011-3389",
                            "https://openwrt.org/docs/guide-user/security/tls",
                        ],
                    ))

                # Weak cipher
                if cipher_name and any(p in cipher_name.upper() for p in _WEAK_CIPHER_PATTERNS):
                    findings.append(self._make_finding(
                        title=f"Weak TLS cipher suite detected: {cipher_name}",
                        description=(
                            f"The server negotiated the weak cipher suite {cipher_name}. "
                            "Weak ciphers provide insufficient cryptographic protection."
                        ),
                        evidence=f"TLS cipher negotiated: {cipher_name}",
                        affected_url=target.url,
                        remediation=(
                            "Configure strong cipher suites only. Recommended: "
                            "ECDHE+AESGCM:ECDHE+AES256:!aNULL:!MD5:!RC4"
                        ),
                        severity=Severity.HIGH,
                        cvss_score=7.4,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        references=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2013-2566",
                            "https://www.openssl.org/docs/man1.1.1/man1/ciphers.html",
                        ],
                    ))

                # Certificate expiry
                findings.extend(self._check_cert_expiry(cert, target))

        except (ConnectionRefusedError, OSError):
            return [], False
        except ssl.SSLError:
            return [], False
        except Exception:
            return [], False

        return findings, True

    def _check_cert_expiry(self, cert: dict, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        not_after = cert.get("notAfter")
        if not not_after:
            return findings
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
            now = datetime.utcnow()
            days_left = (expiry - now).days

            if days_left < 0:
                findings.append(self._make_finding(
                    title="TLS certificate has expired",
                    description=(
                        f"The TLS certificate expired {abs(days_left)} days ago "
                        f"(on {expiry.strftime('%Y-%m-%d')}). Expired certificates "
                        "cause browser warnings and break HTTPS security."
                    ),
                    evidence=f"Certificate notAfter: {not_after}",
                    affected_url=target.url,
                    remediation=(
                        "Renew the TLS certificate immediately. "
                        "Consider using Let's Encrypt for automated renewal."
                    ),
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2014-3566",
                        "https://openwrt.org/docs/guide-user/security/ssl",
                    ],
                ))
            elif days_left < 30:
                findings.append(self._make_finding(
                    title=f"TLS certificate expiring soon: {days_left} days remaining",
                    description=(
                        f"The TLS certificate will expire in {days_left} days "
                        f"(on {expiry.strftime('%Y-%m-%d')}). Take action before expiry."
                    ),
                    evidence=f"Certificate notAfter: {not_after}",
                    affected_url=target.url,
                    remediation="Renew the TLS certificate before it expires.",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    references=[
                        "https://openwrt.org/docs/guide-user/security/ssl",
                    ],
                ))
        except ValueError:
            pass
        return findings

    def _check_https_redirect(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        http_url = f"http://{target.host}:{target.port}/"
        try:
            resp = session.get(http_url, allow_redirects=False)
            location = resp.headers.get("Location", "")
            if resp.status_code not in (301, 302, 307, 308) or "https" not in location:
                findings.append(self._make_finding(
                    title="HTTP to HTTPS redirect missing",
                    description=(
                        "The server does not redirect HTTP connections to HTTPS. "
                        "This allows plaintext transmission of sensitive data."
                    ),
                    evidence=f"HTTP {resp.status_code} response with no HTTPS Location header",
                    affected_url=http_url,
                    remediation=(
                        "Configure uhttpd to redirect all HTTP traffic to HTTPS: "
                        "set option redirect_https '1' in /etc/config/uhttpd"
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    references=[
                        "https://openwrt.org/docs/guide-user/services/webserver/uhttpd",
                    ],
                ))
        except Exception:
            pass
        return findings

    def _check_hsts(self, target: Target, session: object) -> List[Finding]:
        findings: List[Finding] = []
        try:
            resp = session.get(target.url)
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if not hsts:
                findings.append(self._make_finding(
                    title="HSTS header missing",
                    description=(
                        "The HTTPS response does not include a Strict-Transport-Security header. "
                        "Without HSTS, browsers may connect via HTTP on subsequent visits."
                    ),
                    evidence="Strict-Transport-Security header absent from HTTPS response",
                    affected_url=target.url,
                    remediation=(
                        "Add HSTS header: Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains"
                    ),
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                    ],
                ))
            else:
                # Parse max-age
                max_age = 0
                for part in hsts.split(";"):
                    part = part.strip()
                    if part.lower().startswith("max-age="):
                        try:
                            max_age = int(part.split("=", 1)[1])
                        except ValueError:
                            pass
                if max_age < _HSTS_MIN_MAX_AGE:
                    findings.append(self._make_finding(
                        title=f"HSTS max-age too short: {max_age} seconds",
                        description=(
                            f"The Strict-Transport-Security max-age value ({max_age}s) is below "
                            f"the recommended minimum of {_HSTS_MIN_MAX_AGE}s (1 year)."
                        ),
                        evidence=f"Strict-Transport-Security: {hsts}",
                        affected_url=target.url,
                        remediation=(
                            f"Set max-age to at least {_HSTS_MIN_MAX_AGE} (1 year) in the "
                            "Strict-Transport-Security header."
                        ),
                        severity=Severity.LOW,
                        cvss_score=3.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                        ],
                    ))
        except Exception:
            pass
        return findings
