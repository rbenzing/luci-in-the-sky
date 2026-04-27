"""
luci_sky.checks.network — network security checks.

Checks: PortScan, ServiceSecurity, CORSMisconfiguration, DNSRebinding,
        RPCExploitation, UPnPAudit, UPnPPortMapping, WANExposure,
        FirewallAudit, WirelessAudit
"""
from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from luci_sky.checks.base import Check
from luci_sky.checks import register
from luci_sky.config import Config
from luci_sky.models import Category, Confidence, Finding, ScanMode, Severity, Target

_SCAN_PORTS = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 8080, 8443, 8888, 9090]
_DANGEROUS_PORTS = {
    23: ("Telnet", Severity.CRITICAL, 9.8),
    21: ("FTP", Severity.HIGH, 7.5),
    25: ("SMTP", Severity.MEDIUM, 5.3),
    445: ("SMB", Severity.HIGH, 8.1),
    3306: ("MySQL", Severity.HIGH, 7.5),
}


@register
class PortScan(Check):
    """TCP port scan with banner grabbing."""

    id = "port_scan"
    name = "Port Scan"
    category = Category.NETWORK
    severity = Severity.HIGH
    min_mode = ScanMode.PASSIVE
    requires_auth = False
    description = "Scans common TCP ports and grabs service banners."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []

        def scan_port(port: int) -> tuple:
            try:
                sock = socket.create_connection((target.host, port), timeout=config.timeout)
                banner = b""
                try:
                    sock.settimeout(2)
                    banner = sock.recv(1024)
                except Exception:
                    pass
                sock.close()
                return port, True, banner.decode("utf-8", errors="replace")
            except Exception:
                return port, False, ""

        open_results: list = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(scan_port, p): p for p in _SCAN_PORTS}
            for fut in as_completed(futures):
                port, is_open, banner = fut.result()
                if is_open:
                    open_results.append((port, banner))

        # Update target.open_ports in a single pass after the inner executor
        # is complete.  This avoids concurrent appends from the outer scanner
        # ThreadPoolExecutor racing with ServiceSecurity reading the same list.
        for port, banner in open_results:
            if port not in target.open_ports:
                target.open_ports.append(port)
            sev, score = Severity.INFO, 0.0
            desc_extra = ""
            if port in _DANGEROUS_PORTS:
                svc, sev, score = _DANGEROUS_PORTS[port]
                desc_extra = f" Service: {svc} — this is a high-risk open port."
            findings.append(self._make_finding(
                title=f"Open port detected: {port}/TCP{(' (' + _DANGEROUS_PORTS[port][0] + ')') if port in _DANGEROUS_PORTS else ''}",
                description=(
                    f"TCP port {port} is open on {target.host}.{desc_extra}"
                    + (f" Banner: {banner[:100]}" if banner else "")
                ),
                evidence=f"TCP connect to {target.host}:{port} succeeded. Banner: {banner[:200] if banner else 'none'}",
                affected_url=f"{target.scheme}://{target.host}:{port}",
                remediation=(
                    f"If port {port} is not required, close it via firewall rules. "
                    "Review /etc/config/firewall to restrict access."
                ),
                severity=sev,
                cvss_score=score,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                references=[
                    "https://openwrt.org/docs/guide-user/firewall/netfilter_iptables/netfilter_openwrt",
                ],
            ))

        return findings


@register
class ServiceSecurity(Check):
    """Audit security of discovered open services."""

    id = "service_security"
    name = "Service Security Audit"
    category = Category.NETWORK
    severity = Severity.CRITICAL
    min_mode = ScanMode.PASSIVE
    requires_auth = False
    description = "Evaluates the security risk of open network services (Telnet, FTP, etc.)."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        open_ports = list(target.open_ports)

        for port, (svc_name, sev, score) in _DANGEROUS_PORTS.items():
            if port in open_ports:
                if port == 23:  # Telnet — CRITICAL
                    findings.append(self._make_finding(
                        title=f"Telnet service exposed on port {port}",
                        description=(
                            "Telnet transmits all data including credentials in plaintext. "
                            "An attacker with network access can capture authentication credentials "
                            "and session data via passive sniffing."
                        ),
                        evidence=f"Port 23 (Telnet) is open on {target.host}",
                        affected_url=f"telnet://{target.host}:{port}",
                        remediation=(
                            "Disable Telnet immediately. Use SSH instead. "
                            "Run: uci set dropbear.@dropbear[0].enable=1; uci commit dropbear; "
                            "then disable telnet via: uci delete network.@...telnet"
                        ),
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        references=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2019-12272",
                            "https://openwrt.org/docs/guide-user/services/ssh/dropbear",
                        ],
                    ))
                else:
                    findings.append(self._make_finding(
                        title=f"Insecure service exposed: {svc_name} on port {port}",
                        description=f"{svc_name} service is exposed on port {port} of {target.host}.",
                        evidence=f"Port {port} ({svc_name}) is open",
                        affected_url=f"{target.scheme}://{target.host}:{port}",
                        remediation=f"Restrict access to {svc_name} via firewall. Disable if not needed.",
                        severity=sev,
                        cvss_score=score,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        references=[
                            "https://openwrt.org/docs/guide-user/security/openwrt_security",
                        ],
                    ))

        return findings


@register
class CORSMisconfiguration(Check):
    """Check for CORS misconfiguration."""

    id = "cors_misconfiguration"
    name = "CORS Misconfiguration"
    category = Category.NETWORK
    severity = Severity.HIGH
    min_mode = ScanMode.PASSIVE
    requires_auth = False
    description = "Checks CORS headers for wildcard origins and credential-allowing misconfigurations."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        test_url = f"{target.url}/cgi-bin/luci/"
        try:
            resp = session.get(
                test_url,
                headers={"Origin": "https://evil.example.com"},
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "*" and acac == "true":
                findings.append(self._make_finding(
                    title="CORS: wildcard origin with credentials allowed",
                    description=(
                        "The server sets Access-Control-Allow-Origin: * together with "
                        "Access-Control-Allow-Credentials: true. This is a dangerous combination "
                        "that allows any origin to make credentialed cross-origin requests."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    affected_url=test_url,
                    remediation=(
                        "Never combine wildcard CORS with credentials. "
                        "Whitelist specific origins explicitly."
                    ),
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                ))
            elif acao == "*":
                findings.append(self._make_finding(
                    title="CORS: wildcard origin (Access-Control-Allow-Origin: *)",
                    description=(
                        "The server responds with Access-Control-Allow-Origin: * which allows "
                        "any website to make cross-origin requests to the LuCI interface."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    affected_url=test_url,
                    remediation=(
                        "Restrict CORS to specific trusted origins. "
                        "Remove the wildcard CORS header from uhttpd configuration."
                    ),
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                ))
            elif acao and acao != "" and acac == "true":
                # Reflected or arbitrary origin + credentials
                findings.append(self._make_finding(
                    title=f"CORS: reflected origin with credentials allowed: {acao}",
                    description=(
                        f"The server reflects the Origin header ({acao}) back in "
                        "Access-Control-Allow-Origin and allows credentials. "
                        "This enables cross-origin credential theft."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    affected_url=test_url,
                    remediation=(
                        "Implement an explicit origin whitelist. Never reflect arbitrary "
                        "Origins. Do not combine credentials with permissive origins."
                    ),
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                ))
        except Exception:
            pass
        return findings


@register
class DNSRebinding(Check):
    """Test for DNS rebinding vulnerability via Host header manipulation."""

    id = "dns_rebinding"
    name = "DNS Rebinding Check"
    category = Category.NETWORK
    severity = Severity.MEDIUM
    min_mode = ScanMode.ACTIVE
    requires_auth = False
    description = "Tests whether the server accepts requests with malicious Host headers."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        test_url = f"{target.url}/cgi-bin/luci/"
        malicious_host = "attacker.example.com"
        try:
            resp = session.get(test_url, headers={"Host": malicious_host})
            if resp.status_code == 200:
                body = resp.text or ""
                # Check if it looks like real admin content (not a redirect)
                if any(kw in body.lower() for kw in ["admin", "luci", "openwrt", "dashboard"]):
                    findings.append(self._make_finding(
                        title="DNS Rebinding: server accepts arbitrary Host header",
                        description=(
                            "The server responds normally to requests with a manipulated Host "
                            "header. This enables DNS rebinding attacks where a malicious website "
                            "can pivot to the admin interface."
                        ),
                        evidence=f"GET {test_url} Host: {malicious_host} → HTTP {resp.status_code}",
                        affected_url=test_url,
                        remediation=(
                            "Configure uhttpd to validate the Host header against allowed values. "
                            "Add 'option rfc2616_strict 1' to /etc/config/uhttpd."
                        ),
                        severity=Severity.MEDIUM,
                        cvss_score=6.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                        references=[
                            "https://owasp.org/www-community/attacks/DNS_Rebinding",
                        ],
                    ))
        except Exception:
            pass
        return findings


@register
class RPCExploitation(Check):
    """Test ubus/rpcd for unauthenticated method access."""

    id = "rpc_exploitation"
    name = "RPC Exploitation Check"
    category = Category.NETWORK
    severity = Severity.CRITICAL
    min_mode = ScanMode.ACTIVE
    requires_auth = False
    description = "Tests rpcd/ubus endpoints for unauthenticated method invocation."
    cve_ids: List[str] = ["CVE-2021-45444"]

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        rpc_url = f"{target.url}/ubus"
        payload = {"jsonrpc": "2.0", "id": 1, "method": "list", "params": []}
        try:
            resp = session.post(rpc_url, json=payload)
            body = resp.text or ""
            if resp.status_code == 200:
                try:
                    data = json.loads(body)
                    result = data.get("result", None)
                    if isinstance(result, (list, dict)) and result:
                        methods = result if isinstance(result, list) else list(result.keys())
                        if len(methods) > 0:
                            findings.append(self._make_finding(
                                title="ubus RPC accessible without authentication",
                                description=(
                                    "The ubus JSON-RPC endpoint responds to method enumeration "
                                    "without requiring a valid session token. An unauthenticated "
                                    "attacker can invoke system methods."
                                ),
                                evidence=(
                                    f"POST {rpc_url} list method returned {len(methods)} items: "
                                    f"{str(methods[:5])}"
                                ),
                                affected_url=rpc_url,
                                remediation=(
                                    "Restrict rpcd access to authenticated sessions. "
                                    "Configure ACL rules in /etc/rpcd/acl.d/. "
                                    "Update to a version that fixes CVE-2021-45444."
                                ),
                                severity=Severity.CRITICAL,
                                cvss_score=9.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                references=[
                                    "https://nvd.nist.gov/vuln/detail/CVE-2021-45444",
                                ],
                            ))
                except (json.JSONDecodeError, KeyError):
                    pass
        except Exception:
            pass
        return findings


@register
class UPnPAudit(Check):
    """Audit UPnP service discovery and exposure."""

    id = "upnp_audit"
    name = "UPnP Audit"
    category = Category.NETWORK
    severity = Severity.HIGH
    min_mode = ScanMode.ACTIVE
    requires_auth = False
    description = "Checks for UPnP service exposure via HTTP description endpoint."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        upnp_urls = [
            f"http://{target.host}:1900/",
            f"http://{target.host}:5000/rootDesc.xml",
            f"http://{target.host}:49152/rootDesc.xml",
            f"http://{target.host}:1901/",
        ]
        for url in upnp_urls:
            try:
                resp = session.get(url)
                if resp.status_code == 200:
                    body = resp.text or ""
                    if any(kw in body.lower() for kw in ["upnp", "device", "service", "rootdevice"]):
                        findings.append(self._make_finding(
                            title="UPnP service description accessible",
                            description=(
                                "A UPnP device description XML file is accessible from the network. "
                                "UPnP can be exploited to open firewall pinholes or redirect traffic."
                            ),
                            evidence=f"GET {url} → HTTP 200, UPnP XML detected",
                            affected_url=url,
                            remediation=(
                                "Disable UPnP if not required: uci set upnpd.config.enabled=0; "
                                "uci commit upnpd; /etc/init.d/miniupnpd stop"
                            ),
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                            references=[
                                "https://nvd.nist.gov/vuln/detail/CVE-2020-12695",
                            ],
                        ))
                        break
            except Exception:
                continue
        return findings


@register
class UPnPPortMapping(Check):
    """Attempt UPnP port mapping creation (full mode)."""

    id = "upnp_port_mapping"
    name = "UPnP Port Mapping Attempt"
    category = Category.NETWORK
    severity = Severity.HIGH
    min_mode = ScanMode.FULL
    requires_auth = False
    description = "Attempts to add a UPnP port mapping to verify write access to UPnP service."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        # Attempt SOAP AddPortMapping to test write access
        soap_url = f"http://{target.host}:1900/control/WANIPConnection"
        soap_body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
            '<s:Body>'
            '<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
            '<NewRemoteHost></NewRemoteHost>'
            '<NewExternalPort>54321</NewExternalPort>'
            '<NewProtocol>TCP</NewProtocol>'
            '<NewInternalPort>54321</NewInternalPort>'
            '<NewInternalClient>192.168.1.100</NewInternalClient>'
            '<NewEnabled>1</NewEnabled>'
            '<NewPortMappingDescription>test</NewPortMappingDescription>'
            '<NewLeaseDuration>60</NewLeaseDuration>'
            '</u:AddPortMapping>'
            '</s:Body>'
            '</s:Envelope>'
        )
        try:
            resp = session.post(
                soap_url,
                data=soap_body,
                headers={
                    "Content-Type": 'text/xml; charset="utf-8"',
                    "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"',
                },
            )
            if resp.status_code in (200, 201):
                findings.append(self._make_finding(
                    title="UPnP port mapping successfully created",
                    description=(
                        "A UPnP AddPortMapping SOAP request succeeded, indicating the UPnP "
                        "daemon allows unauthenticated external port mapping creation."
                    ),
                    evidence=f"SOAP AddPortMapping to {soap_url} returned HTTP {resp.status_code}",
                    affected_url=soap_url,
                    remediation=(
                        "Disable UPnP or restrict it to the LAN interface only. "
                        "uci set upnpd.config.enabled=0"
                    ),
                    severity=Severity.HIGH,
                    cvss_score=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-12695",
                    ],
                ))
        except Exception:
            pass
        return findings


@register
class WANExposure(Check):
    """Detect WAN-facing LuCI interface exposure (requires auth)."""

    id = "wan_exposure"
    name = "WAN Interface Exposure"
    category = Category.NETWORK
    severity = Severity.CRITICAL
    min_mode = ScanMode.PASSIVE
    requires_auth = True
    description = "Uses UCI to check if uhttpd listens on WAN interface addresses."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        rpc_url = f"{target.url}/ubus"
        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "call",
            "params": ["00000000000000000000000000000000", "uci", "get",
                       {"config": "uhttpd", "section": "main", "option": "listen_http"}],
        }
        try:
            resp = session.post(rpc_url, json=payload)
            body = resp.text or ""
            data = json.loads(body) if body else {}
            result = data.get("result", [None, {}])
            value = result[1].get("value", "") if isinstance(result, list) and len(result) > 1 else ""
            if "0.0.0.0" in str(value) or "::" in str(value):
                findings.append(self._make_finding(
                    title="LuCI interface exposed on all network interfaces (WAN risk)",
                    description=(
                        f"uhttpd is configured to listen on {value}, which includes "
                        "WAN-facing interfaces. This exposes the admin interface to the internet."
                    ),
                    evidence=f"uhttpd listen_http: {value}",
                    affected_url=target.url,
                    remediation=(
                        "Restrict uhttpd to LAN interface only: "
                        "uci set uhttpd.main.listen_http='192.168.1.1:80'; uci commit uhttpd"
                    ),
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    references=[
                        "https://openwrt.org/docs/guide-user/security/openwrt_security",
                    ],
                ))
        except Exception:
            pass
        return findings


@register
class FirewallAudit(Check):
    """Audit firewall rules for dangerous configurations (requires auth)."""

    id = "firewall_audit"
    name = "Firewall Rule Audit"
    category = Category.NETWORK
    severity = Severity.HIGH
    min_mode = ScanMode.PASSIVE
    requires_auth = True
    description = "Retrieves and audits firewall rules for overly permissive configurations."
    cve_ids: List[str] = []

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        rpc_url = f"{target.url}/ubus"
        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "call",
            "params": ["00000000000000000000000000000000", "uci", "get",
                       {"config": "firewall"}],
        }
        try:
            resp = session.post(rpc_url, json=payload)
            body = resp.text or ""
            data = json.loads(body) if body else {}
            result = data.get("result", [None, {}])
            fw_config = result[1] if isinstance(result, list) and len(result) > 1 else {}

            # Check for 'ACCEPT' rules with src=wan and dest_port=80 or 443
            values = json.dumps(fw_config).lower()
            if "accept" in values and "wan" in values:
                findings.append(self._make_finding(
                    title="Firewall: permissive WAN ACCEPT rules detected",
                    description=(
                        "The firewall configuration contains rules that accept traffic from "
                        "the WAN zone. Review these rules to ensure they are intended."
                    ),
                    evidence=f"Firewall config contains WAN ACCEPT rules",
                    affected_url=f"{target.url}/cgi-bin/luci/admin/network/firewall",
                    remediation=(
                        "Review and tighten firewall rules. Apply the principle of least "
                        "privilege. Use /etc/config/firewall to restrict WAN access."
                    ),
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    references=[
                        "https://openwrt.org/docs/guide-user/firewall/firewall_configuration",
                    ],
                ))
        except Exception:
            pass
        return findings


@register
class WirelessAudit(Check):
    """Audit wireless security configuration (requires auth)."""

    id = "wireless_audit"
    name = "Wireless Security Audit"
    category = Category.NETWORK
    severity = Severity.HIGH
    min_mode = ScanMode.PASSIVE
    requires_auth = True
    description = "Reviews wireless UCI configuration for weak encryption and security settings."
    cve_ids: List[str] = ["CVE-2022-23303"]

    def run(self, target: Target, session: object, config: Config) -> List[Finding]:
        findings: List[Finding] = []
        rpc_url = f"{target.url}/ubus"
        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "call",
            "params": ["00000000000000000000000000000000", "uci", "get",
                       {"config": "wireless"}],
        }
        try:
            resp = session.post(rpc_url, json=payload)
            body = resp.text or ""
            data = json.loads(body) if body else {}
            result = data.get("result", [None, {}])
            wireless_config = result[1] if isinstance(result, list) and len(result) > 1 else {}

            config_str = json.dumps(wireless_config).lower()

            if "wep" in config_str:
                findings.append(self._make_finding(
                    title="Wireless: WEP encryption in use (critically weak)",
                    description=(
                        "WEP encryption is detected in the wireless configuration. "
                        "WEP has been broken since 2001 and provides no meaningful security."
                    ),
                    evidence="wireless UCI config contains 'wep' encryption",
                    affected_url=f"{target.url}/cgi-bin/luci/admin/wireless",
                    remediation=(
                        "Replace WEP with WPA3 or at minimum WPA2 with AES/CCMP. "
                        "Set: uci set wireless.@wifi-iface[0].encryption='psk2'"
                    ),
                    severity=Severity.HIGH,
                    cvss_score=8.8,
                    cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2001-0493",
                        "https://openwrt.org/docs/guide-user/network/wifi/encryption",
                    ],
                ))

            if '"none"' in config_str or "'none'" in config_str or "encryption: none" in config_str:
                findings.append(self._make_finding(
                    title="Wireless: open network (no encryption)",
                    description=(
                        "A wireless interface with no encryption is configured. "
                        "This allows anyone within range to access the network."
                    ),
                    evidence="wireless UCI config contains encryption: none",
                    affected_url=f"{target.url}/cgi-bin/luci/admin/wireless",
                    remediation=(
                        "Enable WPA2/WPA3 encryption on all wireless interfaces. "
                        "Set: uci set wireless.@wifi-iface[0].encryption='psk2'"
                    ),
                    severity=Severity.HIGH,
                    cvss_score=8.8,
                    cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    references=[
                        "https://openwrt.org/docs/guide-user/network/wifi/encryption",
                    ],
                ))

        except Exception:
            pass
        return findings
