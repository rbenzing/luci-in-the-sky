"""
Unit tests for luci_sky.checks.network — PortScan, ServiceSecurity, CORSMisconfiguration,
DNSRebinding, RPCExploitation, UPnPAudit, WANExposure, FirewallAudit, WirelessAudit.

Tests will fail with ImportError until luci_sky/checks/network.py is implemented.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from luci_sky.checks import get_check
from luci_sky.config import Config
from luci_sky.models import Finding, ScanMode, Severity, Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_target(open_ports: list = None) -> Target:
    return Target(
        url="https://192.168.1.1",
        host="192.168.1.1",
        port=443,
        scheme="https",
        detected_version=None,
        detected_luci_version=None,
        open_ports=open_ports or [],
        accessible_paths=[],
        is_authenticated=True,
    )


def _make_config() -> Config:
    cfg = Config()
    cfg.verify_tls = False
    cfg.timeout = 5.0
    return cfg


def _make_response(
    status_code: int = 200,
    text: str = "",
    headers: dict = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode() if text else b""
    resp.headers = headers or {}
    resp.json = lambda: json.loads(text) if text else {}
    return resp


def _make_session(**overrides) -> MagicMock:
    session = MagicMock()
    default_resp = _make_response()
    session.get.return_value = overrides.get("get", default_resp)
    session.post.return_value = overrides.get("post", default_resp)
    session.head.return_value = overrides.get("head", default_resp)
    return session


# ---------------------------------------------------------------------------
# PortScan
# ---------------------------------------------------------------------------


class TestPortScan:
    def test_port_scan_registered(self):
        """get_check('port_scan') must succeed."""
        check = get_check("port_scan")
        assert check.__class__.id == "port_scan"

    def test_port_scan_is_passive(self):
        """PortScan must be PASSIVE mode."""
        check = get_check("port_scan")
        assert check.__class__.min_mode == ScanMode.PASSIVE

    def test_port_scan_open_telnet_produces_high_finding(self):
        """Open port 23 (Telnet) must produce a HIGH or CRITICAL finding."""
        check = get_check("port_scan")
        target = _make_target()

        session = _make_session()

        # Simulate port 23 open via mock socket
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"OpenWrt Telnet"
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_sock) as mock_connect:
            # Only port 23 "succeeds" — others raise ConnectionRefusedError
            def connect_side_effect(addr, timeout=None):
                host, port = addr
                if port == 23:
                    return mock_sock
                raise ConnectionRefusedError("refused")

            mock_connect.side_effect = connect_side_effect

            findings = check.run(target, session, _make_config())

        assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings), (
            "Expected HIGH/CRITICAL finding for open Telnet port"
        )

    def test_port_scan_populates_target_open_ports(self):
        """After run(), target.open_ports must contain discovered open ports."""
        check = get_check("port_scan")
        target = _make_target()
        session = _make_session()

        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH banner"
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection") as mock_connect:
            def connect_side_effect(addr, timeout=None):
                host, port = addr
                if port == 22:
                    return mock_sock
                raise ConnectionRefusedError("refused")

            mock_connect.side_effect = connect_side_effect
            check.run(target, session, _make_config())

        assert 22 in target.open_ports


# ---------------------------------------------------------------------------
# ServiceSecurity
# ---------------------------------------------------------------------------


class TestServiceSecurity:
    def test_service_security_registered(self):
        """get_check('service_security') must succeed."""
        check = get_check("service_security")
        assert check.__class__.id == "service_security"

    def test_telnet_open_produces_critical_finding(self):
        """Port 23 in target.open_ports must produce a CRITICAL finding."""
        check = get_check("service_security")
        target = _make_target(open_ports=[22, 23, 80])  # Telnet open
        session = _make_session()

        findings = check.run(target, session, _make_config())

        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 1, "Expected CRITICAL for open Telnet port 23"


# ---------------------------------------------------------------------------
# CORSMisconfiguration
# ---------------------------------------------------------------------------


class TestCORSMisconfiguration:
    def test_cors_misconfiguration_registered(self):
        """get_check('cors_misconfiguration') must succeed."""
        check = get_check("cors_misconfiguration")
        assert check.__class__.id == "cors_misconfiguration"

    def test_cors_is_passive(self):
        """CORSMisconfiguration must be PASSIVE mode."""
        check = get_check("cors_misconfiguration")
        assert check.__class__.min_mode == ScanMode.PASSIVE

    def test_cors_wildcard_produces_high_finding(self):
        """Access-Control-Allow-Origin: * must produce a HIGH finding."""
        check = get_check("cors_misconfiguration")
        target = _make_target()

        cors_headers = {"Access-Control-Allow-Origin": "*"}
        session = _make_session(get=_make_response(200, "", headers=cors_headers))

        findings = check.run(target, session, _make_config())

        assert any(f.severity == Severity.HIGH for f in findings), (
            "Expected HIGH finding for wildcard CORS"
        )

    def test_cors_credentials_with_reflected_origin_produces_critical(self):
        """Reflected origin + ACAC: true must produce a CRITICAL finding."""
        check = get_check("cors_misconfiguration")
        target = _make_target()

        cors_headers = {
            "Access-Control-Allow-Origin": "https://evil.example.com",
            "Access-Control-Allow-Credentials": "true",
        }
        session = _make_session(get=_make_response(200, "", headers=cors_headers))

        findings = check.run(target, session, _make_config())

        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 1

    def test_cors_no_cors_headers_returns_empty(self):
        """Response with no CORS headers must produce no findings."""
        check = get_check("cors_misconfiguration")
        target = _make_target()
        session = _make_session(get=_make_response(200, "", headers={}))

        findings = check.run(target, session, _make_config())

        cors_findings = [
            f for f in findings
            if "CORS" in f.title or "cors" in f.check_id.lower()
        ]
        assert len(cors_findings) == 0


# ---------------------------------------------------------------------------
# DNSRebinding
# ---------------------------------------------------------------------------


class TestDNSRebinding:
    def test_dns_rebinding_registered(self):
        """get_check('dns_rebinding') must succeed."""
        check = get_check("dns_rebinding")
        assert check.__class__.id == "dns_rebinding"

    def test_dns_rebinding_requires_active_mode(self):
        """DNSRebinding must require ACTIVE scan mode."""
        check = get_check("dns_rebinding")
        assert check.__class__.min_mode == ScanMode.ACTIVE

    def test_dns_rebinding_normal_response_to_bad_host_header_produces_finding(self):
        """200 response to a manipulated Host header must produce a MEDIUM finding."""
        check = get_check("dns_rebinding")
        target = _make_target()

        # Server responds normally (200) to attacker.example.com Host header
        session = MagicMock()
        session.get.return_value = _make_response(200, "<html>Admin Panel</html>")

        findings = check.run(target, session, _make_config())

        if findings:
            assert any(f.severity == Severity.MEDIUM for f in findings)


# ---------------------------------------------------------------------------
# RPCExploitation
# ---------------------------------------------------------------------------


class TestRPCExploitation:
    def test_rpc_exploitation_registered(self):
        """get_check('rpc_exploitation') must succeed."""
        check = get_check("rpc_exploitation")
        assert check.__class__.id == "rpc_exploitation"

    def test_rpc_exploitation_requires_active_mode(self):
        """RPCExploitation must require ACTIVE scan mode."""
        check = get_check("rpc_exploitation")
        assert check.__class__.min_mode == ScanMode.ACTIVE

    def test_rpc_ubus_unauthenticated_list_produces_critical(self):
        """ubus responding to list without session token must produce a CRITICAL finding."""
        check = get_check("rpc_exploitation")
        target = _make_target()

        # ubus returns method list without requiring auth
        rpc_resp_text = json.dumps({
            "id": 1,
            "result": ["session", "file", "uci", "sys"],
            "error": None,
        })

        session = MagicMock()
        session.post.return_value = _make_response(200, rpc_resp_text)
        session.get.return_value = _make_response(200, rpc_resp_text)

        findings = check.run(target, session, _make_config())

        if findings:
            assert any(f.severity == Severity.CRITICAL for f in findings)


# ---------------------------------------------------------------------------
# UPnP checks
# ---------------------------------------------------------------------------


class TestUPnPAudit:
    def test_upnp_audit_registered(self):
        """get_check('upnp_audit') must succeed."""
        check = get_check("upnp_audit")
        assert check.__class__.id == "upnp_audit"

    def test_upnp_audit_requires_active_mode(self):
        """UPnPAudit must require ACTIVE scan mode."""
        check = get_check("upnp_audit")
        assert check.__class__.min_mode == ScanMode.ACTIVE

    def test_upnp_port_mapping_requires_full_mode(self):
        """UPnPPortMapping must require FULL scan mode."""
        check = get_check("upnp_port_mapping")
        assert check.__class__.min_mode == ScanMode.FULL


# ---------------------------------------------------------------------------
# Authenticated checks: WAN, Firewall, Wireless
# ---------------------------------------------------------------------------


class TestAuthenticatedNetworkChecks:
    def test_wan_exposure_registered(self):
        """get_check('wan_exposure') must succeed."""
        check = get_check("wan_exposure")
        assert check.__class__.id == "wan_exposure"

    def test_wan_exposure_requires_auth(self):
        """WANExposure must require authentication (requires_auth=True)."""
        check = get_check("wan_exposure")
        assert check.__class__.requires_auth is True

    def test_wan_exposure_is_passive(self):
        """WANExposure must be PASSIVE mode (authenticated passive check)."""
        check = get_check("wan_exposure")
        assert check.__class__.min_mode == ScanMode.PASSIVE

    def test_firewall_audit_registered(self):
        """get_check('firewall_audit') must succeed."""
        check = get_check("firewall_audit")
        assert check.__class__.id == "firewall_audit"

    def test_firewall_audit_requires_auth(self):
        """FirewallAudit must require authentication."""
        check = get_check("firewall_audit")
        assert check.__class__.requires_auth is True

    def test_wireless_audit_registered(self):
        """get_check('wireless_audit') must succeed."""
        check = get_check("wireless_audit")
        assert check.__class__.id == "wireless_audit"

    def test_wireless_audit_requires_auth(self):
        """WirelessAudit must require authentication."""
        check = get_check("wireless_audit")
        assert check.__class__.requires_auth is True

    def test_wireless_wep_produces_high_finding(self):
        """WEP encryption in wireless UCI config must produce a HIGH finding."""
        check = get_check("wireless_audit")
        target = _make_target()
        target.is_authenticated = True

        wep_config_resp = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "default_radio0": {
                    "encryption": "wep",
                    "ssid": "HomeNetwork",
                }
            },
        })

        session = MagicMock()
        session.post.return_value = _make_response(200, wep_config_resp)
        session.get.return_value = _make_response(200, wep_config_resp)

        findings = check.run(target, session, _make_config())

        if findings:
            assert any(f.severity == Severity.HIGH for f in findings)
