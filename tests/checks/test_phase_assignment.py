from luci_sky.checks import get_check
from luci_sky.models import Phase

RECON = ["version_detection", "port_scan", "path_enumeration", "package_enumeration"]
EXPLOIT = [
    "command_injection", "time_based_injection", "path_traversal",
    "default_credentials", "auth_bypass", "rate_limiting", "rate_limit_stress",
    "rpc_exploitation", "dns_rebinding", "upnp_audit", "upnp_port_mapping",
]
ANALYSIS = ["cve_correlation", "service_security", "tls_analysis", "security_headers"]


def test_recon_checks_are_recon():
    for cid in RECON:
        assert get_check(cid).phase == Phase.RECON, cid


def test_exploit_checks_are_exploit():
    for cid in EXPLOIT:
        assert get_check(cid).phase == Phase.EXPLOIT, cid


def test_analysis_checks_are_analysis():
    for cid in ANALYSIS:
        assert get_check(cid).phase == Phase.ANALYSIS, cid
