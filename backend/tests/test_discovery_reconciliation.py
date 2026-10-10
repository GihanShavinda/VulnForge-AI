from types import SimpleNamespace

from app.services.discovery_reconciliation import reconcile_host
from app.services.nmap_xml_parser import ParsedHost


def asset(**overrides):
    base = dict(
        id="asset-1",
        ip_address="192.168.56.20",
        hostname="metasploitable2.lab",
        mac_address="00:0C:29:AA:BB:CC",
        reachable=False,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_reconcile_by_mac_detects_ip_and_hostname_changes():
    host = ParsedHost(
        ip_address="192.168.56.25",
        hostname="metasploitable2-renamed.lab",
        mac_address="00:0C:29:AA:BB:CC",
        vendor="VMware",
        reachable=True,
        state="up",
    )
    result = reconcile_host(host, [asset()])
    assert result.identity_basis == "mac"
    assert "ip_change" in result.changes
    assert "hostname_change" in result.changes
    assert "newly_reachable" in result.changes


def test_reconcile_by_ip_detects_mac_change():
    host = ParsedHost(
        ip_address="192.168.56.20",
        hostname="metasploitable2.lab",
        mac_address="00:0C:29:FF:EE:DD",
        vendor="VMware",
        reachable=True,
        state="up",
    )
    result = reconcile_host(host, [asset()])
    assert result.identity_basis in {"hostname", "ip"}
    assert "mac_change" in result.changes


def test_unknown_observation_is_new_asset():
    host = ParsedHost(
        ip_address="192.168.56.99",
        hostname="new-host.lab",
        mac_address="00:0C:29:00:00:99",
        vendor="VMware",
        reachable=True,
        state="up",
    )
    result = reconcile_host(host, [asset()])
    assert result.asset is None
    assert result.changes == ("new_asset",)
