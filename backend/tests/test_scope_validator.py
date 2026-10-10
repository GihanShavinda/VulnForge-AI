from datetime import datetime, time, timezone
from types import SimpleNamespace

import pytest

from app.services.scope_validator import validate_target


def scope(
    *,
    name: str = "lab",
    cidr: str = "192.168.56.0/24",
    enabled: bool = True,
    require_explicit_authorization: bool = True,
    maintenance_start=None,
    maintenance_end=None,
    timezone_name: str = "Asia/Colombo",
):
    return SimpleNamespace(
        name=name,
        cidr=cidr,
        enabled=enabled,
        require_explicit_authorization=require_explicit_authorization,
        maintenance_start=maintenance_start,
        maintenance_end=maintenance_end,
        timezone_name=timezone_name,
    )


def test_valid_host_in_scope():
    result = validate_target(
        "192.168.56.20",
        [scope()],
        explicitly_authorized=True,
    )
    assert result.allowed is True
    assert result.matched_scope == "lab"


def test_valid_host_requires_explicit_authorization():
    result = validate_target(
        "192.168.56.20",
        [scope()],
        explicitly_authorized=False,
    )
    assert result.allowed is False
    assert "authorization" in result.reason.lower()


def test_invalid_host_outside_scope():
    result = validate_target(
        "10.10.10.10",
        [scope()],
        explicitly_authorized=True,
    )
    assert result.allowed is False
    assert "outside" in result.reason.lower()


@pytest.mark.parametrize(
    "target",
    [
        "not-an-ip",
        "192.168.56.999",
        "192.168.56.0/24",
        "",
    ],
)
def test_invalid_ip_literal(target):
    result = validate_target(
        target,
        [scope()],
        explicitly_authorized=True,
    )
    assert result.allowed is False
    assert result.normalized_target is None


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "::1",
    ],
)
def test_localhost_is_blocked(target):
    result = validate_target(
        target,
        [scope(cidr="0.0.0.0/0") if ":" not in target else scope(cidr="::/0")],
        explicitly_authorized=True,
    )
    assert result.allowed is False
    assert "loopback" in result.reason.lower()


@pytest.mark.parametrize(
    "target,cidr",
    [
        ("224.0.0.1", "0.0.0.0/0"),
        ("ff02::1", "::/0"),
    ],
)
def test_multicast_is_blocked(target, cidr):
    result = validate_target(
        target,
        [scope(cidr=cidr)],
        explicitly_authorized=True,
    )
    assert result.allowed is False
    assert "multicast" in result.reason.lower()


def test_ipv4_network_address_is_blocked():
    result = validate_target(
        "192.168.56.0",
        [scope()],
        explicitly_authorized=True,
    )
    assert result.allowed is False
    assert "network-address" in result.reason.lower()


def test_ipv4_broadcast_is_blocked():
    result = validate_target(
        "192.168.56.255",
        [scope()],
        explicitly_authorized=True,
    )
    assert result.allowed is False
    assert "broadcast" in result.reason.lower()


@pytest.mark.parametrize(
    "target,cidr,expected_phrase",
    [
        ("fe80::1", "fe80::/64", "link-local"),
        ("::", "::/0", "unspecified"),
        ("ff00::1", "::/0", "multicast"),
    ],
)
def test_ipv6_edge_cases_are_blocked(target, cidr, expected_phrase):
    result = validate_target(
        target,
        [scope(cidr=cidr)],
        explicitly_authorized=True,
    )
    assert result.allowed is False
    assert expected_phrase in result.reason.lower()


def test_valid_ipv6_host_in_scope():
    result = validate_target(
        "fd00:56::20",
        [scope(cidr="fd00:56::/64")],
        explicitly_authorized=True,
    )
    assert result.allowed is True


def test_disabled_scope_does_not_allow_target():
    result = validate_target(
        "192.168.56.20",
        [scope(enabled=False)],
        explicitly_authorized=True,
    )
    assert result.allowed is False


def test_target_outside_maintenance_window_is_blocked():
    test_scope = scope(
        maintenance_start=time(22, 0),
        maintenance_end=time(23, 0),
        timezone_name="UTC",
    )

    result = validate_target(
        "192.168.56.20",
        [test_scope],
        explicitly_authorized=True,
        now=datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc),
    )

    assert result.allowed is False
    assert "maintenance window" in result.reason.lower()


def test_target_inside_overnight_maintenance_window_is_allowed():
    test_scope = scope(
        maintenance_start=time(22, 0),
        maintenance_end=time(2, 0),
        timezone_name="UTC",
    )

    result = validate_target(
        "192.168.56.20",
        [test_scope],
        explicitly_authorized=True,
        now=datetime(2026, 10, 7, 23, 30, tzinfo=timezone.utc),
    )

    assert result.allowed is True
