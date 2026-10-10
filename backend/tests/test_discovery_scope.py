from types import SimpleNamespace

from app.services.discovery_scope import validate_discovery_target


def scope(cidr="192.168.56.0/24", *, enabled=True, auth=True):
    return SimpleNamespace(
        name="Primary Lab Scope",
        cidr=cidr,
        enabled=enabled,
        require_explicit_authorization=auth,
    )


def test_discovery_cidr_fully_inside_scope_is_allowed():
    result = validate_discovery_target(
        "192.168.56.0/25", [scope()], explicitly_authorized=True
    )
    assert result.allowed is True


def test_discovery_cidr_larger_than_scope_is_denied():
    result = validate_discovery_target(
        "192.168.0.0/16", [scope()], explicitly_authorized=True
    )
    assert result.allowed is False


def test_discovery_host_outside_scope_is_denied():
    result = validate_discovery_target(
        "8.8.8.8", [scope()], explicitly_authorized=True
    )
    assert result.allowed is False


def test_discovery_requires_authorization():
    result = validate_discovery_target(
        "192.168.56.0/24", [scope()], explicitly_authorized=False
    )
    assert result.allowed is False


def test_discovery_rejects_loopback():
    result = validate_discovery_target(
        "127.0.0.1", [scope("0.0.0.0/0")], explicitly_authorized=True
    )
    assert result.allowed is False
