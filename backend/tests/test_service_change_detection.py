from app.services.service_change_detection import (
    ComparableService,
    detect_current_changes,
    previously_open_now_missing,
)


def test_new_port():
    current = ComparableService(
        port=8080,
        protocol="tcp",
        state="open",
        service="http",
        version="1.0",
    )

    changes = detect_current_changes(
        current=current,
        previous_same_endpoint=None,
        previous_same_port=[],
    )

    assert changes == ["new_port"]


def test_version_changed():
    previous = ComparableService(
        port=80,
        protocol="tcp",
        state="open",
        service="http",
        version="1.0",
    )

    current = ComparableService(
        port=80,
        protocol="tcp",
        state="open",
        service="http",
        version="2.0",
    )

    changes = detect_current_changes(
        current=current,
        previous_same_endpoint=previous,
        previous_same_port=[previous],
    )

    assert changes == ["version_changed"]


def test_service_changed():
    previous = ComparableService(
        port=8080,
        protocol="tcp",
        state="open",
        service="http",
        version="1.0",
    )

    current = ComparableService(
        port=8080,
        protocol="tcp",
        state="open",
        service="http-proxy",
        version="1.0",
    )

    changes = detect_current_changes(
        current=current,
        previous_same_endpoint=previous,
        previous_same_port=[previous],
    )

    assert changes == ["service_changed"]


def test_protocol_changed():
    previous_udp = ComparableService(
        port=53,
        protocol="udp",
        state="open",
        service="domain",
        version="9.18",
    )

    current_tcp = ComparableService(
        port=53,
        protocol="tcp",
        state="open",
        service="domain",
        version="9.18",
    )

    changes = detect_current_changes(
        current=current_tcp,
        previous_same_endpoint=None,
        previous_same_port=[previous_udp],
    )

    assert "new_port" in changes
    assert "protocol_changed" in changes


def test_missing_previous_open_port_is_not_assumed_closed():
    previous = [
        ComparableService(
            port=23,
            protocol="tcp",
            state="open",
            service="telnet",
            version=None,
        )
    ]

    current = [
        ComparableService(
            port=22,
            protocol="tcp",
            state="open",
            service="ssh",
            version="9",
        )
    ]

    missing = previously_open_now_missing(previous, current)

    # A service missing from a later scan is not proof that the port is closed.
    # It may be filtered, timed out, tcpwrapped, or otherwise not observed.
    assert missing == []


def test_explicit_closed_port():
    previous = ComparableService(
        port=8080,
        protocol="tcp",
        state="open",
        service="http",
        version="1.0",
    )

    current = ComparableService(
        port=8080,
        protocol="tcp",
        state="closed",
        service="http",
        version="1.0",
    )

    changes = detect_current_changes(
        current=current,
        previous_same_endpoint=previous,
        previous_same_port=[previous],
    )

    assert changes == ["closed_port"]


def test_tcpwrapped_does_not_create_service_or_version_change():
    previous = ComparableService(
        port=21,
        protocol="tcp",
        state="open",
        service="ftp",
        version="2.3.4",
    )

    current = ComparableService(
        port=21,
        protocol="tcp",
        state="open",
        service="tcpwrapped",
        version=None,
    )

    changes = detect_current_changes(
        current=current,
        previous_same_endpoint=previous,
        previous_same_port=[previous],
    )

    assert changes == []


def test_missing_version_does_not_create_version_change():
    previous = ComparableService(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        version="9.6",
    )

    current = ComparableService(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        version=None,
    )

    changes = detect_current_changes(
        current=current,
        previous_same_endpoint=previous,
        previous_same_port=[previous],
    )

    assert changes == []


def test_filtered_port_is_not_closed_port():
    previous = ComparableService(
        port=5432,
        protocol="tcp",
        state="open",
        service="postgresql",
        version="8.3",
    )

    current = ComparableService(
        port=5432,
        protocol="tcp",
        state="filtered",
        service="postgresql",
        version=None,
    )

    changes = detect_current_changes(
        current=current,
        previous_same_endpoint=previous,
        previous_same_port=[previous],
    )

    assert "closed_port" not in changes