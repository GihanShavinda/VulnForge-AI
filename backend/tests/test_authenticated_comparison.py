from app.services.authenticated_comparison import _ports

def test_parse_linux_listening_socket():
    text="tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*"
    ports=_ports(text)
    assert ("tcp",22) in ports
    assert ("udp",53) in ports
