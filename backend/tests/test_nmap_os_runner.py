from pathlib import Path

from app.services.nmap_os_runner import build_nmap_os_command


def test_nmap_os_command_preserves_xml_and_os_detection(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("app.services.nmap_os_runner.get_nmap_executable", lambda: r"C:\Program Files (x86)\Nmap\nmap.exe")
    output = tmp_path / "os.xml"
    command = build_nmap_os_command("192.168.37.131/32", output)
    assert "-O" in command
    assert "--osscan-guess" in command
    assert "-oX" in command
    assert str(output) in command
    assert command[-1] == "192.168.37.131/32"
