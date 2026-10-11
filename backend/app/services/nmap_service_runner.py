from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.services.nmap_runner import get_nmap_executable


@dataclass(frozen=True)
class NmapServiceExecutionResult:
    command: list[str]
    xml_text: str
    stderr: str
    returncode: int


def build_service_command(
    target: str,
    protocol: str,
    top_ports: int,
    output_file: Path,
) -> list[str]:
    if protocol not in {"tcp", "udp"}:
        raise ValueError("protocol must be 'tcp' or 'udp'.")
    if top_ports < 1 or top_ports > 2000:
        raise ValueError("top_ports must be between 1 and 2000.")

    command = [
        get_nmap_executable(),
        "-Pn",
        "-sV",
        "--version-all",
        "--top-ports",
        str(top_ports),
        "--script",
        "banner,ftp-anon,smb-protocols",
        "-oX",
        str(output_file),
    ]

    # TCP connect scans are intentionally used on Windows so VulnForge does not
    # require raw-packet privileges for ordinary TCP service enumeration.
    if protocol == "tcp":
        command.insert(1, "-sT")
    else:
        # UDP scanning may require elevated privileges/Npcap support on Windows.
        command.insert(1, "-sU")

    command.append(target)
    return command


def run_nmap_service_enumeration(
    target: str,
    protocol: str,
    top_ports: int,
    timeout_seconds: int = 900,
) -> NmapServiceExecutionResult:
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be greater than zero.")

    with tempfile.TemporaryDirectory(prefix="vulnforge-services-") as tmp:
        output_file = Path(tmp) / "services.xml"
        command = build_service_command(target, protocol, top_ports, output_file)

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Nmap service enumeration exceeded the {timeout_seconds}-second timeout."
            ) from exc
        except OSError as exc:
            raise RuntimeError(f"Failed to start Nmap service enumeration: {exc}") from exc

        xml_text = (
            output_file.read_text(encoding="utf-8", errors="replace")
            if output_file.exists()
            else ""
        )
        stderr = completed.stderr or ""

        if completed.returncode != 0:
            raise RuntimeError(
                "Nmap service enumeration failed with exit code "
                f"{completed.returncode}: {stderr.strip() or 'No error message returned by Nmap.'}"
            )
        if not xml_text.strip():
            raise RuntimeError("Nmap completed but did not produce XML service evidence.")

        return NmapServiceExecutionResult(
            command=command,
            xml_text=xml_text,
            stderr=stderr,
            returncode=completed.returncode,
        )
