from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings


@dataclass(frozen=True)
class NmapExecutionResult:
    command: list[str]
    xml_text: str
    stderr: str
    returncode: int


def get_nmap_executable() -> str:
    """
    Resolve the Nmap executable.

    Resolution order:
    1. NMAP_PATH from backend/.env / application settings
    2. System/user PATH via shutil.which("nmap")

    This is especially useful on Windows where VS Code may not inherit
    the latest PATH immediately after Nmap installation.
    """
    settings = get_settings()

    configured_path = settings.nmap_path.strip()

    if configured_path:
        path = Path(configured_path).expanduser()

        if path.is_file():
            return str(path.resolve())

        raise RuntimeError(
            "Configured NMAP_PATH does not exist: "
            f"{configured_path}"
        )

    detected_path = shutil.which("nmap")

    if detected_path:
        return detected_path

    raise RuntimeError(
        "Nmap executable was not found. "
        "Set NMAP_PATH in backend/.env or add Nmap to Windows PATH."
    )


def build_discovery_command(
    target: str,
    method: str,
    output_file: Path,
) -> list[str]:
    """
    Build a safe Nmap host-discovery command.

    Important:
    - No port scan is performed because -sn is always used.
    - XML output is written using -oX.
    - Scope validation must be performed before this function is called
      by the discovery service.
    """
    nmap_executable = get_nmap_executable()

    base = [
        nmap_executable,
        "-R",
        "-oX",
        str(output_file),
    ]

    normalized_method = method.strip().lower()

    if normalized_method == "icmp":
        # Host discovery only.
        #
        # -PE : ICMP Echo Request
        # -PP : ICMP Timestamp Request
        # -PM : ICMP Address Mask Request
        probe_args = [
            "-sn",
            "-PE",
            "-PP",
            "-PM",
        ]

    elif normalized_method == "arp":
        # ARP discovery is appropriate for hosts on the same local
        # Ethernet / VMware Host-Only segment.
        probe_args = [
            "-sn",
            "-PR",
        ]

    elif normalized_method == "tcp":
        # TCP host-discovery probes only.
        # -sn prevents a normal port scan.
        #
        # SYN probes:
        # 80   HTTP
        # 443  HTTPS
        # 445  SMB
        # 3389 RDP
        #
        # ACK probes:
        # 80 / 443
        probe_args = [
            "-sn",
            "-PS80,443,445,3389",
            "-PA80,443",
        ]

    else:
        raise ValueError(
            "Unsupported discovery method. "
            "Expected one of: icmp, arp, tcp."
        )

    return [
        *base,
        *probe_args,
        target,
    ]


def run_nmap_discovery(
    target: str,
    method: str,
    timeout_seconds: int = 300,
) -> NmapExecutionResult:
    """
    Execute an authorized Nmap host-discovery operation and return
    preserved XML evidence.

    Scope validation is intentionally NOT duplicated here.
    The discovery orchestration/service layer must validate the complete
    target/IP/CIDR against an approved ScanScope before invoking this
    function.
    """
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be greater than zero.")

    # Resolve before creating the command so configuration problems fail
    # before launching any subprocess.
    get_nmap_executable()

    with tempfile.TemporaryDirectory(
        prefix="vulnforge-discovery-"
    ) as tmp:
        output_file = Path(tmp) / "discovery.xml"

        command = build_discovery_command(
            target=target,
            method=method,
            output_file=output_file,
        )

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                shell=False,
                encoding="utf-8",
                errors="replace",
            )

        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Nmap discovery exceeded the "
                f"{timeout_seconds}-second timeout."
            ) from exc

        except OSError as exc:
            raise RuntimeError(
                f"Failed to start Nmap: {exc}"
            ) from exc

        xml_text = ""

        if output_file.exists():
            xml_text = output_file.read_text(
                encoding="utf-8",
                errors="replace",
            )

        stderr = completed.stderr or ""

        if completed.returncode != 0:
            raise RuntimeError(
                "Nmap discovery failed with exit code "
                f"{completed.returncode}: "
                f"{stderr.strip() or 'No error message returned by Nmap.'}"
            )

        if not xml_text.strip():
            raise RuntimeError(
                "Nmap completed but did not produce XML discovery evidence."
            )

        return NmapExecutionResult(
            command=command,
            xml_text=xml_text,
            stderr=stderr,
            returncode=completed.returncode,
        )