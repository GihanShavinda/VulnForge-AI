from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.services.nmap_runner import get_nmap_executable


@dataclass(frozen=True)
class NmapOSExecutionResult:
    command: list[str]
    xml_text: str
    stderr: str
    returncode: int


def build_nmap_os_command(target: str, output_file: Path) -> list[str]:
    return [get_nmap_executable(), "-Pn", "-O", "--osscan-guess", "--max-os-tries", "2", "-oX", str(output_file), target]


def run_nmap_os_detection(target: str, timeout_seconds: int = 300) -> NmapOSExecutionResult:
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be greater than zero.")

    with tempfile.TemporaryDirectory(prefix="vulnforge-os-") as tmp:
        output_file = Path(tmp) / "os.xml"
        command = build_nmap_os_command(target, output_file)
        try:
            completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout_seconds, check=False, shell=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Nmap OS detection exceeded the {timeout_seconds}-second timeout.") from exc
        except OSError as exc:
            raise RuntimeError(f"Failed to start Nmap OS detection: {exc}") from exc

        xml_text = output_file.read_text(encoding="utf-8", errors="replace") if output_file.exists() else ""
        stderr = completed.stderr or ""
        if completed.returncode != 0:
            raise RuntimeError(f"Nmap OS detection failed with exit code {completed.returncode}: {stderr.strip() or 'No error message returned by Nmap.'}")
        if not xml_text.strip():
            raise RuntimeError("Nmap completed but did not produce OS XML evidence.")
        return NmapOSExecutionResult(command, xml_text, stderr, completed.returncode)
