from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WhatWebExecutionResult:
    url: str
    command: list[str]
    payload: object
    raw_text: str
    stderr: str
    returncode: int


def get_whatweb_executable() -> str | None:
    configured = os.getenv("WHATWEB_PATH")
    if configured:
        return configured
    return shutil.which("whatweb") or shutil.which("whatweb.exe")


def run_whatweb(url: str, timeout_seconds: int = 60) -> WhatWebExecutionResult:
    executable = get_whatweb_executable()
    if not executable:
        raise RuntimeError("WhatWeb is not installed or not available on PATH. Set WHATWEB_PATH if installed.")

    with tempfile.TemporaryDirectory(prefix="vulnforge-whatweb-") as tmp:
        output_file = Path(tmp) / "whatweb.json"
        command = [executable, "--no-errors", "--color=never", f"--log-json={output_file}", url]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout_seconds, check=False, shell=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"WhatWeb exceeded the {timeout_seconds}-second timeout for {url}.") from exc
        except OSError as exc:
            raise RuntimeError(f"Failed to start WhatWeb: {exc}") from exc
        if completed.returncode != 0:
            raise RuntimeError(f"WhatWeb failed for {url} with exit code {completed.returncode}: {(completed.stderr or '').strip() or 'No error message returned.'}")
        raw_text = output_file.read_text(encoding="utf-8", errors="replace") if output_file.exists() else (completed.stdout or "")
        try:
            payload = json.loads(raw_text) if raw_text.strip() else []
        except json.JSONDecodeError:
            payload = []
        return WhatWebExecutionResult(url, command, payload, raw_text, completed.stderr or "", completed.returncode)
