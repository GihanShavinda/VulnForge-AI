from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.core.config import get_settings


def _safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())[:180] or "default"


def cache_root() -> Path:
    root = Path(get_settings().threat_intel_cache_dir)
    if not root.is_absolute():
        root = Path.cwd() / root
    root.mkdir(parents=True, exist_ok=True)
    return root


def cache_path(namespace: str, key: str) -> Path:
    directory = cache_root() / _safe(namespace)
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{_safe(key)}.json"


def write_cache(namespace: str, key: str, payload: dict[str, Any]) -> Path:
    path = cache_path(namespace, key)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2),
        encoding="utf-8",
    )
    return path


def read_cache(namespace: str, key: str) -> dict[str, Any] | None:
    path = cache_path(namespace, key)
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None
