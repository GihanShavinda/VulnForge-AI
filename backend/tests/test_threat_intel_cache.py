from pathlib import Path
from types import SimpleNamespace

import app.services.threat_intel_cache as cache


def test_offline_cache_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(
        cache,
        "get_settings",
        lambda: SimpleNamespace(threat_intel_cache_dir=str(tmp_path)),
    )

    payload = {"id": "CVE-2026-1234", "value": {"a": 1}}
    path = cache.write_cache("nvd", "CVE-2026-1234", payload)

    assert Path(path).exists()
    assert cache.read_cache("nvd", "CVE-2026-1234") == payload
