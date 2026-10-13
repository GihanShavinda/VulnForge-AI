def test_v5_legacy_asset_field_policy():
    from app.services.authenticated_assessment_service import _legacy_windows
    from types import SimpleNamespace

    class DB:
        def scalar(self, _query):
            return None

    assert _legacy_windows(DB(), SimpleNamespace(id="x", operating_system="Windows 7")) is True
    assert _legacy_windows(DB(), SimpleNamespace(id="x", operating_system="Windows XP")) is True
    assert _legacy_windows(DB(), SimpleNamespace(id="x", operating_system="Windows 10")) is False
