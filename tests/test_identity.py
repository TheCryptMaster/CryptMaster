from cryptmaster.identity import get_or_create_local_salt, get_system_id


def test_salt_is_persisted(tmp_path, monkeypatch):
    monkeypatch.setattr("cryptmaster.identity.platformdirs.user_config_dir", lambda *_: str(tmp_path / "cfg"))
    first = get_or_create_local_salt()
    second = get_or_create_local_salt()
    assert first == second
    assert len(first) == 32


def test_system_id_is_stable(tmp_path, monkeypatch):
    monkeypatch.setattr("cryptmaster.identity.platformdirs.user_config_dir", lambda *_: str(tmp_path / "cfg"))
    assert get_system_id() == get_system_id()
