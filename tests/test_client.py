import httpx
import pytest

from cryptmaster.client import CryptMasterClient
from cryptmaster.exceptions import EnrollmentError, SecretNotFoundError, VaultUnreachableError


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("cryptmaster.identity.platformdirs.user_config_dir", lambda *_: str(tmp_path / "cfg"))
    return CryptMasterClient("vault.example.com", max_retries=1, backoff_seconds=0)


def test_defaults_to_tls_verification(client):
    assert client.verify_tls is True


def test_enroll_server_success(client, monkeypatch):
    monkeypatch.setattr(
        client, "_post", lambda path, payload: {"response": "enrollment pending"}
    )
    assert client.enroll_server() == "enrollment pending"


def test_enroll_server_banned_raises(client, monkeypatch):
    monkeypatch.setattr(
        client, "_post", lambda path, payload: {"response": "This server has been banned"}
    )
    with pytest.raises(EnrollmentError):
        client.enroll_server()


def test_get_secret_success(client, monkeypatch):
    calls = []

    def fake_post(path, payload):
        calls.append(path)
        if path == "/v2/start_auth":
            return {"response": "Awaiting Key", "nonce": "abc123"}
        return {"response": "SUCCESS", "secret": "hunter2"}

    monkeypatch.setattr(client, "_post", fake_post)
    assert client.get_secret("db_password") == "hunter2"
    assert calls == ["/v2/start_auth", "/v2/get_secret"]


def test_get_secret_not_found_raises(client, monkeypatch):
    def fake_post(path, payload):
        if path == "/v2/start_auth":
            return {"response": "Awaiting Key", "nonce": "abc123"}
        return {"response": "No secret found"}

    monkeypatch.setattr(client, "_post", fake_post)
    with pytest.raises(SecretNotFoundError):
        client.get_secret("nonexistent")


def test_get_secret_no_nonce_raises(client, monkeypatch):
    monkeypatch.setattr(client, "_post", lambda path, payload: {"response": "Unauthorized"})
    with pytest.raises(VaultUnreachableError):
        client.get_secret("db_password")


def test_post_retries_then_raises(client, monkeypatch):
    def always_fail(*args, **kwargs):
        raise httpx.ConnectError("boom", request=httpx.Request("POST", "https://x"))

    monkeypatch.setattr(httpx, "post", always_fail)
    with pytest.raises(VaultUnreachableError):
        client._post("/v2/start_auth", {})
