"""Crypt Master client v2.

Differences from v1:
  * TLS verification is ON by default and configurable, not hardcoded to
    `verify=False`. v1's client silently trusted any certificate on every
    request, which defeated the point of the cert setup in the server's own
    README.
  * Failures raise typed exceptions instead of `print()` + `sleep(20)` +
    silent retry forever. Retries are still supported, but bounded and
    explicit, with exponential backoff.
  * Machine identity uses SHA-256 (see identity.py), not MD5.
"""
from __future__ import annotations

import time

import httpx
from argon2 import PasswordHasher

from .exceptions import EnrollmentError, SecretNotFoundError, VaultUnreachableError
from .identity import get_or_create_local_salt, get_system_id

_ph = PasswordHasher()


class CryptMasterClient:
    def __init__(
        self,
        server: str,
        port: int = 2053,
        verify_tls: bool | str = True,
        timeout: float = 5.0,
        max_retries: int = 3,
        backoff_seconds: float = 2.0,
    ):
        self.salt = get_or_create_local_salt()
        self.system_id = get_system_id()
        self.base_url = f"https://{server}:{port}"
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self.base_url}{path}"
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                response = httpx.post(
                    url, json=payload, timeout=self.timeout, verify=self.verify_tls
                )
            except httpx.HTTPError as exc:
                last_exc = exc
            else:
                if response.status_code == 200:
                    return response.json()
                last_exc = RuntimeError(f"{response.status_code}: {response.text}")
            time.sleep(self.backoff_seconds * (2**attempt))
        raise VaultUnreachableError(f"failed to reach {url} after {self.max_retries} attempts") from last_exc

    def enroll_server(self) -> str:
        payload = {"system_id": self.system_id, "system_salt": self.salt}
        response = self._post("/v2/enroll_server", payload)
        status = response.get("response", "")
        if status not in ("enrollment pending", "enrollment is still pending"):
            raise EnrollmentError(status or "unknown enrollment error")
        return status

    def get_secret(self, requested_secret: str) -> str:
        auth_payload = {"system_id": self.system_id}
        auth_response = self._post("/v2/start_auth", auth_payload)
        nonce = auth_response.get("nonce")
        if nonce is None:
            raise VaultUnreachableError("vault did not issue an auth nonce (is this server enrolled?)")

        proof = _ph.hash(nonce + self.salt)
        payload = {
            "system_id": self.system_id,
            "auth_response": proof,
            "requested_password": requested_secret,
        }
        response = self._post("/v2/get_secret", payload)
        secret = response.get("secret")
        if secret is not None:
            return secret
        raise SecretNotFoundError(response.get("response", "no secret returned"))
