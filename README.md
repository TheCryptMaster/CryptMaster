# Crypt Master - Client (v2)

A small library for fetching secrets from a [Crypt Master vault](https://github.com/TheCryptMaster/CryptMasterServer)
instead of keeping them in local application config.

**This is a ground-up rewrite.** The original implementation is preserved,
unmodified, on the [`legacy-v1`](../../tree/legacy-v1) branch.

## What changed from v1

- TLS certificate verification is **on by default** (`verify_tls=True`).
  v1 hardcoded `verify=False` on every request, which meant the "secure"
  client accepted any certificate from anyone in the network path.
- Machine identity uses SHA-256 instead of MD5, and no longer shells out to
  parse `ls -l /dev/disk/by-uuid` output.
- The local salt file is created with `0600` permissions.
- Failures raise typed exceptions (`EnrollmentError`, `SecretNotFoundError`,
  `VaultUnreachableError`) instead of `print()`-and-`sleep(20)`-forever
  loops, with bounded, explicit retries and exponential backoff.

## Usage

```python
from cryptmaster import CryptMasterClient

client = CryptMasterClient("secure-api.yourdomain.com")

# One-time, run once per app server, then approve it from the vault's admin CLI:
client.enroll_server()

# After enrollment is approved and an admin has opened the vault (TOTP login):
db_password = client.get_secret("db_password")
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```
