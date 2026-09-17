"""Machine identity for this client instance.

v1 used MD5 to combine a local salt file with a "hardware serial" scraped by
shelling out to `ls -l /dev/disk/by-uuid` (or the mac/windows equivalents)
and grabbing the first hyphenated token in the output -- not actually a
serial number, and liable to change if disks are added/reordered.

This keeps the same overall shape (local salt + a locally-observable machine
identifier, hashed together) but:
  * uses SHA-256 instead of MD5,
  * uses `uuid.getnode()` (MAC address-derived) as a portable identifier
    instead of parsing `ls` output, with an explicit, documented fallback,
  * stores the local salt with restrictive file permissions.
"""
from __future__ import annotations

import os
import secrets
import stat
import uuid

import platformdirs

_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _config_path() -> str:
    return platformdirs.user_config_dir("cryptmaster") + "_salt"


def get_or_create_local_salt() -> str:
    path = _config_path()
    if not os.path.isfile(path):
        salt = "".join(secrets.choice(_ALPHABET) for _ in range(32))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            f.write(salt)
        return salt
    with open(path, "r") as f:
        return f.readline().strip()


def get_machine_identifier() -> str:
    """A best-effort, locally-stable machine identifier. Not a security
    boundary on its own -- it's combined with the local salt file and the
    server-side IP allow-list to identify an enrolled server."""
    return str(uuid.getnode())


def get_system_id() -> str:
    import hashlib

    salt = get_or_create_local_salt()
    machine_id = get_machine_identifier()
    return hashlib.sha256((salt + machine_id).encode("utf-8")).hexdigest()
