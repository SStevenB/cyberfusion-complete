# ingestion/secrets.py
#
# Safest-practical local secret handling for a student project.
#
# Priority:
#   1. OS keychain via the `keyring` package (macOS Keychain / Windows Cred
#      Manager / Linux Secret Service) — secrets never touch disk in plaintext.
#   2. Fallback: a local file data/secrets.local.json with a LOUD warning.
#      This file is gitignored and never committed.
#
# Secrets are referenced by a stable key like "tenable.api_key". The UI masks
# them and only ever shows whether a secret is set, never its value.

import json
import os
from typing import Optional

SECRETS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "secrets.local.json")
_SERVICE = "cyberfusion"

# Detect keyring availability once.
try:
    import keyring  # type: ignore
    # Some environments have keyring installed but no working backend.
    try:
        keyring.get_keyring()
        _KEYRING_OK = True
    except Exception:
        _KEYRING_OK = False
except Exception:
    keyring = None
    _KEYRING_OK = False


def backend_name() -> str:
    """Human-readable description of where secrets are stored."""
    if _KEYRING_OK:
        try:
            return f"OS keychain ({keyring.get_keyring().__class__.__name__})"
        except Exception:
            return "OS keychain"
    return "local file (data/secrets.local.json) — less secure"


def is_secure() -> bool:
    """True if secrets go to the OS keychain rather than a local file."""
    return _KEYRING_OK


def _load_file() -> dict:
    if not os.path.exists(SECRETS_FILE):
        return {}
    try:
        with open(SECRETS_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_file(data: dict) -> None:
    os.makedirs(os.path.dirname(SECRETS_FILE), exist_ok=True)
    with open(SECRETS_FILE, "w") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(SECRETS_FILE, 0o600)  # owner-only read/write
    except OSError:
        pass


def set_secret(key: str, value: str) -> None:
    """Store a secret. Uses keychain if available, else the local file."""
    if not value:
        return
    if _KEYRING_OK:
        keyring.set_password(_SERVICE, key, value)
    else:
        data = _load_file()
        data[key] = value
        _save_file(data)


def get_secret(key: str) -> Optional[str]:
    """Retrieve a secret value (returns None if unset)."""
    if _KEYRING_OK:
        try:
            return keyring.get_password(_SERVICE, key)
        except Exception:
            return None
    return _load_file().get(key)


def has_secret(key: str) -> bool:
    return bool(get_secret(key))


def delete_secret(key: str) -> None:
    if _KEYRING_OK:
        try:
            keyring.delete_password(_SERVICE, key)
        except Exception:
            pass
    else:
        data = _load_file()
        data.pop(key, None)
        _save_file(data)


def masked(key: str) -> str:
    """Return a masked representation for UI display."""
    val = get_secret(key)
    if not val:
        return "— not set —"
    if len(val) <= 6:
        return "••••••"
    return val[:3] + "•" * (len(val) - 6) + val[-3:]
