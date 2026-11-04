"""Saved sign-in credentials for the login page.

Kept apart from the tenant databases on purpose: one Fernet-encrypted file
(AES-128-CBC + HMAC-SHA256) in the data directory, holding every tenant the
user chose to remember. The key comes only from CX_CREDENTIALS_KEY in the
environment (.env), never from the data directory, so a copy of the data
directory alone can't be decrypted. Without a usable key the feature is off
and nothing is written.

Secrets (API key / client secret) never leave this module except to sign
in: profiles() returns them masked for display.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken

import db

logger = logging.getLogger(__name__)

KEY_ENV_VAR = "CX_CREDENTIALS_KEY"
STORE_PATH = db.DATA_DIR / "saved_credentials.enc"

_lock = threading.Lock()


def _fernet() -> Fernet | None:
    key = os.environ.get(KEY_ENV_VAR, "").strip()
    if not key:
        return None
    try:
        return Fernet(key.encode())
    except ValueError:
        logger.error("%s is not a valid Fernet key; saved credentials are disabled.", KEY_ENV_VAR)
        return None


def enabled() -> bool:
    return _fernet() is not None


def profile_id(tenant: str, base_url: str, iam_url: str) -> str:
    """Stable id for one tenant on one Checkmarx One instance."""
    identity = "\n".join((tenant.strip().lower(), base_url.strip().lower(), iam_url.strip().lower()))
    return hashlib.sha256(identity.encode()).hexdigest()[:16]


def _load(fernet: Fernet) -> list[dict]:
    try:
        ciphertext = STORE_PATH.read_bytes()
    except FileNotFoundError:
        return []
    try:
        return json.loads(fernet.decrypt(ciphertext)).get("profiles", [])
    except (InvalidToken, ValueError):
        # A changed or wrong key: treat as empty rather than failing sign-in.
        # The next save overwrites the unreadable file.
        logger.warning("Saved credentials could not be decrypted with the current %s; ignoring them.", KEY_ENV_VAR)
        return []


def _write(fernet: Fernet, profiles: list[dict]) -> None:
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ciphertext = fernet.encrypt(json.dumps({"version": 1, "profiles": profiles}).encode())
    tmp_path = STORE_PATH.with_suffix(".tmp")
    # Owner-only before anything is written (chmod too: O_CREAT's mode
    # doesn't apply to a leftover tmp file), then an atomic swap so a crash
    # mid-write never leaves a truncated file behind.
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(tmp_path, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(ciphertext)
    os.replace(tmp_path, STORE_PATH)


def _mask(secret: str | None) -> str:
    if not secret:
        return ""
    return "••••" + secret[-4:] if len(secret) > 8 else "••••"


def profiles() -> list[dict]:
    """Saved tenants for display, most recently used first. Secrets masked."""
    fernet = _fernet()
    if fernet is None:
        return []
    with _lock:
        saved = _load(fernet)
    return [
        {
            "id": p["id"],
            "tenant": p["tenant"],
            "base_url": p["base_url"],
            "iam_url": p["iam_url"],
            "auth_method": p["auth_method"],
            "client_id": p.get("client_id"),
            "secret_hint": _mask(p.get("api_key") if p["auth_method"] == "api_key" else p.get("client_secret")),
            "saved_at": p.get("saved_at"),
        }
        for p in sorted(saved, key=lambda p: p.get("saved_at") or "", reverse=True)
    ]


def get(pid: str) -> dict | None:
    """One saved profile with its secrets, for signing in."""
    fernet = _fernet()
    if fernet is None:
        return None
    with _lock:
        return next((p for p in _load(fernet) if p["id"] == pid), None)


def save(tenant, base_url, iam_url, auth_method, client_id, client_secret, api_key) -> None:
    """Remember (or refresh) a tenant after a successful sign-in. Only the
    secret for the chosen auth method is kept."""
    fernet = _fernet()
    if fernet is None:
        return
    pid = profile_id(tenant, base_url, iam_url)
    entry = {
        "id": pid,
        "tenant": tenant,
        "base_url": base_url,
        "iam_url": iam_url,
        "auth_method": auth_method,
        "client_id": client_id if auth_method == "client_credentials" else None,
        "client_secret": client_secret if auth_method == "client_credentials" else None,
        "api_key": api_key if auth_method == "api_key" else None,
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    with _lock:
        saved = [p for p in _load(fernet) if p["id"] != pid]
        _write(fernet, [entry, *saved])


def forget(pid: str) -> bool:
    fernet = _fernet()
    if fernet is None:
        return False
    with _lock:
        saved = _load(fernet)
        remaining = [p for p in saved if p["id"] != pid]
        if len(remaining) == len(saved):
            return False
        _write(fernet, remaining)
    return True
