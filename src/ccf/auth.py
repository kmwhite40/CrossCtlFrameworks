"""Authentication primitives — password hashing, API tokens, signed sessions.

Uses only the Python standard library (PBKDF2-HMAC-SHA256 for passwords, HMAC
for session signatures, ``secrets`` for tokens) to avoid extra dependencies.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

_PBKDF2_ROUNDS = 210_000


@dataclass(frozen=True)
class Principal:
    """The authenticated caller. ``org_id is None`` means an unscoped principal
    (auth disabled / system) that bypasses tenant filtering."""

    user_id: int | None
    email: str
    org_id: int | None
    role: str

    @property
    def is_global(self) -> bool:
        return self.org_id is None


# Used when auth is disabled — open, unscoped, full access (current behaviour).
SYSTEM_PRINCIPAL = Principal(user_id=None, email="system", org_id=None, role="admin")


def hash_password(password: str, *, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt}${dk.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        _algo, rounds, salt, digest = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), digest)


def new_api_token() -> str:
    return secrets.token_urlsafe(32)


def sign_session(user_id: int, secret: str, *, ttl_hours: int, now: float | None = None) -> str:
    exp = int(now if now is not None else time.time()) + ttl_hours * 3600
    raw = json.dumps({"uid": user_id, "exp": exp}, separators=(",", ":")).encode()
    payload = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_session(token: str, secret: str, *, now: float | None = None) -> int | None:
    try:
        payload, sig = token.split(".", 1)
    except ValueError:
        return None
    expect = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        return None
    try:
        padded = payload + "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("exp", 0) < (now if now is not None else time.time()):
        return None
    uid = data.get("uid")
    return uid if isinstance(uid, int) else None
