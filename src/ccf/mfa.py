"""TOTP: the algorithm, and nothing that touches a database.

Spec: ``docs/superpowers/specs/2026-09-23-mfa-totp-design.md``.

RFC 4226 (HOTP) and RFC 6238 (TOTP) implemented on the standard library rather
than pulled in as a dependency: it is roughly twenty lines, it is exactly
specified, and both RFCs publish test vectors, so the implementation can be
pinned against the specification itself rather than against another
implementation of it.

Everything here is a pure function over an explicit ``now``. No wall clock
reaches this module, because a drift or replay test driven by real time is a
test that passes for the wrong reason at 00:00:29.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote

#: RFC 4226 §4 R6 sets a 128-bit floor and recommends 160, which is also the
#: HMAC-SHA1 block-aligned size. 20 bytes encodes to 32 base32 characters.
SECRET_BYTES = 20

#: RFC 6238 defaults. These are not tunable because every authenticator app in
#: practice implements exactly this triple, and an option nobody can use is a
#: branch nobody tests.
DIGITS = 6
PERIOD_SECONDS = 30

#: Steps of clock skew accepted either side of the current one. Each extra step
#: multiplies the guess space an attacker gets per window, so this stays at the
#: smallest value that tolerates an ordinary unsynchronised phone.
DRIFT_STEPS = 1


def generate_secret() -> str:
    """A fresh base32 TOTP secret, in the form authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    """Base32 with padding restored and whitespace tolerated.

    Users retype these by hand from a screen, so spaces and lowercase are
    normalised rather than rejected -- the alternative is an authenticator that
    "does not work" for a reason nobody can see.
    """
    cleaned = secret.strip().replace(" ", "").upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def timestep(now: float, *, period: int = PERIOD_SECONDS) -> int:
    """RFC 6238 ``T`` -- the counter a code is generated from."""
    return int(now) // period


def hotp(secret: str, counter: int, *, digits: int = DIGITS) -> str:
    """RFC 4226 HOTP. Pinned against the RFC's own test vectors."""
    mac = hmac.new(_decode_secret(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    # Dynamic truncation, RFC 4226 §5.3: the low nibble of the last byte picks
    # the offset, and the high bit of the selected word is masked off so the
    # result is sign-independent across implementations.
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFF_FFFF
    return str(code % (10**digits)).zfill(digits)


def verify(
    secret: str,
    code: str,
    *,
    now: float,
    last_used_step: int | None = None,
    drift: int = DRIFT_STEPS,
) -> int | None:
    """Return the step ``code`` is valid for, or ``None``.

    The step is returned rather than a bool because the caller must persist it:
    RFC 6238 §5.2 requires that a code accepted once is not accepted again, and
    the only way to enforce that is to remember which step was spent. A code
    observed over a shoulder or left in a proxy log stays valid for the rest of
    its window otherwise.

    ``last_used_step`` refuses that step **and every earlier one**. Refusing
    only the exact step would leave the other drift-window steps replayable.
    """
    cleaned = code.strip().replace(" ", "")
    if not cleaned.isdigit() or len(cleaned) != DIGITS:
        return None
    current = timestep(now)
    for step in range(current - drift, current + drift + 1):
        if last_used_step is not None and step <= last_used_step:
            continue
        # Constant-time: a short-circuiting == leaks how many leading digits
        # were right, which is a per-digit oracle over a six-digit space.
        if hmac.compare_digest(hotp(secret, step), cleaned):
            return step
    return None


def provisioning_uri(secret: str, *, account: str, issuer: str) -> str:
    """The ``otpauth://`` URI an authenticator app consumes.

    ``issuer`` is repeated in the label and the parameter, which is what the
    Key URI Format asks for and what makes the entry legible in an app that
    holds accounts for several systems.
    """
    label = quote(f"{issuer}:{account}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}"
        f"&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD_SECONDS}"
    )


def format_for_manual_entry(secret: str) -> str:
    """The secret in groups of four, for typing in by hand.

    Concord ships no QR encoder -- that is a dependency, and this repository
    adds those sparingly -- so manual entry is the primary path rather than the
    fallback, and it is formatted to be read off a screen without losing place.
    """
    return " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))


# ── recovery codes ──────────────────────────────────────────────────────────

RECOVERY_CODE_COUNT = 10
_RECOVERY_BYTES = 10  # 80 bits, base32 -> 16 characters


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Single-use codes, formatted in two readable halves."""
    out = []
    for _ in range(count):
        raw = base64.b32encode(secrets.token_bytes(_RECOVERY_BYTES)).decode("ascii").rstrip("=")
        out.append(f"{raw[:8]}-{raw[8:]}")
    return out


def normalize_recovery_code(code: str) -> str:
    return code.strip().replace(" ", "").replace("-", "").upper()


def hash_recovery_code(code: str) -> str:
    """SHA-256, deliberately NOT ``auth.hash_password``.

    Password stretching exists because people choose guessable passwords. A
    recovery code is 80 random bits, so there is nothing to stretch -- and
    running 210,000 PBKDF2 rounds against ten stored codes on every login
    attempt is a denial-of-service surface a caller controls for free.

    This divergence is deliberate and is stated here so it does not read as
    somebody not knowing where ``hash_password`` lives.
    """
    return hashlib.sha256(normalize_recovery_code(code).encode("utf-8")).hexdigest()
