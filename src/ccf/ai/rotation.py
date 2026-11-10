"""Rewrapping stored ciphertext onto the current key-encryption key.

Spec: ``docs/superpowers/specs/2026-09-23-key-rotation-design.md`` §3.

Rotation is **explicit**. Nothing here runs from a read path: a read that
writes can fail, deadlock, or sit inside a transaction that later rolls back,
leaving an operator believing a rotation completed. And lazy rewrapping makes
"is it finished?" unanswerable, because what remains is whichever rows nobody
happened to read.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from ..config import get_settings
from ..models import OrgNotifyChannel
from ..models_ai_actions import AiProviderConfig
from ..models_grc import ConnectorConfig
from ..models_identity import UserMfaCredential
from .cipher import (
    AAD_CREDENTIAL,
    AAD_MFA,
    AAD_NOTIFY_CHANNEL,
    KmsUnavailableError,
    PayloadAuthenticationError,
    UnknownKeyError,
    build_cipher,
    token_key_id,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class EncryptedColumn:
    """One place ciphertext is stored, and the context it was written with."""

    model: Any
    column: str
    aad: bytes
    label: str


#: Every column holding envelope ciphertext. A fourth one added later and not
#: listed here would be silently left behind on an old key, so
#: ``tests/test_key_rotation.py`` asserts this list against the models that
#: actually carry such a column.
ENCRYPTED_COLUMNS: tuple[EncryptedColumn, ...] = (
    EncryptedColumn(
        AiProviderConfig, "encrypted_credential", AAD_CREDENTIAL, "ai_provider_configs"
    ),
    EncryptedColumn(ConnectorConfig, "encrypted_credential", AAD_CREDENTIAL, "connector_configs"),
    EncryptedColumn(UserMfaCredential, "secret_encrypted", AAD_MFA, "user_mfa_credentials"),
    EncryptedColumn(OrgNotifyChannel, "encrypted_url", AAD_NOTIFY_CHANNEL, "org_notify_channels"),
)


#: Why a ``damaged`` row could not be read. Fixed phrases, never exception
#: text: an error message can quote the bytes it choked on.
DAMAGED_NOT_CIPHERTEXT = "the stored value is not a ciphertext this code wrote"
DAMAGED_NOT_AUTHENTIC = (
    "the key is present but the value did not authenticate: it belongs to "
    "another store, or the stored bytes were modified"
)


@dataclass
class RewrapReport:
    """What moved, what was already current, and what could not be read."""

    rewrapped: int = 0
    already_current: int = 0
    #: ``(table, row id, the key id the row needs)``: rows a missing key would
    #: rescue. Reported rather than counted as a bare failure: an operator who
    #: dropped a predecessor too early needs to know which key to put back.
    unreadable: list[tuple[str, int, str | None]] = field(default_factory=list)
    #: ``(table, row id, why)``: rows no key will rescue -- not a ciphertext at
    #: all, or one that fails authentication under a key that IS configured.
    #: Kept apart from ``unreadable`` so the operator is never told to restore
    #: a key that is not missing. The secret has to be entered again.
    damaged: list[tuple[str, int, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.unreadable and not self.damaged


async def rewrap_all(session: AsyncSession) -> RewrapReport:
    """Move every stored value onto the current key. Running twice is a no-op."""
    settings = get_settings()
    report = RewrapReport()

    for spec in ENCRYPTED_COLUMNS:
        cipher = build_cipher(settings, aad=spec.aad)
        rows = (await session.execute(select(spec.model))).scalars().all()
        for row in rows:
            token = getattr(row, spec.column, None)
            if not token:
                continue
            # Parsed inside the handling, not before it: one value that is not
            # a ciphertext at all used to raise out of the sweep, naming no
            # row and leaving every later row on the old key.
            try:
                if not cipher.needs_rewrap(token):
                    report.already_current += 1
                    continue
            except Exception:
                report.damaged.append((spec.label, row.id, DAMAGED_NOT_CIPHERTEXT))
                continue
            try:
                setattr(row, spec.column, cipher.rewrap(token))
            except UnknownKeyError as e:
                report.unreadable.append((spec.label, row.id, e.missing_key_id))
                continue
            except KmsUnavailableError:
                # Not an unreadable row: KMS could not answer, which a retry
                # may fix. Reporting it beside genuinely orphaned rows would
                # tell an operator to restore a key that was never missing.
                raise
            except PayloadAuthenticationError:
                report.damaged.append((spec.label, row.id, DAMAGED_NOT_AUTHENTIC))
                continue
            except Exception:
                # The token parsed (needs_rewrap did), so its key id is safe to
                # read; what failed is not established, so it is filed where a
                # key might help, as before.
                report.unreadable.append((spec.label, row.id, token_key_id(token)))
                continue
            report.rewrapped += 1

    await session.flush()
    return report
