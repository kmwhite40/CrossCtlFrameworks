"""Envelope encryption for organization-scoped AI credentials.

Credentials are never stored in plaintext. Each secret is encrypted with a random
per-secret data-encryption key (DEK); the DEK is wrapped by a pluggable
:class:`KeyProvider` (the key-encryption key, KEK). Today the KEK is a local master
key from configuration; :class:`KeyProvider` is the seam where AWS KMS, Azure Key
Vault, GCP Secret Manager, or Vault drop in later — the stored token format does not
change, so migrating the KEK does not require re-encrypting payloads schema-wide.

Token layout (url-safe base64 of):
    version(1) | wrapped_len(2, big-endian) | wrapped_dek | nonce(12) | ciphertext

Decryption is intended to run only inside the gateway. Only :func:`mask` output
(last 4 chars) is ever surfaced to callers, the API, the UI, or logs.
"""

from __future__ import annotations

import base64
import hashlib
import os
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    from ..config import Settings

_VERSION = 1
_NONCE_LEN = 12
_DEK_LEN = 32  # AES-256


class CredentialStorageError(RuntimeError):
    """Raised when no key provider is configured — fail closed, never store plaintext."""


class KeyProvider(ABC):
    """Wraps/unwraps a data-encryption key with a key-encryption key (KEK)."""

    @abstractmethod
    def generate_data_key(self) -> tuple[bytes, bytes]:
        """Return ``(plaintext_dek, wrapped_dek)``."""

    @abstractmethod
    def unwrap_data_key(self, wrapped_dek: bytes) -> bytes:
        """Return the plaintext DEK for a previously wrapped DEK."""


class LocalKeyProvider(KeyProvider):
    """KEK derived from a configured master secret; wraps DEKs with AES-256-GCM.

    The master secret is stretched to a 32-byte KEK with SHA-256. Provide a strong,
    random ``ai_credential_master_key`` in any shared deployment. Swap this class for
    a KMS-backed provider without changing the stored token format.
    """

    def __init__(self, master_key: str) -> None:
        if not master_key or len(master_key) < 16:
            raise CredentialStorageError(
                "ai_credential_master_key must be set to a strong value (>=16 chars) "
                "to store AI credentials"
            )
        self._kek = hashlib.sha256(master_key.encode("utf-8")).digest()

    def generate_data_key(self) -> tuple[bytes, bytes]:
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(_NONCE_LEN)
        wrapped = nonce + AESGCM(self._kek).encrypt(nonce, dek, b"ccf-dek")
        return dek, wrapped

    def unwrap_data_key(self, wrapped_dek: bytes) -> bytes:
        nonce, blob = wrapped_dek[:_NONCE_LEN], wrapped_dek[_NONCE_LEN:]
        return AESGCM(self._kek).decrypt(nonce, blob, b"ccf-dek")


class CredentialCipher:
    """Envelope-encrypts/decrypts credential strings via a :class:`KeyProvider`."""

    def __init__(self, key_provider: KeyProvider) -> None:
        self._kp = key_provider

    def encrypt(self, plaintext: str) -> str:
        dek, wrapped = self._kp.generate_data_key()
        nonce = os.urandom(_NONCE_LEN)
        ct = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), b"ccf-cred")
        wl = len(wrapped)
        blob = bytes([_VERSION]) + wl.to_bytes(2, "big") + wrapped + nonce + ct
        return base64.urlsafe_b64encode(blob).decode("ascii")

    def decrypt(self, token: str) -> str:
        blob = base64.urlsafe_b64decode(token.encode("ascii"))
        if not blob or blob[0] != _VERSION:
            raise ValueError("unsupported credential token version")
        wl = int.from_bytes(blob[1:3], "big")
        off = 3
        wrapped = blob[off : off + wl]
        off += wl
        nonce = blob[off : off + _NONCE_LEN]
        off += _NONCE_LEN
        ct = blob[off:]
        dek = self._kp.unwrap_data_key(wrapped)
        return AESGCM(dek).decrypt(nonce, ct, b"ccf-cred").decode("utf-8")


def mask(secret: str) -> str:
    """Return a non-reversible display identifier (last 4 chars) for a secret."""
    if not secret:
        return ""
    tail = secret[-4:]
    return f"…{tail}"


def build_cipher(settings: Settings) -> CredentialCipher:
    """Construct the configured cipher, or raise if credential storage is unavailable."""
    provider = getattr(settings, "ai_credential_key_provider", "local")
    if provider == "local":
        master = getattr(settings, "ai_credential_master_key", None)
        if not master:
            raise CredentialStorageError(
                "AI credential storage is disabled: set CCF_AI_CREDENTIAL_MASTER_KEY "
                "(local key provider) or configure a KMS key provider"
            )
        return CredentialCipher(LocalKeyProvider(master))
    # aws_kms / azure_kv / gcp_sm / vault providers plug in here.
    raise CredentialStorageError(
        f"AI credential key provider '{provider}' is not implemented yet"
    )
