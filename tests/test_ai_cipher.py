"""Unit tests for envelope-encrypted AI credential storage (no DB)."""

from __future__ import annotations

import base64

import pytest

from ccf.ai.cipher import (
    CredentialCipher,
    CredentialStorageError,
    LocalKeyProvider,
    PayloadAuthenticationError,
    UnknownKeyError,
    build_cipher,
    mask,
)


def _cipher() -> CredentialCipher:
    return CredentialCipher(LocalKeyProvider("a-strong-master-key-32-bytes-long!"))


def test_round_trip() -> None:
    c = _cipher()
    secret = "sk-ant-api03-abcdef0123456789"
    token = c.encrypt(secret)
    assert token != secret
    assert secret not in token  # plaintext not present in the token
    assert c.decrypt(token) == secret


def test_ciphertext_is_nondeterministic() -> None:
    c = _cipher()
    assert c.encrypt("same-secret") != c.encrypt("same-secret")  # random DEK + nonce


def test_tamper_is_detected() -> None:
    c = _cipher()
    token = c.encrypt("secret-value")
    raw = bytearray(base64.urlsafe_b64decode(token))
    raw[-1] ^= 0x01  # flip a ciphertext bit
    tampered = base64.urlsafe_b64encode(bytes(raw)).decode()
    # The AES-GCM tag still rejects it; the exception is now Concord's own
    # subclass rather than the library's `InvalidTag`, so the API routes that
    # already catch `CredentialStorageError` return a clean error instead of a
    # 500 from an uncaught cryptography exception. Nothing in `src` caught
    # `InvalidTag`.
    with pytest.raises(PayloadAuthenticationError):
        c.decrypt(tampered)


def test_wrong_master_key_cannot_decrypt() -> None:
    """Now refused before any decrypt is attempted.

    A stored value names the key that wrapped it, so a provider without that
    key says so by key id rather than failing an authentication tag. The
    guarantee the test exists for -- a wrong key cannot read the value -- is
    unchanged and the failure is now diagnosable.
    """
    token = _cipher().encrypt("secret-value")
    other = CredentialCipher(LocalKeyProvider("a-different-master-key-32-chars!!"))
    with pytest.raises(UnknownKeyError):
        other.decrypt(token)


def test_mask_shows_only_last4() -> None:
    assert mask("sk-ant-1234567890") == "…7890"
    assert mask("") == ""


def test_weak_master_key_rejected() -> None:
    with pytest.raises(CredentialStorageError):
        LocalKeyProvider("short")


def test_build_cipher_fails_closed_without_key() -> None:
    class S:
        ai_credential_key_provider = "local"
        ai_credential_master_key = None

    with pytest.raises(CredentialStorageError):
        build_cipher(S())


def test_build_cipher_unimplemented_provider() -> None:
    class S:
        ai_credential_key_provider = "aws_kms"
        ai_credential_master_key = None

    with pytest.raises(CredentialStorageError):
        build_cipher(S())
