"""Envelope encryption for organization-scoped AI credentials.

Credentials are never stored in plaintext. Each secret is encrypted with a random
per-secret data-encryption key (DEK); the DEK is wrapped by a pluggable
:class:`KeyProvider` (the key-encryption key, KEK). Today the KEK is a local master
key from configuration; :class:`KeyProvider` is the seam where AWS KMS, Azure Key
Vault, GCP Secret Manager, or Vault drop in later — the stored token format does not
change, so migrating the KEK does not require re-encrypting payloads schema-wide.

Token layout (url-safe base64 of):
    v2: 2 | key_id(8) | wrapped_len(2, big-endian) | wrapped_dek | nonce(12) | ciphertext
    v1: 1 |            wrapped_len(2, big-endian) | wrapped_dek | nonce(12) | ciphertext

**Version 1 is read forever and never written again.** It carries no key id, so
a v1 blob is decrypted by trying each configured key; AES-GCM authenticates, so
a wrong key fails the tag rather than returning plausible garbage. v1 also keeps
the original ``sha256(master_key)`` KEK derivation, because that is what wrapped
those rows -- re-deriving them with the current KDF would "fix" the weakness by
making the data unreadable. They move to v2, and to the stronger derivation,
when an operator rewraps them.

See ``docs/superpowers/specs/2026-09-23-key-rotation-design.md``.

Decryption is intended to run only inside the gateway. Only :func:`mask` output
(last 4 chars) is ever surfaced to callers, the API, the UI, or logs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, ClassVar

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    from ..config import Settings

_VERSION = 2
_LEGACY_VERSION = 1
_NONCE_LEN = 12
_DEK_LEN = 32  # AES-256
_KEY_ID_LEN = 8

#: Domain separator for the key identifier. A one-way function of the key, so a
#: blob's header identifies which key it needs without leaking that key.
_KEY_ID_LABEL = b"ccf-kek-id-v1"

#: PBKDF2 rather than HKDF: ``LocalKeyProvider`` accepts a 16-character value,
#: so the input may well be a passphrase, and stretching is the entire point.
#: HKDF assumes its input is already high-entropy, which this one is not.
_KDF_ROUNDS = 600_000

#: A KEK has to be re-derivable from configuration alone, and there is nowhere
#: to persist a random salt that is not itself the thing being protected. A
#: fixed salt is weaker than a per-deployment one; that is the accepted cost of
#: a derivable key, and the round count carries the defence.
_KDF_SALT = b"ccf-kek-pbkdf2-v1"

#: Derivation is cached by key id. ``build_cipher`` constructs a provider per
#: call, and 600,000 rounds on every decrypt would turn signing in into a
#: denial-of-service surface a caller controls for free.
_KEK_CACHE: dict[str, bytes] = {}

#: Counts derivations that actually ran, so a test can assert the cache works
#: without timing anything. A dict rather than an int so incrementing it needs
#: no ``global``.
_STATS: dict[str, int] = {"derivations": 0}


def derivation_count() -> int:
    """How many KEK derivations have actually run this process."""
    return _STATS["derivations"]


def reset_key_cache() -> None:
    """Drop cached KEKs. For tests that change the configured keys."""
    _KEK_CACHE.clear()
    _STATS["derivations"] = 0


def key_id(master_key: str) -> str:
    """A stable, non-reversible identifier for a master key."""
    return hmac.new(
        master_key.encode("utf-8"), _KEY_ID_LABEL, hashlib.sha256
    ).hexdigest()[: _KEY_ID_LEN * 2]


def _derive_kek(master_key: str) -> bytes:
    """The v2 key-encryption key, cached by key id."""
    kid = key_id(master_key)
    cached = _KEK_CACHE.get(kid)
    if cached is not None:
        return cached
    _STATS["derivations"] += 1
    kek = hashlib.pbkdf2_hmac("sha256", master_key.encode("utf-8"), _KDF_SALT, _KDF_ROUNDS)
    _KEK_CACHE[kid] = kek
    return kek


def _legacy_kek(master_key: str) -> bytes:
    """What v1 rows were actually wrapped with. Never used for new writes."""
    return hashlib.sha256(master_key.encode("utf-8")).digest()


class CredentialStorageError(RuntimeError):
    """Raised when no key provider is configured — fail closed, never store plaintext."""


class PayloadAuthenticationError(CredentialStorageError):
    """The key was right and the ciphertext did not authenticate.

    Raised for BOTH tampering and a context mismatch, because at this point the
    two are indistinguishable: AES-GCM reports one tag failure either way.

    A ``CredentialStorageError`` subclass rather than the library's
    ``InvalidTag`` so the API routes that already catch the former return a
    clean error rather than a 500 from an uncaught cryptography exception.
    Nothing in ``src`` caught ``InvalidTag``.
    """


class KmsUnavailableError(CredentialStorageError):
    """KMS refused or could not be reached, and this code cannot tell which.

    Throttling, a network failure, an access denial, a disabled key and a
    genuinely foreign ciphertext all arrive here as one exception. Naming one
    of them -- and prescribing a setting the KMS provider does not read --
    would assert something this code has not established, and would send an
    operator to fix a key that was never the problem.

    Distinguishing a throttle from an access denial means reading botocore
    error codes, which is a real improvement and a separate change. What is
    fixed here is the false claim.
    """

    def __init__(self, kid: str | None, cause: Exception) -> None:
        self.key_id = kid
        self.cause = cause
        named = f" (key {kid})" if kid else ""
        super().__init__(
            f"AWS KMS could not decrypt this value{named}: {type(cause).__name__}: "
            f"{cause}. This may be throttling, a network failure, a permission "
            "or key-state problem, or a ciphertext this KMS key did not wrap -- "
            "KMS does not distinguish them here. Retry before concluding the "
            "key is wrong."
        )


class UnknownKeyError(CredentialStorageError):
    """This blob needs a key this deployment does not have configured.

    Distinct from its parent on purpose. "No key is configured" and "this row
    needs key ``a1b2c3…``, which is not configured" are different operator
    problems with different fixes, and they used to surface as the same
    exception carrying the same nothing. ``missing_key_id`` is the value an
    operator puts back into the predecessor list.
    """

    def __init__(self, missing_key_id: str | None) -> None:
        self.missing_key_id = missing_key_id
        if missing_key_id:
            super().__init__(
                f"this value was encrypted with key {missing_key_id}, which is not "
                "configured; add it to ai_credential_previous_keys to read it"
            )
        else:
            super().__init__(
                "this value could not be decrypted with any configured key"
            )


class KeyProvider(ABC):
    """Wraps/unwraps a data-encryption key with a key-encryption key (KEK)."""

    @abstractmethod
    def generate_data_key(self) -> tuple[bytes, bytes]:
        """Return ``(plaintext_dek, wrapped_dek)``."""

    @abstractmethod
    def unwrap_data_key(self, wrapped_dek: bytes, *, kid: str | None = None) -> bytes:
        """Return the plaintext DEK for a previously wrapped DEK.

        ``kid`` names the key that wrapped it, or is ``None`` for a version-1
        blob, which recorded none.
        """


class LocalKeyProvider(KeyProvider):
    """KEKs derived from configured master secrets; wraps DEKs with AES-256-GCM.

    Holds **one current key and any number of predecessors**. New writes always
    use the current key; a read finds the key the blob names. That pair is what
    makes the master secret rotatable at all: before this, changing it orphaned
    every stored value with an AES-GCM tag failure that named nothing.

    Swap this class for a KMS-backed provider without changing the stored token
    format.
    """

    def __init__(self, master_key: str, *, previous_keys: Sequence[str] = ()) -> None:
        if not master_key or len(master_key) < 16:
            raise CredentialStorageError(
                "ai_credential_master_key must be set to a strong value (>=16 chars) "
                "to store AI credentials"
            )
        self._current = master_key
        # Deduplicated, current first: a predecessor list that still contains the
        # current key is an ordinary state mid-rotation, not an error.
        seen = {key_id(master_key)}
        self._all: list[str] = [master_key]
        for key in previous_keys:
            if key and key_id(key) not in seen:
                seen.add(key_id(key))
                self._all.append(key)

    @property
    def current_key_id(self) -> str:
        return key_id(self._current)

    def generate_data_key(self) -> tuple[bytes, bytes]:
        """Always the current key. Rotation is a write-forward operation."""
        kek = _derive_kek(self._current)
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(_NONCE_LEN)
        wrapped = nonce + AESGCM(kek).encrypt(nonce, dek, b"ccf-dek")
        return dek, wrapped

    def unwrap_data_key(self, wrapped_dek: bytes, *, kid: str | None = None) -> bytes:
        """Unwrap with the named key, or -- for a v1 blob -- with whichever works.

        ``kid`` is ``None`` only for version-1 blobs, which record no key id.
        Trying each key in turn is safe rather than sloppy: AES-GCM
        authenticates, so a wrong key fails the tag instead of returning
        plausible garbage.
        """
        nonce, blob = wrapped_dek[:_NONCE_LEN], wrapped_dek[_NONCE_LEN:]
        if kid is not None:
            match = next((k for k in self._all if key_id(k) == kid), None)
            if match is None:
                raise UnknownKeyError(kid)
            return AESGCM(_derive_kek(match)).decrypt(nonce, blob, b"ccf-dek")

        for key in self._all:
            # v1 rows were wrapped with the original sha256 derivation, so that
            # is what reads them. Re-deriving with the current KDF would "fix"
            # the weakness by making the data unreadable.
            for kek in (_legacy_kek(key), _derive_kek(key)):
                try:
                    return AESGCM(kek).decrypt(nonce, blob, b"ccf-dek")
                except Exception:
                    continue
        raise UnknownKeyError(None)


#: Default associated data. Kept as the literal the first release wrote so
#: every credential already in a database still decrypts.
AAD_CREDENTIAL = b"ccf-cred"

#: TOTP shared secrets. A distinct context so a ciphertext lifted from the
#: credential store does not decrypt as an authenticator secret, or the
#: reverse: AES-GCM authenticates this value, so getting it wrong fails the
#: tag rather than returning the wrong plaintext.
AAD_MFA = b"ccf-mfa"


class KmsKeyProvider(KeyProvider):
    """KEK held by AWS KMS. The key material never enters this process.

    This is what the ``KeyProvider`` abstraction was written for, and the
    reason the local provider's rotation work came first: the envelope format
    already records a key id, so moving a deployment from the local provider to
    this one is the same ``ccf keys-rewrap`` sweep as any other rotation.

    **Rotation of the KMS key itself is KMS's job**, not this class's. A KMS key
    with automatic rotation enabled re-wraps under new material while
    ``Decrypt`` keeps reading old ciphertext, and nothing here has to know. The
    key id below identifies *which KMS key was configured*, so a deployment
    moving between two distinct KMS keys still gets a rewrap it can verify.

    ``EncryptionContext`` is KMS's associated data. It binds a wrapped data key
    to this application, so a ciphertext lifted from another system that shares
    the KMS key does not unwrap here.
    """

    #: Mirrors the local provider's AAD on the wrap operation.
    ENCRYPTION_CONTEXT: ClassVar[dict[str, str]] = {"application": "concord", "purpose": "dek"}

    def __init__(self, kms_key_id: str, *, region: str | None = None, client: Any = None) -> None:
        if not kms_key_id:
            raise CredentialStorageError(
                "ai_credential_kms_key_id must be set to use the aws_kms key provider"
            )
        self._kms_key_id = kms_key_id
        self._region = region
        self._client = client

    @property
    def current_key_id(self) -> str:
        """Derived from the configured KMS key identifier, same shape as local.

        A one-way function of the ARN rather than the ARN itself: the envelope
        header is stored beside the ciphertext and an account id is not a thing
        to write into every row.
        """
        return hmac.new(
            self._kms_key_id.encode("utf-8"), _KEY_ID_LABEL, hashlib.sha256
        ).hexdigest()[: _KEY_ID_LEN * 2]

    def _kms(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3  # noqa: PLC0415
        except ImportError as e:  # pragma: no cover - depends on the install extra
            raise CredentialStorageError(
                "the aws_kms key provider needs boto3; install the aws extra"
            ) from e
        self._client = boto3.client("kms", region_name=self._region)
        return self._client

    def generate_data_key(self) -> tuple[bytes, bytes]:
        resp = self._kms().generate_data_key(
            KeyId=self._kms_key_id,
            KeySpec="AES_256",
            EncryptionContext=self.ENCRYPTION_CONTEXT,
        )
        return resp["Plaintext"], resp["CiphertextBlob"]

    def unwrap_data_key(self, wrapped_dek: bytes, *, kid: str | None = None) -> bytes:
        """``kid`` is informational here: KMS resolves the key from the blob.

        A blob wrapped by a KMS key this caller is not permitted to use fails at
        KMS with an access error rather than silently returning the wrong thing,
        which is the same fail-closed direction as the local provider.
        """
        try:
            resp = self._kms().decrypt(
                CiphertextBlob=wrapped_dek,
                EncryptionContext=self.ENCRYPTION_CONTEXT,
            )
        except Exception as e:
            # NOT UnknownKeyError. That error names one cause and prescribes
            # `ai_credential_previous_keys`, which this provider never reads --
            # so a throttle, a network blip, an access denial or a disabled key
            # all produced "add it to ai_credential_previous_keys to read it",
            # telling an operator a rotation failed on a missing key when the
            # key was fine and a retry would have worked.
            #
            # KMS resolves the key from the blob itself, so this provider
            # cannot distinguish "wrong key" from "KMS said no". It says what
            # it knows and carries the underlying error, exactly as
            # PayloadAuthenticationError does for the ambiguity one layer down.
            raise KmsUnavailableError(kid, e) from e
        return bytes(resp["Plaintext"])


class CredentialCipher:
    """Envelope-encrypts/decrypts strings via a :class:`KeyProvider`.

    ``aad`` names what the ciphertext is *for*. Two stores sharing one key and
    one context are two stores whose values are interchangeable, which is the
    same class of confusion ``_portal_secret`` exists to prevent one layer up.
    """

    def __init__(self, key_provider: KeyProvider, *, aad: bytes = AAD_CREDENTIAL) -> None:
        self._kp = key_provider
        self._aad = aad

    @property
    def current_key_id(self) -> str | None:
        """The key new writes use, for status output and rewrap decisions."""
        kid = getattr(self._kp, "current_key_id", None)
        return str(kid) if kid is not None else None

    def encrypt(self, plaintext: str) -> str:
        """Always writes version 2, always under the current key."""
        dek, wrapped = self._kp.generate_data_key()
        nonce = os.urandom(_NONCE_LEN)
        ct = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), self._aad)
        kid = self.current_key_id or "0" * (_KEY_ID_LEN * 2)
        blob = (
            bytes([_VERSION])
            + bytes.fromhex(kid)
            + len(wrapped).to_bytes(2, "big")
            + wrapped
            + nonce
            + ct
        )
        return base64.urlsafe_b64encode(blob).decode("ascii")

    def decrypt(self, token: str) -> str:
        kid, wrapped, nonce, ct = _parse(token)
        dek = self._kp.unwrap_data_key(wrapped, kid=kid)
        try:
            return AESGCM(dek).decrypt(nonce, ct, self._aad).decode("utf-8")
        except Exception as e:
            # What is known: the DEK unwrapped, so the key-encryption key was
            # right, and the payload then failed its authentication tag. Two
            # causes produce that and nothing here can tell them apart -- the
            # wrong `aad` (a value read against a store it does not belong to)
            # or ciphertext that has been modified. Naming one would assert
            # something this code has not established.
            raise PayloadAuthenticationError(
                "the data key unwrapped but the payload did not authenticate: "
                "either this value belongs to a different store, or the stored "
                "bytes have been modified"
            ) from e

    def needs_rewrap(self, token: str) -> bool:
        """Whether this value is not already under the current key, at version 2."""
        kid, _wrapped, _nonce, _ct = _parse(token)
        return kid != self.current_key_id

    def rewrap(self, token: str) -> str:
        """Decrypt under whichever key holds it, re-encrypt under the current one.

        Deliberately NOT called from any read path. A read that writes can fail,
        deadlock, or run inside a transaction that then rolls back -- leaving an
        operator believing a rotation finished. And lazy rewrapping makes "is
        rotation done?" unanswerable, because what remains is whichever rows
        nobody happened to read.
        """
        return self.encrypt(self.decrypt(token))


def _parse(token: str) -> tuple[str | None, bytes, bytes, bytes]:
    """Split a stored token into ``(key_id, wrapped_dek, nonce, ciphertext)``.

    ``key_id`` is ``None`` for a version-1 blob, which recorded none.
    """
    blob = base64.urlsafe_b64decode(token.encode("ascii"))
    if not blob:
        raise ValueError("empty credential token")
    version = blob[0]
    if version == _VERSION:
        kid: str | None = blob[1 : 1 + _KEY_ID_LEN].hex()
        off = 1 + _KEY_ID_LEN
    elif version == _LEGACY_VERSION:
        kid = None
        off = 1
    else:
        raise ValueError(f"unsupported credential token version {version}")
    wl = int.from_bytes(blob[off : off + 2], "big")
    off += 2
    wrapped = blob[off : off + wl]
    off += wl
    nonce = blob[off : off + _NONCE_LEN]
    off += _NONCE_LEN
    return kid, wrapped, nonce, blob[off:]


def token_key_id(token: str) -> str | None:
    """The key a stored value needs, or ``None`` if it predates key ids."""
    return _parse(token)[0]


def mask(secret: str) -> str:
    """Return a non-reversible display identifier (last 4 chars) for a secret."""
    if not secret:
        return ""
    tail = secret[-4:]
    return f"…{tail}"


def build_cipher(settings: Settings, *, aad: bytes = AAD_CREDENTIAL) -> CredentialCipher:
    """Construct the configured cipher, or raise if credential storage is unavailable."""
    provider = getattr(settings, "ai_credential_key_provider", "local")
    if provider == "local":
        master = getattr(settings, "ai_credential_master_key", None)
        if not master:
            raise CredentialStorageError(
                "AI credential storage is disabled: set CCF_AI_CREDENTIAL_MASTER_KEY "
                "(local key provider) or configure a KMS key provider"
            )
        previous = getattr(settings, "ai_credential_previous_keys", None) or []
        return CredentialCipher(LocalKeyProvider(master, previous_keys=previous), aad=aad)
    if provider == "aws_kms":
        return CredentialCipher(
            KmsKeyProvider(
                getattr(settings, "ai_credential_kms_key_id", None) or "",
                region=getattr(settings, "ai_credential_kms_region", None),
            ),
            aad=aad,
        )
    # azure_kv / gcp_sm / vault plug in here, the same way.
    raise CredentialStorageError(
        f"AI credential key provider '{provider}' is not implemented yet"
    )
