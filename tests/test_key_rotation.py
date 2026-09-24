"""Rotating the credential master key without orphaning stored secrets.

Spec: ``docs/superpowers/specs/2026-09-23-key-rotation-design.md`` §6.

The test that carries the most weight is
``test_a_version_one_blob_written_by_the_old_code_still_decrypts``. It builds a
blob byte by byte with the ORIGINAL format and the ORIGINAL ``sha256``
derivation rather than calling the new ``encrypt`` -- a round trip through the
new code would agree with itself while saying nothing at all about the rows
already sitting in a customer's database.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select

from ccf.ai import cipher as cipher_mod
from ccf.ai.cipher import (
    AAD_CREDENTIAL,
    AAD_MFA,
    CredentialCipher,
    CredentialStorageError,
    LocalKeyProvider,
    UnknownKeyError,
    build_cipher,
    key_id,
    token_key_id,
)
from ccf.ai.rotation import ENCRYPTED_COLUMNS, rewrap_all
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, User
from ccf.models_identity import UserMfaCredential

pytestmark = pytest.mark.usefixtures("fresh_engine")

KEY_A = "key-a-aaaaaaaaaaaaaaaaaaaaaaaaaaa"
KEY_B = "key-b-bbbbbbbbbbbbbbbbbbbbbbbbbbb"
KEY_C = "key-c-ccccccccccccccccccccccccccc"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch):
    """Set the current key and its predecessors, clearing the derivation cache."""

    def apply(current: str, previous: list[str] | None = None) -> None:
        monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", current)
        if previous:
            # pydantic-settings parses a list field from JSON.
            monkeypatch.setenv("CCF_AI_CREDENTIAL_PREVIOUS_KEYS", json.dumps(previous))
        else:
            monkeypatch.delenv("CCF_AI_CREDENTIAL_PREVIOUS_KEYS", raising=False)
        get_settings.cache_clear()

    cipher_mod.reset_key_cache()
    yield apply
    cipher_mod.reset_key_cache()
    get_settings.cache_clear()


# ── §6.1 the round trip still works ─────────────────────────────────────────


@pytest.mark.parametrize("aad", [AAD_CREDENTIAL, AAD_MFA])
def test_a_value_round_trips_under_one_key(keys, aad: bytes) -> None:
    keys(KEY_A)
    c = build_cipher(get_settings(), aad=aad)
    assert c.decrypt(c.encrypt("s3cret-value")) == "s3cret-value"


def test_a_value_does_not_cross_between_the_two_stores(keys) -> None:
    """The contexts are what stop a credential ciphertext being readable as an
    authenticator secret. Same key, different store, must not decrypt."""
    keys(KEY_A)
    token = build_cipher(get_settings(), aad=AAD_CREDENTIAL).encrypt("not-a-totp-secret")
    with pytest.raises(CredentialStorageError):
        build_cipher(get_settings(), aad=AAD_MFA).decrypt(token)


# ── §6.2 the one that is about real customer data ───────────────────────────


def _version_one_blob(master_key: str, plaintext: str, aad: bytes) -> str:
    """A token in the ORIGINAL format, wrapped with the ORIGINAL derivation.

    Written out longhand on purpose. Producing this with the new ``encrypt``
    and asserting the new ``decrypt`` reads it would prove only that the code
    agrees with itself.
    """
    kek = hashlib.sha256(master_key.encode("utf-8")).digest()
    dek = AESGCM.generate_key(bit_length=256)
    wrap_nonce = os.urandom(12)
    wrapped = wrap_nonce + AESGCM(kek).encrypt(wrap_nonce, dek, b"ccf-dek")
    nonce = os.urandom(12)
    ct = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), aad)
    blob = bytes([1]) + len(wrapped).to_bytes(2, "big") + wrapped + nonce + ct
    return base64.urlsafe_b64encode(blob).decode("ascii")


def test_a_version_one_blob_written_by_the_old_code_still_decrypts(keys) -> None:
    keys(KEY_A)
    legacy = _version_one_blob(KEY_A, "written-before-rotation", AAD_CREDENTIAL)
    assert token_key_id(legacy) is None
    assert build_cipher(get_settings()).decrypt(legacy) == "written-before-rotation"


def test_a_version_one_blob_is_readable_under_a_predecessor_key(keys) -> None:
    """v1 rows name no key, so every configured key is tried."""
    keys(KEY_B, previous=[KEY_A])
    legacy = _version_one_blob(KEY_A, "old-row", AAD_CREDENTIAL)
    assert build_cipher(get_settings()).decrypt(legacy) == "old-row"


def test_a_version_one_blob_with_no_matching_key_is_refused_not_guessed(keys) -> None:
    """AES-GCM authenticates, so a wrong key fails the tag. It must raise
    rather than return plausible garbage."""
    keys(KEY_B)
    legacy = _version_one_blob(KEY_A, "unreachable", AAD_CREDENTIAL)
    with pytest.raises(UnknownKeyError):
        build_cipher(get_settings()).decrypt(legacy)


# ── §6.3 / §6.4 rotation end to end ─────────────────────────────────────────


def test_rotation_keeps_values_readable_and_rewrapping_frees_the_old_key(keys) -> None:
    keys(KEY_A)
    token = build_cipher(get_settings()).encrypt("rotate-me")
    assert token_key_id(token) == key_id(KEY_A)

    # B becomes current, A becomes a predecessor. Nothing is re-entered.
    keys(KEY_B, previous=[KEY_A])
    c = build_cipher(get_settings())
    assert c.decrypt(token) == "rotate-me"
    assert c.needs_rewrap(token) is True

    moved = c.rewrap(token)
    assert token_key_id(moved) == key_id(KEY_B)

    # With A gone entirely the rewrapped value is still readable.
    keys(KEY_B)
    assert build_cipher(get_settings()).decrypt(moved) == "rotate-me"


def test_before_rewrapping_dropping_the_old_key_breaks_it_and_names_it(keys) -> None:
    """The negative that gives the test above its meaning, plus §4: the error
    has to say WHICH key to put back."""
    keys(KEY_A)
    token = build_cipher(get_settings()).encrypt("still-on-a")

    keys(KEY_B)  # A dropped too early
    with pytest.raises(UnknownKeyError) as caught:
        build_cipher(get_settings()).decrypt(token)
    assert caught.value.missing_key_id == key_id(KEY_A)
    assert key_id(KEY_A) in str(caught.value)


# ── §6.5 the key id identifies without leaking ──────────────────────────────


def test_the_key_id_is_stable_distinct_and_not_the_key(keys) -> None:
    assert key_id(KEY_A) == key_id(KEY_A)
    assert key_id(KEY_A) != key_id(KEY_B)
    keys(KEY_A)
    token = build_cipher(get_settings()).encrypt("x")
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    assert KEY_A.encode() not in raw
    assert hashlib.sha256(KEY_A.encode()).digest() not in raw


# ── §6.9 the derivation is cached ───────────────────────────────────────────


def test_the_key_derivation_is_cached_across_ciphers(keys) -> None:
    """600,000 PBKDF2 rounds on every decrypt would make signing in a
    denial-of-service surface. Counted, not timed."""
    keys(KEY_A)
    cipher_mod.reset_key_cache()
    build_cipher(get_settings()).encrypt("one")
    after_first = cipher_mod.derivation_count()
    assert after_first == 1

    for _ in range(5):
        build_cipher(get_settings()).encrypt("more")
    assert cipher_mod.derivation_count() == after_first


# ── §6.7 / §6.8 / §6.10 the sweep ───────────────────────────────────────────


async def _seed_mfa_row(token: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"Rot-{os.urandom(4).hex()}")
        s.add(org)
        await s.flush()
        user = User(
            organization_id=org.id, email=f"rot-{os.urandom(4).hex()}@k.test", active=True
        )
        s.add(user)
        await s.flush()
        cred = UserMfaCredential(
            organization_id=org.id, user_id=user.id, secret_encrypted=token
        )
        s.add(cred)
        await s.flush()
        return org.id, cred.id


@pytest.mark.asyncio
async def test_the_sweep_moves_a_row_and_is_idempotent(keys) -> None:
    keys(KEY_A)
    token = build_cipher(get_settings(), aad=AAD_MFA).encrypt("JBSWY3DPEHPK3PXP")
    _org_id, cred_id = await _seed_mfa_row(token)

    keys(KEY_B, previous=[KEY_A])
    async with session_scope() as s:
        report = await rewrap_all(s)
    # Not `report.ok`: other tests leave rows wrapped under keys this one never
    # configures, and a global assertion would fail on their account.
    assert not any(row_id == cred_id for _t, row_id, _k in report.unreadable)
    assert report.rewrapped >= 1

    async with session_scope() as s:
        cred = await s.get(UserMfaCredential, cred_id)
        assert cred is not None
        assert token_key_id(cred.secret_encrypted) == key_id(KEY_B)
        assert (
            build_cipher(get_settings(), aad=AAD_MFA).decrypt(cred.secret_encrypted)
            == "JBSWY3DPEHPK3PXP"
        )

    # Second sweep moves nothing.
    async with session_scope() as s:
        again = await rewrap_all(s)
    assert again.rewrapped == 0
    assert again.already_current >= 1


@pytest.mark.asyncio
async def test_a_row_whose_key_is_unknown_is_reported_and_left_alone(keys) -> None:
    """§3.1. An operator who dropped a predecessor too early needs the key id,
    and the row must still be there to rescue once they put it back."""
    keys(KEY_C)
    orphan = build_cipher(get_settings(), aad=AAD_MFA).encrypt("ORPHANSECRET")
    _org_id, cred_id = await _seed_mfa_row(orphan)

    keys(KEY_A)  # C is not configured at all
    async with session_scope() as s:
        report = await rewrap_all(s)

    assert not report.ok
    assert any(
        table == "user_mfa_credentials" and row_id == cred_id and kid == key_id(KEY_C)
        for table, row_id, kid in report.unreadable
    ), report.unreadable

    async with session_scope() as s:
        cred = await s.get(UserMfaCredential, cred_id)
        assert cred is not None
        assert cred.secret_encrypted == orphan, "the unreadable row was modified"

    # And it is recoverable once the key comes back. Asserted on THIS row, not
    # on `rescued.ok`: the sweep covers every row in a shared database, so a
    # global assertion here would depend on what other tests happen to have
    # left wrapped under keys this test never configured.
    keys(KEY_A, previous=[KEY_C])
    async with session_scope() as s:
        rescued = await rewrap_all(s)
    assert not any(row_id == cred_id for _t, row_id, _k in rescued.unreadable), (
        f"row {cred_id} still unreadable after its key was restored: {rescued.unreadable}"
    )

    async with session_scope() as s:
        cred = await s.get(UserMfaCredential, cred_id)
        assert cred is not None
        assert token_key_id(cred.secret_encrypted) == key_id(KEY_A)
        assert (
            build_cipher(get_settings(), aad=AAD_MFA).decrypt(cred.secret_encrypted)
            == "ORPHANSECRET"
        )


def test_every_encrypted_column_in_the_schema_is_in_the_sweep() -> None:
    """A fourth encrypted column added later and not listed would be silently
    left behind on an old key. Derived from the models, not from a hand-list."""
    import ccf.models  # noqa: PLC0415, F401
    from ccf.models import Base  # noqa: PLC0415

    found = {
        (mapper.class_.__name__, column.key)
        for mapper in Base.registry.mappers
        for column in mapper.columns
        if "encrypted" in column.key
    }
    swept = {(spec.model.__name__, spec.column) for spec in ENCRYPTED_COLUMNS}
    assert found == swept, (
        f"encrypted columns not covered by the rotation sweep: {sorted(found - swept)}"
    )


@pytest.mark.asyncio
async def test_the_sweep_reads_the_stores_it_claims_to(keys) -> None:
    """Each listed model must actually be queryable — a typo in the list would
    otherwise make a store silently contribute nothing."""
    keys(KEY_A)
    async with session_scope() as s:
        for spec in ENCRYPTED_COLUMNS:
            await s.execute(select(spec.model).limit(1))
            assert hasattr(spec.model, spec.column), f"{spec.label}.{spec.column} missing"


def test_a_local_provider_deduplicates_the_current_key_from_its_predecessors() -> None:
    """Leaving the new key in the predecessor list mid-rotation is ordinary."""
    provider = LocalKeyProvider(KEY_A, previous_keys=[KEY_A, KEY_B, KEY_B])
    c = CredentialCipher(provider)
    assert c.decrypt(c.encrypt("fine")) == "fine"


# ── the KMS provider ────────────────────────────────────────────────────────


class _FakeKms:
    """Enough of the KMS API to exercise the provider, with the AWS semantics
    that matter: the encryption context must match on decrypt, and a blob this
    key did not wrap is an error rather than wrong plaintext."""

    def __init__(self, key_arn: str = "arn:aws:kms:us-gov-west-1:1:key/abc") -> None:
        self.key_arn = key_arn
        self._wrapped: dict[bytes, tuple[bytes, dict[str, str]]] = {}
        self.generate_calls = 0
        self.decrypt_calls = 0

    def generate_data_key(self, *, KeyId: str, KeySpec: str, EncryptionContext: dict) -> dict:  # noqa: N803
        assert KeySpec == "AES_256"
        assert KeyId == self.key_arn
        self.generate_calls += 1
        plaintext = os.urandom(32)
        blob = b"blob-" + os.urandom(8)
        self._wrapped[blob] = (plaintext, dict(EncryptionContext))
        return {"Plaintext": plaintext, "CiphertextBlob": blob}

    def decrypt(self, *, CiphertextBlob: bytes, EncryptionContext: dict) -> dict:  # noqa: N803
        self.decrypt_calls += 1
        entry = self._wrapped.get(bytes(CiphertextBlob))
        if entry is None:
            raise RuntimeError("InvalidCiphertextException")
        plaintext, context = entry
        if context != EncryptionContext:
            raise RuntimeError("InvalidCiphertextException: encryption context mismatch")
        return {"Plaintext": plaintext}


def _kms_cipher(kms: _FakeKms, *, aad: bytes = AAD_CREDENTIAL) -> CredentialCipher:
    from ccf.ai.cipher import KmsKeyProvider  # noqa: PLC0415

    return CredentialCipher(KmsKeyProvider(kms.key_arn, client=kms), aad=aad)


def test_the_kms_provider_round_trips_without_holding_key_material() -> None:
    kms = _FakeKms()
    c = _kms_cipher(kms)
    token = c.decrypt(c.encrypt("kms-secret"))
    assert token == "kms-secret"
    assert kms.generate_calls == 1
    assert kms.decrypt_calls == 1


def test_the_kms_provider_binds_an_encryption_context() -> None:
    """KMS's associated data. Without it, a wrapped key lifted from another
    system sharing the KMS key would unwrap here."""
    from ccf.ai.cipher import KmsKeyProvider  # noqa: PLC0415

    kms = _FakeKms()
    provider = KmsKeyProvider(kms.key_arn, client=kms)
    _plain, blob = provider.generate_data_key()

    # The same blob under a different context is refused by KMS itself, which
    # raises its own error -- the provider is not involved at this level.
    with pytest.raises(RuntimeError, match="encryption context"):
        kms.decrypt(CiphertextBlob=blob, EncryptionContext={"application": "something-else"})

    # And the provider maps that AWS-side refusal onto Concord's own error, so
    # a caller sees the same failure whichever provider is configured.
    provider.ENCRYPTION_CONTEXT = {"application": "tampered"}  # type: ignore[misc]
    with pytest.raises(UnknownKeyError):
        provider.unwrap_data_key(blob)

    # The context the provider actually sends is the one that works.
    assert KmsKeyProvider(kms.key_arn, client=kms).unwrap_data_key(blob) == _plain


def test_a_blob_the_kms_key_did_not_wrap_is_refused_not_guessed() -> None:
    from ccf.ai.cipher import KmsKeyProvider  # noqa: PLC0415

    provider = KmsKeyProvider("arn:aws:kms:us-gov-west-1:1:key/abc", client=_FakeKms())
    with pytest.raises(UnknownKeyError):
        provider.unwrap_data_key(b"not-a-blob-this-key-made")


def test_the_kms_key_id_identifies_the_configured_key_without_printing_it() -> None:
    """The envelope header sits beside every row; an account id is not a thing
    to write into all of them."""
    from ccf.ai.cipher import KmsKeyProvider  # noqa: PLC0415

    arn = "arn:aws:kms:us-gov-west-1:123456789012:key/abc"
    provider = KmsKeyProvider(arn, client=_FakeKms(arn))
    kid = provider.current_key_id
    assert len(kid) == 16
    assert "123456789012" not in kid
    assert KmsKeyProvider(arn, client=_FakeKms(arn)).current_key_id == kid
    other = "arn:aws:kms:us-gov-west-1:123456789012:key/def"
    assert KmsKeyProvider(other, client=_FakeKms(other)).current_key_id != kid


def test_moving_from_the_local_provider_to_kms_is_an_ordinary_rewrap(keys) -> None:
    """The point of doing the local provider's rotation first: the envelope
    already records a key id, so switching providers is the same sweep."""
    keys(KEY_A)
    local_token = build_cipher(get_settings()).encrypt("migrate-me")
    assert token_key_id(local_token) == key_id(KEY_A)

    kms = _FakeKms()
    kms_cipher = _kms_cipher(kms)
    # Decrypt with the local cipher, encrypt with KMS -- exactly what the sweep
    # does, minus the database.
    moved = kms_cipher.encrypt(build_cipher(get_settings()).decrypt(local_token))
    assert kms_cipher.decrypt(moved) == "migrate-me"
    assert token_key_id(moved) != token_key_id(local_token)


def test_the_kms_provider_refuses_to_start_without_a_key_id() -> None:
    from ccf.ai.cipher import KmsKeyProvider  # noqa: PLC0415

    with pytest.raises(CredentialStorageError):
        KmsKeyProvider("")


def test_build_cipher_wires_the_aws_kms_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Previously this raised 'not implemented yet'."""
    from ccf.ai.cipher import KmsKeyProvider  # noqa: PLC0415

    monkeypatch.setenv("CCF_AI_CREDENTIAL_KEY_PROVIDER", "aws_kms")
    monkeypatch.setenv("CCF_AI_CREDENTIAL_KMS_KEY_ID", "arn:aws:kms:us-gov-west-1:1:key/abc")
    get_settings.cache_clear()
    try:
        c = build_cipher(get_settings())
        assert isinstance(c._kp, KmsKeyProvider)
    finally:
        get_settings.cache_clear()


def test_an_mfa_secret_written_before_the_format_change_still_decrypts(keys) -> None:
    """A seam between two changes made a day apart.

    The authenticator store shipped while ``encrypt`` wrote version 1; the
    rotation work moved new writes to version 2. Any secret enrolled in between
    is a v1 blob **in the MFA context**, and every v1 test above uses the
    credential context. If the legacy path were context-blind, a user's
    authenticator would stop working the day the deployment upgraded -- and
    they would be locked out of their own account by a format change.
    """
    keys(KEY_A)
    legacy = _version_one_blob(KEY_A, "JBSWY3DPEHPK3PXP", AAD_MFA)
    assert token_key_id(legacy) is None
    assert build_cipher(get_settings(), aad=AAD_MFA).decrypt(legacy) == "JBSWY3DPEHPK3PXP"


def test_a_version_one_mfa_secret_does_not_decrypt_in_the_credential_store(keys) -> None:
    """And the contexts still separate at version 1, not only at version 2."""
    keys(KEY_A)
    legacy = _version_one_blob(KEY_A, "JBSWY3DPEHPK3PXP", AAD_MFA)
    with pytest.raises(CredentialStorageError):
        build_cipher(get_settings(), aad=AAD_CREDENTIAL).decrypt(legacy)


@pytest.mark.asyncio
async def test_the_sweep_moves_a_version_one_mfa_secret_to_the_current_key(keys) -> None:
    """The upgrade path for that same user, end to end."""
    keys(KEY_A)
    legacy = _version_one_blob(KEY_A, "OLDENROLMENT2345", AAD_MFA)
    _org_id, cred_id = await _seed_mfa_row(legacy)

    keys(KEY_B, previous=[KEY_A])
    async with session_scope() as s:
        report = await rewrap_all(s)
    assert not any(row_id == cred_id for _t, row_id, _k in report.unreadable), report.unreadable

    async with session_scope() as s:
        cred = await s.get(UserMfaCredential, cred_id)
        assert cred is not None
        assert token_key_id(cred.secret_encrypted) == key_id(KEY_B)
        assert (
            build_cipher(get_settings(), aad=AAD_MFA).decrypt(cred.secret_encrypted)
            == "OLDENROLMENT2345"
        )
