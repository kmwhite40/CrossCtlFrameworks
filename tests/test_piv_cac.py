"""PIV / CAC sign-in.

Spec: ``docs/superpowers/specs/2026-09-24-piv-cac-design.md`` §6.

Certificates here are **built**, not pasted. A hand-written PEM fixture would
pin whatever the author believed the encoding was; generating one with
``cryptography`` means the parser is exercised against a real DER
``otherName``, which is the part that is easy to get wrong.
"""

from __future__ import annotations

import datetime as dt
import itertools

import pytest
from alembic import command
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.auth_deps import SESSION_COOKIE
from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.identity import piv
from ccf.models import Organization, User
from ccf.models_identity import ExternalIdentity

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
TRUSTED = "10.0.0.0/8"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _der_utf8(value: str) -> bytes:
    """A DER UTF8String, the encoding a real UPN otherName carries."""
    raw = value.encode("utf-8")
    if len(raw) < 0x80:
        return bytes([0x0C, len(raw)]) + raw
    length = len(raw).to_bytes((len(raw).bit_length() + 7) // 8, "big")
    return bytes([0x0C, 0x80 | len(length)]) + length + raw


def _certificate(*, upn: str | None = None, email: str | None = None) -> str:
    """A self-signed certificate shaped like a PIV credential.

    Self-signed on purpose: this module never validates a chain, because the
    TLS terminator does that. What is under test is the identity extraction.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DOE.JOHN.Q.1234567890")])
    names: list[x509.GeneralName] = []
    if upn is not None:
        names.append(x509.OtherName(piv.UPN_OID, _der_utf8(upn)))
    if email is not None:
        names.append(x509.RFC822Name(email))

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=365))
    )
    if names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names), critical=False
        )
    cert = builder.sign(key, None)
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _client(peer: str = "10.1.2.3") -> AsyncClient:
    """A client whose *immediate* peer address is ``peer``.

    ASGI carries it in ``scope["client"]``, which is what ``request.client.host``
    reads -- the connection, not a header.
    """
    transport = ASGITransport(app=create_app(), client=(peer, 40000))
    return AsyncClient(transport=transport, base_url="http://t", follow_redirects=False)


@pytest.fixture
def piv_on(monkeypatch: pytest.MonkeyPatch):
    def apply(*, trusted: str | None = TRUSTED, enabled: bool = True) -> None:
        monkeypatch.setenv("CCF_PIV_ENABLED", "true" if enabled else "false")
        if trusted is None:
            monkeypatch.setenv("CCF_PIV_TRUSTED_PROXIES", "[]")
        else:
            monkeypatch.setenv("CCF_PIV_TRUSTED_PROXIES", f'["{trusted}"]')
        get_settings.cache_clear()

    apply()
    yield apply
    get_settings.cache_clear()


async def _linked_user(upn: str, *, active: bool = True) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"PIV Org {next(_SEQ)}")
        s.add(org)
        await s.flush()
        user = User(
            organization_id=org.id,
            email=f"piv-{next(_SEQ)}@piv.test",
            role="admin",
            active=active,
        )
        s.add(user)
        await s.flush()
        s.add(
            ExternalIdentity(
                organization_id=org.id, user_id=user.id, provider="piv", subject=upn
            )
        )
        await s.flush()
        return org.id, user.id


def _headers(pem: str, *, verify: str = "SUCCESS") -> dict[str, str]:
    return {"x-ssl-client-cert": pem, "x-ssl-client-verify": verify}


# ── §6.1 the failure this feature is arranged around ────────────────────────


@pytest.mark.asyncio
async def test_a_forged_header_from_an_untrusted_peer_authenticates_nobody(piv_on) -> None:
    """These are HTTP headers. If Concord trusts them from any source, anyone
    who reaches the app directly authenticates as anyone."""
    upn = f"forged-{next(_SEQ)}@mil"
    await _linked_user(upn)

    async with _client(peer="203.0.113.9") as c:  # outside 10.0.0.0/8
        resp = await c.get("/auth/piv", headers=_headers(_certificate(upn=upn)))

    assert resp.status_code == 404, resp.text
    # Not merely a non-303: assert no session was minted.
    assert SESSION_COOKIE not in resp.cookies


@pytest.mark.asyncio
async def test_x_forwarded_for_cannot_put_a_caller_inside_the_trusted_range(piv_on) -> None:
    """The peer is the connection, never a header -- which is forgeable by
    exactly the argument that makes the check necessary."""
    upn = f"xff-{next(_SEQ)}@mil"
    await _linked_user(upn)

    headers = _headers(_certificate(upn=upn))
    headers["x-forwarded-for"] = "10.1.2.3"
    async with _client(peer="203.0.113.9") as c:
        resp = await c.get("/auth/piv", headers=headers)

    assert resp.status_code == 404
    assert SESSION_COOKIE not in resp.cookies


@pytest.mark.asyncio
async def test_an_empty_trusted_list_refuses_to_enable(piv_on) -> None:
    """The permissive reading of "unset" is how this becomes a bypass."""
    piv_on(trusted=None)
    upn = f"empty-{next(_SEQ)}@mil"
    await _linked_user(upn)

    async with _client() as c:
        resp = await c.get("/auth/piv", headers=_headers(_certificate(upn=upn)))

    assert resp.status_code == 500
    assert "TRUSTED_PROXIES" in resp.text
    assert SESSION_COOKIE not in resp.cookies


@pytest.mark.asyncio
async def test_disabled_by_default_sends_the_caller_to_the_ordinary_login(piv_on) -> None:
    piv_on(enabled=False)
    async with _client() as c:
        resp = await c.get("/auth/piv", headers=_headers(_certificate(upn="x@mil")))
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


# ── §6.4 the terminator has to say it verified ──────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("verify", ["FAILED", "NONE", "", "success-ish"])
async def test_a_verify_header_that_is_not_success_is_refused(piv_on, verify: str) -> None:
    """``NONE`` and ``FAILED`` are both ordinary nginx values, and absent is
    what you get when the directive was never added."""
    upn = f"verify-{next(_SEQ)}@mil"
    await _linked_user(upn)

    async with _client() as c:
        resp = await c.get(
            "/auth/piv", headers=_headers(_certificate(upn=upn), verify=verify)
        )
    assert resp.status_code == 401
    assert SESSION_COOKIE not in resp.cookies


# ── §6.5 / §6.6 identity comes out of the SAN ───────────────────────────────


def test_the_upn_is_read_from_a_real_san() -> None:
    pem = _certificate(upn="1234567890@mil", email="john.doe@agency.gov")
    identity = piv.identity_from_pem(pem)
    assert identity.subject == "1234567890@mil"
    assert identity.email == "john.doe@agency.gov"


def test_a_long_upn_uses_the_long_der_length_form() -> None:
    """The two-byte header only covers values under 128 bytes; a realistic PIV
    UPN can exceed that, and getting the long form wrong silently truncates."""
    upn = ("x" * 200) + "@mil"
    assert piv.identity_from_pem(_certificate(upn=upn)).subject == upn


def test_a_certificate_with_no_upn_is_refused_and_does_not_fall_back_to_the_dn() -> None:
    """The subject DN is right there and is deliberately not used: its format
    varies by terminator and it is ambiguous to compare."""
    pem = _certificate(email="only.email@agency.gov")
    with pytest.raises(piv.PivError) as caught:
        piv.identity_from_pem(pem)
    assert "userPrincipalName" in str(caught.value)
    assert "DOE.JOHN.Q" not in str(caught.value)


def test_a_certificate_with_no_san_at_all_is_refused() -> None:
    with pytest.raises(piv.PivError):
        piv.identity_from_pem(_certificate())


def test_something_that_is_not_a_certificate_is_refused() -> None:
    with pytest.raises(piv.PivError):
        piv.identity_from_pem("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----")


# ── the trusted-peer predicate on its own ───────────────────────────────────


@pytest.mark.parametrize(
    ("peer", "cidrs", "expected"),
    [
        ("10.1.2.3", ["10.0.0.0/8"], True),
        ("203.0.113.9", ["10.0.0.0/8"], False),
        ("10.1.2.3", [], False),
        (None, ["10.0.0.0/8"], False),
        ("not-an-address", ["10.0.0.0/8"], False),
        ("10.1.2.3", ["not-a-cidr", "10.0.0.0/8"], True),
        ("10.1.2.3", ["not-a-cidr"], False),
        ("::1", ["::1/128"], True),
    ],
)
def test_peer_trust(peer: str | None, cidrs: list[str], expected: bool) -> None:
    """A malformed entry is skipped, never treated as a wildcard, and never
    allowed to abort the entries after it."""
    assert piv.peer_is_trusted(peer, cidrs) is expected


# ── §6.7 / §6.8 / §6.9 mapping to an account ────────────────────────────────


@pytest.mark.asyncio
async def test_an_unlinked_certificate_is_refused_with_a_distinguishable_reason(
    piv_on,
) -> None:
    """Valid-but-unknown is not the same problem as invalid, and an
    administrator needs to tell them apart."""
    async with _client() as c:
        resp = await c.get(
            "/auth/piv", headers=_headers(_certificate(upn=f"unknown-{next(_SEQ)}@mil"))
        )
    assert resp.status_code == 403
    assert "not linked" in resp.text
    assert SESSION_COOKIE not in resp.cookies


@pytest.mark.asyncio
async def test_a_linked_certificate_signs_the_user_in(piv_on) -> None:
    upn = f"linked-{next(_SEQ)}@mil"
    _org_id, user_id = await _linked_user(upn)

    async with _client() as c:
        resp = await c.get("/auth/piv", headers=_headers(_certificate(upn=upn)))

    assert resp.status_code == 303, resp.text
    assert resp.headers["location"] == "/"
    assert SESSION_COOKIE in resp.cookies

    async with session_scope() as s:
        ident = (
            await s.execute(
                select(ExternalIdentity).where(ExternalIdentity.subject == upn)
            )
        ).scalar_one()
        assert ident.user_id == user_id
        assert ident.last_login_at is not None


@pytest.mark.asyncio
async def test_a_deactivated_user_is_refused_with_a_valid_linked_certificate(piv_on) -> None:
    upn = f"deactivated-{next(_SEQ)}@mil"
    await _linked_user(upn, active=False)

    async with _client() as c:
        resp = await c.get("/auth/piv", headers=_headers(_certificate(upn=upn)))

    assert resp.status_code == 403
    assert "deactivated" in resp.text
    assert SESSION_COOKIE not in resp.cookies


@pytest.mark.asyncio
async def test_a_certificate_never_creates_an_account(piv_on) -> None:
    """Holding a card says the government issued a credential. It does not say
    this person should have an account in this tenant."""
    upn = f"nocreate-{next(_SEQ)}@mil"
    async with session_scope() as s:
        before = len((await s.execute(select(User))).scalars().all())

    async with _client() as c:
        resp = await c.get("/auth/piv", headers=_headers(_certificate(upn=upn)))
    assert resp.status_code == 403

    async with session_scope() as s:
        after = len((await s.execute(select(User))).scalars().all())
        assert after == before, "a certificate provisioned an account"


@pytest.mark.asyncio
async def test_the_identity_resolves_to_its_own_users_organization(piv_on) -> None:
    """Pinned on an unscoped session: ``get_session`` binds the RLS tenant, so
    an HTTP-only check could not tell an app predicate from the policy."""
    upn = f"tenant-{next(_SEQ)}@mil"
    org_id, user_id = await _linked_user(upn)
    other_org_id, _other = await _linked_user(f"other-{next(_SEQ)}@mil")
    assert org_id != other_org_id

    async with session_scope() as s:
        from ccf.identity.provisioning import user_for_certificate  # noqa: PLC0415

        user = await user_for_certificate(
            s, piv.CertificateIdentity(subject=upn, email=None)
        )
        assert user.id == user_id
        assert user.organization_id == org_id
