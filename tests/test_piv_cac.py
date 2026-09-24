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
from datetime import UTC, datetime

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
    """PIV configured, **and real authentication turned on**.

    Without `CCF_AUTH_ENABLED`, `require_role("admin")` resolves every caller
    to `SYSTEM_PRINCIPAL`, whose `org_id` is None -- and every organization
    predicate in the linking routes is written `if principal.org_id is not
    None`, so all of them become no-ops. Four cross-tenant assertions here
    passed against the wrong behaviour until this was added: the same shape as
    the RLS masking that made nineteen cross-tenant tests unable to fail.
    """

    def apply(*, trusted: str | None = TRUSTED, enabled: bool = True) -> None:
        monkeypatch.setenv("CCF_AUTH_ENABLED", "true")
        monkeypatch.setenv("CCF_AUTH_SESSION_SECRET", "piv-test-secret")
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


# ── linking a certificate to an account ─────────────────────────────────────
#
# Found by reviewing the seams between this feature and the rest, not by
# reviewing the feature: every piece above was correct, and nothing in the
# application could create the link they all depend on. `/auth/piv` could only
# ever answer "valid but not linked", so the whole path was unreachable.


async def _admin(org_id: int) -> str:
    """An admin bearer token for ``org_id``.

    The token is minted here and returned, never read back off a reloaded row:
    ``api_token`` is write-only (IA-09) and only the hash persists, so a
    reloaded user reports ``None`` and reusing it authenticates as nobody --
    a 401 indistinguishable from a successful scoping refusal.
    """
    from ccf.auth import hash_password, new_api_token  # noqa: PLC0415

    async with session_scope() as s:
        user = User(
            organization_id=org_id,
            email=f"admin-{next(_SEQ)}@piv.test",
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
        )
        s.add(user)
        token = new_api_token()
        user.api_token = token
        await s.flush()
        return token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _org_and_user(label: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"PIV Link {label} {next(_SEQ)}")
        s.add(org)
        await s.flush()
        user = User(
            organization_id=org.id,
            email=f"{label}-{next(_SEQ)}@piv.test",
            role="viewer",
            active=True,
        )
        s.add(user)
        await s.flush()
        return org.id, user.id


@pytest.mark.asyncio
async def test_an_admin_links_a_certificate_and_it_then_signs_the_user_in(piv_on) -> None:
    """The end-to-end path the feature exists for, which nothing could reach."""
    org_id, user_id = await _org_and_user("happy")
    token = await _admin(org_id)
    upn = f"linkme-{next(_SEQ)}@mil"
    pem = _certificate(upn=upn, email="holder@agency.gov")

    async with _client() as c:
        created = await c.post(
            "/api/identity/piv-links",
            json={"user_id": user_id, "certificate_pem": pem},
            headers=_auth(token),
        )
        assert created.status_code == 201, created.text
        assert created.json()["subject"] == upn

        signed_in = await c.get("/auth/piv", headers=_headers(pem))

    assert signed_in.status_code == 303, signed_in.text
    assert SESSION_COOKIE in signed_in.cookies


@pytest.mark.asyncio
async def test_an_admin_cannot_link_a_certificate_to_another_tenants_user(piv_on) -> None:
    """The SCIM lesson, applied before it could become the SCIM defect.

    Linking is the one write that grants sign-in as a specific account, so an
    admin of one tenant reaching a user in another would be account takeover
    with an audit trail saying it was authorised.
    """
    _mine_org, _mine_user = await _org_and_user("mine")
    victim_org, victim_user = await _org_and_user("victim")
    token = await _admin(_mine_org)
    upn = f"crosstenant-{next(_SEQ)}@mil"

    async with _client() as c:
        resp = await c.post(
            "/api/identity/piv-links",
            json={"user_id": victim_user, "certificate_pem": _certificate(upn=upn)},
            headers=_auth(token),
        )

    # 404, not 403: whether that id exists in another tenant is not information
    # to hand back.
    assert resp.status_code == 404, resp.text
    async with session_scope() as s:
        assert (
            await s.execute(
                select(ExternalIdentity).where(ExternalIdentity.subject == upn)
            )
        ).scalar_one_or_none() is None
    assert victim_org  # named for the reader


@pytest.mark.asyncio
async def test_a_certificate_already_linked_elsewhere_is_refused_without_naming_who(
    piv_on,
) -> None:
    """`subject` is unique across the deployment, so naming the holder would
    tell an administrator of one tenant about a user in another."""
    org_a, user_a = await _org_and_user("holder")
    org_b, user_b = await _org_and_user("claimant")
    upn = f"contested-{next(_SEQ)}@mil"
    pem = _certificate(upn=upn)

    async with _client() as c:
        first = await c.post(
            "/api/identity/piv-links",
            json={"user_id": user_a, "certificate_pem": pem},
            headers=_auth(await _admin(org_a)),
        )
        assert first.status_code == 201, first.text

        second = await c.post(
            "/api/identity/piv-links",
            json={"user_id": user_b, "certificate_pem": pem},
            headers=_auth(await _admin(org_b)),
        )

    assert second.status_code == 409
    body = second.text
    assert str(user_a) not in body
    assert "@piv.test" not in body


@pytest.mark.asyncio
async def test_linking_the_same_certificate_to_the_same_user_twice_is_idempotent(
    piv_on,
) -> None:
    org_id, user_id = await _org_and_user("idempotent")
    token = await _admin(org_id)
    pem = _certificate(upn=f"twice-{next(_SEQ)}@mil")

    async with _client() as c:
        first = await c.post(
            "/api/identity/piv-links",
            json={"user_id": user_id, "certificate_pem": pem},
            headers=_auth(token),
        )
        second = await c.post(
            "/api/identity/piv-links",
            json={"user_id": user_id, "certificate_pem": pem},
            headers=_auth(token),
        )
    assert first.status_code == 201
    assert second.status_code in (200, 201)
    assert second.json()["id"] == first.json()["id"]


@pytest.mark.asyncio
async def test_a_certificate_with_no_upn_cannot_be_linked(piv_on) -> None:
    """The same refusal the login path makes, at the point of linking -- so an
    administrator finds out now rather than when somebody cannot sign in."""
    org_id, user_id = await _org_and_user("noupn")

    async with _client() as c:
        resp = await c.post(
            "/api/identity/piv-links",
            json={"user_id": user_id, "certificate_pem": _certificate(email="x@y.gov")},
            headers=_auth(await _admin(org_id)),
        )
    assert resp.status_code == 422
    assert "userPrincipalName" in resp.text


@pytest.mark.asyncio
async def test_listing_shows_only_this_organizations_links(piv_on) -> None:
    org_a, user_a = await _org_and_user("list-a")
    org_b, user_b = await _org_and_user("list-b")
    upn_a, upn_b = f"list-a-{next(_SEQ)}@mil", f"list-b-{next(_SEQ)}@mil"

    async with _client() as c:
        for org, user, upn in ((org_a, user_a, upn_a), (org_b, user_b, upn_b)):
            r = await c.post(
                "/api/identity/piv-links",
                json={"user_id": user, "certificate_pem": _certificate(upn=upn)},
                headers=_auth(await _admin(org)),
            )
            assert r.status_code == 201, r.text

        listed = await c.get("/api/identity/piv-links", headers=_auth(await _admin(org_a)))

    subjects = {row["subject"] for row in listed.json()}
    assert upn_a in subjects
    assert upn_b not in subjects, "another tenant's link was listed"


@pytest.mark.asyncio
async def test_unlinking_stops_the_certificate_signing_in(piv_on) -> None:
    org_id, user_id = await _org_and_user("unlink")
    token = await _admin(org_id)
    upn = f"unlink-{next(_SEQ)}@mil"
    pem = _certificate(upn=upn)

    async with _client() as c:
        created = await c.post(
            "/api/identity/piv-links",
            json={"user_id": user_id, "certificate_pem": pem},
            headers=_auth(token),
        )
        link_id = created.json()["id"]
        assert (await c.get("/auth/piv", headers=_headers(pem))).status_code == 303

        removed = await c.delete(f"/api/identity/piv-links/{link_id}", headers=_auth(token))
        assert removed.status_code == 204

        after = await c.get("/auth/piv", headers=_headers(pem))
    assert after.status_code == 403
    assert SESSION_COOKIE not in after.cookies


@pytest.mark.asyncio
async def test_an_admin_cannot_unlink_another_tenants_link(piv_on) -> None:
    org_a, user_a = await _org_and_user("del-a")
    org_b, _user_b = await _org_and_user("del-b")
    upn = f"del-{next(_SEQ)}@mil"

    async with _client() as c:
        created = await c.post(
            "/api/identity/piv-links",
            json={"user_id": user_a, "certificate_pem": _certificate(upn=upn)},
            headers=_auth(await _admin(org_a)),
        )
        link_id = created.json()["id"]
        resp = await c.delete(
            f"/api/identity/piv-links/{link_id}", headers=_auth(await _admin(org_b))
        )

    assert resp.status_code == 404
    async with session_scope() as s:
        assert await s.get(ExternalIdentity, link_id) is not None


@pytest.mark.asyncio
async def test_a_non_admin_cannot_link_a_certificate(piv_on) -> None:
    """Not self-service: a user who could link their own could link it to
    somebody else's account."""
    from ccf.auth import hash_password, new_api_token  # noqa: PLC0415

    org_id, user_id = await _org_and_user("viewer")
    async with session_scope() as s:
        viewer = User(
            organization_id=org_id,
            email=f"viewer-{next(_SEQ)}@piv.test",
            role="viewer",
            active=True,
            password_hash=hash_password("pw"),
        )
        s.add(viewer)
        token = new_api_token()
        viewer.api_token = token
        await s.flush()

    async with _client() as c:
        resp = await c.post(
            "/api/identity/piv-links",
            json={"user_id": user_id, "certificate_pem": _certificate(upn="v@mil")},
            headers=_auth(token),
        )
    assert resp.status_code in (401, 403), resp.text


# ── the seam with the second factor ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_certificate_sign_in_does_not_additionally_challenge_for_a_code(
    piv_on, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deliberate, and pinned here because nothing else says so.

    A PIV or CAC credential is **already** multi-factor: the card is something
    you have and the PIN is something you know, checked by the card itself
    before it will sign. Demanding a TOTP code on top would add a third factor
    of a weaker kind, and would strand any card holder whose phone is not with
    them at a terminal.

    The same decision was made explicitly for single sign-on -- the identity
    provider owns that second factor -- and is recorded in the MFA design spec.
    It was NOT recorded for this path, which is how it came to be a property
    nobody had decided. This test is that decision.

    ``Organization.mfa_policy`` now DOES gate sessions
    (``auth_gate_middleware``), so this matters more than when it was written:
    a policy of ``all`` routes an unenrolled user to enrolment on every page.
    It keys off the session cookie, and a certificate sign-in mints one -- so a
    card holder whose organization requires a second factor is sent to enrol in
    TOTP as well.

    That is the conservative direction and is left alone deliberately: the gate
    cannot tell which credential minted the cookie, and guessing would be the
    weaker default. Narrowing it to exempt certificate holders is a real
    improvement and its own change, needing the session to record how it was
    established.
    """
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "piv-mfa-seam-key-0123456789")
    get_settings.cache_clear()

    upn = f"mfa-seam-{next(_SEQ)}@mil"
    org_id, user_id = await _linked_user(upn)

    # Give the user an ACTIVE authenticator, so the password path would demand
    # a code from them.
    from ccf.identity.mfa_service import begin_enrolment, is_challenged  # noqa: PLC0415
    from ccf.models_identity import UserMfaCredential  # noqa: PLC0415

    async with session_scope() as s:
        user = await s.get(User, user_id)
        assert user is not None
        await begin_enrolment(s, user)
    async with session_scope() as s:
        cred = (
            await s.execute(
                select(UserMfaCredential).where(UserMfaCredential.user_id == user_id)
            )
        ).scalar_one()
        cred.activated_at = datetime.now(UTC)

    # The positive control: without it, "no code was demanded" would be
    # satisfied by an account that has no authenticator at all.
    async with session_scope() as s:
        assert await is_challenged(s, user_id) is True

    async with _client() as c:
        resp = await c.get("/auth/piv", headers=_headers(_certificate(upn=upn)))

    assert resp.status_code == 303, resp.text
    assert resp.headers["location"] == "/"
    assert SESSION_COOKIE in resp.cookies
    assert "concord_mfa_pending" not in resp.cookies
    assert org_id  # named for the reader
