"""Single sign-on hardening.

Spec: ``docs/superpowers/specs/2026-09-24-sso-hardening-design.md`` §7.

The discovery document and the token endpoint are served by a stub transport
rather than mocked at the function boundary, so the tests can assert **which
host the client secret actually reached** -- the finding in §2 is precisely
that it went somewhere it should not have, and a mock of ``exchange_code``
would have nothing to say about that.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.identity import oidc, provisioning
from ccf.models import Organization, User

pytestmark = pytest.mark.usefixtures("fresh_engine")

ISSUER = "https://idp.example.gov"
FOREIGN = "https://attacker.example.net"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


class _Idp:
    """A stub identity provider that records every host it was asked for."""

    def __init__(self, *, token_endpoint: str | None = None,
                 userinfo_endpoint: str | None = None) -> None:
        self.doc = {
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": token_endpoint or f"{ISSUER}/token",
            "userinfo_endpoint": userinfo_endpoint or f"{ISSUER}/userinfo",
        }
        self.hosts_called: list[str] = []
        self.token_posts: list[dict[str, Any]] = []

    def transport(self) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            self.hosts_called.append(request.url.host)
            path = request.url.path
            if path.endswith("/.well-known/openid-configuration"):
                return httpx.Response(200, json=self.doc)
            if path.endswith("/token"):
                self.token_posts.append(dict(parse_qs(request.content.decode())))
                return httpx.Response(200, json={"access_token": "at"})
            if path.endswith("/userinfo"):
                return httpx.Response(
                    200, json={"sub": "s1", "email": "u@idp.example.gov",
                               "email_verified": True},
                )
            return httpx.Response(404)

        return httpx.MockTransport(handle)


@pytest.fixture
def idp(monkeypatch: pytest.MonkeyPatch):
    """Configure OIDC and route all client traffic through a stub provider."""

    def install(stub: _Idp) -> _Idp:
        real_client = httpx.AsyncClient

        def factory(*a: Any, **kw: Any) -> httpx.AsyncClient:
            kw["transport"] = stub.transport()
            return real_client(*a, **kw)

        monkeypatch.setattr(oidc.httpx, "AsyncClient", factory)
        return stub

    monkeypatch.setenv("CCF_OIDC_ENABLED", "true")
    monkeypatch.setenv("CCF_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("CCF_OIDC_CLIENT_ID", "concord")
    monkeypatch.setenv("CCF_OIDC_CLIENT_SECRET", "super-secret-value")
    monkeypatch.setenv("CCF_OIDC_REDIRECT_URI", "https://concord.example.gov/auth/callback")
    get_settings.cache_clear()
    oidc.reset_discovery_cache()
    yield install
    oidc.reset_discovery_cache()
    get_settings.cache_clear()


# ── §7.3 / §7.4 the client secret does not leave the issuer ─────────────────


@pytest.mark.asyncio
async def test_a_foreign_token_endpoint_is_refused_and_the_secret_is_not_sent(idp) -> None:
    """The finding: `token_endpoint` came from the discovery document and the
    client secret was POSTed to it with nothing checking whose host it was."""
    stub = idp(_Idp(token_endpoint=f"{FOREIGN}/token"))

    with pytest.raises(oidc.OidcError) as caught:
        await oidc.exchange_code("c", code_verifier="v" * 64)

    assert "attacker.example.net" in str(caught.value)
    # The assertion that matters: not merely that it raised, but that nothing
    # ever reached the foreign host.
    assert "attacker.example.net" not in stub.hosts_called, stub.hosts_called
    assert stub.token_posts == []


@pytest.mark.asyncio
async def test_a_foreign_userinfo_endpoint_is_refused_before_the_token_call(idp) -> None:
    stub = idp(_Idp(userinfo_endpoint=f"{FOREIGN}/userinfo"))
    with pytest.raises(oidc.OidcError):
        await oidc.exchange_code("c", code_verifier="v" * 64)
    assert stub.token_posts == [], "the secret was sent before userinfo was validated"


@pytest.mark.asyncio
async def test_a_plain_http_endpoint_is_refused(idp) -> None:
    stub = idp(_Idp(token_endpoint="http://idp.example.gov/token"))
    with pytest.raises(oidc.OidcError) as caught:
        await oidc.exchange_code("c", code_verifier="v" * 64)
    assert "https" in str(caught.value)
    assert stub.token_posts == []


@pytest.mark.asyncio
async def test_the_issuers_own_endpoints_are_accepted(idp) -> None:
    """A check that refuses everything is not a check."""
    stub = idp(_Idp())
    claims = await oidc.exchange_code("c", code_verifier="v" * 64)
    assert claims["email"] == "u@idp.example.gov"
    assert stub.token_posts, "the exchange never happened"


# ── §7.5 / §7.6 PKCE ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_authorization_url_carries_an_s256_challenge(idp) -> None:
    idp(_Idp())
    verifier = oidc.new_code_verifier()
    url = await oidc.authorization_url("st", code_verifier=verifier)
    query = parse_qs(urlsplit(url).query)

    assert query["code_challenge_method"] == ["S256"], query
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode().rstrip("=")
    assert query["code_challenge"] == [expected]
    # The verifier itself must never be in the redirect.
    assert verifier not in url


@pytest.mark.asyncio
async def test_the_verifier_is_sent_at_exchange_and_matches_the_challenge(idp) -> None:
    stub = idp(_Idp())
    verifier = oidc.new_code_verifier()
    await oidc.authorization_url("st", code_verifier=verifier)
    await oidc.exchange_code("c", code_verifier=verifier)

    posted = stub.token_posts[0]
    assert posted["code_verifier"] == [verifier]
    assert oidc.code_challenge(posted["code_verifier"][0]) == oidc.code_challenge(verifier)


def test_a_verifier_is_within_the_rfc7636_length_bounds() -> None:
    for _ in range(20):
        v = oidc.new_code_verifier()
        assert 43 <= len(v) <= 128, len(v)


# ── §7.8 discovery is cached ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_discovery_is_fetched_once_across_two_authorization_requests(idp) -> None:
    """It used to be fetched on every authorization AND every callback: two
    extra round trips per sign-in. Counted, not timed."""
    idp(_Idp())
    oidc.reset_discovery_cache()
    await oidc.authorization_url("a", code_verifier="v" * 64)
    await oidc.authorization_url("b", code_verifier="v" * 64)
    await oidc.exchange_code("c", code_verifier="v" * 64)
    assert oidc.discovery_fetch_count() == 1


# ── §7.1 / §7.2 email verification ──────────────────────────────────────────


def test_an_explicitly_unverified_email_is_refused_whatever_the_setting() -> None:
    """The provider is stating a fact about the address, not omitting one."""
    claims = {"sub": "s", "email": "x@y.gov", "email_verified": False}
    assert provisioning.email_verification_ok(claims, require=False) is False
    assert provisioning.email_verification_ok(claims, require=True) is False


def test_an_absent_claim_is_allowed_by_default_and_refused_when_required() -> None:
    """Both directions, so the middle case cannot collapse into either extreme.

    Treating absence as "unverified" would break every deployment whose
    provider omits the optional claim -- absence of evidence as evidence of
    absence, which this programme keeps finding.
    """
    claims = {"sub": "s", "email": "x@y.gov"}
    assert provisioning.email_verification_ok(claims, require=False) is True
    assert provisioning.email_verification_ok(claims, require=True) is False


def test_a_string_true_is_honoured() -> None:
    """Some providers send the claim as a string."""
    assert provisioning.email_verification_ok(
        {"email_verified": "true"}, require=True
    ) is True
    assert provisioning.email_verification_ok(
        {"email_verified": "false"}, require=False
    ) is False


@pytest.mark.asyncio
async def test_an_unverified_email_cannot_claim_an_existing_account() -> None:
    """The defect in one test.

    Resolution falls back to ``User.email`` and then writes a permanent
    ``ExternalIdentity`` link, so an unverified address was handed somebody
    else's account and kept it.
    """
    async with session_scope() as s:
        org = Organization(name="SSO Takeover Org")
        s.add(org)
        await s.flush()
        victim = User(
            organization_id=org.id, email="victim@idp.example.gov",
            role="admin", active=True, full_name="The Victim",
        )
        s.add(victim)
        await s.flush()
        org_id, victim_id = org.id, victim.id

    async with session_scope() as s:
        with pytest.raises(provisioning.ProvisioningError) as caught:
            await provisioning.provision_from_oidc(
                s,
                claims={
                    "sub": "attacker-subject",
                    "email": "victim@idp.example.gov",
                    "email_verified": False,
                    "name": "Not The Victim",
                },
                org_id=org_id,
            )
    assert "not verified" in str(caught.value)

    async with session_scope() as s:
        user = (await s.execute(select(User).where(User.id == victim_id))).scalar_one()
        assert user.full_name == "The Victim"
        assert user.role == "admin"


@pytest.mark.asyncio
async def test_a_verified_email_still_provisions() -> None:
    """A fix that refuses everything is not a fix."""
    async with session_scope() as s:
        org = Organization(name="SSO Happy Org")
        s.add(org)
        await s.flush()
        org_id = org.id

    async with session_scope() as s:
        user, created = await provisioning.provision_from_oidc(
            s,
            claims={
                "sub": "good-subject",
                "email": "good@idp.example.gov",
                "email_verified": True,
                "name": "Good User",
            },
            org_id=org_id,
        )
        assert created is True
        assert user.organization_id == org_id


# ── §7.7 / §7.9 which tenant a NEW user lands in ────────────────────────────


@pytest.mark.asyncio
async def test_jit_creation_is_refused_when_the_tenant_is_ambiguous() -> None:
    """``_default_org_id`` was ``ORDER BY id LIMIT 1`` -- whichever organization
    happened to exist first. On a multi-tenant deployment that put a new user
    into somebody else's tenant, with that tenant's data."""
    from fastapi import HTTPException  # noqa: PLC0415

    from ccf.api.routes.identity import _sso_provisioning_org  # noqa: PLC0415

    async with session_scope() as s:
        for name in ("SSO Ambiguous A", "SSO Ambiguous B"):
            s.add(Organization(name=name))
        await s.flush()

    async with session_scope() as s:
        with pytest.raises(HTTPException) as caught:
            await _sso_provisioning_org(s, None)
    assert "more than one organization" in str(caught.value.detail)


@pytest.mark.asyncio
async def test_an_existing_user_signs_in_during_exactly_that_condition() -> None:
    """The other half, and the reason the refusal is narrow.

    An existing user's organization is on their own row. Provisioning uses the
    resolved value only when it CREATES, so ambiguity must not stop anybody who
    already has an account -- refusing a sign-in would lock a whole deployment
    out by adding a second tenant.
    """
    async with session_scope() as s:
        a = Organization(name="SSO Existing A")
        b = Organization(name="SSO Existing B")
        s.add_all([a, b])
        await s.flush()
        user = User(
            organization_id=b.id, email="existing@idp.example.gov", role="viewer", active=True
        )
        s.add(user)
        await s.flush()
        b_id, user_id = b.id, user.id

    # Deliberately passing the WRONG org: it must not be used for an existing
    # account, and this is what proves the resolution never touches one.
    async with session_scope() as s:
        resolved, created = await provisioning.provision_from_oidc(
            s,
            claims={
                "sub": "existing-subject",
                "email": "existing@idp.example.gov",
                "email_verified": True,
            },
            org_id=999_999,
        )
        assert created is False
        assert resolved.id == user_id
        assert resolved.organization_id == b_id, "an existing user was moved between tenants"


@pytest.mark.asyncio
async def test_a_configured_organization_is_honoured_and_a_bad_one_is_refused() -> None:
    from fastapi import HTTPException  # noqa: PLC0415

    from ccf.api.routes.identity import _sso_provisioning_org  # noqa: PLC0415

    async with session_scope() as s:
        org = Organization(name="SSO Configured Org")
        s.add(org)
        await s.flush()
        org_id = org.id

    async with session_scope() as s:
        assert await _sso_provisioning_org(s, org_id) == org_id
        with pytest.raises(HTTPException) as caught:
            await _sso_provisioning_org(s, 987_654)
    assert "does not match any organization" in str(caught.value.detail)
