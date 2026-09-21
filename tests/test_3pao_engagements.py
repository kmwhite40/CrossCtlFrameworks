"""3PAO engagements: the vocabulary, the period, the revocation, the scope.

A 3PAO is an independent assessment firm, so it is modelled through the
external portal rather than the internal role enum -- see
``docs/superpowers/specs/2026-09-21-3pao-engagement-design.md``. These tests pin
the four things that change: ``kind`` is a vocabulary that is enforced (§2), an
engagement is the unit a credential hangs off (§3), an engagement-backed grant
must expire and cannot outlive its engagement (§4), independence is observed and
never refused (§5), and scope follows the system (§6).

Every test cleans up the organization it seeds: ``clean_migrated_db`` resets the
schema once per *session*, so a leaked row is visible to every later module.
"""

from __future__ import annotations

import importlib.util
import itertools
import os
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.constants import EXTERNAL_PRINCIPAL_KINDS
from ccf.db import session_scope, set_session_tenant
from ccf.models import Organization, System, User
from ccf.models_portal import AssessmentEngagement, ExternalAccessGrant
from ccf.packages import service as pkg_service
from ccf.portal import service as portal
from ccf.reliability.checks import _check_external_grant_expiration

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


def _tag() -> str:
    return str(next(_SEQ))


def _cfg() -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    return cfg


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    command.upgrade(_cfg(), "head")


@pytest.fixture
async def orgs() -> AsyncIterator[list[int]]:
    """Track seeded organizations and delete them, with everything that cascades.

    A leftover org is not inert here: a ``cr26_documents`` row with a non-NULL
    ``document_key`` breaks migration 0081's downgrade and fails *other* test
    files later in the same session, far from the cause.
    """
    created: list[int] = []
    try:
        yield created
    finally:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            for org_id in created:
                await s.execute(delete(Organization).where(Organization.id == org_id))


async def _org(created: list[int], name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name, description="3PAO engagement test")
        s.add(org)
        await s.flush()
        created.append(org.id)
        return org.id


async def _system(org_id: int, name: str) -> int:
    async with session_scope() as s:
        row = System(organization_id=org_id, name=name, baseline="moderate")
        s.add(row)
        await s.flush()
        return row.id


async def _assessor(org_id: int, name: str, email: str | None = None) -> int:
    async with session_scope() as s:
        principal = await portal.create_principal(
            s, org_id=org_id, name=name, kind="assessor", email=email
        )
        return principal.id


async def _engagement(
    org_id: int,
    system_id: int,
    principal_id: int,
    *,
    period_from: datetime | None = None,
    period_to: datetime | None = None,
) -> int:
    now = datetime.now(UTC)
    async with session_scope() as s:
        engagement = await portal.create_engagement(
            s,
            org_id=org_id,
            system_id=system_id,
            assessor_principal_id=principal_id,
            period_from=period_from or now,
            period_to=period_to or (now + timedelta(days=30)),
            authorized_by="admin@csp.test",
        )
        return engagement.id


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


@pytest.fixture
def auth_enabled() -> Iterator[None]:
    """Run the admin routes under real auth.

    Most route tests in this repo run as ``SYSTEM_PRINCIPAL``, which is global,
    and ``require_role`` returns early for a global principal -- so the portal
    admin routes' ``require_role("admin")`` is never actually exercised there.
    Mirrors ``tests/test_waivers_api_rbac.py``'s harness.
    """
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _user(org_id: int, email: str, role: str) -> str:
    async with session_scope() as s:
        user = User(
            email=email, organization_id=org_id, role=role, active=True,
            password_hash=hash_password("pw"), api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- §2: kind is a vocabulary -----------------------------------------------


@pytest.mark.asyncio
async def test_invalid_kind_refused_at_service_and_route(
    orgs: list[int], auth_enabled: None
) -> None:
    """§8.7. ``kind`` used to live in a trailing comment: ``"assesor"`` stored
    fine and behaved identically to a real member.

    The literal below is asserted against the constant on purpose -- with the
    vocabulary defined in one place and used in another, a silent edit to it
    would otherwise pass every test in the suite.
    """
    assert EXTERNAL_PRINCIPAL_KINDS == ("customer", "assessor", "vendor")

    tag = _tag()
    org = await _org(orgs, f"3PAO Kind Org {tag}")

    async with session_scope() as s:
        with pytest.raises(ValueError, match="assesor") as service_err:
            await portal.create_principal(s, org_id=org, name="Typo Firm", kind="assesor")
        # From the vocabulary check, not from some other ValueError on the way.
        assert "unknown external principal kind" in str(service_err.value)

    async with session_scope() as s:
        with pytest.raises(ValueError, match="unknown external principal kind"):
            await portal.create_grant(s, org_id=org, principal_name="Typo Firm", kind="assesor")

    admin = await _user(org, f"kind-admin-{tag}@3pao.test", "admin")
    async with _client() as c:
        bad = await c.post(
            "/api/admin/portal/principals",
            json={"organization_id": org, "name": "Typo Firm", "kind": "assesor"},
            headers=_auth(admin),
        )
        assert bad.status_code == 422, bad.text
        assert "unknown external principal kind" in bad.json()["detail"]

        good = await c.post(
            "/api/admin/portal/principals",
            json={"organization_id": org, "name": "Real Firm", "kind": "assessor"},
            headers=_auth(admin),
        )
        assert good.status_code == 200, good.text
        assert good.json()["kind"] == "assessor"

    # Nothing outside the vocabulary reached the table.
    async with session_scope() as s:
        await set_session_tenant(s, None)
        stored = (
            await s.execute(
                text(
                    "SELECT kind FROM ccf.external_principals WHERE organization_id = :org"
                ),
                {"org": org},
            )
        ).scalars().all()
    assert set(stored) == {"assessor"}


@pytest.mark.asyncio
async def test_non_admin_cannot_reach_the_engagement_routes(
    orgs: list[int], auth_enabled: None
) -> None:
    """The role gate is real, not bypassed by a global test principal."""
    tag = _tag()
    org = await _org(orgs, f"3PAO RBAC Org {tag}")
    viewer = await _user(org, f"viewer-{tag}@3pao.test", "viewer")
    async with _client() as c:
        denied = await c.post(
            "/api/admin/portal/principals",
            json={"organization_id": org, "name": "Firm", "kind": "assessor"},
            headers=_auth(viewer),
        )
        assert denied.status_code == 403, denied.text
        listed = await c.get(
            "/api/admin/portal/engagements",
            params={"organization_id": org},
            headers=_auth(viewer),
        )
        assert listed.status_code == 403, listed.text


# --- §4: expiry and revocation ----------------------------------------------


@pytest.mark.asyncio
async def test_engagement_backed_grant_without_ttl_is_refused(
    orgs: list[int], auth_enabled: None
) -> None:
    """§8.1, rule 1. ``ttl_days=None`` stores ``expires_at=None`` and ``_valid``
    treats a null expiry as valid, so the grant would never expire. Refused
    rather than defaulted: substituting a TTL would put an expiry nobody chose
    on a federal assessment credential."""
    tag = _tag()
    org = await _org(orgs, f"3PAO NoTTL Org {tag}")
    system = await _system(org, f"NoTTL Sys {tag}")
    principal = await _assessor(org, "No-TTL 3PAO")
    engagement = await _engagement(org, system, principal)

    async with session_scope() as s:
        with pytest.raises(ValueError, match="ttl_days") as err:
            await portal.create_grant(
                s, org_id=org, principal_name="", principal_id=principal, kind="assessor",
                engagement_id=engagement, ttl_days=None,
            )
        assert "never expires" in str(err.value)

    # A grant with a TTL is accepted, so the refusal above is about the TTL and
    # not about engagement-backed grants being unissuable altogether.
    async with session_scope() as s:
        ok = await portal.create_grant(
            s, org_id=org, principal_name="", principal_id=principal, kind="assessor",
            engagement_id=engagement, ttl_days=7,
        )
        assert ok.expires_at is not None

    admin = await _user(org, f"nottl-admin-{tag}@3pao.test", "admin")
    async with _client() as c:
        refused = await c.post(
            "/api/admin/portal/grants",
            json={"organization_id": org, "principal_name": "", "principal_id": principal,
                  "kind": "assessor", "engagement_id": engagement, "ttl_days": None},
            headers=_auth(admin),
        )
        assert refused.status_code == 422, refused.text
        assert "ttl_days" in refused.json()["detail"]

    # Nothing without an expiry was written for this engagement.
    async with session_scope() as s:
        await set_session_tenant(s, None)
        unbounded = (
            await s.execute(
                select(ExternalAccessGrant).where(
                    ExternalAccessGrant.engagement_id == engagement,
                    ExternalAccessGrant.expires_at.is_(None),
                )
            )
        ).scalars().all()
    assert unbounded == []


@pytest.mark.asyncio
async def test_grant_expiry_is_capped_at_period_to_and_the_caller_is_told(
    orgs: list[int],
) -> None:
    """§8.2, rule 2. 90 days asked for on a 30-day engagement gets 30 -- and
    ``expiry_capped`` says so, rather than leaving the caller to notice."""
    tag = _tag()
    org = await _org(orgs, f"3PAO Cap Org {tag}")
    system = await _system(org, f"Cap Sys {tag}")
    principal = await _assessor(org, "Capped 3PAO")
    now = datetime.now(UTC)
    period_to = now + timedelta(days=30)
    engagement = await _engagement(org, system, principal, period_from=now, period_to=period_to)

    async with session_scope() as s:
        capped = await portal.create_grant(
            s, org_id=org, principal_name="", principal_id=principal, kind="assessor",
            engagement_id=engagement, ttl_days=90,
        )
        assert capped.expiry_capped is True
        assert capped.expires_at == period_to
        capped_id = capped.id

    async with session_scope() as s:
        stored = await s.get(ExternalAccessGrant, capped_id)
        assert stored is not None
        assert stored.expires_at == period_to

    # A TTL inside the period is left exactly as asked, so the cap is a cap and
    # not an unconditional overwrite.
    async with session_scope() as s:
        short = await portal.create_grant(
            s, org_id=org, principal_name="", principal_id=principal, kind="assessor",
            engagement_id=engagement, ttl_days=5,
        )
        assert short.expiry_capped is False
        assert short.expires_at is not None
        assert short.expires_at < period_to


@pytest.mark.asyncio
async def test_revoking_an_engagement_revokes_every_grant_under_it(orgs: list[int]) -> None:
    """§8.3, rule 3. Two grants, the second issued after the first, and one
    revocation ends both.

    Asserts on the grant ROWS as well as on resolution: rule 4 rejects any grant
    under a revoked engagement at resolution time, so resolution alone would go
    green even with the revoke-every-grant loop deleted. The rows are what an
    operator sees in the admin list, and they must say what is true.
    """
    tag = _tag()
    org = await _org(orgs, f"3PAO Revoke Org {tag}")
    system = await _system(org, f"Revoke Sys {tag}")
    principal = await _assessor(org, "Revoked 3PAO")
    engagement = await _engagement(org, system, principal)

    async with session_scope() as s:
        first = await portal.create_grant(
            s, org_id=org, principal_name="", principal_id=principal, kind="assessor",
            engagement_id=engagement, ttl_days=10,
        )
        first_id, first_token = first.id, first.token
    async with session_scope() as s:
        second = await portal.create_grant(
            s, org_id=org, principal_name="", principal_id=principal, kind="assessor",
            engagement_id=engagement, ttl_days=10, label="rotated token",
        )
        second_id, second_token = second.id, second.token

    async with session_scope() as s:
        assert await portal.resolve_grant(s, first_token) is not None
        assert await portal.resolve_grant(s, second_token) is not None

    async with session_scope() as s:
        assert await portal.revoke_engagement(s, engagement, actor="admin@csp.test") is True

    async with session_scope() as s:
        for gid in (first_id, second_id):
            row = await s.get(ExternalAccessGrant, gid)
            assert row is not None
            assert row.revoked is True, f"grant {gid} still live after the engagement ended"
        engagement_row = await s.get(AssessmentEngagement, engagement)
        assert engagement_row is not None and engagement_row.revoked_at is not None

    async with session_scope() as s:
        assert await portal.resolve_grant(s, first_token) is None
        assert await portal.resolve_grant(s, second_token) is None


@pytest.mark.asyncio
async def test_grant_under_an_ended_engagement_is_rejected_at_resolution(
    orgs: list[int],
) -> None:
    """§8.4, rule 4 -- the most important test in the change.

    The grant row is written DIRECTLY, bypassing ``create_grant``, so this
    exercises resolution-time enforcement and not issuance-time: a row written
    before this change, or by a future path that forgets rules 1-3, still has to
    be caught. Its own ``expires_at`` is 30 days out and it is not revoked; the
    only thing wrong with it is that the engagement behind it has ended.
    """
    tag = _tag()
    org = await _org(orgs, f"3PAO Elapsed Org {tag}")
    system = await _system(org, f"Elapsed Sys {tag}")
    principal = await _assessor(org, "Elapsed 3PAO")
    now = datetime.now(UTC)
    elapsed = await _engagement(
        org, system, principal,
        period_from=now - timedelta(days=60), period_to=now - timedelta(days=1),
    )
    current = await _engagement(
        org, system, principal,
        period_from=now - timedelta(days=1), period_to=now + timedelta(days=60),
    )

    async def _direct_grant(engagement_id: int, token: str) -> None:
        async with session_scope() as s:
            row = ExternalAccessGrant(
                organization_id=org, principal_id=principal, kind="assessor",
                engagement_id=engagement_id, expires_at=now + timedelta(days=30),
                revoked=False, scope={"package_ids": [], "evidence_ids": []},
            )
            row.token = token
            s.add(row)
            await s.flush()

    elapsed_token = f"elapsed-engagement-{tag}-" + "z" * 20
    current_token = f"current-engagement-{tag}-" + "z" * 20
    await _direct_grant(elapsed, elapsed_token)
    await _direct_grant(current, current_token)

    async with session_scope() as s:
        # The control: an identically-written row under a live engagement DOES
        # resolve, so the rejection below is the engagement check and not a
        # mistyped token or an unwritable row.
        assert await portal.resolve_grant(s, current_token) is not None
        rejected = await portal.resolve_grant(s, elapsed_token)
        assert rejected is None, "a grant whose engagement has ended must not resolve"

    # And by the cookie path, which authenticates off a grant id rather than a token.
    async with session_scope() as s:
        await set_session_tenant(s, None)
        elapsed_id = (
            await s.execute(
                select(ExternalAccessGrant.id).where(
                    ExternalAccessGrant.engagement_id == elapsed
                )
            )
        ).scalar_one()
    async with session_scope() as s:
        assert await portal.resolve_grant_by_id(s, elapsed_id) is None

    # A revoked (rather than elapsed) engagement is rejected the same way.
    async with session_scope() as s:
        row = await s.get(AssessmentEngagement, current)
        assert row is not None
        row.revoked_at = datetime.now(UTC)
    async with session_scope() as s:
        assert await portal.resolve_grant(s, current_token) is None


# --- §5: independence is named, never refused -------------------------------


@pytest.mark.asyncio
async def test_domain_match_is_observed_and_does_not_block(orgs: list[int]) -> None:
    """§8.8. Concord cannot verify independence -- it is ownership, contracts
    and staffing, none of which any field here records. It compares strings,
    says what it saw, and creates the engagement regardless."""
    tag = _tag()
    org_name = f"Tenant Cloud Services {tag}"
    org = await _org(orgs, org_name)
    system = await _system(org, f"Independence Sys {tag}")
    await _user(org, f"ciso-{tag}@sharedmail{tag}.test", "admin")

    matching = await _assessor(
        org, f"Assessors Of {tag}", email=f"lead-{tag}@sharedmail{tag}.test"
    )
    matched_id = await _engagement(org, system, matching)

    async with session_scope() as s:
        engagement = await s.get(AssessmentEngagement, matched_id)
        assert engagement is not None
        note = engagement.independence_note
        assert note is not None, "a domain match must be recorded"
        assert f"sharedmail{tag}.test" in note
        assert engagement.revoked_at is None  # observed, not blocked
    # Phrased as an observation, never as a finding/warning/conflict (§5).
    lowered = note.lower()
    for word in ("conflict", "violation", "warning", "finding", "not independent", "fail"):
        assert word not in lowered, f"independence_note reads as a judgement: {note!r}"
    assert "observed" in lowered
    assert "does not determine independence" in lowered

    # An assessor on its own domain, with its own name, produces no note at all.
    independent = await _assessor(
        org, f"Wholly Separate 3PAO {tag}", email=f"lead-{tag}@independent-3pao-{tag}.test"
    )
    clean_id = await _engagement(org, system, independent)
    async with session_scope() as s:
        clean = await s.get(AssessmentEngagement, clean_id)
        assert clean is not None
        assert clean.independence_note is None


@pytest.mark.asyncio
async def test_engagement_requires_an_assessor_principal(orgs: list[int]) -> None:
    """The one rule ``kind`` carries: an assessment credential cannot be issued
    to a party that is not an assessor (§2, last line)."""
    tag = _tag()
    org = await _org(orgs, f"3PAO Kind Rule Org {tag}")
    system = await _system(org, f"Kind Rule Sys {tag}")
    async with session_scope() as s:
        customer = await portal.create_principal(
            s, org_id=org, name="A Customer", kind="customer"
        )
        customer_id = customer.id
    now = datetime.now(UTC)
    async with session_scope() as s:
        with pytest.raises(ValueError, match="requires kind 'assessor'"):
            await portal.create_engagement(
                s, org_id=org, system_id=system, assessor_principal_id=customer_id,
                period_from=now, period_to=now + timedelta(days=30),
            )


# --- §6: scope follows the system -------------------------------------------


@pytest.mark.asyncio
async def test_assessor_grant_cannot_reach_another_system_in_the_same_tenant(
    orgs: list[int],
) -> None:
    """§8.5. Two systems in ONE tenant.

    The portal's tenant-isolation tests pass regardless of this bug, because
    both systems belong to the same organization -- there is no tenant boundary
    between them to catch it. The engagement's ``system_id`` is the only thing
    that does.
    """
    tag = _tag()
    org = await _org(orgs, f"3PAO Scope Org {tag}")
    assessed = await _system(org, f"Assessed Sys {tag}")
    other = await _system(org, f"Other Sys {tag}")
    async with session_scope() as s:
        in_scope = await pkg_service.create_package(
            s, org_id=org, system_id=assessed, kind="json", label=f"Assessed pkg {tag}"
        )
        out_of_scope = await pkg_service.create_package(
            s, org_id=org, system_id=other, kind="json", label=f"Other-system pkg {tag}"
        )
        in_scope_id, out_of_scope_id = in_scope.id, out_of_scope.id

    principal = await _assessor(org, f"Scoped 3PAO {tag}")
    engagement = await _engagement(org, assessed, principal)
    async with session_scope() as s:
        grant = await portal.create_grant(
            s, org_id=org, principal_name="", principal_id=principal, kind="assessor",
            engagement_id=engagement, ttl_days=10,
        )
        token = grant.token

    async with session_scope() as s:
        resolved = await portal.resolve_grant(s, token)
        assert resolved is not None
        contents = await portal.grant_contents(s, resolved)
    visible = {p["id"] for p in contents["packages"]}
    assert in_scope_id in visible, "the assessed system's package must be visible"
    assert out_of_scope_id not in visible, (
        "a package belonging to a different system in the same tenant reached an "
        "assessor's grant"
    )


@pytest.mark.asyncio
async def test_package_created_mid_engagement_is_visible(orgs: list[int]) -> None:
    """§8.6. The widening §6 states out loud: an assessment is of a system, not
    of a snapshot, so packages created after the engagement began are in scope,
    and ``period_to`` is what bounds it. Pinned so it stays a decision."""
    tag = _tag()
    org = await _org(orgs, f"3PAO Widening Org {tag}")
    system = await _system(org, f"Widening Sys {tag}")
    principal = await _assessor(org, f"Mid-Assessment 3PAO {tag}")
    engagement = await _engagement(org, system, principal)
    async with session_scope() as s:
        grant = await portal.create_grant(
            s, org_id=org, principal_name="", principal_id=principal, kind="assessor",
            engagement_id=engagement, ttl_days=10,
        )
        token = grant.token

    async with session_scope() as s:
        resolved = await portal.resolve_grant(s, token)
        assert resolved is not None
        before = await portal.grant_contents(s, resolved)
    assert before["packages"] == []

    async with session_scope() as s:
        later = await pkg_service.create_package(
            s, org_id=org, system_id=system, kind="json", label=f"Built mid-assessment {tag}"
        )
        later_id = later.id

    async with session_scope() as s:
        resolved = await portal.resolve_grant(s, token)
        assert resolved is not None
        after = await portal.grant_contents(s, resolved)
    assert later_id in {p["id"] for p in after["packages"]}


# --- §8.9: the HTTP boundary ------------------------------------------------


@pytest.mark.asyncio
async def test_every_engagement_field_crosses_the_http_boundary(
    orgs: list[int], auth_enabled: None
) -> None:
    """§8.9. On the CR26 modules, deleting result fields from a route left the
    whole suite green. The expected keys come from the model's own columns, so
    a field dropped from the route's response dict fails here rather than
    quietly disappearing from the API."""
    tag = _tag()
    org = await _org(orgs, f"3PAO HTTP Org {tag}")
    system = await _system(org, f"HTTP Sys {tag}")
    admin = await _user(org, f"http-admin-{tag}@3pao.test", "admin")
    now = datetime.now(UTC)

    async with _client() as c:
        principal = await c.post(
            "/api/admin/portal/principals",
            json={"organization_id": org, "name": f"HTTP 3PAO {tag}", "kind": "assessor",
                  "email": f"lead-{tag}@http-3pao.test",
                  "organization_name": f"HTTP 3PAO {tag}"},
            headers=_auth(admin),
        )
        assert principal.status_code == 200, principal.text

        created = await c.post(
            "/api/admin/portal/engagements",
            json={"organization_id": org, "system_id": system,
                  "assessor_principal_id": principal.json()["id"],
                  "period_from": now.isoformat(),
                  "period_to": (now + timedelta(days=30)).isoformat(),
                  "authorized_by": f"http-admin-{tag}@3pao.test"},
            headers=_auth(admin),
        )
        assert created.status_code == 200, created.text
        body = created.json()

        expected = set(AssessmentEngagement.__table__.columns.keys())
        assert expected <= set(body), (
            f"engagement fields missing from the API response: {sorted(expected - set(body))}"
        )
        assert body["system_id"] == system
        assert body["assessor_principal_id"] == principal.json()["id"]
        assert body["revoked_at"] is None

        listed = await c.get(
            "/api/admin/portal/engagements", params={"organization_id": org},
            headers=_auth(admin),
        )
        assert listed.status_code == 200, listed.text
        assert expected <= set(listed.json()[0])

        # The grant issued under it reports the engagement and the capping.
        grant = await c.post(
            "/api/admin/portal/grants",
            json={"organization_id": org, "principal_name": "",
                  "principal_id": principal.json()["id"], "kind": "assessor",
                  "engagement_id": body["id"], "ttl_days": 365},
            headers=_auth(admin),
        )
        assert grant.status_code == 200, grant.text
        assert grant.json()["engagement_id"] == body["id"]
        assert grant.json()["expiry_capped"] is True

        revoked = await c.post(
            f"/api/admin/portal/engagements/{body['id']}/revoke", headers=_auth(admin)
        )
        assert revoked.status_code == 200, revoked.text
        assert revoked.json() == {"revoked": True}

        after = await c.get(
            "/api/admin/portal/engagements", params={"organization_id": org},
            headers=_auth(admin),
        )
        assert after.json()[0]["revoked_at"] is not None


# --- §8.10: the migration ---------------------------------------------------


def _migration_module() -> object:
    path = Path("migrations/versions/0083_3pao_engagements.py").resolve()
    spec = importlib.util.spec_from_file_location("ccf_migration_0083", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_TABLE_SQL = (
    "SELECT count(*) FROM information_schema.tables "
    "WHERE table_schema = 'ccf' AND table_name = 'assessment_engagements'"
)
_COLUMN_SQL = (
    "SELECT count(*) FROM information_schema.columns "
    "WHERE table_schema = 'ccf' AND table_name = 'external_access_grants' "
    "AND column_name = 'engagement_id'"
)
_POLICY_SQL = (
    "SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'ccf' AND c.relname = 'assessment_engagements' "
    "AND p.polname = 'tenant_isolation'"
)


async def _catalogue() -> tuple[int, int, int]:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        return (
            (await s.execute(text(_TABLE_SQL))).scalar_one(),
            (await s.execute(text(_COLUMN_SQL))).scalar_one(),
            (await s.execute(text(_POLICY_SQL))).scalar_one(),
        )


async def _ensure_head(cfg: Config, *, caller: str) -> None:
    try:
        command.upgrade(cfg, "head")
    except Exception as exc:  # pragma: no cover - only on a broken downgrade
        raise RuntimeError(
            f"{caller} could not leave the shared test database at head -- every "
            f"other test module's migration fixture will now fail. Original error: {exc!r}"
        ) from exc


@pytest.mark.asyncio
async def test_migration_0083_round_trips_and_reports_out_of_vocabulary_kind(
    orgs: list[int], capfd: pytest.CaptureFixture[str]
) -> None:
    """§8.10. The round trip is asserted against the CATALOGUE -- the table, the
    column and the RLS policy -- not against alembic's exit code, which is 0 for
    a ``downgrade()`` that drops nothing.

    And a ``kind`` value outside the vocabulary must survive the upgrade
    untouched and be COUNTED (§7): refusing to migrate would block an upgrade
    over data an operator cannot see, and rewriting the row would destroy the
    record of what was there.
    """
    cfg = _cfg()
    await _ensure_head(cfg, caller="test_migration_0083 (setup)")

    tag = _tag()
    org = await _org(orgs, f"3PAO Migration Org {tag}")
    # Written as raw SQL: the service layer now refuses this value, which is the
    # point -- only a row that predates the enforcement can look like this.
    async with session_scope() as s:
        odd_id = (
            await s.execute(
                text(
                    "INSERT INTO ccf.external_principals (organization_id, kind, name) "
                    "VALUES (:org, 'assesor', :name) RETURNING id"
                ),
                {"org": org, "name": f"Legacy Typo Firm {tag}"},
            )
        ).scalar_one()

    assert await _catalogue() == (1, 1, 1)

    capfd.readouterr()  # drop anything logged before the round trip
    command.downgrade(cfg, "0082_pipeline_stage")
    assert await _catalogue() == (0, 0, 0), (
        "downgrade must actually remove the table, the grant column and the policy"
    )
    await _ensure_head(cfg, caller="test_migration_0083 round trip")

    assert await _catalogue() == (1, 1, 1)

    # Read from the migration log stream itself -- alembic's env.py re-runs
    # ``fileConfig`` on every command, which clears handlers added to its own
    # loggers, so a capture handler would silently collect nothing.
    reported = capfd.readouterr().err
    assert "external kind values outside" in reported, (
        "the upgrade must report out-of-vocabulary kind rows"
    )
    assert "LEFT UNCHANGED" in reported
    assert "external_principals: 1 row(s)" in reported

    # The row is still there, still spelled the way it was.
    async with session_scope() as s:
        await set_session_tenant(s, None)
        kind = (
            await s.execute(
                text("SELECT kind FROM ccf.external_principals WHERE id = :id"), {"id": odd_id}
            )
        ).scalar_one()
    assert kind == "assesor"

    # The counting itself, exercised directly rather than only through the fact
    # that ``upgrade()`` did not crash.
    module = _migration_module()
    from sqlalchemy import create_engine  # noqa: PLC0415 - sync engine, this check only

    engine = create_engine(str(get_settings().database_url_sync))
    try:
        with engine.connect() as conn:
            counts = module.report_out_of_vocabulary_kinds(conn)  # type: ignore[attr-defined]
    finally:
        engine.dispose()
    assert counts.get("external_principals", 0) >= 1


async def test_an_elapsed_engagement_does_not_report_its_grant_as_active(
    orgs: list[int],
) -> None:
    """The operator surface must not claim access that does not exist.

    ``_valid`` stops resolving a grant once its engagement elapses (§4 rule 4),
    but the portal-admin page used to classify a grant from its own row alone --
    ``revoked`` then ``expires_at`` -- so a grant with a live expiry under a
    dead engagement displayed as ``active``. The row said access was live; the
    resolution path denied it. Both now go through ``grant_status``.

    The grant is written directly, with an expiry deliberately in the future,
    so the only thing that can make it non-active is the engagement.
    """
    now = datetime.now(UTC)
    org_id = await _org(orgs, f"stale-engagement-org-{_tag()}")
    system_id = await _system(org_id, "s")
    principal_id = await _assessor(org_id, "Firm")
    engagement_id = await _engagement(
        org_id, system_id, principal_id,
        period_from=now - timedelta(days=60), period_to=now + timedelta(days=1),
    )
    async with session_scope() as s:
        await set_session_tenant(s, None)
        grant = ExternalAccessGrant(
            organization_id=org_id, principal_id=principal_id, kind="assessor",
            engagement_id=engagement_id, expires_at=now + timedelta(days=365),
        )
        grant.token = new_api_token()
        s.add(grant)
        await s.flush()
        grant_id = grant.id

        # While the engagement is current, everything agrees it is active.
        current = await portal.current_engagement_ids(s, [engagement_id])
        assert portal.grant_status(grant, current) == "active"
        assert await portal.resolve_grant_by_id(s, grant_id) is not None

        # Elapse the engagement without touching the grant.
        engagement = await s.get(AssessmentEngagement, engagement_id)
        assert engagement is not None
        engagement.period_to = now - timedelta(days=1)
        await s.flush()

        current = await portal.current_engagement_ids(s, [engagement_id])
        assert portal.grant_status(grant, current) == "engagement ended"
        assert await portal.resolve_grant_by_id(s, grant_id) is None
        # The grant's own expiry is untouched and still in the future -- so
        # nothing but the engagement can be producing this answer.
        assert grant.expires_at is not None and grant.expires_at > now
        assert not grant.revoked


async def test_the_hygiene_check_counts_an_engagement_ended_grant(orgs: list[int]) -> None:
    """A check that reports a clean bill of health it has not verified is worse
    than one that does not run.

    ``_check_external_grant_expiration`` counted only ``expires_at < now()``, so
    an un-revoked grant under a dead engagement was reported as nothing to see.
    It is counted now, and counted *separately* -- an expired grant needs a new
    token, an engagement-ended one may need nothing at all.
    """
    now = datetime.now(UTC)
    org_id = await _org(orgs, f"hygiene-org-{_tag()}")
    system_id = await _system(org_id, "s")
    principal_id = await _assessor(org_id, "Firm")
    engagement_id = await _engagement(
        org_id, system_id, principal_id,
        period_from=now - timedelta(days=60), period_to=now + timedelta(days=1),
    )
    async with session_scope() as s:
        await set_session_tenant(s, None)
        grant = ExternalAccessGrant(
            organization_id=org_id, principal_id=principal_id, kind="assessor",
            engagement_id=engagement_id, expires_at=now + timedelta(days=365),
        )
        grant.token = new_api_token()
        s.add(grant)
        await s.flush()

        engagement = await s.get(AssessmentEngagement, engagement_id)
        assert engagement is not None
        engagement.period_to = now - timedelta(days=1)
        await s.flush()

        check = await _check_external_grant_expiration(s)
        assert check.status == "warn", check
        # Counted under its own cause, not lumped in with self-expired grants.
        #
        # Asserted on the engagement-ended COUNT, never on the absence of the
        # word "expired": this check counts database-wide, so any other module
        # that leaves an expired grant behind would break an absence assertion
        # and the failure would surface here, far from its cause. (It did --
        # running this file after tests/test_portal.py.) If the two causes were
        # ever lumped together the message would carry a single "N expired" and
        # no engagement-ended count at all, so this still catches that.
        assert "1 engagement-ended" in check.message, check.message
