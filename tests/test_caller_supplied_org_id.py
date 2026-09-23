"""A caller may not name an organization other than its own.

The class this file pins is distinct from the id-in-path scoping fixed at
``2a2137f``: here the **tenant identity itself** arrives as a caller-supplied
body field, query parameter or form field, and the handler used to trust it
over the authenticated principal. An id-in-path sweep cannot see that shape,
and neither could the reviews that missed it.

**What RLS does and does not cover.** Measured on ``main`` before the fix, over
the real authenticated HTTP path: org A naming org B got ``200`` with zero rows
from ``/api/queries/{key}/run`` and an empty CSV from ``/export``; ``200 []``
from ``/api/admin/portal/grants``; and ``500`` from the two POSTs, where the
``tenant_isolation`` WITH CHECK refused the INSERT. So Postgres RLS did mask
the reads and did block the writes -- but it is the backstop
``ccf.api.deps.get_session`` documents itself as sitting *beneath*, not the
check. The same ``run_query`` call on an unscoped ``session_scope()`` returned
org B's evidence in full, because there was no app-layer org predicate at all.
That is what these tests pin.

Every guard here lives in ``ccf.api.auth_deps.resolve_caller_org``, which
decides from ``principal.org_id`` alone before any query runs -- so an HTTP
``403`` cannot be produced by RLS (RLS yields an empty ``200`` or a ``500``),
and the two are distinguishable end to end. The layer tests at the bottom go
further and call the handlers directly on an unscoped ``session_scope()``,
asserting the owning org still succeeds there first.
"""

from __future__ import annotations

import itertools
import os
from datetime import UTC, date, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.auth_deps import resolve_caller_org
from ccf.api.main import create_app
from ccf.auth import Principal, hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import service as ev_service
from ccf.models import Organization, System, User
from ccf.models_evidence import EvidenceObject
from ccf.models_portal import ExternalAccessGrant, ExternalPrincipal

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()

#: An organization id that does not exist. Used to prove the refusal is decided
#: from the principal alone and therefore discloses nothing about what exists.
_NO_SUCH_ORG = 99_999_999


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled() -> None:
    """Auth ON for every test in this module.

    Without it every request resolves to ``SYSTEM_PRINCIPAL``, whose
    ``org_id`` is ``None`` -- the *global* path, which by design honours a
    supplied ``organization_id``. A test written the usual way would therefore
    exercise the bypass and never reach the guard.
    """
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _tag() -> str:
    return f"{next(_SEQ)}-{os.urandom(3).hex()}"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _mk_tenant(tag: str, side: str) -> tuple[str, int]:
    """An org + an ``admin`` user in it. Returns ``(bearer_token, org_id)``.

    ``admin`` deliberately: the portal admin routes are ``require_role("admin")``
    gated, so a lesser role would be refused by the role gate and the org guard
    would never be reached.
    """
    async with session_scope() as s:
        org = Organization(name=f"CallerOrg {side} {tag}")
        s.add(org)
        await s.flush()
        s.add(
            user := User(
                email=f"{side}-{tag}@caller-org.test",
                organization_id=org.id,
                role="admin",
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
        )
        await s.flush()
        return user.api_token, org.id


async def _cleanup(*org_ids: int) -> None:
    async with session_scope() as s:
        await s.execute(
            delete(ExternalAccessGrant).where(ExternalAccessGrant.organization_id.in_(org_ids))
        )
        await s.execute(
            delete(ExternalPrincipal).where(ExternalPrincipal.organization_id.in_(org_ids))
        )
        await s.execute(delete(EvidenceObject).where(EvidenceObject.organization_id.in_(org_ids)))
        await s.execute(delete(System).where(System.organization_id.in_(org_ids)))
        await s.execute(delete(User).where(User.organization_id.in_(org_ids)))
        await s.execute(delete(Organization).where(Organization.id.in_(org_ids)))


async def _seed_expired_evidence(org_id: int, title: str) -> None:
    async with session_scope() as s:
        await ev_service.create_object(
            s, org_id=org_id, title=title, control_id="AC-2", expires_on=date(2018, 6, 1)
        )


async def _grants_in(org_id: int) -> list[ExternalAccessGrant]:
    """Every grant row in ``org_id``, read on an **unscoped** session.

    Unscoped on purpose: asserting "no grant landed in the victim org" through
    a tenant-bound session would be satisfied by RLS hiding the row rather than
    by the row never existing.
    """
    async with session_scope() as s:
        return list(
            (
                await s.execute(
                    select(ExternalAccessGrant).where(
                        ExternalAccessGrant.organization_id == org_id
                    )
                )
            )
            .scalars()
            .all()
        )


# --- /api/queries: run + export --------------------------------------------


@pytest.mark.asyncio
async def test_query_run_refuses_a_foreign_organization_id_in_the_body() -> None:
    tag = _tag()
    token_a, org_a = await _mk_tenant(tag, "a")
    _token_b, org_b = await _mk_tenant(tag, "b")
    secret = f"VICTIM-EVIDENCE-{tag}"
    try:
        await _seed_expired_evidence(org_b, secret)
        await _seed_expired_evidence(org_a, f"OWN-EVIDENCE-{tag}")
        async with _client() as c:
            foreign = await c.post(
                "/api/queries/expired-evidence/run",
                json={"organization_id": org_b, "params": {}},
                headers=_auth(token_a),
            )
            assert foreign.status_code == 403, foreign.text
            # Asserted on the body, not only the status: a 403 that still
            # rendered rows would be the same breach with a different label.
            assert secret not in foreign.text
            assert "rows" not in foreign.json()

            own = await c.post(
                "/api/queries/expired-evidence/run",
                json={"organization_id": org_a, "params": {}},
                headers=_auth(token_a),
            )
            assert own.status_code == 200, own.text
            titles = {r["title"] for r in own.json()["rows"]}
            assert f"OWN-EVIDENCE-{tag}" in titles  # the owning org is not locked out
            assert secret not in titles
    finally:
        await _cleanup(org_a, org_b)


@pytest.mark.asyncio
async def test_query_export_returns_no_foreign_rows() -> None:
    """The export is the sharper half: ``run`` returns JSON a UI may filter,
    while ``/export`` hands back a CSV file the caller keeps."""
    tag = _tag()
    token_a, org_a = await _mk_tenant(tag, "a")
    _token_b, org_b = await _mk_tenant(tag, "b")
    secret = f"VICTIM-CSV-{tag}"
    try:
        await _seed_expired_evidence(org_b, secret)
        await _seed_expired_evidence(org_a, f"OWN-CSV-{tag}")
        async with _client() as c:
            foreign = await c.post(
                "/api/queries/expired-evidence/export",
                json={"organization_id": org_b, "params": {}},
                headers=_auth(token_a),
            )
            assert foreign.status_code == 403, foreign.text
            assert secret not in foreign.text
            # Not a CSV at all -- no attachment is produced for a refused org.
            assert "text/csv" not in foreign.headers.get("content-type", "")

            own = await c.post(
                "/api/queries/expired-evidence/export",
                json={"organization_id": org_a, "params": {}},
                headers=_auth(token_a),
            )
            assert own.status_code == 200, own.text
            assert "text/csv" in own.headers["content-type"]
            assert f"OWN-CSV-{tag}" in own.text
            assert secret not in own.text
    finally:
        await _cleanup(org_a, org_b)


@pytest.mark.asyncio
async def test_queries_ui_refuses_a_foreign_organization_id_in_the_query_string() -> None:
    """The server-rendered twin at ``/queries`` -- same defect, different
    transport, and the one an operator reaches by editing the URL."""
    tag = _tag()
    token_a, org_a = await _mk_tenant(tag, "a")
    _token_b, org_b = await _mk_tenant(tag, "b")
    secret = f"VICTIM-UI-{tag}"
    try:
        await _seed_expired_evidence(org_b, secret)
        async with _client() as c:
            foreign = await c.get(
                "/queries",
                params={"key": "expired-evidence", "organization_id": org_b, "run": "1"},
                headers=_auth(token_a),
            )
            assert foreign.status_code == 403, foreign.text
            assert secret not in foreign.text

            own = await c.get(
                "/queries",
                params={"key": "expired-evidence", "organization_id": org_a, "run": "1"},
                headers=_auth(token_a),
            )
            assert own.status_code == 200, own.text
            assert secret not in own.text
    finally:
        await _cleanup(org_a, org_b)


# --- /api/admin/portal -----------------------------------------------------


@pytest.mark.asyncio
async def test_portal_grant_cannot_be_issued_against_another_organization() -> None:
    """Issuing a grant mints a bearer credential into an org's packages and
    evidence. Before the guard this reached the INSERT and was refused by the
    RLS WITH CHECK -- a ``500``, i.e. the database answering an authorization
    question the application never asked."""
    tag = _tag()
    token_a, org_a = await _mk_tenant(tag, "a")
    _token_b, org_b = await _mk_tenant(tag, "b")
    try:
        async with _client() as c:
            foreign = await c.post(
                "/api/admin/portal/grants",
                json={
                    "organization_id": org_b,
                    "principal_name": f"Attacker {tag}",
                    "kind": "assessor",
                    "label": f"ATTACK-{tag}",
                    "ttl_days": 10,
                },
                headers=_auth(token_a),
            )
            assert foreign.status_code == 403, foreign.text
            assert "token" not in foreign.json()  # no credential was minted

            own = await c.post(
                "/api/admin/portal/grants",
                json={
                    "organization_id": org_a,
                    "principal_name": f"Own {tag}",
                    "kind": "customer",
                    "label": f"OWN-{tag}",
                    "ttl_days": 10,
                },
                headers=_auth(token_a),
            )
            assert own.status_code == 200, own.text
            assert own.json()["token"]

        # The effect, not the status code: nothing landed in the victim org,
        # and the caller's own grant really was written to its own org.
        assert await _grants_in(org_b) == []
        assert [g.label for g in await _grants_in(org_a)] == [f"OWN-{tag}"]
    finally:
        await _cleanup(org_a, org_b)


@pytest.mark.asyncio
async def test_portal_grants_cannot_be_listed_for_another_organization() -> None:
    tag = _tag()
    token_a, org_a = await _mk_tenant(tag, "a")
    token_b, org_b = await _mk_tenant(tag, "b")
    try:
        async with _client() as c:
            seeded = await c.post(
                "/api/admin/portal/grants",
                json={
                    "organization_id": org_b,
                    "principal_name": f"Victim {tag}",
                    "kind": "customer",
                    "label": f"VICTIM-{tag}",
                    "ttl_days": 10,
                },
                headers=_auth(token_b),
            )
            assert seeded.status_code == 200, seeded.text

            foreign = await c.get(
                "/api/admin/portal/grants",
                params={"organization_id": org_b},
                headers=_auth(token_a),
            )
            assert foreign.status_code == 403, foreign.text
            assert f"VICTIM-{tag}" not in foreign.text

            own = await c.get(
                "/api/admin/portal/grants",
                params={"organization_id": org_a},
                headers=_auth(token_a),
            )
            assert own.status_code == 200, own.text
            assert own.json() == []  # org A has none -- and learns nothing of B's
    finally:
        await _cleanup(org_a, org_b)


@pytest.mark.asyncio
async def test_portal_engagements_and_principals_refuse_a_foreign_organization() -> None:
    """The other three admin-portal routes that take the tenant from the
    request: ``POST /engagements``, ``GET /engagements`` and
    ``POST /principals``. The last was not in the original report -- the sweep
    found it."""
    tag = _tag()
    token_a, org_a = await _mk_tenant(tag, "a")
    _token_b, org_b = await _mk_tenant(tag, "b")
    try:
        async with _client() as c:
            listed = await c.get(
                "/api/admin/portal/engagements",
                params={"organization_id": org_b},
                headers=_auth(token_a),
            )
            assert listed.status_code == 403, listed.text

            created = await c.post(
                "/api/admin/portal/engagements",
                json={
                    "organization_id": org_b,
                    "system_id": 1,
                    "assessor_principal_id": 1,
                    "period_from": datetime.now(UTC).isoformat(),
                    "period_to": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
                },
                headers=_auth(token_a),
            )
            # 403 before the 422 the unknown assessor id would otherwise earn:
            # the org check runs first, so a foreign org cannot be probed for
            # which principal ids are valid in it.
            assert created.status_code == 403, created.text

            principal = await c.post(
                "/api/admin/portal/principals",
                json={"organization_id": org_b, "name": f"Firm {tag}", "kind": "assessor"},
                headers=_auth(token_a),
            )
            assert principal.status_code == 403, principal.text

            own = await c.post(
                "/api/admin/portal/principals",
                json={"organization_id": org_a, "name": f"Own Firm {tag}", "kind": "assessor"},
                headers=_auth(token_a),
            )
            assert own.status_code == 200, own.text

        async with session_scope() as s:
            landed = (
                (
                    await s.execute(
                        select(ExternalPrincipal.organization_id, ExternalPrincipal.name).where(
                            ExternalPrincipal.organization_id.in_([org_a, org_b])
                        )
                    )
                )
                .all()
            )
        assert landed == [(org_a, f"Own Firm {tag}")]
    finally:
        await _cleanup(org_a, org_b)


@pytest.mark.asyncio
async def test_refusal_discloses_nothing_about_whether_the_named_org_exists() -> None:
    """Why this is a ``403`` and not the repo's cross-tenant ``404``.

    ``tests/test_waivers_api_rbac.py``'s rule is about *resources*: another
    tenant's row is 404 because confirming the id exists is itself a
    disclosure. This refusal is decided from ``principal.org_id`` alone, before
    any lookup -- so a real foreign org and an invented one are answered
    identically, and nothing about what exists leaks. What is reported is
    exactly a permission the caller lacks.
    """
    tag = _tag()
    token_a, org_a = await _mk_tenant(tag, "a")
    _token_b, org_b = await _mk_tenant(tag, "b")
    try:
        async with _client() as c:
            real = await c.get(
                "/api/admin/portal/grants",
                params={"organization_id": org_b},
                headers=_auth(token_a),
            )
            invented = await c.get(
                "/api/admin/portal/grants",
                params={"organization_id": _NO_SUCH_ORG},
                headers=_auth(token_a),
            )
        assert real.status_code == invented.status_code == 403
        assert real.text == invented.text
    finally:
        await _cleanup(org_a, org_b)


# --- the server-rendered /admin/portal twins --------------------------------


@pytest.mark.asyncio
async def test_portal_admin_ui_refuses_a_foreign_organization() -> None:
    """``/admin/portal`` (page), its grant form, and its revoke form. The
    previous branch scoped the JSON revoke route and deferred these."""
    tag = _tag()
    token_a, org_a = await _mk_tenant(tag, "a")
    token_b, org_b = await _mk_tenant(tag, "b")
    try:
        async with _client() as c:
            seeded = await c.post(
                "/api/admin/portal/grants",
                json={
                    "organization_id": org_b,
                    "principal_name": f"Victim UI {tag}",
                    "kind": "customer",
                    "label": f"VICTIM-UI-{tag}",
                    "ttl_days": 10,
                },
                headers=_auth(token_b),
            )
            assert seeded.status_code == 200, seeded.text
            victim_grant_id = seeded.json()["id"]

            page = await c.get(
                "/admin/portal", params={"organization_id": org_b}, headers=_auth(token_a)
            )
            assert page.status_code == 403, page.text[:400]
            assert f"VICTIM-UI-{tag}" not in page.text

            form = await c.post(
                "/admin/portal/grants",
                data={
                    "organization_id": str(org_b),
                    "principal_name": f"Attacker UI {tag}",
                    "kind": "customer",
                    "ttl_days": "10",
                    "label": f"ATTACK-UI-{tag}",
                },
                headers=_auth(token_a),
            )
            assert form.status_code == 403, form.text[:400]

            # Revoke needs BOTH checks, and each is load-bearing on its own.
            #
            # (a) Naming its OWN org and passing org B's grant id. The form
            #     field is clean, so only the path-id predicate can catch this
            #     -- 404, because a grant id's existence is a disclosure.
            revoke_own_org_foreign_id = await c.post(
                f"/admin/portal/grants/{victim_grant_id}/revoke",
                data={"organization_id": str(org_a)},
                headers=_auth(token_a),
                follow_redirects=False,
            )
            assert revoke_own_org_foreign_id.status_code == 404, (
                revoke_own_org_foreign_id.text[:400]
            )

            # (b) Naming org B, so that the path-id predicate would compare
            #     org B's grant against org B and wave it through. Only
            #     ``resolve_caller_org`` catches this one -- 403, and before
            #     any lookup. Without it the grant-id predicate is theatre:
            #     the caller simply supplies the org the row belongs to.
            revoke_foreign_org = await c.post(
                f"/admin/portal/grants/{victim_grant_id}/revoke",
                data={"organization_id": str(org_b)},
                headers=_auth(token_a),
                follow_redirects=False,
            )
            assert revoke_foreign_org.status_code == 403, revoke_foreign_org.text[:400]

            own_page = await c.get(
                "/admin/portal", params={"organization_id": org_a}, headers=_auth(token_a)
            )
            assert own_page.status_code == 200, own_page.text[:400]

        # Effect, not status: org B's grant is untouched and nothing was
        # issued into org B.
        b_grants = await _grants_in(org_b)
        assert [(g.id, g.revoked) for g in b_grants] == [(victim_grant_id, False)]
        assert [g.label for g in b_grants] == [f"VICTIM-UI-{tag}"]
    finally:
        await _cleanup(org_a, org_b)


@pytest.mark.asyncio
async def test_portal_admin_ui_owner_can_still_revoke_its_own_grant() -> None:
    """The guard is a gate, not a wall: the owning org's own revoke still
    works. Asserted before trusting any refusal above."""
    tag = _tag()
    token_a, org_a = await _mk_tenant(tag, "a")
    try:
        async with _client() as c:
            issued = await c.post(
                "/api/admin/portal/grants",
                json={
                    "organization_id": org_a,
                    "principal_name": f"Own UI {tag}",
                    "kind": "customer",
                    "label": f"OWN-UI-{tag}",
                    "ttl_days": 10,
                },
                headers=_auth(token_a),
            )
            assert issued.status_code == 200, issued.text
            grant_id = issued.json()["id"]

            revoked = await c.post(
                f"/admin/portal/grants/{grant_id}/revoke",
                data={"organization_id": str(org_a)},
                headers=_auth(token_a),
                follow_redirects=False,
            )
            assert revoked.status_code == 303, revoked.text[:400]
        assert [(g.id, g.revoked) for g in await _grants_in(org_a)] == [(grant_id, True)]
    finally:
        await _cleanup(org_a)


# --- the global (CLI / ETL / scheduler) principal ---------------------------


@pytest.mark.asyncio
async def test_global_principal_may_still_name_any_organization() -> None:
    """``principal.org_id is None`` is the CLI/ETL/scheduler path, the one
    ``require_role`` already short-circuits for, and the only way an operator
    names an org at all. Breaking it in a hardening branch is a self-inflicted
    outage, so it is asserted directly rather than assumed.

    Run at the handler layer on an unscoped ``session_scope()`` -- exactly the
    session those callers use, with RLS in bypass -- so this is the real path
    and not an HTTP approximation of it.
    """
    from ccf.api.routes.portal import (  # noqa: PLC0415
        GrantIn,
        create_grant_endpoint,
        list_grants_endpoint,
    )
    from ccf.queries import run_query  # noqa: PLC0415

    tag = _tag()
    _token_a, org_a = await _mk_tenant(tag, "a")
    _token_b, org_b = await _mk_tenant(tag, "b")
    cli = Principal(user_id=None, email="cli@concord", org_id=None, role="admin")
    try:
        await _seed_expired_evidence(org_b, f"CLI-SEES-{tag}")
        async with session_scope() as s:
            issued = await create_grant_endpoint(
                GrantIn(
                    organization_id=org_b,
                    principal_name=f"CLI Issued {tag}",
                    label=f"CLI-{tag}",
                    ttl_days=10,
                ),
                session=s,
                principal=cli,
            )
            assert issued["token"]

            listed = await list_grants_endpoint(
                organization_id=org_b, session=s, principal=cli
            )
            assert [g["label"] for g in listed] == [f"CLI-{tag}"]

            result = await run_query(s, "expired-evidence", {}, org_id=org_b)
            assert [r["title"] for r in result["rows"]] == [f"CLI-SEES-{tag}"]

            # And still scoped to what it asked for -- not a blanket bypass.
            assert await run_query(s, "expired-evidence", {}, org_id=org_a) == {
                **result,
                "rows": [],
                "count": 0,
            }
    finally:
        await _cleanup(org_a, org_b)


# --- the guard at the layer it lives in -------------------------------------


@pytest.mark.asyncio
async def test_portal_org_guards_reject_a_foreign_principal_without_rls() -> None:
    """The portal handlers' own guards, on an **unscoped** session.

    ``ccf.api.deps.get_session`` binds the RLS tenant from the principal, so an
    HTTP-only test cannot tell this guard apart from the ``tenant_isolation``
    policy on ``external_access_grants``. Here RLS is in bypass (the CLI and
    scheduler's own ``session_scope()``), which is the configuration in which
    the app-layer predicate is the only defense. The owning org is asserted to
    succeed first in each case, so the refusal is provably the org check and
    not a seeding failure.
    """
    from ccf.api.routes.portal import (  # noqa: PLC0415
        GrantIn,
        create_grant_endpoint,
        list_grants_endpoint,
    )

    tag = _tag()
    _token_a, org_a = await _mk_tenant(tag, "a")
    _token_b, org_b = await _mk_tenant(tag, "b")
    owner = Principal(
        user_id=None, email=f"owner-{tag}@caller-org.test", org_id=org_b, role="admin"
    )
    outsider = Principal(
        user_id=None, email=f"outsider-{tag}@caller-org.test", org_id=org_a, role="admin"
    )
    try:
        async with session_scope() as s:  # unscoped: RLS is not filtering here
            issued = await create_grant_endpoint(
                GrantIn(
                    organization_id=org_b,
                    principal_name=f"Layer Owner {tag}",
                    label=f"LAYER-{tag}",
                    ttl_days=10,
                ),
                session=s,
                principal=owner,
            )
            assert issued["token"]  # the owning org is not locked out

            found = await list_grants_endpoint(
                organization_id=org_b, session=s, principal=owner
            )
            assert [g["label"] for g in found] == [f"LAYER-{tag}"]

            with pytest.raises(HTTPException) as exc_create:
                await create_grant_endpoint(
                    GrantIn(
                        organization_id=org_b,
                        principal_name=f"Layer Outsider {tag}",
                        label=f"LAYER-ATTACK-{tag}",
                        ttl_days=10,
                    ),
                    session=s,
                    principal=outsider,
                )
            assert exc_create.value.status_code == 403

            with pytest.raises(HTTPException) as exc_list:
                await list_grants_endpoint(
                    organization_id=org_b, session=s, principal=outsider
                )
            assert exc_list.value.status_code == 403

        # Nothing the outsider asked for exists, on an unscoped read.
        assert [g.label for g in await _grants_in(org_b)] == [f"LAYER-{tag}"]
    finally:
        await _cleanup(org_a, org_b)


def test_resolve_caller_org_rule() -> None:
    """The whole rule, as three lines of truth table -- no DB, no HTTP.

    Pure by design: the decision uses ``principal.org_id`` only, which is what
    makes the refusal free of any disclosure about the named org.
    """
    # Tenant principal: own org and an absent value both resolve to its own.
    assert resolve_caller_org(7, 7) == 7
    assert resolve_caller_org(7, None) == 7
    # Tenant principal naming anything else: refused.
    for foreign in (8, _NO_SUCH_ORG):
        with pytest.raises(HTTPException) as exc:
            resolve_caller_org(7, foreign)
        assert exc.value.status_code == 403
    # Global principal: the supplied value is honoured, including None.
    assert resolve_caller_org(None, 8) == 8
    assert resolve_caller_org(None, None) is None
