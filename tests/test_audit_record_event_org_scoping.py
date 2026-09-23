"""``record_event`` — the non-HTTP audit path — must scope its row to a tenant.

``audit_middleware`` resolves ``organization_id`` from the request principal
(DATA-06, migration 0044). :func:`ccf.api.audit.record_event`, the path every
non-HTTP audited mutation takes (portal, packs, waivers, patching, enforcement,
CR26, AI governance, catalog revisions, retention, JIT provisioning), did not:
it left the column NULL.

NULL is not "no one can see it". The ``tenant_isolation`` policy added by
migration 0044 reads

    ccf.current_tenant() IS NULL
    OR organization_id IS NULL
    OR organization_id = ccf.current_tenant()

so a NULL-org row is visible to **every** tenant, by design -- that clause
exists so genuinely platform-wide events (a catalog revision adopted for the
whole deployment) stay readable everywhere. A tenant-scoped event that lands
NULL therefore does not merely lose its scoping; it is published to every
organization on the deployment, readable through ``/api/audit`` by any scoped
admin or assessor.

What is pinned here:

1. A tenant-scoped event written by ``record_event`` is invisible to another
   org's admin over HTTP (the exposure).
2. A genuinely global event -- recorded on an unscoped session, as CLI/ETL and
   platform-wide operations run -- stays NULL-org and stays visible to every
   tenant. The fix may not close the exposure by making everything global-blind.
3. The owning org still reads its own events.
4. ``audit_middleware``'s resolution is unchanged, asserted by equality.
5. The hash chain still verifies, and a real tamper is still detected --
   ``organization_id`` is a scoping column outside the hash payload and must
   stay that way.
6. The scoping holds at the layer it lives: asserted against the database
   through a clamped session, not only over HTTP. ``get_session`` binds the RLS
   tenant for every request, so an HTTP-only assertion cannot tell a correctly
   scoped row from RLS doing the work on some other column.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from starlette.requests import Request
from starlette.responses import JSONResponse

import ccf.catalog.revisions as revisions_mod
from ccf.api.audit import _GENESIS, audit_middleware, record_event, row_hash
from ccf.api.main import create_app
from ccf.api.routes.audit import verify_chain
from ccf.auth import Principal, hash_password, new_api_token
from ccf.catalog.impact import AdoptionImpact
from ccf.catalog.revisions import adopt_revision, materialize_revision
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.models import AuditLog, CatalogSource, Organization, User
from tests.test_catalog_materialize import _documents

pytestmark = pytest.mark.usefixtures("fresh_engine")

_ENTITY = "audit_org_scope"
#: Middleware-written rows need a path prefix ``_SKIP_PREFIXES`` does not drop:
#: every ``/api/audit*`` path is skipped entirely, so an ``audit``-prefixed
#: entity would silently never be recorded at all.
_MW_ENTITY = "orgscopemw"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled() -> AsyncIterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


@pytest.fixture
async def clean_chain() -> AsyncIterator[None]:
    """Run against a controlled chain and leave one behind.

    ``verify_chain`` walks the entire table from genesis, so any assertion
    about linkage is only deterministic on a chain this module owns end to end
    -- the same reason ``tests/test_audit_chain_multitenant.py`` empties the
    table around each of its tests.
    """
    await _reset_chain()
    try:
        yield
    finally:
        await _reset_chain()


async def _reset_chain() -> None:
    async with session_scope() as s:
        await s.execute(delete(AuditLog))


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _mk_admin(email: str, org_name: str) -> tuple[str, int]:
    """An org plus an admin in it; returns (bearer token, org id)."""
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == org_name))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name=org_name)
            s.add(org)
            await s.flush()
        user = (
            await s.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        if user is None:
            user = User(
                email=email,
                organization_id=org.id,
                role="admin",
                active=True,
                password_hash=hash_password("pw"),
            )
            s.add(user)
        # Always mint a fresh token: ``User`` persists only ``api_token_hash``
        # (IA-09), so a reloaded row reports ``api_token is None`` and reusing
        # it would authenticate as nobody -- a 401 that looks like a scoping
        # result. Each test gets its own usable credential for the same admin.
        token = new_api_token()
        user.api_token = token
        await s.flush()
        return token, org.id


async def _record_as_tenant(org_id: int, actor: str, tag: str) -> None:
    """One ``record_event`` on a session clamped to ``org_id``.

    ``set_session_tenant`` is exactly what ``ccf.api.deps.get_session`` does for
    every authenticated request, so this is the production append path that the
    portal/packs/waivers/... services take -- not a hand-built row.
    """
    factory = get_session_factory()
    async with factory() as s:
        await set_session_tenant(s, org_id)
        await record_event(
            s, actor=actor, action="create", entity_type=_ENTITY, entity_id=tag,
            diff={"tag": tag}, organization_id=org_id,
        )
        await s.commit()


async def _record_unscoped(actor: str, tag: str) -> None:
    """One ``record_event`` on an unscoped session -- CLI/ETL and platform-wide work."""
    async with session_scope() as s:
        await record_event(
            s, actor=actor, action="create", entity_type=_ENTITY, entity_id=tag,
            diff={"tag": tag}, organization_id=None,
        )


async def _drive_middleware(principal: Principal | None, tag: str) -> None:
    """One audit row written by the real ``audit_middleware``.

    Driven directly rather than over HTTP (same technique as
    ``tests/test_audit_reentry.py``) so the principal on the request is exactly
    the one this test names.
    """
    path = f"/api/{_MW_ENTITY}/{tag}"
    body = json.dumps({"tag": tag}).encode()
    consumed = {"done": False}

    async def receive() -> dict[str, object]:
        if consumed["done"]:
            return {"type": "http.disconnect"}
        consumed["done"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    state: dict[str, object] = {} if principal is None else {"principal": principal}
    request = Request(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "scheme": "http",
            "server": ("test", 80),
            "client": ("test", 123),
            "headers": [(b"content-type", b"application/json")],
            "state": state,
        },
        receive,
    )

    async def call_next(_request: Request) -> JSONResponse:
        return JSONResponse({"ok": True}, status_code=201)

    await audit_middleware(request, call_next)


async def _actors_visible_to(token: str, actor: str) -> list[str]:
    async with _client() as c:
        r = await c.get("/api/audit", params={"actor": actor}, headers=_auth(token))
        assert r.status_code == 200, r.text
        return [e["actor"] for e in r.json()]


async def _org_of(entity_id: str) -> int | None:
    async with session_scope() as s:
        return (
            await s.execute(
                select(AuditLog.organization_id).where(AuditLog.entity_id == entity_id)
            )
        ).scalar_one()


async def _verify() -> dict:
    async with session_scope() as s:
        return await verify_chain(
            session=s,
            _principal=Principal(
                user_id=None, email="verify@audit-org-scope.test", org_id=None, role="admin"
            ),
        )


# --- 1. the exposure ---------------------------------------------------------


@pytest.mark.asyncio
async def test_record_event_row_is_not_readable_by_another_tenant(clean_chain: None) -> None:
    """An org-A event written via ``record_event`` must not reach an org-B admin.

    Both admins pass the identical ``require_role("admin", "assessor")`` gate,
    so the only thing that can separate them is the row's ``organization_id``
    under ``tenant_isolation``. With the column left NULL the policy's
    ``organization_id IS NULL`` clause publishes the row to every tenant.
    """
    _, org_a = await _mk_admin("owner@audit-org-scope.test", "Audit Org Scope A")
    token_b, org_b = await _mk_admin("intruder@audit-org-scope.test", "Audit Org Scope B")
    assert org_a != org_b

    await _record_as_tenant(org_a, "owner@audit-org-scope.test", "scoped-a")

    leaked = await _actors_visible_to(token_b, "owner@audit-org-scope.test")
    assert leaked == [], (
        f"org B's admin read org A's non-HTTP audit event: {leaked!r} "
        f"(row organization_id={await _org_of('scoped-a')!r}, org A={org_a})"
    )


# --- 2. a genuinely global event stays global --------------------------------


@pytest.mark.asyncio
async def test_a_global_event_stays_visible_to_every_tenant(clean_chain: None) -> None:
    """An event recorded on an unscoped session belongs to no tenant.

    ``session_scope`` (CLI/ETL) leaves the session unscoped, which is what a
    genuinely platform-wide operation runs as. Such a row stays NULL-org, and
    migration 0044's ``organization_id IS NULL`` clause is what keeps it
    readable by every tenant. Closing the exposure above by forcing an org onto
    these would both hide platform events from everyone and assert something
    false about who did what.
    """
    token_a, _ = await _mk_admin("owner@audit-org-scope.test", "Audit Org Scope A")
    token_b, _ = await _mk_admin("intruder@audit-org-scope.test", "Audit Org Scope B")

    await _record_unscoped("platform@audit-org-scope.test", "global-1")
    assert await _org_of("global-1") is None, "an unscoped event must not acquire an org"

    for token, who in ((token_a, "A"), (token_b, "B")):
        seen = await _actors_visible_to(token, "platform@audit-org-scope.test")
        assert seen == ["platform@audit-org-scope.test"], f"org {who} lost the global event"


# --- 3. the owner still reads its own ----------------------------------------


@pytest.mark.asyncio
async def test_the_owning_org_still_reads_its_own_events(clean_chain: None) -> None:
    """Scoping the row must not hide it from the organization it belongs to."""
    token_a, org_a = await _mk_admin("owner@audit-org-scope.test", "Audit Org Scope A")

    await _record_as_tenant(org_a, "owner@audit-org-scope.test", "scoped-own")

    seen = await _actors_visible_to(token_a, "owner@audit-org-scope.test")
    assert seen == ["owner@audit-org-scope.test"], "the owning org lost its own event"
    assert await _org_of("scoped-own") == org_a


# --- 4. the middleware is untouched ------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("authenticated", [True, False])
async def test_audit_middleware_org_resolution_is_unchanged(
    clean_chain: None, authenticated: bool
) -> None:
    """``audit_middleware`` already resolves the org from the principal.

    Asserted by equality against the exact expected value -- the principal's
    ``org_id`` for a real authenticated user, ``None`` for an unauthenticated
    request -- rather than by a truthiness or "is not None" check, which would
    pass for any org at all.
    """
    _, org_a = await _mk_admin("owner@audit-org-scope.test", "Audit Org Scope A")
    principal = (
        Principal(user_id=1, email="mw@audit-org-scope.test", org_id=org_a, role="admin")
        if authenticated
        else None
    )
    expected = org_a if authenticated else None

    await _drive_middleware(principal, "mw-1")

    async with session_scope() as s:
        row = (
            await s.execute(select(AuditLog).where(AuditLog.entity_type == _MW_ENTITY))
        ).scalar_one()
        assert row.organization_id == expected
        # ...and the org stayed out of the hash payload, for this row as written.
        content = {
            "actor": row.actor,
            "action": row.action,
            "entity_type": row.entity_type,
            "entity_id": row.entity_id,
            "diff": row.diff,
        }
        assert row.row_hash == row_hash(row.prev_hash or _GENESIS, content)


# --- 5. the chain is unaffected ----------------------------------------------


@pytest.mark.asyncio
async def test_chain_still_verifies_across_scoped_global_and_middleware_rows(
    clean_chain: None,
) -> None:
    """A mixed chain -- org A, global, org B, middleware -- must verify as one.

    ``organization_id`` is a scoping column deliberately outside the hash
    payload (migration 0044), so setting it may not perturb linkage in either
    direction.
    """
    _, org_a = await _mk_admin("owner@audit-org-scope.test", "Audit Org Scope A")
    _, org_b = await _mk_admin("intruder@audit-org-scope.test", "Audit Org Scope B")

    await _record_as_tenant(org_a, "owner@audit-org-scope.test", "mix-a")
    await _record_unscoped("platform@audit-org-scope.test", "mix-global")
    await _record_as_tenant(org_b, "intruder@audit-org-scope.test", "mix-b")
    await _drive_middleware(
        Principal(user_id=1, email="mw@audit-org-scope.test", org_id=org_a, role="admin"),
        "mix-mw",
    )

    # The chain must actually span both orgs, or this proves nothing.
    assert await _org_of("mix-a") == org_a
    assert await _org_of("mix-b") == org_b

    verdict = await _verify()
    assert verdict["ok"] is True, verdict
    assert verdict["checked"] == 4


@pytest.mark.asyncio
async def test_a_real_tamper_is_still_detected_on_a_scoped_chain(clean_chain: None) -> None:
    """Scoping rows may not be paid for with weaker tamper evidence."""
    _, org_a = await _mk_admin("owner@audit-org-scope.test", "Audit Org Scope A")
    _, org_b = await _mk_admin("intruder@audit-org-scope.test", "Audit Org Scope B")

    await _record_as_tenant(org_a, "owner@audit-org-scope.test", "tamper-1")
    await _record_as_tenant(org_b, "intruder@audit-org-scope.test", "tamper-2")
    assert (await _verify())["ok"] is True, "chain must be intact before tampering"

    async with session_scope() as s:
        row = (
            await s.execute(select(AuditLog).where(AuditLog.entity_id == "tamper-2"))
        ).scalar_one()
        row_id = row.id
        row.actor = "evil@attacker.test"

    verdict = await _verify()
    assert verdict["ok"] is False, "tampering with a tenant-scoped row went undetected"
    assert verdict["broken_at_id"] == row_id

    # Changing only the scoping column must NOT read as tamper: it is outside
    # the hash payload precisely so it can be corrected.
    async with session_scope() as s:
        row = (await s.execute(select(AuditLog).where(AuditLog.id == row_id))).scalar_one()
        row.actor = "intruder@audit-org-scope.test"
        row.organization_id = org_a
    assert (await _verify())["ok"] is True, "the scoping column must stay out of the chain"


# --- 6. pinned at the layer, not only over HTTP ------------------------------


@pytest.mark.asyncio
async def test_scoping_holds_against_the_database_not_only_over_http(
    clean_chain: None,
) -> None:
    """Asserted through a clamped session against the table itself.

    Every HTTP request session is tenant-clamped by ``ccf.api.deps.get_session``
    before a route ever runs, so an HTTP-only assertion cannot separate "the row
    carries the right org" from "RLS happened to hide it". This drives
    ``set_session_tenant`` directly and asserts both halves: the row's stored
    ``organization_id``, and what each clamped session can actually select.
    """
    _, org_a = await _mk_admin("owner@audit-org-scope.test", "Audit Org Scope A")
    _, org_b = await _mk_admin("intruder@audit-org-scope.test", "Audit Org Scope B")

    await _record_as_tenant(org_a, "owner@audit-org-scope.test", "layer-a")
    await _record_unscoped("platform@audit-org-scope.test", "layer-global")

    assert await _org_of("layer-a") == org_a
    assert await _org_of("layer-global") is None

    factory = get_session_factory()
    for org_id, expected in ((org_a, ["layer-a", "layer-global"]), (org_b, ["layer-global"])):
        async with factory() as s:
            await set_session_tenant(s, org_id)
            visible = sorted(
                (
                    await s.execute(
                        select(AuditLog.entity_id)
                        .where(AuditLog.entity_type == _ENTITY)
                        .order_by(AuditLog.entity_id)
                    )
                )
                .scalars()
                .all()
            )
            assert visible == sorted(expected), f"tenant {org_id} saw {visible}"


# --- 2b. the real global call site, driven from a tenant-clamped session -----


@pytest.mark.asyncio
@pytest.mark.usefixtures("isolate_source_rows")
async def test_adopting_a_catalog_revision_stays_global_on_a_clamped_session(
    clean_chain: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``adopt_revision`` is the hard case, so it is pinned on the real path.

    A ``CatalogRevision`` carries no ``organization_id`` and no RLS: adopting
    one moves a single deployment-wide pointer. But it is adopted by an *org
    admin*, over HTTP, on a session ``get_session`` has clamped to that admin's
    org -- so anything that inferred the event's tenant from the session would
    stamp the whole deployment's catalog change with whichever org happened to
    click the button, and hide it from every other tenant. It must stay NULL,
    and every tenant must still read it.
    """
    _, org_a = await _mk_admin("owner@audit-org-scope.test", "Audit Org Scope A")
    token_b, _ = await _mk_admin("intruder@audit-org-scope.test", "Audit Org Scope B")

    async def _empty_impact(session: object, **kw: object) -> AdoptionImpact:
        return AdoptionImpact()

    # An empty impact is forced rather than hoped for: the suite shares one
    # schema, so another module's content would otherwise make it non-empty
    # and adoption would refuse.
    monkeypatch.setattr(revisions_mod, "build_adoption_impact", _empty_impact)

    async with session_scope() as s:
        source = CatalogSource(
            key="audit_org_scope_adopt",
            name="audit_org_scope_adopt",
            kind="oscal_catalog",
            url="https://example.test/catalog.json",
        )
        s.add(source)
        await s.flush()
        rev = await materialize_revision(
            s,
            source=source,
            documents=_documents(),
            upstream_commit_sha="c" * 40,
            data_root=tmp_path,
        )
        rev_id = rev.id

    # Adopt on a session clamped to org A, exactly as the route does.
    factory = get_session_factory()
    async with factory() as s:
        await set_session_tenant(s, org_a)
        await adopt_revision(s, revision_id=rev_id, actor="owner@audit-org-scope.test")
        await s.commit()

    async with session_scope() as s:
        row = (
            await s.execute(
                select(AuditLog).where(
                    AuditLog.entity_type == "catalog_revision",
                    AuditLog.entity_id == str(rev_id),
                )
            )
        ).scalar_one()
        assert row.organization_id is None, (
            "adopting a catalog revision is deployment-wide; stamping it with the "
            "adopting admin's org hides it from every other tenant"
        )

    # ...and org B, which did nothing here, still learns the catalog moved.
    seen = await _actors_visible_to(token_b, "owner@audit-org-scope.test")
    assert seen == ["owner@audit-org-scope.test"]


# --- the classification itself must stay mandatory ---------------------------


def test_record_event_has_no_default_organization() -> None:
    """``organization_id`` must have no default, so no call site can omit it.

    This is the guard, not a style check. A default of ``None`` would be the
    exposure restored in slow motion: every future call site that forgot the
    argument would compile, pass review, and silently publish its tenant's
    events to every organization -- the ``organization_id IS NULL`` clause in
    migration 0044 makes "unset" and "visible to all" the same value. An
    omission has to be a ``TypeError``, loudly, at the call.
    """
    param = inspect.signature(record_event).parameters["organization_id"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY
    assert param.default is inspect.Parameter.empty

    # And the signature is really enforced, not merely declared.
    with pytest.raises(TypeError, match="organization_id"):
        record_event(
            object(), actor="a", action="create", entity_type=_ENTITY, entity_id="x", diff={}
        )


# --- the classification, made enforceable ------------------------------------

#: The ONLY audit events on this platform that belong to no tenant, as
#: ``module -> number of call sites``. Both are deployment-wide by construction
#: and say so at the call site:
#:
#: * ``ccf.catalog.revisions.adopt_revision`` -- a ``CatalogRevision`` has no
#:   ``organization_id`` and no RLS; adopting one moves a single pointer for the
#:   whole deployment, and the impact behind its 409 is computed across every
#:   org's content for exactly that reason.
#: * ``ccf.posture.retention.prune_resource_detail`` -- takes no ``org_id`` and
#:   deletes across every organization; its own docstring pins that contract.
#:
#: Everything else has a tenant and must name it.
_GLOBAL_CALL_SITES = {
    "src/ccf/catalog/revisions.py": 1,
    "src/ccf/posture/retention.py": 1,
}


def test_only_the_classified_global_call_sites_record_a_tenantless_event() -> None:
    """No audit call site may hardcode ``organization_id=None`` off this list.

    Requiring the argument (above) forces every call site to answer the
    question; it cannot force a *correct* answer, and the wrong one is silent.
    ``organization_id=None`` is not "unscoped" -- migration 0044's
    ``tenant_isolation`` predicate publishes a NULL-org row to every tenant --
    so a tenant-scoped call site that answers ``None`` re-opens the exposure at
    one subsystem instead of all of them, and nothing about it looks wrong in a
    diff.

    So the classification itself is the assertion: a literal ``None`` at an
    audit call site is a deliberate, enumerated act. A new global event has to
    be argued for here, in front of this comment, rather than typed. Call sites
    that pass an expression (``w.organization_id``, ``org_id``, ...) are not
    examined -- what they resolve to at runtime is what the behavioural tests
    above and in each subsystem's own suite are for.
    """
    literal_none: dict[str, int] = {}
    examined = 0
    for path in sorted(Path("src").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else None
            )
            if name not in ("record_event", "_audit"):
                continue
            examined += 1
            for kw in node.keywords:
                if kw.arg != "organization_id":
                    continue
                if isinstance(kw.value, ast.Constant) and kw.value.value is None:
                    literal_none[str(path)] = literal_none.get(str(path), 0) + 1

    # Guard the guard: if this stops finding call sites (a rename, a moved
    # module), it would pass vacuously forever.
    assert examined >= 35, f"only found {examined} audit call sites; the walk is broken"
    assert literal_none == _GLOBAL_CALL_SITES, (
        "audit call sites recording a tenantless event changed: "
        f"{literal_none} != {_GLOBAL_CALL_SITES}"
    )
