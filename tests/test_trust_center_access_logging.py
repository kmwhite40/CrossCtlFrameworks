"""Access logging for FedRAMP Certification Data (CDS-TRC-ACL).

The portal log is append-only and keeps every row at least six months, for
every database role; each row names its grantee so deleting the principal or
the grant does not orphan it; refused credentials are logged; the provider
gets a per-grantee monthly summary and each party gets its own log.
"""

from __future__ import annotations

import csv
import io
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import DBAPIError

from ccf import portal
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, User
from ccf.models_cr26 import Cr26Document
from ccf.models_portal import ExternalAccessGrant, ExternalPortalAuditEvent, ExternalPrincipal
from ccf.portal import access_log

pytestmark = pytest.mark.usefixtures("fresh_engine")

E = ExternalPortalAuditEvent


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
def _auth_enabled() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


class World:
    def __init__(self) -> None:
        self.ids: dict[str, int] = {}
        self.admin: dict[str, str] = {}
        self.viewer: dict[str, str] = {}


async def _world() -> World:
    w = World()
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"acl-{tag}")
        s.add(org)
        await s.flush()
        shared = System(organization_id=org.id, name=f"Shared {tag}", certification_class="C")
        s.add(shared)
        await s.flush()
        tokens = {}
        for role in ("admin", "viewer"):
            u = User(
                email=f"{role}-{tag}@csp.example",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            tokens[role] = u.api_token
        s.add(
            Cr26Document(
                organization_id=org.id,
                system_id=shared.id,
                kind="sdr",
                document_key=None,
                document={"kind": "sdr"},
                ruleset_version="2026.10.13.01",
                schema_version="0.1.1",
                is_valid=True,
                validation_errors=[],
            )
        )
        w.ids.update(org=org.id, shared=shared.id)
        w.admin = {"Authorization": f"Bearer {tokens['admin']}"}
        w.viewer = {"Authorization": f"Bearer {tokens['viewer']}"}
    return w


async def _grant(c: AsyncClient, w: World, **kw: Any) -> dict[str, Any]:
    body = {
        "organization_id": w.ids["org"],
        "principal_name": "Department of Examples",
        "organization_name": "DoE",
        "kind": "agency",
        "certification_system_ids": [w.ids["shared"]],
        **kw,
    }
    r = await c.post("/api/admin/portal/grants", json=body, headers=w.admin)
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()
    return out


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _events(grant_id: int, action: str | None = None) -> list[ExternalPortalAuditEvent]:
    async with session_scope() as s:
        q = select(E).where(E.grant_id == grant_id).order_by(E.id)
        if action is not None:
            q = q.where(E.action == action)
        return list((await s.execute(q)).scalars().all())


async def _one_event(w: World) -> int:
    async with session_scope() as s:
        g = await portal.create_grant(
            s,
            org_id=w.ids["org"],
            principal_name="Dept",
            kind="agency",
            certification_system_ids=[w.ids["shared"]],
        )
        await portal.record_access(s, g, action="view")
        eid = (await s.execute(select(func.max(E.id)).where(E.grant_id == g.id))).scalar_one()
    return int(eid)


# ── append-only, six months, every role ───────────────────────────────────


@pytest.mark.asyncio
async def test_no_role_can_alter_a_logged_event() -> None:
    """On an unscoped (superuser) session: the trigger, not the REVOKE, refuses."""
    eid = await _one_event(await _world())
    with pytest.raises(DBAPIError, match="append-only"):
        async with session_scope() as s:
            await s.execute(update(E).where(E.id == eid).values(action="download"))
    with pytest.raises(DBAPIError, match="append-only"):
        async with session_scope() as s:
            await s.execute(update(E).where(E.id == eid).values(grantee_name="Someone else"))


@pytest.mark.asyncio
async def test_a_live_grants_events_cannot_be_detached_from_it() -> None:
    """Nulling ``grant_id`` is allowed only as the foreign key's own action,
    after the grant is gone; done by hand it would drop the events from the
    party's log."""
    eid = await _one_event(await _world())
    with pytest.raises(DBAPIError, match="append-only"):
        async with session_scope() as s:
            await s.execute(update(E).where(E.id == eid).values(grant_id=None))


@pytest.mark.asyncio
async def test_the_log_cannot_be_truncated() -> None:
    await _one_event(await _world())
    with pytest.raises(DBAPIError, match="cannot be truncated"):
        async with session_scope() as s:
            await s.execute(text("TRUNCATE ccf.external_portal_audit_events"))


@pytest.mark.asyncio
async def test_hard_deleting_an_organization_with_recent_history_is_refused() -> None:
    w = await _world()
    await _one_event(w)
    with pytest.raises(DBAPIError, match="six-month retention"):
        async with session_scope() as s:
            await s.execute(delete(Organization).where(Organization.id == w.ids["org"]))


@pytest.mark.asyncio
async def test_an_event_younger_than_six_months_cannot_be_deleted() -> None:
    eid = await _one_event(await _world())
    with pytest.raises(DBAPIError, match="six-month retention"):
        async with session_scope() as s:
            await s.execute(delete(E).where(E.id == eid))


@pytest.mark.asyncio
async def test_an_event_older_than_six_months_may_be_deleted() -> None:
    w = await _world()
    async with session_scope() as s:
        s.add(
            E(
                organization_id=w.ids["org"],
                action="view",
                created_at=datetime.now(UTC) - timedelta(days=200),
            )
        )
        await s.flush()
        old = (await s.execute(select(func.max(E.id)))).scalar_one()
    async with session_scope() as s:
        await s.execute(delete(E).where(E.id == old))
    async with session_scope() as s:
        assert await s.get(E, old) is None


@pytest.mark.asyncio
async def test_the_application_role_holds_insert_but_not_update_or_delete() -> None:
    async with session_scope() as s:
        privs = {
            p: (
                await s.execute(
                    text(
                        "SELECT has_table_privilege('ccf_app', "
                        "'ccf.external_portal_audit_events', :p)"
                    ),
                    {"p": p},
                )
            ).scalar_one()
            for p in ("INSERT", "SELECT", "UPDATE", "DELETE")
        }
    assert privs == {"INSERT": True, "SELECT": True, "UPDATE": False, "DELETE": False}


# ── the grantee is named on the row ───────────────────────────────────────


@pytest.mark.asyncio
async def test_deleting_the_principal_and_the_grant_leaves_the_history_named(
    _auth_enabled: None,
) -> None:
    w = await _world()
    async with _client() as c:
        g = await _grant(c, w)
        await c.get("/api/portal/certification-data", headers=_bearer(g["token"]))
    async with session_scope() as s:
        grant = await s.get(ExternalAccessGrant, g["id"])
        assert grant is not None
        principal_id = grant.principal_id
        ids = [e.id for e in await _events(g["id"])]
        await s.execute(delete(ExternalPrincipal).where(ExternalPrincipal.id == principal_id))
        # The foreign key's own SET NULL is the one UPDATE the trigger allows.
        await s.execute(delete(ExternalAccessGrant).where(ExternalAccessGrant.id == g["id"]))
    async with session_scope() as s:
        rows = (await s.execute(select(E).where(E.id.in_(ids)))).scalars().all()
    assert len(rows) == len(ids) >= 2
    for e in rows:
        assert e.grant_id is None
        assert (e.grantee_name, e.grantee_kind, e.grantee_organization) == (
            "Department of Examples",
            "agency",
            "DoE",
        )


# ── refused credentials are logged ────────────────────────────────────────


async def _revoke(c: AsyncClient, w: World, g: dict[str, Any]) -> None:
    r = await c.post(f"/api/admin/portal/grants/{g['id']}/revoke", headers=w.admin)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_a_revoked_or_expired_token_is_logged_as_refused(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        revoked = await _grant(c, w)
        expired = await _grant(c, w)
        await _revoke(c, w, revoked)
        async with session_scope() as s:
            await s.execute(
                update(ExternalAccessGrant)
                .where(ExternalAccessGrant.id == expired["id"])
                .values(expires_at=datetime.now(UTC) - timedelta(days=1))
            )
        for g in (revoked, expired):
            r = await c.get("/api/portal/certification-data", headers=_bearer(g["token"]))
            assert r.status_code == 401
    assert [e.detail for e in await _events(revoked["id"], "refused")] == ["revoked"]
    assert [e.detail for e in await _events(expired["id"], "refused")] == ["expired"]


@pytest.mark.asyncio
async def test_a_revoked_link_token_is_logged(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        g = await _grant(c, w)
        await _revoke(c, w, g)
        page = await c.get("/portal", params={"token": g["token"]})
    assert page.status_code == 200
    assert [e.detail for e in await _events(g["id"], "refused")] == ["revoked"]


@pytest.mark.asyncio
async def test_a_cookie_for_a_revoked_grant_is_logged_against_that_grant(
    _auth_enabled: None,
) -> None:
    """Both cookie paths, each on its own grant so neither hides behind the throttle."""
    w = await _world()
    async with _client() as c:
        via_api, via_page = await _grant(c, w), await _grant(c, w)
        jars = {}
        for g in (via_api, via_page):
            mint = await c.get("/portal", params={"token": g["token"]}, follow_redirects=False)
            jars[g["id"]] = mint.cookies
            await _revoke(c, w, g)
        api = await c.get("/api/portal/session", cookies=jars[via_api["id"]])
        page = await c.get("/portal", cookies=jars[via_page["id"]])
    assert api.status_code == 401
    assert page.status_code == 200
    assert [e.detail for e in await _events(via_api["id"], "refused")] == ["revoked"]
    assert [e.detail for e in await _events(via_page["id"], "refused")] == ["revoked"]


@pytest.mark.asyncio
async def test_a_replayed_dead_token_is_logged_once_per_window(_auth_enabled: None) -> None:
    """The log cannot be pruned for six months, so a former grantee replaying a
    dead token must not grow it at will: one record per grant, reason and window."""
    w = await _world()
    async with _client() as c:
        g = await _grant(c, w)
        await _revoke(c, w, g)
        for _ in range(5):
            r = await c.get("/api/portal/certification-data", headers=_bearer(g["token"]))
            assert r.status_code == 401
    assert len(await _events(g["id"], "refused")) == 1


@pytest.mark.asyncio
async def test_a_refusal_older_than_the_window_does_not_suppress_a_new_one(
    _auth_enabled: None,
) -> None:
    w = await _world()
    async with _client() as c:
        g = await _grant(c, w)
        await _revoke(c, w, g)
        async with session_scope() as s:
            s.add(
                E(
                    organization_id=w.ids["org"],
                    grant_id=g["id"],
                    action="refused",
                    detail="revoked",
                    created_at=datetime.now(UTC)
                    - portal.service.REFUSAL_LOG_WINDOW
                    - timedelta(minutes=1),
                )
            )
        await c.get("/api/portal/certification-data", headers=_bearer(g["token"]))
    assert len(await _events(g["id"], "refused")) == 2


@pytest.mark.asyncio
async def test_an_unknown_token_names_no_party_and_logs_nothing(_auth_enabled: None) -> None:
    async with session_scope() as s:
        before = (await s.execute(select(func.count()).where(E.action == "refused"))).scalar_one()
    async with _client() as c:
        r = await c.get("/api/portal/certification-data", headers=_bearer("not-a-token"))
    assert r.status_code == 401
    async with session_scope() as s:
        after = (await s.execute(select(func.count()).where(E.action == "refused"))).scalar_one()
    assert after == before


# ── the provider's summary ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_summary_counts_access_per_grantee_and_leaves_out_admin_actions(
    _auth_enabled: None,
) -> None:
    w = await _world()
    async with _client() as c:
        g = await _grant(c, w)
        bearer = _bearer(g["token"])
        base = f"/api/portal/certification-data/{w.ids['shared']}"
        await c.get("/api/portal/certification-data", headers=bearer)
        await c.get(f"{base}/sdr", headers=bearer)
        await c.get(f"{base}/sdr", params={"format": "md"}, headers=bearer)
        await c.get(f"{base}/cpo", headers=bearer)  # denied
        await c.post(f"/api/admin/portal/grants/{g['id']}/revoke", headers=w.admin)
        await c.get("/api/portal/certification-data", headers=bearer)  # refused
        r = await c.get(
            "/api/admin/portal/access-log-summary",
            params={"organization_id": w.ids["org"]},
            headers=w.admin,
        )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["rule"] == "CDS-TRC-ACL"
    assert out["statement"].startswith("Trust centers MUST log access")
    assert out["oldest_event_at"] is not None
    month = datetime.now(UTC).strftime("%Y-%m")
    rows = {row["target_type"]: row for row in out["rows"]}
    cert = rows["certification_data"]
    assert (cert["month"], cert["grant_id"], cert["grantee_name"], cert["grantee_kind"]) == (
        month,
        g["id"],
        "Department of Examples",
        "agency",
    )
    assert (cert["view"], cert["download"], cert["denied"]) == (1, 2, 1)
    assert rows[None]["refused"] == 1
    # "issued" and "revoked" are what the provider did, not access.
    assert all(row["other"] == 0 for row in out["rows"])
    assert sum(sum(row[a] for a in access_log.ACCESS_ACTIONS) for row in out["rows"]) == 5


@pytest.mark.asyncio
async def test_the_summary_csv_and_its_since_filter(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        g = await _grant(c, w, principal_name="=cmd|' /C calc'!A0")
        await c.get("/api/portal/certification-data", headers=_bearer(g["token"]))
        r = await c.get(
            "/api/admin/portal/access-log-summary",
            params={"organization_id": w.ids["org"], "fmt": "csv"},
            headers=w.admin,
        )
        later = await c.get(
            "/api/admin/portal/access-log-summary",
            params={
                "organization_id": w.ids["org"],
                "since": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            },
            headers=w.admin,
        )
    rows = list(csv.reader(io.StringIO(r.text)))
    assert tuple(rows[0]) == access_log.SUMMARY_FIELDS
    rec = dict(zip(access_log.SUMMARY_FIELDS, rows[1], strict=True))
    assert rec["grantee_name"] == "'=cmd|' /C calc'!A0"
    assert later.json()["rows"] == []


@pytest.mark.asyncio
async def test_the_summary_never_includes_another_organization() -> None:
    """The service's own org filter, on an unscoped session where RLS cannot mask it."""
    mine, theirs = await _world(), await _world()
    await _one_event(mine)
    await _one_event(theirs)
    async with session_scope() as s:
        out = await access_log.summary(s, org_id=mine.ids["org"])
        their_grants = set(
            (
                await s.execute(
                    select(ExternalAccessGrant.id).where(
                        ExternalAccessGrant.organization_id == theirs.ids["org"]
                    )
                )
            ).scalars()
        )
    assert out["rows"]
    assert not their_grants & {r["grant_id"] for r in out["rows"]}


@pytest.mark.asyncio
async def test_only_an_admin_of_that_organization_gets_the_summary(_auth_enabled: None) -> None:
    mine, theirs = await _world(), await _world()
    async with _client() as c:
        viewer = await c.get(
            "/api/admin/portal/access-log-summary",
            params={"organization_id": mine.ids["org"]},
            headers=mine.viewer,
        )
        foreign = await c.get(
            "/api/admin/portal/access-log-summary",
            params={"organization_id": theirs.ids["org"]},
            headers=mine.admin,
        )
        bad = await c.get(
            "/api/admin/portal/access-log-summary",
            params={"organization_id": mine.ids["org"], "fmt": "xml"},
            headers=mine.admin,
        )
    assert (viewer.status_code, foreign.status_code, bad.status_code) == (403, 403, 422)


@pytest.mark.asyncio
async def test_an_unscoped_caller_must_name_the_organization_for_the_summary() -> None:
    async with _client() as c:
        r = await c.get("/api/admin/portal/access-log-summary")
    assert r.status_code == 422


# ── each party's own log ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_party_sees_its_own_log_and_no_one_elses(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        mine = await _grant(c, w)
        other = await _grant(c, w, principal_name="Another Agency")
        await c.get("/api/portal/certification-data", headers=_bearer(other["token"]))
        await c.get("/api/portal/certification-data", headers=_bearer(mine["token"]))
        r = await c.get("/api/portal/access-log", headers=_bearer(mine["token"]))
        anon = await c.get("/api/portal/access-log")
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["grant_id"] == mine["id"]
    actions = [(e["action"], e["target_type"]) for e in out["events"]]
    assert ("view", "certification_data") in actions
    assert ("issued", None) in actions
    assert len(out["events"]) == len(await _events(mine["id"])) - 1  # not its own read yet
    assert anon.status_code == 401
    # Reading the log is itself logged.
    assert [e.target_type for e in await _events(mine["id"], "view")][-1] == "access_log"
