"""Inventory and history of access to FedRAMP Certification Data (CDS-TRC-AAI).

A grant records who issued it and who revoked it, and when; the first
revocation is the one kept. The inventory lists every grant that covers or
covered certification data -- ended ones included -- with its downloads, and
exports as CSV (formula-safe) and JSON (with the pinned rule text).
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
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from ccf import portal
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, User
from ccf.models_cr26 import Cr26Document
from ccf.models_portal import ExternalAccessGrant, ExternalPrincipal
from ccf.portal import inventory

pytestmark = pytest.mark.usefixtures("fresh_engine")


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
        self.admin_email = ""


async def _world() -> World:
    w = World()
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"aai-{tag}")
        s.add(org)
        await s.flush()
        shared = System(organization_id=org.id, name=f"Shared {tag}", certification_class="C")
        s.add(shared)
        await s.flush()
        users = {}
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
            users[role] = u
        await s.flush()
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
        w.admin = {"Authorization": f"Bearer {users['admin'].api_token}"}
        w.viewer = {"Authorization": f"Bearer {users['viewer'].api_token}"}
        w.admin_email = users["admin"].email
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


async def _inventory(c: AsyncClient, w: World, **params: Any) -> Any:
    r = await c.get(
        "/api/admin/portal/certification-access-inventory",
        params={"organization_id": w.ids["org"], **params},
        headers=w.admin,
    )
    assert r.status_code == 200, r.text
    return r


# ── the grant records its own history ─────────────────────────────────────


@pytest.mark.asyncio
async def test_issuing_and_revoking_record_who_and_when(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        g = await _grant(c, w)
        before = datetime.now(UTC)
        r = await c.post(f"/api/admin/portal/grants/{g['id']}/revoke", headers=w.admin)
        assert r.status_code == 200, r.text
        listed = await c.get(
            "/api/admin/portal/grants", params={"organization_id": w.ids["org"]}, headers=w.admin
        )
    row = next(x for x in listed.json() if x["id"] == g["id"])
    assert row["issued_by"] == w.admin_email
    assert row["revoked_by"] == w.admin_email
    revoked_at = datetime.fromisoformat(row["revoked_at"])
    assert before - timedelta(seconds=5) <= revoked_at <= datetime.now(UTC)


@pytest.mark.asyncio
async def test_revoking_again_does_not_rewrite_the_first_revocation() -> None:
    w = await _world()
    async with session_scope() as s:
        g = await portal.create_grant(
            s,
            org_id=w.ids["org"],
            principal_name="Dept",
            kind="agency",
            certification_system_ids=[w.ids["shared"]],
            actor="issuer@csp.example",
        )
        gid = g.id
    async with session_scope() as s:
        assert await portal.revoke_grant(s, gid, actor="first@csp.example")
    async with session_scope() as s:
        first = await s.get(ExternalAccessGrant, gid)
        assert first is not None
        first_at = first.revoked_at
    async with session_scope() as s:
        assert await portal.revoke_grant(s, gid, actor="second@csp.example")
    async with session_scope() as s:
        again = await s.get(ExternalAccessGrant, gid)
    assert again is not None
    assert again.revoked_by == "first@csp.example"
    assert again.revoked_at == first_at
    assert again.issued_by == "issuer@csp.example"


@pytest.mark.asyncio
async def test_a_revocation_time_on_a_live_grant_is_refused_by_the_database() -> None:
    w = await _world()
    async with session_scope() as s:
        g = await portal.create_grant(
            s,
            org_id=w.ids["org"],
            principal_name="Dept",
            kind="agency",
            certification_system_ids=[w.ids["shared"]],
        )
        gid = g.id
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            await s.execute(
                update(ExternalAccessGrant)
                .where(ExternalAccessGrant.id == gid)
                .values(revoked_at=datetime.now(UTC))
            )


# ── the inventory ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_inventory_keeps_ended_grants_and_omits_ones_without_certification_data(
    _auth_enabled: None,
) -> None:
    w = await _world()
    async with _client() as c:
        live = await _grant(c, w)
        ended = await _grant(c, w, principal_name="Dept of Former Access")
        await _grant(c, w, principal_name="Package Only", certification_system_ids=[])
        assessor = await _grant(c, w, principal_name="3PAO Firm", kind="assessor")
        await c.post(f"/api/admin/portal/grants/{ended['id']}/revoke", headers=w.admin)
        everyone = (await _inventory(c, w)).json()
        agencies = (await _inventory(c, w, kind="agency")).json()
        bad = await c.get(
            "/api/admin/portal/certification-access-inventory",
            params={"organization_id": w.ids["org"], "kind": "pirate"},
            headers=w.admin,
        )
    by_id = {g["grant_id"]: g for g in everyone["grants"]}
    assert set(by_id) == {live["id"], ended["id"], assessor["id"]}
    assert by_id[live["id"]]["status"] == "active"
    assert by_id[ended["id"]]["status"] == "revoked"
    assert by_id[ended["id"]]["revoked_by"] == w.admin_email
    assert by_id[live["id"]]["principal_organization"] == "DoE"
    assert by_id[live["id"]]["systems"] == [
        {"id": w.ids["shared"], "name": by_id[live["id"]]["systems"][0]["name"], "deleted": False}
    ]
    assert {g["grant_id"] for g in agencies["grants"]} == {live["id"], ended["id"]}
    assert bad.status_code == 422


@pytest.mark.asyncio
async def test_downloads_count_only_certification_data_reads(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        g = await _grant(c, w)
        bearer = {"Authorization": f"Bearer {g['token']}"}
        base = f"/api/portal/certification-data/{w.ids['shared']}"
        assert (await c.get(f"{base}/sdr", headers=bearer)).status_code == 200
        assert (
            await c.get(f"{base}/sdr", params={"format": "md"}, headers=bearer)
        ).status_code == 200
        assert (await c.get(f"{base}/cpo", headers=bearer)).status_code == 404  # denied
        await c.get("/api/portal/certification-data", headers=bearer)  # a view, not a download
        async with session_scope() as s:
            # A package or evidence download is not access to certification data.
            grant = await s.get(ExternalAccessGrant, g["id"])
            assert grant is not None
            await portal.record_access(
                s, grant, action="download", target_type="evidence", target_id="1"
            )
        row = (await _inventory(c, w)).json()["grants"][0]
    assert row["downloads"] == 2
    assert row["first_accessed_at"] is not None
    assert row["first_accessed_at"] <= row["last_accessed_at"]


@pytest.mark.asyncio
async def test_a_deleted_system_stays_in_the_history_by_name(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        await _grant(c, w)
        async with session_scope() as s:
            sysm = await s.get(System, w.ids["shared"])
            assert sysm is not None
            sysm.deleted_at = datetime.now(UTC)
            name = sysm.name
        row = (await _inventory(c, w)).json()["grants"][0]
        text = (await _inventory(c, w, fmt="csv")).text
    assert row["systems"] == [{"id": w.ids["shared"], "name": name, "deleted": True}]
    assert f"{name} (deleted)" in text


@pytest.mark.asyncio
async def test_another_organizations_grants_never_appear() -> None:
    """The service's own org filter, on an unscoped session where RLS cannot mask it."""
    mine, theirs = await _world(), await _world()
    async with session_scope() as s:
        for w in (mine, theirs):
            await portal.create_grant(
                s,
                org_id=w.ids["org"],
                principal_name="Dept",
                kind="agency",
                certification_system_ids=[w.ids["shared"]],
            )
    async with session_scope() as s:
        rows = await inventory.access_inventory(s, org_id=mine.ids["org"])
        their_ids = set(
            (
                await s.execute(
                    select(ExternalAccessGrant.id).where(
                        ExternalAccessGrant.organization_id == theirs.ids["org"]
                    )
                )
            ).scalars()
        )
    assert rows and not their_ids & {r["grant_id"] for r in rows}


@pytest.mark.asyncio
async def test_only_an_admin_of_that_organization_may_export(_auth_enabled: None) -> None:
    mine, theirs = await _world(), await _world()
    async with _client() as c:
        viewer = await c.get(
            "/api/admin/portal/certification-access-inventory",
            params={"organization_id": mine.ids["org"]},
            headers=mine.viewer,
        )
        foreign = await c.get(
            "/api/admin/portal/certification-access-inventory",
            params={"organization_id": theirs.ids["org"]},
            headers=mine.admin,
        )
        bad_fmt = await c.get(
            "/api/admin/portal/certification-access-inventory",
            params={"organization_id": mine.ids["org"], "fmt": "xlsx"},
            headers=mine.admin,
        )
    assert viewer.status_code == 403
    assert foreign.status_code == 403
    assert bad_fmt.status_code == 422


# ── the exports ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_json_names_the_rule_as_pinned(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        await _grant(c, w)
        out = (await _inventory(c, w)).json()
    assert out["rule"] == "CDS-TRC-AAI"
    assert out["statement"].startswith("Trust centers MUST maintain an inventory and history")
    assert out["rules_version"] == "2026.10.13.01"
    assert out["count"] == 1
    assert set(out["grants"][0]) == set(inventory.FIELDS)


@pytest.mark.asyncio
async def test_the_csv_has_the_fields_in_order_and_no_live_formulas(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        await _grant(
            c,
            w,
            principal_name='=HYPERLINK("http://evil.example","x")',
            organization_name="@SUM(1)",
            label="-2+3",
        )
        r = await _inventory(c, w, fmt="csv")
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    assert tuple(rows[0]) == inventory.FIELDS
    rec = dict(zip(inventory.FIELDS, rows[1], strict=True))
    assert rec["principal_name"] == '\'=HYPERLINK("http://evil.example","x")'
    assert rec["principal_organization"] == "'@SUM(1)"
    assert rec["label"] == "'-2+3"
    assert rec["issued_by"] == w.admin_email
    assert rec["revoked_at"] == ""


def test_every_formula_lead_is_neutralized() -> None:
    for lead in ("=", "+", "-", "@", "\t", "\r"):
        assert inventory.csv_cell(f"{lead}1") == f"'{lead}1"
    assert inventory.csv_cell("Department") == "Department"
    assert inventory.csv_cell(None) == ""


# ── the page ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_admin_page_shows_the_inventory_and_unrecorded_history(
    _auth_enabled: None,
) -> None:
    w = await _world()
    async with _client() as c:
        g = await _grant(c, w)
        async with session_scope() as s:
            # A grant from before 0108 with no audit event to backfill from.
            await s.execute(
                update(ExternalAccessGrant)
                .where(ExternalAccessGrant.id == g["id"])
                .values(issued_by=None)
            )
        page = await c.get(
            "/admin/portal", params={"organization_id": w.ids["org"]}, headers=w.admin
        )
    assert page.status_code == 200, page.text
    assert "Certification data access" in page.text
    assert "CDS-TRC-AAI" in page.text
    assert "issuer not recorded" in page.text
    assert "certification-access-inventory?organization_id=" in page.text


@pytest.mark.asyncio
async def test_an_unscoped_caller_must_name_the_organization() -> None:
    """With auth off the caller is global: no organization means no answer,
    not an empty inventory that reads as "nobody has access"."""
    async with _client() as c:
        r = await c.get("/api/admin/portal/certification-access-inventory")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_a_grant_whose_certification_list_is_empty_or_null_is_not_listed() -> None:
    """``scope -> 'certification_system_ids'`` is SQL-not-NULL for ``[]`` and for
    JSON ``null``; neither shares anything, so neither is in the inventory."""
    w = await _world()
    async with session_scope() as s:
        principal = ExternalPrincipal(organization_id=w.ids["org"], kind="agency", name="Legacy")
        s.add(principal)
        await s.flush()
        for value in ([], None):
            s.add(
                ExternalAccessGrant(
                    organization_id=w.ids["org"],
                    principal_id=principal.id,
                    kind="agency",
                    token=uuid.uuid4().hex,
                    scope={"certification_system_ids": value},
                )
            )
    async with session_scope() as s:
        assert await inventory.access_inventory(s, org_id=w.ids["org"]) == []


# ── the independent review's findings ────────────────────────────────────


@pytest.mark.asyncio
async def test_a_grant_cannot_carry_a_kind_its_principal_does_not_have(_auth_enabled: None) -> None:
    """Reusing an agency principal with the body's default kind ("customer")
    would hide the agency from ``kind=agency`` -- refused, not stored."""
    w = await _world()
    async with _client() as c:
        first = await _grant(c, w)
        async with session_scope() as s:
            g = await s.get(ExternalAccessGrant, first["id"])
            assert g is not None
            agency_principal = g.principal_id
        r = await c.post(
            "/api/admin/portal/grants",
            json={
                "organization_id": w.ids["org"],
                "principal_name": "",
                "principal_id": agency_principal,
                "certification_system_ids": [w.ids["shared"]],
            },
            headers=w.admin,
        )
    assert r.status_code == 422
    assert "agency" in r.json()["detail"]


@pytest.mark.asyncio
async def test_the_inventory_reports_the_principals_kind() -> None:
    """A row written before the issuance check, whose grant kind disagrees with
    its principal, is reported and filtered by who the principal is."""
    w = await _world()
    async with session_scope() as s:
        principal = ExternalPrincipal(organization_id=w.ids["org"], kind="agency", name="Agency")
        s.add(principal)
        await s.flush()
        s.add(
            ExternalAccessGrant(
                organization_id=w.ids["org"],
                principal_id=principal.id,
                kind="customer",
                token=uuid.uuid4().hex,
                scope={"certification_system_ids": [w.ids["shared"]]},
            )
        )
    async with session_scope() as s:
        rows = await inventory.access_inventory(s, org_id=w.ids["org"], kind="agency")
    assert [r["principal_kind"] for r in rows] == ["agency"]


@pytest.mark.asyncio
async def test_listing_the_documents_counts_as_access(_auth_enabled: None) -> None:
    """The index already shows each document's title and digest: an agency that
    only lists has accessed certification data, and must not read as "never"."""
    w = await _world()
    async with _client() as c:
        g = await _grant(c, w)
        await c.get(
            "/api/portal/certification-data", headers={"Authorization": f"Bearer {g['token']}"}
        )
        row = (await _inventory(c, w)).json()["grants"][0]
    assert row["downloads"] == 0
    assert row["first_accessed_at"] is not None
    assert row["last_accessed_at"] is not None


@pytest.mark.asyncio
async def test_a_grant_whose_systems_are_all_deleted_does_not_read_as_active(
    _auth_enabled: None,
) -> None:
    w = await _world()
    async with _client() as c:
        await _grant(c, w)
        async with session_scope() as s:
            sysm = await s.get(System, w.ids["shared"])
            assert sysm is not None
            sysm.deleted_at = datetime.now(UTC)
        row = (await _inventory(c, w)).json()["grants"][0]
    assert row["status"] == "systems deleted"


def test_revoke_locks_the_row_before_deciding() -> None:
    """Two concurrent revokes must not both see ``revoked=False``: the read that
    decides is ``SELECT ... FOR UPDATE``. Pinned on the source because a race
    test against one connection pool is not deterministic."""
    import inspect  # noqa: PLC0415

    src = inspect.getsource(portal.revoke_grant)
    assert "with_for_update()" in src
    assert "session.get(ExternalAccessGrant" not in src
