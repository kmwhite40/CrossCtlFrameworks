"""DATA-03: ``framework_controls`` tenant isolation + independent per-org upsert.

``ccf.framework_controls`` is a tenant-facing upload target
(``POST /api/framework-controls/{code}[/csv]`` ->
``ccf.api.routes.automation._upsert_controls``) that, before migration
0046, had no ``organization_id`` and a *global* unique key on
``(framework_code, identifier)`` — so one tenant's upload for a given
framework code silently overwrote another tenant's rows, and every tenant
could read every other tenant's uploaded controls via
``GET /api/framework-controls/{code}``.

This module proves the fix end-to-end at the layer that matters most: the
actual upload path (``_upsert_controls``), not just raw ORM inserts.
- Two tenants uploading the *same* ``framework_code`` with an overlapping
  ``identifier`` end up with two independent rows, neither clobbering the
  other (the old bug).
- A re-upload from one tenant only ever updates that tenant's own row.
- A NULL-org (global/seeded) row stays visible to both tenants and is never
  matched/overwritten by either tenant's upload.
- RLS enforces the same isolation at the DB layer even for a raw SELECT that
  doesn't go through the app's ``org_id`` filter.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from ccf.api.routes.automation import _upsert_controls
from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import FrameworkControl, Organization

pytestmark = pytest.mark.usefixtures("fresh_engine")

_CODE = "RLSCOVFW"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _seed_two_orgs() -> tuple[int, int]:
    async with session_scope() as s:  # unscoped (bypass) — full access
        ids: list[int] = []
        for org_name in ("FcOrgA", "FcOrgB"):
            org = (
                await s.execute(select(Organization).where(Organization.name == org_name))
            ).scalar_one_or_none() or Organization(name=org_name)
            if org.id is None:
                s.add(org)
                await s.flush()
            ids.append(org.id)
        return ids[0], ids[1]


@pytest.mark.asyncio
async def test_two_orgs_upload_same_framework_code_independently() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")

    org_a, org_b = await _seed_two_orgs()

    try:
        # A globally-shared/seeded reference row for the same framework code +
        # a shared identifier — written unscoped (organization_id=None), the
        # same shape a seed/ETL job would produce.
        async with session_scope() as s:
            await set_session_tenant(s, None)
            await _upsert_controls(
                s,
                _CODE,
                [{"identifier": "GLOBAL-01", "title": "Shared reference control"}],
                source="seed",
                org_id=None,
            )
            await s.commit()

        # Org A uploads AC-01 with its own title.
        async with session_scope() as s:
            await set_session_tenant(s, org_a)
            counts_a = await _upsert_controls(
                s,
                _CODE,
                [{"identifier": "AC-01", "title": "Org A's AC-01"}],
                source="json_upload",
                org_id=org_a,
            )
            await s.commit()
        assert counts_a == {"created": 1, "updated": 0}

        # Org B uploads the SAME identifier, AC-01, with a different title —
        # under the old global unique key this would have overwritten org A's
        # row (or the insert would have raced/failed on the unique
        # constraint). Now it must create an independent row.
        async with session_scope() as s:
            await set_session_tenant(s, org_b)
            counts_b = await _upsert_controls(
                s,
                _CODE,
                [{"identifier": "AC-01", "title": "Org B's AC-01"}],
                source="json_upload",
                org_id=org_b,
            )
            await s.commit()
        assert counts_b == {"created": 1, "updated": 0}

        # --- Isolation: each tenant sees only its own upload + the global row.
        async with session_scope() as s:
            await set_session_tenant(s, org_a)
            rows = (
                (
                    await s.execute(
                        select(FrameworkControl).where(FrameworkControl.framework_code == _CODE)
                    )
                )
                .scalars()
                .all()
            )
            by_ident = {r.identifier: r for r in rows}
            assert set(by_ident) == {"AC-01", "GLOBAL-01"}, "tenant A leaked/missing rows"
            assert by_ident["AC-01"].title == "Org A's AC-01"
            assert by_ident["AC-01"].organization_id == org_a
            assert by_ident["GLOBAL-01"].organization_id is None

        async with session_scope() as s:
            await set_session_tenant(s, org_b)
            rows = (
                (
                    await s.execute(
                        select(FrameworkControl).where(FrameworkControl.framework_code == _CODE)
                    )
                )
                .scalars()
                .all()
            )
            by_ident = {r.identifier: r for r in rows}
            assert set(by_ident) == {"AC-01", "GLOBAL-01"}, "tenant B leaked/missing rows"
            assert by_ident["AC-01"].title == "Org B's AC-01"
            assert by_ident["AC-01"].organization_id == org_b

        # --- Independent re-upload: org A updates its AC-01; org B's row (and
        # the global row) must be untouched.
        async with session_scope() as s:
            await set_session_tenant(s, org_a)
            counts_a2 = await _upsert_controls(
                s,
                _CODE,
                [{"identifier": "AC-01", "title": "Org A's AC-01 (revised)"}],
                source="json_upload",
                org_id=org_a,
            )
            await s.commit()
        assert counts_a2 == {"created": 0, "updated": 1}

        async with session_scope() as s:
            await set_session_tenant(s, None)  # unscoped bypass — see everything
            rows = (
                (
                    await s.execute(
                        select(FrameworkControl)
                        .where(
                            FrameworkControl.framework_code == _CODE,
                            FrameworkControl.identifier == "AC-01",
                        )
                        .order_by(FrameworkControl.organization_id)
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 2, "expected exactly two independent AC-01 rows (org A + org B)"
            titles_by_org = {r.organization_id: r.title for r in rows}
            assert titles_by_org[org_a] == "Org A's AC-01 (revised)"
            assert titles_by_org[org_b] == "Org B's AC-01", "org A's re-upload overwrote org B"

        # --- Raw RLS check (no app-layer org_id filter at all): a plain
        # SELECT under tenant B still can't see tenant A's row.
        async with session_scope() as s:
            await set_session_tenant(s, org_b)
            ids = (
                await s.execute(
                    select(FrameworkControl.id).where(
                        FrameworkControl.framework_code == _CODE,
                        FrameworkControl.organization_id == org_a,
                    )
                )
            ).scalars().all()
            assert ids == [], "RLS did not block a cross-tenant SELECT by organization_id"
    finally:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            await s.execute(
                delete(FrameworkControl).where(FrameworkControl.framework_code == _CODE)
            )


@pytest.mark.asyncio
async def test_two_global_rows_same_identifier_raise_integrity_error() -> None:
    """Migration 0047: two NULL-org (global) rows for the same
    ``(framework_code, identifier)`` must still collide.

    0046's ``(organization_id, framework_code, identifier)`` unique
    constraint defaults to Postgres' NULLS DISTINCT behavior, so two
    NULL-org rows no longer collide on that constraint alone — the partial
    unique index added in 0047 (``uq_framework_controls_global``, scoped to
    ``organization_id IS NULL``) restores the old global-uniqueness
    invariant for seeded/shared reference rows.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("partial unique index is a PostgreSQL feature")

    try:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            s.add(
                FrameworkControl(
                    organization_id=None,
                    framework_code=_CODE,
                    identifier="GLOBAL-DUP",
                    title="First global row",
                )
            )
        # First row committed. The second must collide with it on the
        # partial unique index — let the IntegrityError propagate out of
        # session_scope (which rolls back on exception) so pytest.raises
        # observes it cleanly rather than a session left needing rollback.
        with pytest.raises(IntegrityError):
            async with session_scope() as s:
                await set_session_tenant(s, None)
                s.add(
                    FrameworkControl(
                        organization_id=None,
                        framework_code=_CODE,
                        identifier="GLOBAL-DUP",
                        title="Second global row — must collide",
                    )
                )
                await s.flush()
    finally:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            await s.execute(
                delete(FrameworkControl).where(FrameworkControl.framework_code == _CODE)
            )
