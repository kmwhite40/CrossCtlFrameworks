"""Pin migration 0108's backfill of grant issuance and revocation history.

A downgrade to 0107 drops ``issued_by``/``revoked_at``/``revoked_by``; the
re-upgrade must recover them from the audit log -- actor and time from the
same event -- and must leave a revoked grant with no event unrecorded rather
than invent a date. Deleting either backfill ``UPDATE`` must fail this test.

Shared database: the downgrade drops these three columns for every grant other
modules wrote. Every one of those written through ``portal.service`` has the
audit events the backfill reads, and the module snapshots and restores the
rest, so it leaves the database as it found it.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from ccf import portal
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_portal import ExternalAccessGrant, ExternalPrincipal

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _cfg() -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    return cfg


@pytest.mark.asyncio
async def test_migration_0108_backfills_history_from_the_audit_log() -> None:
    cfg = _cfg()
    command.upgrade(cfg, "head")

    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"m0108-{tag}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"S {tag}")
        s.add(sysm)
        await s.flush()
        audited = await portal.create_grant(
            s,
            org_id=org.id,
            principal_name="Dept",
            kind="agency",
            certification_system_ids=[sysm.id],
            actor="issuer@csp.example",
        )
        live = await portal.create_grant(
            s,
            org_id=org.id,
            principal_name="Dept 2",
            kind="agency",
            certification_system_ids=[sysm.id],
            actor="issuer2@csp.example",
        )
        await portal.revoke_grant(s, audited.id, actor="revoker@csp.example")
        # Revoked with no audit event behind it: what a pre-0108 row written
        # outside the service looks like.
        principal = ExternalPrincipal(organization_id=org.id, kind="agency", name="Silent")
        s.add(principal)
        await s.flush()
        silent = ExternalAccessGrant(
            organization_id=org.id,
            principal_id=principal.id,
            kind="agency",
            token=uuid.uuid4().hex,
            revoked=True,
            scope={"certification_system_ids": [sysm.id]},
        )
        s.add(silent)
        await s.flush()
        ids = {"audited": audited.id, "live": live.id, "silent": silent.id}
        original_revoked_at = audited.revoked_at

    async with session_scope() as s:
        snapshot = {
            row.id: row
            for row in (
                await s.execute(
                    text(
                        "SELECT id, issued_by, revoked_at, revoked_by "
                        "FROM ccf.external_access_grants WHERE id <> ALL(:mine)"
                    ),
                    {"mine": list(ids.values())},
                )
            ).all()
        }

    command.downgrade(cfg, "0107_vulnerability_evaluations")
    command.upgrade(cfg, "head")
    async with session_scope() as s:
        for gid, row in snapshot.items():
            await s.execute(
                text(
                    "UPDATE ccf.external_access_grants SET "
                    "issued_by = coalesce(issued_by, :ib), "
                    "revoked_at = coalesce(revoked_at, :ra), "
                    "revoked_by = coalesce(revoked_by, :rb) WHERE id = :id"
                ),
                {"ib": row.issued_by, "ra": row.revoked_at, "rb": row.revoked_by, "id": gid},
            )

    async with session_scope() as s:
        got = {k: await s.get(ExternalAccessGrant, v) for k, v in ids.items()}
        event_at = (
            await s.execute(
                text(
                    "SELECT at FROM ccf.audit_log WHERE entity_type = 'external_grant' "
                    "AND action = 'delete' AND entity_id = :id"
                ),
                {"id": str(ids["audited"])},
            )
        ).scalar_one()

    a, live_g, silent_g = got["audited"], got["live"], got["silent"]
    assert a is not None and live_g is not None and silent_g is not None
    assert a.issued_by == "issuer@csp.example"
    assert a.revoked_by == "revoker@csp.example"
    assert a.revoked_at == event_at  # the same event's time, not a new one
    assert original_revoked_at is not None
    assert abs(a.revoked_at - original_revoked_at) < timedelta(seconds=5)
    assert live_g.issued_by == "issuer2@csp.example"
    assert live_g.revoked_at is None and live_g.revoked_by is None
    assert silent_g.revoked and silent_g.revoked_at is None and silent_g.revoked_by is None
    assert silent_g.issued_by is None

    # 0109 ran again on the way back up: its events name their grantee.
    async with session_scope() as s:
        named = (
            await s.execute(
                text(
                    "SELECT DISTINCT grantee_name, grantee_kind "
                    "FROM ccf.external_portal_audit_events WHERE grant_id = :id"
                ),
                {"id": ids["audited"]},
            )
        ).all()
    assert [tuple(r) for r in named] == [("Dept", "agency")]
