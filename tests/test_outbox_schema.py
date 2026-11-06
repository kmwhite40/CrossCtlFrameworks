"""``outbox_jobs``: the event bus's durable work queue, and ``claim_jobs`` eligibility.

The table is tenant-owned (``organization_id`` is NULL only for platform-only
jobs), so it carries the standard tenant-isolation policy, forced. ``claim_jobs``
gains an optional eligibility predicate so a job scheduled for later (backoff,
settle delay) is not claimed early; with no predicate prep and the assessment
engine behave exactly as before.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, text

from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import Event, Organization
from ccf.models_outbox import OutboxJob
from ccf.queue import claim_jobs

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
async def _clean() -> AsyncIterator[None]:
    async def _wipe() -> None:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            await s.execute(delete(OutboxJob))

    await _wipe()
    yield
    await _wipe()


async def _event(s, org_id: int | None = None) -> int:  # type: ignore[no-untyped-def]
    ev = Event(
        organization_id=org_id, verb="created", entity_type="poam", entity_id="1", summary="x"
    )
    s.add(ev)
    await s.flush()
    return ev.id


@pytest.mark.asyncio
async def test_outbox_jobs_is_tenant_isolated() -> None:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        row = (
            await s.execute(
                text(
                    "SELECT c.relrowsecurity, c.relforcerowsecurity, "
                    "pg_get_expr(p.polqual, p.polrelid) "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "LEFT JOIN pg_policy p ON p.polrelid = c.oid "
                    "AND p.polname = 'tenant_isolation' "
                    "WHERE n.nspname = 'ccf' AND c.relname = 'outbox_jobs'"
                )
            )
        ).one()
    assert row[0] is True
    assert row[1] is True
    assert row[2] is not None and "current_tenant" in row[2]

    # Behavioural: a tenant session sees its own job and not another's.
    async with session_scope() as s:
        await set_session_tenant(s, None)
        org_a = Organization(name=f"outbox-a-{uuid.uuid4().hex[:6]}")
        org_b = Organization(name=f"outbox-b-{uuid.uuid4().hex[:6]}")
        s.add_all([org_a, org_b])
        await s.flush()
        for org in (org_a, org_b):
            ev = await _event(s, org.id)
            s.add(
                OutboxJob(
                    organization_id=org.id,
                    consumer="c",
                    scope_key=f"org:{org.id}",
                    trigger_event_id=ev,
                )
            )
        await s.flush()
        a_id, b_id = org_a.id, org_b.id
    async with session_scope() as s:
        await set_session_tenant(s, a_id)
        seen = {
            r for (r,) in (await s.execute(text("SELECT organization_id FROM ccf.outbox_jobs")))
        }
    assert seen == {a_id}  # positive control (own row visible) and b_id excluded
    assert b_id not in seen


@pytest.mark.asyncio
async def test_claim_jobs_honours_an_eligibility_predicate() -> None:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        ev = await _event(s)
        now = datetime.now(UTC)
        s.add_all(
            [
                OutboxJob(
                    consumer="c",
                    scope_key="due",
                    trigger_event_id=ev,
                    next_attempt_at=now - timedelta(minutes=5),
                ),
                OutboxJob(
                    consumer="c",
                    scope_key="later",
                    trigger_event_id=ev,
                    next_attempt_at=now + timedelta(hours=1),
                ),
            ]
        )
    async with session_scope() as s:
        await set_session_tenant(s, None)
        claimed = await claim_jobs(
            s, OutboxJob, worker="w", limit=10, eligible=OutboxJob.next_attempt_at <= func.now()
        )
        assert [j.scope_key for j in claimed] == ["due"]
        assert claimed[0].status == "claimed" and claimed[0].attempts == 1
        # Positive control: without a predicate the future job is claimable.
        rest = await claim_jobs(s, OutboxJob, worker="w", limit=10)
        assert [j.scope_key for j in rest] == ["later"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("use_order_by", "expected"), [(False, "first-created"), (True, "second-created")]
)
async def test_claim_jobs_order_by_overrides_created_at(use_order_by: bool, expected: str) -> None:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        ev = await _event(s)
        now = datetime.now(UTC)
        s.add_all(
            [
                OutboxJob(
                    consumer="c",
                    scope_key="first-created",
                    trigger_event_id=ev,
                    created_at=now - timedelta(hours=2),
                    next_attempt_at=now,
                ),
                OutboxJob(
                    consumer="c",
                    scope_key="second-created",
                    trigger_event_id=ev,
                    created_at=now - timedelta(hours=1),
                    next_attempt_at=now - timedelta(days=1),
                ),
            ]
        )
        await s.flush()
        claimed = await claim_jobs(
            s,
            OutboxJob,
            worker="w",
            limit=1,
            order_by=OutboxJob.next_attempt_at if use_order_by else None,
        )
        assert [j.scope_key for j in claimed] == [expected]
