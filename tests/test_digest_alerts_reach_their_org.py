"""The scheduler's alerts are stored with the organization they concern.

The global digest step ran unscoped, so every org alert carried
``organization_id`` NULL: invisible to every member (RLS and the inbox filter),
and per-org rollup keys collapsed every tenant into one ``...:None`` row.
"""

from __future__ import annotations

import itertools
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, select, text

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import digest, scheduler
from ccf.models import Notification, Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(autouse=True)
async def _only_this_tests_notifications() -> AsyncIterator[None]:
    """Remove the notifications a test created: run_all and the scheduler write
    for whichever orgs they are given, and later modules count notifications."""
    async with session_scope() as s:
        before = (await s.execute(select(func.max(Notification.id)))).scalar() or 0
    yield
    async with session_scope() as s:
        await s.execute(delete(Notification).where(Notification.id > before))


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _org_with_expiring_ato(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"{name} {next(_SEQ)}")
        s.add(org)
        await s.flush()
        sysm = System(
            organization_id=org.id,
            name=f"{name} system {next(_SEQ)}",
            ato_expires_on=date.today() + timedelta(days=10),
        )
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


async def test_the_scheduled_cycle_stores_each_orgs_alert_under_that_org(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a_org, a_sys = await _org_with_expiring_ato("Digest A")
    b_org, b_sys = await _org_with_expiring_ato("Digest B")

    async def no_poll(session: object, **_: object) -> list[object]:
        await session.execute(text("SELECT 1"))  # type: ignore[attr-defined]
        return []

    monkeypatch.setattr(scheduler, "poll_sources", no_poll)

    # Only this test's organizations: the real cycle would otherwise escalate
    # every other module's overdue tasks in the shared database.
    async def only_ours(session: object) -> list[int]:
        return [a_org, b_org]

    monkeypatch.setattr(scheduler, "_active_org_ids", only_ours)
    try:
        await scheduler.run_cycle()
        async with session_scope() as s:
            rows = {
                n.dedupe_key: n.organization_id
                for n in (
                    await s.execute(
                        select(Notification).where(
                            Notification.dedupe_key.in_([f"ato:{a_sys}", f"ato:{b_sys}"])
                        )
                    )
                ).scalars()
            }
        assert rows == {f"ato:{a_sys}": a_org, f"ato:{b_sys}": b_org}
    finally:
        async with session_scope() as s:
            await s.execute(
                delete(Notification).where(
                    Notification.dedupe_key.in_([f"ato:{a_sys}", f"ato:{b_sys}"])
                )
            )


async def test_an_unscoped_digest_raises_only_platform_alerts() -> None:
    _org, sysm = await _org_with_expiring_ato("Digest Platform")
    async with session_scope() as s:
        counts = await digest.run(s, today=datetime.now(UTC).date())
        found = (
            await s.execute(select(Notification).where(Notification.dedupe_key == f"ato:{sysm}"))
        ).scalar_one_or_none()
    assert set(counts) == {"catalog"}
    assert found is None  # no org-less org alert is ever written again


async def test_run_all_covers_every_org(monkeypatch: pytest.MonkeyPatch) -> None:
    org, sysm = await _org_with_expiring_ato("Digest All")

    async def only_ours(session: object) -> list[int]:
        return [org]

    monkeypatch.setattr(digest, "active_org_ids", only_ours)
    async with session_scope() as s:
        out = await digest.run_all(s, today=datetime.now(UTC).date())
        n = (
            await s.execute(select(Notification).where(Notification.dedupe_key == f"ato:{sysm}"))
        ).scalar_one()
        assert n.organization_id == org
        assert out[str(org)]["ato"] >= 1
        await s.delete(n)


async def test_the_governance_page_scan_still_raises_org_alerts_unscoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    from ccf.api.main import create_app  # noqa: PLC0415

    org, sysm = await _org_with_expiring_ato("Digest Page")

    async def only_ours(session: object) -> list[int]:
        return [org]

    monkeypatch.setattr(digest, "active_org_ids", only_ours)
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.post("/governance/scan", follow_redirects=False)
        assert r.status_code == 303
    async with session_scope() as s:
        n = (
            await s.execute(select(Notification).where(Notification.dedupe_key == f"ato:{sysm}"))
        ).scalar_one()
        assert n.organization_id == org
        await s.delete(n)
