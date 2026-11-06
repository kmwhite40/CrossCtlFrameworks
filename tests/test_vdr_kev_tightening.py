"""A KEV due date tightens an open flaw's deadline without anyone evaluating it.

CISA adds a CVE to KEV with a due date; a POA&M naming that CVE must be due by
then. Before this, ``due_on`` moved only when someone recorded an evaluation,
so a flaw nobody touched kept a deadline later than the one CISA set. The
scheduler now runs :func:`ccf.vdr.service.tighten_due_dates` per organization,
after the KEV sync, so a newly listed CVE reaches its POA&Ms the same cycle.

Only earlier, never later; only open flaws (a risk acceptance's ``due_on`` is
its expiry, which only an approval moves); never another organization's.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.governance import scheduler
from ccf.intel import kev as kev_mod
from ccf.models import POAM, AuditLog, Organization, System
from ccf.models_program import KevEntry
from ccf.packs import sync as pack_sync_mod
from ccf.vdr import service as vdr_service

pytestmark = pytest.mark.usefixtures("fresh_engine")

NOW = datetime.now(UTC)
TODAY = NOW.date()
KEV_DUE = TODAY + timedelta(days=3)


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _cve() -> str:
    return f"CVE-2099-{uuid.uuid4().int % 10_000_000:07d}"


@pytest.fixture
async def cve() -> AsyncIterator[str]:
    c = _cve()
    async with session_scope() as s:
        s.add(
            KevEntry(
                cve_id=c,
                name="test",
                date_added=TODAY - timedelta(days=1),
                due_date=KEV_DUE,
                catalog_version="test",
                synced_at=NOW,
            )
        )
    yield c
    async with session_scope() as s:
        await s.execute(delete(KevEntry).where(KevEntry.cve_id == c))


async def _system(*, deleted: bool = False, org_id: int | None = None) -> tuple[int, int]:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        if org_id is None:
            org = Organization(name=f"kevt-{tag}")
            s.add(org)
            await s.flush()
            org_id = org.id
        sysm = System(
            organization_id=org_id,
            name=f"kevt {tag}",
            certification_class="C",
            deleted_at=NOW if deleted else None,
        )
        s.add(sysm)
        await s.flush()
        return org_id, sysm.id


async def _poam(system_id: int, cve: str, **kw: Any) -> int:
    base: dict[str, Any] = {
        "system_id": system_id,
        "title": "OpenSSL flaw",
        "weakness": f"Refs: {cve}",
        "severity": "high",
        "status": "open",
        "source": "scan",
        "scanner": "nessus",
        "identified_on": TODAY,
        "due_on": TODAY + timedelta(days=30),
        "finding_uid": uuid.uuid4().hex,
    }
    base.update(kw)
    async with session_scope() as s:
        p = POAM(**base)
        s.add(p)
        await s.flush()
        return p.id


async def _due(pid: int) -> Any:
    async with session_scope() as s:
        return (await s.execute(select(POAM.due_on).where(POAM.id == pid))).scalar_one()


async def _tighten(org_id: int) -> dict[str, Any]:
    async with session_scope() as s:
        return await vdr_service.tighten_due_dates(s, org_id=org_id, now=NOW)


@pytest.mark.asyncio
async def test_a_kev_due_date_tightens_an_open_flaw_and_is_audited(cve: str) -> None:
    org, sysm = await _system()
    pid = await _poam(sysm, cve)
    untouched = await _poam(sysm, _cve())
    out = await _tighten(org)
    assert out == {"organization_id": org, "flaws_checked": 2, "tightened": 1}
    assert await _due(pid) == KEV_DUE
    assert await _due(untouched) == TODAY + timedelta(days=30)
    async with session_scope() as s:
        audit = (
            await s.execute(
                select(AuditLog).where(
                    AuditLog.action == "vdr_due_tightened", AuditLog.entity_id == str(pid)
                )
            )
        ).scalar_one()
    assert audit.actor == "scheduler" and audit.organization_id == org
    # A second pass finds nothing left to move.
    assert (await _tighten(org))["tightened"] == 0


@pytest.mark.asyncio
async def test_it_never_moves_a_due_date_later(cve: str) -> None:
    org, sysm = await _system()
    earlier = TODAY + timedelta(days=1)
    pid = await _poam(sysm, cve, due_on=earlier)
    assert (await _tighten(org))["tightened"] == 0
    assert await _due(pid) == earlier


@pytest.mark.asyncio
async def test_it_sets_a_due_date_on_a_flaw_that_had_none(cve: str) -> None:
    org, sysm = await _system()
    pid = await _poam(sysm, cve, due_on=None)
    await _tighten(org)
    assert await _due(pid) == KEV_DUE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kw",
    [
        # The acceptance's expiry: only an approval moves it.
        {"status": "risk_accepted", "owner_user_id": None, "acceptance_rationale": "AO"},
        {"status": "completed"},
        {"status": "closed"},
        # Not a VER flaw: a control-gap POA&M is not a vulnerability deadline.
        {"source": "assessment", "scanner": None},
    ],
    ids=["risk_accepted", "completed", "closed", "not_a_flaw"],
)
async def test_it_leaves_alone_what_is_not_an_open_flaw(cve: str, kw: dict[str, Any]) -> None:
    org, sysm = await _system()
    pid = await _poam(sysm, cve, **kw)
    assert (await _tighten(org))["tightened"] == 0
    assert await _due(pid) == TODAY + timedelta(days=30)


@pytest.mark.asyncio
async def test_a_deleted_system_and_another_org_are_out_of_reach(cve: str) -> None:
    org, _ = await _system()
    # Same organization: only the deleted-system filter can keep it out.
    _, gone = await _system(deleted=True, org_id=org)
    other_org, other_sys = await _system()
    gone_pid = await _poam(gone, cve)
    other_pid = await _poam(other_sys, cve)
    # Unscoped session: RLS would hide the other org's row anyway and mask a
    # missing organization filter (concord-rls-masks-tenant-tests).
    async with session_scope() as s:
        await set_session_tenant(s, None)
        out = await vdr_service.tighten_due_dates(s, org_id=org, now=NOW)
    assert out["flaws_checked"] == 0
    assert await _due(other_pid) == TODAY + timedelta(days=30)
    assert await _due(gone_pid) == TODAY + timedelta(days=30)
    assert other_org != org


@pytest.mark.asyncio
async def test_the_scheduler_tightens_in_the_cycle_that_syncs_the_kev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The KEV sync runs before the per-tenant pass, so a CVE CISA lists today
    reaches its POA&Ms this cycle -- not the next one."""
    c = _cve()
    org, sysm = await _system()
    pid = await _poam(sysm, c)

    async def fake_refresh(session: Any, *, today: Any = None) -> dict[str, Any]:
        session.add(
            KevEntry(
                cve_id=c,
                name="listed today",
                date_added=TODAY,
                due_date=KEV_DUE,
                catalog_version="test",
                synced_at=NOW,
            )
        )
        await session.flush()
        return {"synced": 1}

    async def no_pack_sync(session: Any, org_id: int | None) -> dict[str, Any]:
        return {"organization_id": org_id, "sources": 0, "pending": 0, "installed": 0}

    async def no_poll(session: Any) -> list[Any]:
        return []

    monkeypatch.setattr(kev_mod, "refresh_kev", fake_refresh)
    monkeypatch.setattr(pack_sync_mod, "sync_for_org", no_pack_sync)
    monkeypatch.setattr(scheduler, "poll_sources", no_poll)
    monkeypatch.setenv("CCF_KEV_SYNC_ENABLED", "true")
    get_settings.cache_clear()
    try:
        out = await scheduler.run_cycle()
        assert out.get("kev") == {"synced": 1}
        assert await _due(pid) == KEV_DUE
        assert any(r["organization_id"] == org and r["tightened"] == 1 for r in out["vdr_due"])
    finally:
        monkeypatch.setenv("CCF_KEV_SYNC_ENABLED", "false")
        get_settings.cache_clear()
        async with session_scope() as s:
            await s.execute(delete(KevEntry).where(KevEntry.cve_id == c))
