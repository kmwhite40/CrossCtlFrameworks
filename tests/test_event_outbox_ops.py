"""Operator visibility for the event bus: the reliability check, requeue, retention.

The test DB is shared and the check looks at every organization's jobs, so each
test starts from an empty ``outbox_jobs`` (an unscoped delete; ccf_app has no
DELETE) and asserts on its own rows. Job rows are read back on an UNSCOPED
session: RLS would hide a job requeued under the wrong organization.
"""

from __future__ import annotations

import itertools
import os
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.events import consumers, retention
from ccf.governance import scheduler
from ccf.models import Event, Organization, User
from ccf.models_outbox import OutboxJob
from ccf.packs import sync as pack_sync_mod
from ccf.reliability import checks
from ccf.reliability.checks import FAIL, PASS, WARN, _check_event_outbox

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
DERIVED = "assurance_graph"
OTHER_DERIVED = "capability_derive"


def _ago(**kw: float) -> datetime:
    return datetime.now(UTC) - timedelta(**kw)


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
async def _empty_outbox() -> AsyncIterator[None]:
    async def wipe() -> None:
        async with session_scope() as s:
            await s.execute(delete(OutboxJob))

    await wipe()
    yield
    await wipe()


async def _org() -> int:
    async with session_scope() as s:
        org = Organization(name=f"outbox-ops-{uuid.uuid4().hex[:8]}")
        s.add(org)
        await s.flush()
        return org.id


async def _event(org_id: int | None, *, created_at: datetime | None = None) -> int:
    async with session_scope() as s:
        ev = Event(organization_id=org_id, verb="noted", entity_type="ops_test", summary="t")
        if created_at is not None:
            ev.created_at = created_at
        s.add(ev)
        await s.flush()
        return ev.id


async def _job(consumer: str, *, org_id: int | None = None, **cols: Any) -> int:
    """A job row; ``event_at`` sets its trigger event's time."""
    event_at = cols.pop("event_at", None)
    event_id = await _event(org_id, created_at=event_at)
    async with session_scope() as s:
        j = OutboxJob(
            organization_id=org_id,
            consumer=consumer,
            scope_key=f"org:{org_id}",
            trigger_event_id=event_id,
            **cols,
        )
        s.add(j)
        await s.flush()
        return j.id


async def _get(job_id: int) -> OutboxJob | None:
    async with session_scope() as s:  # unscoped
        return (
            await s.execute(select(OutboxJob).where(OutboxJob.id == job_id))
        ).scalar_one_or_none()


async def _check() -> checks.Check:
    async with session_scope() as s:
        return await _check_event_outbox(s)


# --- the reliability check ---------------------------------------------------


async def test_the_consumers_the_tests_use_are_registered() -> None:
    import ccf.events  # noqa: F401, PLC0415

    assert DERIVED in consumers.REGISTRY and OTHER_DERIVED in consumers.REGISTRY
    assert "webhook" in consumers.REGISTRY


async def test_an_empty_queue_passes_and_says_so() -> None:
    c = await _check()
    assert c.status == PASS, c.message


async def test_a_dead_letter_fails_the_check_by_name() -> None:
    await _job(DERIVED, status="failed", last_error="boom-first")
    await _job(DERIVED, status="failed", last_error="boom-second")
    await _job("webhook", status="failed", last_error="hook-down")
    c = await _check()
    assert c.status == FAIL
    assert f"{DERIVED}: 2 failed" in c.message
    assert "boom-first" in c.message  # the OLDEST error
    assert "boom-second" not in c.message
    assert "webhook: 1 failed" in c.message and "hook-down" in c.message


async def test_a_stalled_queue_warns() -> None:
    await _job(DERIVED, status="pending", next_attempt_at=_ago(minutes=10))
    c = await _check()
    assert c.status == WARN
    assert "worker" in c.message


async def test_a_queue_that_is_not_stalled_does_not_warn() -> None:
    # Positive control for the stall test: each of these must NOT warn.
    await _job(DERIVED, status="pending", next_attempt_at=_ago(minutes=1))  # fresh
    await _job(DERIVED, status="pending", next_attempt_at=_ago(hours=-1))  # backing off
    await _job("unregistered-consumer", status="pending", next_attempt_at=_ago(hours=3))
    c = await _check()
    assert c.status == PASS, c.message


async def test_freshness_over_target_warns() -> None:
    now = datetime.now(UTC)
    await _job(DERIVED, status="done", event_at=now - timedelta(seconds=200), finished_at=now)
    c = await _check()
    assert c.status == WARN
    assert "p95" in c.message and "60" in c.message


async def test_freshness_within_target_passes_with_the_p95_stated() -> None:
    now = datetime.now(UTC)
    for _ in range(3):
        await _job(
            OTHER_DERIVED, status="merged", event_at=now - timedelta(seconds=12), finished_at=now
        )
    c = await _check()
    assert c.status == PASS
    assert "p95 12" in c.message


async def test_slow_webhooks_and_old_jobs_are_not_in_the_freshness_figure() -> None:
    now = datetime.now(UTC)
    # A slow webhook (ruling R29) and a slow derived job outside the 24 h window.
    await _job("webhook", status="done", event_at=now - timedelta(seconds=900), finished_at=now)
    await _job(
        DERIVED,
        status="done",
        event_at=now - timedelta(hours=30, seconds=900),
        finished_at=now - timedelta(hours=30),
    )
    await _job(DERIVED, status="done", event_at=now - timedelta(seconds=5), finished_at=now)
    c = await _check()
    assert c.status == PASS, c.message
    assert "p95 5" in c.message


async def test_the_check_is_in_the_suite() -> None:
    assert _check_event_outbox in checks._CHECKS


# --- requeue -----------------------------------------------------------------


async def _mk_user(org_id: int, role: str) -> str:
    async with session_scope() as s:
        user = User(
            email=f"{role}-{next(_SEQ)}-{uuid.uuid4().hex[:6]}@outbox-ops.test",
            organization_id=org_id,
            role=role,
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token


def _client() -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=create_app(), raise_app_exceptions=False), base_url="http://t"
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _url(consumer: str) -> str:
    return f"/admin/reliability/outbox/{consumer}/requeue"


async def _failed(consumer: str, org_id: int) -> int:
    return await _job(
        consumer,
        org_id=org_id,
        status="failed",
        attempts=5,
        last_error="it broke",
        finished_at=_ago(minutes=3),
        next_attempt_at=_ago(hours=1),
    )


async def test_requeue_needs_admin_and_resets_attempts() -> None:
    org = await _org()
    job = await _failed(DERIVED, org)
    done = await _job(DERIVED, org_id=org, status="done", attempts=2, finished_at=_ago(minutes=1))
    owner = await _mk_user(org, "control_owner")
    admin = await _mk_user(org, "admin")
    async with _client() as c:
        refused = await c.post(_url(DERIVED), headers=_auth(owner))
        assert refused.status_code == 403, refused.text
        j = await _get(job)
        assert j is not None and j.status == "failed" and j.attempts == 5  # untouched

        before = datetime.now(UTC)
        ok = await c.post(_url(DERIVED), headers=_auth(admin), follow_redirects=False)
        assert ok.status_code == 303, ok.text
    j = await _get(job)
    assert j is not None
    assert j.status == "pending" and j.attempts == 0
    assert j.next_attempt_at >= before - timedelta(seconds=5)
    assert j.last_error is None and j.finished_at is None
    assert j.result["requeued_from_error"] == "it broke"
    # The page offered the button, and the action is audited.
    async with session_scope() as s:
        audited = (
            await s.execute(
                text(
                    "SELECT count(*) FROM ccf.audit_log WHERE action = 'outbox.requeue' "
                    "AND entity_id = :c AND organization_id = :o"
                ),
                {"c": DERIVED, "o": org},
            )
        ).scalar_one()
    assert audited == 1
    d = await _get(done)  # only FAILED jobs are requeued
    assert d is not None and d.status == "done" and d.attempts == 2


async def test_a_tenant_admin_requeues_only_their_own_orgs_jobs() -> None:
    mine, theirs = await _org(), await _org()
    my_job = await _failed(DERIVED, mine)
    their_job = await _failed(DERIVED, theirs)
    their_other_consumer = await _failed(OTHER_DERIVED, mine)
    admin = await _mk_user(mine, "admin")
    async with _client() as c:
        r = await c.post(_url(DERIVED), headers=_auth(admin), follow_redirects=False)
        assert r.status_code == 303
    assert (await _get(my_job)).status == "pending"  # type: ignore[union-attr]
    assert (await _get(their_job)).status == "failed"  # type: ignore[union-attr]
    assert (await _get(their_other_consumer)).status == "failed"  # type: ignore[union-attr]


async def test_a_platform_admin_requeues_every_orgs_jobs() -> None:
    a, b = await _org(), await _org()
    ja, jb = await _failed(DERIVED, a), await _failed(DERIVED, b)
    os.environ["CCF_AUTH_ENABLED"] = "false"  # unscoped SYSTEM principal
    get_settings.cache_clear()
    async with _client() as c:
        r = await c.post(_url(DERIVED), follow_redirects=False)
        assert r.status_code == 303, r.text
    assert (await _get(ja)).status == "pending"  # type: ignore[union-attr]
    assert (await _get(jb)).status == "pending"  # type: ignore[union-attr]


async def test_the_page_offers_requeue_only_for_failed_consumers() -> None:
    org = await _org()
    await _failed(DERIVED, org)
    admin = await _mk_user(org, "admin")
    async with _client() as c:
        page = await c.get("/admin/reliability", headers=_auth(admin))
    assert page.status_code == 200, page.text
    assert f'action="{_url(DERIVED)}"' in page.text
    assert _url(OTHER_DERIVED) not in page.text


# --- retention ---------------------------------------------------------------


async def test_retention_keeps_failed_jobs() -> None:
    old = _ago(days=100)
    kept_failed = [
        await _job(c, status="failed", last_error="x", finished_at=old, created_at=old)
        for c in (DERIVED, "webhook")
    ]
    dead_no_stamp = await _job(DERIVED, status="failed", created_at=old)  # reaper: no finished_at
    # Positive controls: the same age, but finished, must go.
    gone = [
        await _job(DERIVED, status="done", finished_at=_ago(days=2)),
        await _job(DERIVED, status="merged", finished_at=_ago(days=2)),
        await _job("webhook", status="done", finished_at=_ago(days=31)),
        await _job(DERIVED, status="done", created_at=_ago(days=2)),  # NULL finished_at
    ]
    # Inside the window: stays.
    young = [
        await _job(DERIVED, status="done", finished_at=_ago(hours=1)),
        await _job(DERIVED, status="merged", finished_at=_ago(hours=23)),
        await _job("webhook", status="done", finished_at=_ago(days=2)),
        await _job("webhook", status="done", finished_at=_ago(days=29)),
        await _job(DERIVED, status="pending"),
    ]
    async with session_scope() as s:
        counts = await retention.purge_outbox(s)
    assert counts == {"derived": 3, "webhook": 1}
    for j in [*kept_failed, dead_no_stamp, *young]:
        assert await _get(j) is not None, j
    for j in gone:
        assert await _get(j) is None, j


async def _stub_cycle(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_poll(session: object, **_: object) -> list[object]:
        return []

    async def stub_sync(session: object, org_id: int | None) -> dict[str, object]:
        return {"organization_id": org_id, "sources": 0, "pending": 0, "installed": 0}

    monkeypatch.setattr(scheduler, "poll_sources", no_poll)
    monkeypatch.setattr(pack_sync_mod, "sync_for_org", stub_sync)
    monkeypatch.setenv("CCF_KEV_SYNC_ENABLED", "false")
    get_settings.cache_clear()


async def test_the_scheduler_runs_retention_as_a_global_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _stub_cycle(monkeypatch)
    gone = await _job(DERIVED, status="done", finished_at=_ago(days=3))
    failed = await _job(DERIVED, status="failed", finished_at=_ago(days=3))
    out = await scheduler.run_cycle()
    assert out["outbox_retention"]["derived"] >= 1
    assert "outbox_retention" not in out["global_failures"]
    assert await _get(gone) is None
    assert await _get(failed) is not None


async def test_a_retention_failure_is_contained_and_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _stub_cycle(monkeypatch)

    async def boom(session: Any, **_: object) -> dict[str, int]:
        await session.execute(text("SELECT 1/0"))
        return {}

    monkeypatch.setattr(retention, "purge_outbox", boom)
    out = await scheduler.run_cycle()
    assert "outbox_retention" in out["global_failures"]
    assert "outbox_retention" not in out
