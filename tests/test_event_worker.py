"""The outbox worker: claim + merge, run under the scope's tenant, retry, dead-letter.

Every tenant assertion is made inside ``run`` by reading ``ccf.current_tenant()``
off the connection, and job rows are read back on an UNSCOPED session: RLS would
hide a job filed under the wrong organization and let a check pass vacuously.

The test DB is shared and other modules leave pending outbox jobs behind. Those
belong to consumers that are not registered here, and the worker claims only
registered consumers (ruling R3), so a drain in this module touches only this
module's own jobs. Assertions are still pinned to this test's own job ids.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import delete, func, select, text, update

from ccf.db import session_scope
from ccf.events import consumers, outbox, worker
from ccf.events.consumers import Consumer, register
from ccf.governance import bus
from ccf.models import Event, Organization, System
from ccf.models_outbox import OutboxJob

pytestmark = pytest.mark.usefixtures("fresh_engine")

PAST = datetime(2000, 1, 1, tzinfo=UTC)


@pytest.fixture(autouse=True)
async def _no_live_jobs_left_behind() -> AsyncIterator[None]:
    """Delete every pending/claimed job this test created, whatever its consumer.

    The test DB is shared: a pending ``webhook`` job left here (next_attempt_at
    in the past) would be the first thing the real webhook consumer's tests
    claim. Jobs created during the test are those above the starting id mark;
    the delete runs on an unscoped superuser session (ccf_app has no DELETE).
    """
    async with session_scope() as s:
        mark = (await s.execute(select(func.coalesce(func.max(OutboxJob.id), 0)))).scalar_one()
    yield
    async with session_scope() as s:
        await s.execute(
            delete(OutboxJob).where(
                OutboxJob.id > mark, OutboxJob.status.in_(("pending", "claimed"))
            )
        )


def _future(seconds: int = 3600) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=seconds)


@pytest.fixture
def registered() -> Iterator[list[str]]:
    names: list[str] = []
    yield names
    for n in names:
        consumers.REGISTRY.pop(n, None)


def _add(
    registered: list[str],
    run: Any,
    *,
    entity: str | None = None,
    scope: Any = None,
    settle: int = 15,
    max_attempts: int = 5,
    name: str | None = None,
) -> Consumer:
    c = Consumer(
        name=name or f"w{uuid.uuid4().hex[:10]}",
        matches=(lambda e, v: e == entity) if entity else (lambda e, v: False),
        scope=scope or (lambda ev: f"org:{ev.organization_id}"),
        run=run,
        settle_seconds=settle,
        max_attempts=max_attempts,
    )
    register(c)
    registered.append(c.name)
    return c


@pytest.fixture
async def world() -> AsyncIterator[dict[str, Any]]:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"worker-{tag}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"worker {tag}", certification_class="C")
        s.add(sysm)
        await s.flush()
        ev = Event(organization_id=org.id, verb="noted", entity_type="worker_test", summary="t")
        s.add(ev)
        await s.flush()
        w = {"org": org.id, "system": sysm.id, "event": ev.id, "entity": f"t{tag}"}
    yield w


async def _event(org_id: int | None, payload: dict[str, Any] | None = None) -> int:
    async with session_scope() as s:
        ev = Event(
            organization_id=org_id,
            verb="noted",
            entity_type="worker_test",
            summary="t",
            payload=payload or {},
        )
        s.add(ev)
        await s.flush()
        return ev.id


async def _job(
    consumer: str,
    scope_key: str,
    *,
    org_id: int | None,
    event_id: int,
    at: datetime = PAST,
    max_attempts: int = 5,
    result: dict[str, Any] | None = None,
) -> int:
    async with session_scope() as s:
        j = OutboxJob(
            organization_id=org_id,
            consumer=consumer,
            scope_key=scope_key,
            trigger_event_id=event_id,
            next_attempt_at=at,
            max_attempts=max_attempts,
            result=result or {},
        )
        s.add(j)
        await s.flush()
        return j.id


async def _get(job_id: int) -> OutboxJob:
    async with session_scope() as s:
        job = await s.get(OutboxJob, job_id)
        assert job is not None
        return job


async def _jobs_for(consumer: str) -> list[OutboxJob]:
    async with session_scope() as s:
        return list(
            (
                await s.execute(
                    select(OutboxJob).where(OutboxJob.consumer == consumer).order_by(OutboxJob.id)
                )
            )
            .scalars()
            .all()
        )


async def _tenant(session: Any) -> tuple[int | None, str]:
    row = (await session.execute(text("SELECT ccf.current_tenant(), current_user"))).one()
    return row[0], row[1]


# ── coalescing ───────────────────────────────────────────────────────────────


async def test_a_thousand_events_make_one_graph_rebuild(
    world: dict[str, Any], registered: list[str]
) -> None:
    runs: list[str] = []

    async def _count(session: Any, key: str, job: Any) -> dict[str, Any]:
        runs.append(key)
        return {"rebuilt": True}

    c = _add(registered, _count, entity=world["entity"])
    async with session_scope() as s:
        for _ in range(1000):
            await bus.emit(
                s,
                verb="updated",
                entity_type=world["entity"],
                summary="x",
                org_id=world["org"],
                dispatch=False,
            )
    jobs = await _jobs_for(c.name)
    assert len(jobs) == 1000 and {j.status for j in jobs} == {"pending"}

    counts = await worker.drain_once(worker="w1", now=_future(60))

    assert runs == [f"org:{world['org']}"]
    jobs = await _jobs_for(c.name)
    [ran] = [j for j in jobs if j.status == "done"]
    merged = [j for j in jobs if j.status == "merged"]
    assert ran.absorbed == 999
    assert len(merged) == 999
    assert {j.merged_into for j in merged} == {ran.id}
    assert ran.result == {"rebuilt": True}
    assert ran.finished_at is not None
    assert counts["done"] >= 1 and counts["merged"] >= 999


async def test_a_change_during_a_run_is_picked_up_once(
    world: dict[str, Any], registered: list[str]
) -> None:
    runs: list[int] = []

    async def _writes_meanwhile(session: Any, key: str, job: Any) -> dict[str, Any]:
        runs.append(job.id)
        if len(runs) == 1:
            # Another request changes the scope while the rebuild runs.
            token = outbox.CURRENT_CONSUMER.set(None)
            try:
                async with session_scope() as other:
                    for _ in range(3):
                        await bus.emit(
                            other,
                            verb="updated",
                            entity_type=world["entity"],
                            summary="x",
                            org_id=world["org"],
                            dispatch=False,
                        )
            finally:
                outbox.CURRENT_CONSUMER.reset(token)
        return {}

    c = _add(registered, _writes_meanwhile, entity=world["entity"], settle=0)
    first = await _job(c.name, f"org:{world['org']}", org_id=world["org"], event_id=world["event"])

    await worker.drain_once(worker="w1", now=_future())
    assert runs == [first]
    pending = [j for j in await _jobs_for(c.name) if j.status == "pending"]
    # The changes made during the run were not merged into it (it had already
    # read its records) and none was lost.
    assert len(pending) == 3

    await worker.drain_once(worker="w1", now=_future())
    assert len(runs) == 2  # the three collapse into one run
    after = await _jobs_for(c.name)
    assert [j.status for j in after].count("pending") == 0
    second = next(j for j in after if j.id == runs[1])
    assert second.status == "done" and second.absorbed == 2


async def test_a_job_waits_out_its_settle_delay(
    world: dict[str, Any], registered: list[str]
) -> None:
    runs: list[int] = []

    async def _rec(session: Any, key: str, job: Any) -> dict[str, Any]:
        runs.append(job.id)
        return {}

    c = _add(registered, _rec, entity=world["entity"], settle=15)
    async with session_scope() as s:
        await bus.emit(
            s, verb="updated", entity_type=world["entity"], summary="x", org_id=world["org"]
        )
    [job] = await _jobs_for(c.name)

    await worker.drain_once(worker="w1")
    assert runs == []
    assert (await _get(job.id)).status == "pending"

    await worker.drain_once(worker="w1", now=job.next_attempt_at + timedelta(seconds=1))
    assert runs == [job.id]  # positive control
    assert (await _get(job.id)).status == "done"


async def test_webhook_jobs_never_merge(world: dict[str, Any], monkeypatch: Any) -> None:
    """Two webhooks subscribed to one event share ``(webhook, event:N)``; merging
    them would silently drop one subscriber's delivery."""
    delivered: list[int] = []

    async def _deliver(session: Any, key: str, job: Any) -> dict[str, Any]:
        delivered.append(job.result["webhook_id"])
        return {"status_code": 200}

    monkeypatch.setitem(
        consumers.REGISTRY,
        "webhook",
        Consumer(name="webhook", matches=lambda e, v: False, scope=lambda ev: None, run=_deliver),
    )
    key = f"event:{world['event']}"
    # Older than anything another module left behind, so a limit-1 drain takes ours.
    a = await _job(
        "webhook",
        key,
        org_id=world["org"],
        event_id=world["event"],
        at=PAST - timedelta(days=2),
        result={"webhook_id": 101},
    )
    b = await _job(
        "webhook",
        key,
        org_id=world["org"],
        event_id=world["event"],
        at=PAST - timedelta(days=1),
        result={"webhook_id": 102},
    )

    await worker.drain_once(worker="w1", limit=1, now=_future())
    ja, jb = await _get(a), await _get(b)
    assert ja.status == "done" and ja.absorbed == 0
    assert jb.status == "pending"  # not merged
    assert ja.result == {"webhook_id": 101, "status_code": 200}  # run's dict merged in

    await worker.drain_once(worker="w1", limit=1, now=_future())
    assert (await _get(b)).status == "done"
    assert delivered == [101, 102]


# ── one run per scope ────────────────────────────────────────────────────────


async def test_two_drains_never_run_one_scope_at_once(
    world: dict[str, Any], registered: list[str]
) -> None:
    """Drain A holds scope S mid-run; drain B must skip S's new pending job and
    still take another scope (positive control).

    Timing limit: B starts only after A's claim has committed (A is inside
    ``run``), so this exercises the running-scope exclusion, not two claim
    transactions interleaving; the next test covers that.
    """
    started, release = asyncio.Event(), asyncio.Event()
    running: set[str] = set()
    overlaps: list[str] = []
    runs: list[str] = []

    async def _slow(session: Any, key: str, job: Any) -> dict[str, Any]:
        if key in running:
            overlaps.append(key)
            return {}
        running.add(key)
        runs.append(key)
        try:
            if key == s_key and len(runs) == 1:
                started.set()
                await asyncio.wait_for(release.wait(), timeout=20)
        finally:
            running.discard(key)
        return {}

    c = _add(registered, _slow)
    s_key, t_key = f"org:{world['org']}", f"system:{world['system']}"
    await _job(c.name, s_key, org_id=world["org"], event_id=world["event"])

    a = asyncio.create_task(worker.drain_once(worker="A", now=_future()))
    await asyncio.wait_for(started.wait(), timeout=20)
    later = await _job(c.name, s_key, org_id=world["org"], event_id=world["event"])
    await _job(c.name, t_key, org_id=world["org"], event_id=world["event"])

    b = await asyncio.wait_for(worker.drain_once(worker="B", now=_future()), timeout=20)
    assert runs == [s_key, t_key]  # B ran the other scope, not S
    assert b["done"] == 1
    assert (await _get(later)).status == "pending"

    release.set()
    await asyncio.wait_for(a, timeout=20)
    await worker.drain_once(worker="C", now=_future())
    assert (await _get(later)).status == "done"
    assert overlaps == []


async def test_two_claims_at_the_same_instant_take_one_scope_once(
    world: dict[str, Any], registered: list[str], monkeypatch: Any
) -> None:
    """A pauses inside its claim transaction, after claiming S's first job and
    before merging; B claims meanwhile. B must not take S's second job.

    Timing limit: B is given 0.5 s to reach its claim before A resumes. If B is
    slower than that, the test still passes but no longer exercises the
    interleaving; with the claim lock removed it fails (two runs of S, or a
    deadlock between the two merges), recorded in the task report.
    """
    paused, go = asyncio.Event(), asyncio.Event()
    runs: list[str] = []
    real_claim = worker.claim_jobs

    async def _claim(session: Any, model: Any, **kw: Any) -> Any:
        got = await real_claim(session, model, **kw)
        if kw["worker"] == "A" and got and not paused.is_set():
            paused.set()
            await asyncio.wait_for(go.wait(), timeout=20)
        return got

    async def _rec(session: Any, key: str, job: Any) -> dict[str, Any]:
        runs.append(key)
        return {}

    monkeypatch.setattr(worker, "claim_jobs", _claim)
    c = _add(registered, _rec)
    s_key = f"org:{world['org']}"
    first = await _job(c.name, s_key, org_id=world["org"], event_id=world["event"])
    second = await _job(
        c.name, s_key, org_id=world["org"], event_id=world["event"], at=PAST + timedelta(seconds=1)
    )

    a = asyncio.create_task(worker.drain_once(worker="A", now=_future()))
    await asyncio.wait_for(paused.wait(), timeout=20)
    b = asyncio.create_task(worker.drain_once(worker="B", now=_future()))
    await asyncio.sleep(0.5)
    go.set()
    await asyncio.wait_for(asyncio.gather(a, b), timeout=30)

    assert runs == [s_key]
    j1, j2 = await _get(first), await _get(second)
    assert j1.status == "done" and j1.absorbed == 1
    assert (j2.status, j2.merged_into) == ("merged", first)


# ── retries and dead letters ─────────────────────────────────────────────────


async def test_a_failing_job_backs_off_then_dead_letters_at_its_cap(
    world: dict[str, Any], registered: list[str]
) -> None:
    async def _boom(session: Any, key: str, job: Any) -> dict[str, Any]:
        raise RuntimeError("boom " + "x" * 10_000)

    c = _add(registered, _boom, max_attempts=3)
    jid = await _job(
        c.name, f"org:{world['org']}", org_id=world["org"], event_id=world["event"], max_attempts=3
    )
    t0 = _future()

    counts = await worker.drain_once(worker="w1", now=t0)
    job = await _get(jid)
    assert counts["retried"] == 1
    assert (job.status, job.attempts) == ("pending", 1)
    assert job.next_attempt_at == t0 + timedelta(seconds=60)
    assert job.last_error is not None and job.last_error.startswith("RuntimeError: boom")
    assert len(job.last_error) == 4000
    assert job.claimed_by is None

    await worker.drain_once(worker="w1", now=t0 + timedelta(seconds=59))
    assert (await _get(jid)).attempts == 1  # still backing off

    t1 = t0 + timedelta(seconds=60)
    await worker.drain_once(worker="w1", now=t1)
    job = await _get(jid)
    assert (job.status, job.attempts) == ("pending", 2)
    assert job.next_attempt_at == t1 + timedelta(seconds=120)

    t2 = t1 + timedelta(seconds=120)
    counts = await worker.drain_once(worker="w1", now=t2)
    job = await _get(jid)
    assert counts["failed"] == 1
    assert (job.status, job.attempts) == ("failed", 3)
    assert job.last_error is not None and job.last_error.startswith("RuntimeError: boom")

    await worker.drain_once(worker="w1", now=t2 + timedelta(days=30))
    assert (await _get(jid)).attempts == 3  # a dead letter is never reclaimed


async def test_backoff_counts_from_the_failure_not_the_drain_start(
    world: dict[str, Any], registered: list[str]
) -> None:
    """A late job in a slow batch must still wait its full first backoff."""
    failed_at: list[datetime] = []

    async def _slow_boom(session: Any, key: str, job: Any) -> dict[str, Any]:
        await asyncio.sleep(1.2)
        failed_at.append(datetime.now(UTC))
        raise RuntimeError("down")

    c = _add(registered, _slow_boom)
    jid = await _job(c.name, f"org:{world['org']}", org_id=world["org"], event_id=world["event"])
    start = datetime.now(UTC)
    await worker.drain_once(worker="w1")  # no explicit now: the production path
    job = await _get(jid)
    assert (job.status, job.attempts) == ("pending", 1)
    assert failed_at and failed_at[0] - start >= timedelta(seconds=1.2)
    assert job.next_attempt_at >= failed_at[0] + timedelta(seconds=60)


async def test_a_webhook_backs_off_from_170_seconds(
    world: dict[str, Any], monkeypatch: Any
) -> None:
    async def _down(session: Any, key: str, job: Any) -> dict[str, Any]:
        raise ConnectionError("refused")

    monkeypatch.setitem(
        consumers.REGISTRY,
        "webhook",
        Consumer(name="webhook", matches=lambda e, v: False, scope=lambda ev: None, run=_down),
    )
    jid = await _job(
        "webhook",
        f"event:{world['event']}",
        org_id=world["org"],
        event_id=world["event"],
        at=PAST - timedelta(days=3),
        max_attempts=8,
        result={"webhook_id": 7},
    )
    t0 = _future()
    await worker.drain_once(worker="w1", limit=1, now=t0)
    job = await _get(jid)
    assert (job.status, job.attempts) == ("pending", 1)
    assert job.next_attempt_at == t0 + timedelta(seconds=170)
    assert job.result == {"webhook_id": 7}  # a failure keeps the delivery's target


async def test_a_killed_worker_is_reaped_and_rerun(
    world: dict[str, Any], registered: list[str]
) -> None:
    runs: list[int] = []

    async def _rec(session: Any, key: str, job: Any) -> dict[str, Any]:
        runs.append(job.id)
        return {}

    c = _add(registered, _rec)
    stale = await _job(c.name, f"org:{world['org']}", org_id=world["org"], event_id=world["event"])
    fresh = await _job(
        c.name, f"system:{world['system']}", org_id=world["org"], event_id=world["event"]
    )
    # Two crashed jobs of a cap-8 consumer: one is under its own cap, one at it.
    webhook_live = await _job(
        "webhook",
        f"event:{world['event']}",
        org_id=world["org"],
        event_id=world["event"],
        max_attempts=8,
    )
    webhook_dead = await _job(
        "webhook",
        f"event:{world['event']}",
        org_id=world["org"],
        event_id=world["event"],
        max_attempts=8,
    )
    async with session_scope() as s:
        long_ago = datetime.now(UTC) - timedelta(minutes=30)
        for jid, attempts in ((stale, 1), (webhook_live, 5), (webhook_dead, 8)):
            await s.execute(
                update(OutboxJob)
                .where(OutboxJob.id == jid)
                .values(status="claimed", claimed_by="dead", claimed_at=long_ago, attempts=attempts)
            )
        await s.execute(
            update(OutboxJob)
            .where(OutboxJob.id == fresh)
            .values(status="claimed", claimed_by="alive", claimed_at=datetime.now(UTC), attempts=1)
        )

    assert await worker.reap() >= 3
    assert (await _get(fresh)).status == "claimed"  # a live worker's job is left alone
    assert (await _get(webhook_live)).status == "pending"  # 5 < its own cap of 8
    dead = await _get(webhook_dead)
    assert dead.status == "failed" and dead.last_error is not None
    assert "(8)" in dead.last_error

    await worker.drain_once(worker="w2", now=_future())
    job = await _get(stale)
    assert runs == [stale]
    assert (job.status, job.attempts) == ("done", 2)


async def _reclaim(job_id: int, *, by: str = "w2") -> None:
    """What a reap then another worker's claim does to a row, committed."""
    async with session_scope() as s:
        await s.execute(
            update(OutboxJob)
            .where(OutboxJob.id == job_id)
            .values(
                status="claimed",
                claimed_by=by,
                claimed_at=datetime.now(UTC),
                attempts=OutboxJob.attempts + 1,
            )
        )


async def _reap_only(job_id: int) -> None:
    """The reaper's requeue, with no worker having re-claimed it yet."""
    async with session_scope() as s:
        await s.execute(
            update(OutboxJob)
            .where(OutboxJob.id == job_id)
            .values(status="pending", claimed_by=None, claimed_at=None)
        )


_TAKEOVERS = {
    "w2": ("claimed", "w2", 2),
    "w1-again": ("claimed", "w1", 2),  # same worker name: only attempts tells them apart
    "reaped": ("pending", None, 1),
}


@pytest.mark.parametrize("takeover", list(_TAKEOVERS))
@pytest.mark.parametrize("fails", [False, True], ids=["success", "failure"])
async def test_a_late_settle_never_overwrites_a_newer_claim(
    world: dict[str, Any], registered: list[str], fails: bool, takeover: str
) -> None:
    """The run outlives its claim: the reaper requeues it and (maybe) another
    claim takes it. w1's outcome must not land on the row, success or failure."""
    holder: dict[str, int] = {}

    async def _overtaken(session: Any, key: str, job: Any) -> dict[str, Any]:
        if takeover == "reaped":
            await _reap_only(holder["id"])
        else:
            await _reclaim(holder["id"], by="w2" if takeover == "w2" else "w1")
        if fails:
            raise RuntimeError("late failure")
        return {"late": True}

    c = _add(registered, _overtaken)
    jid = await _job(c.name, f"org:{world['org']}", org_id=world["org"], event_id=world["event"])
    holder["id"] = jid

    counts = await worker.drain_once(worker="w1", now=_future())

    assert counts["lost"] == 1
    assert counts["done"] == counts["retried"] == counts["failed"] == 0
    job = await _get(jid)
    assert (job.status, job.claimed_by, job.attempts) == _TAKEOVERS[takeover]
    assert job.finished_at is None
    assert job.last_error is None and "late" not in (job.result or {})


async def test_the_settle_fence_lets_the_current_claim_settle(
    world: dict[str, Any], registered: list[str]
) -> None:
    """Positive control for the fence: an un-overtaken run settles normally."""

    async def _ok(session: Any, key: str, job: Any) -> dict[str, Any]:
        return {"ok": True}

    c = _add(registered, _ok)
    jid = await _job(c.name, f"org:{world['org']}", org_id=world["org"], event_id=world["event"])
    counts = await worker.drain_once(worker="w1", now=_future())
    assert counts["done"] == 1 and counts["lost"] == 0
    job = await _get(jid)
    assert (job.status, job.claimed_by, job.result) == ("done", None, {"ok": True})


async def test_a_claim_lost_before_the_run_starts_is_not_run(
    world: dict[str, Any], registered: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch's later job can wait past the reap threshold behind slow runs; by
    the time its turn comes another worker may hold it. It must not run twice."""
    runs: list[int] = []

    async def _rec(session: Any, key: str, job: Any) -> dict[str, Any]:
        runs.append(job.id)
        return {}

    c = _add(registered, _rec)
    jid = await _job(c.name, f"org:{world['org']}", org_id=world["org"], event_id=world["event"])
    real_claim = worker._claim

    async def _claim_then_lose(**kw: Any) -> Any:
        out = await real_claim(**kw)
        await _reclaim(jid)
        return out

    monkeypatch.setattr(worker, "_claim", _claim_then_lose)
    counts = await worker.drain_once(worker="w1", now=_future())
    assert runs == [] and counts["lost"] == 1
    job = await _get(jid)
    assert (job.status, job.claimed_by, job.attempts) == ("claimed", "w2", 2)


# ── which tenant a job runs under ────────────────────────────────────────────


async def test_the_consumer_runs_under_the_scopes_tenant(
    world: dict[str, Any], registered: list[str]
) -> None:
    seen: dict[str, tuple[int | None, str]] = {}

    async def _who(session: Any, key: str, job: Any) -> dict[str, Any]:
        seen[key] = await _tenant(session)
        return {}

    c = _add(registered, _who)
    sys_key, org_key = f"system:{world['system']}", f"org:{world['org']}"
    # Filed with no organization: only the scope can supply the tenant.
    await _job(c.name, sys_key, org_id=None, event_id=world["event"])
    await _job(c.name, org_key, org_id=world["org"], event_id=world["event"])

    await worker.drain_once(worker="w1", now=_future())
    assert seen[sys_key] == (world["org"], "ccf_app")
    assert seen[org_key] == (world["org"], "ccf_app")


async def test_only_an_orgless_event_job_runs_unscoped(
    world: dict[str, Any], monkeypatch: Any
) -> None:
    seen: dict[int, tuple[int | None, str]] = {}

    async def _who(session: Any, key: str, job: Any) -> dict[str, Any]:
        seen[job.result["webhook_id"]] = await _tenant(session)
        return {}

    monkeypatch.setitem(
        consumers.REGISTRY,
        "webhook",
        Consumer(name="webhook", matches=lambda e, v: False, scope=lambda ev: None, run=_who),
    )
    orgless = await _event(None)
    await _job(
        "webhook",
        f"event:{orgless}",
        org_id=None,
        event_id=orgless,
        at=PAST - timedelta(days=5),
        result={"webhook_id": 1},
    )
    await _job(
        "webhook",
        f"event:{world['event']}",
        org_id=world["org"],
        event_id=world["event"],
        at=PAST - timedelta(days=4),
        result={"webhook_id": 2},
    )
    await worker.drain_once(worker="w1", limit=2, now=_future())
    assert seen[1][0] is None and seen[1][1] != "ccf_app"
    assert seen[2] == (world["org"], "ccf_app")  # an org webhook job is scoped


async def test_a_null_org_consumer_job_never_runs_unscoped(
    world: dict[str, Any], registered: list[str]
) -> None:
    ran: list[str] = []

    async def _rec(session: Any, key: str, job: Any) -> dict[str, Any]:
        ran.append(key)
        return {}

    c = _add(registered, _rec)
    unknown = await _job(c.name, "widget:5", org_id=None, event_id=world["event"])
    typo = await _job(c.name, "sytem:5", org_id=world["org"], event_id=world["event"])
    garbage = await _job(c.name, "system:abc", org_id=world["org"], event_id=world["event"])
    good = await _job(c.name, f"org:{world['org']}", org_id=None, event_id=world["event"])

    counts = await worker.drain_once(worker="w1", now=_future())
    assert ran == [f"org:{world['org']}"]  # positive control
    for jid, key in ((unknown, "widget:5"), (typo, "sytem:5"), (garbage, "system:abc")):
        job = await _get(jid)
        assert (job.status, job.attempts) == ("failed", 1), key
        assert job.last_error == f"unresolvable scope: {key}"
    assert counts["failed"] >= 3
    assert (await _get(good)).status == "done"


async def test_a_deleted_system_finishes_as_skipped(
    world: dict[str, Any], registered: list[str]
) -> None:
    ran: list[str] = []

    async def _rec(session: Any, key: str, job: Any) -> dict[str, Any]:
        ran.append(key)
        return {}

    c = _add(registered, _rec)
    jid = await _job(
        c.name, f"system:{world['system']}", org_id=world["org"], event_id=world["event"]
    )
    async with session_scope() as s:
        await s.execute(
            update(System).where(System.id == world["system"]).values(deleted_at=datetime.now(UTC))
        )
    counts = await worker.drain_once(worker="w1", now=_future())
    job = await _get(jid)
    assert ran == []
    assert job.status == "done" and job.result == {"skipped": "scope gone"}
    assert job.finished_at is not None
    assert counts["skipped"] >= 1


# ── which jobs this worker may claim ─────────────────────────────────────────


async def test_an_unregistered_consumers_job_is_left_alone(
    world: dict[str, Any], registered: list[str]
) -> None:
    async def _rec(session: Any, key: str, job: Any) -> dict[str, Any]:
        return {}

    c = _add(registered, _rec)
    orphan = await _job(
        f"gone{uuid.uuid4().hex[:8]}",
        f"org:{world['org']}",
        org_id=world["org"],
        event_id=world["event"],
    )
    mine = await _job(c.name, f"org:{world['org']}", org_id=world["org"], event_id=world["event"])
    await worker.drain_once(worker="w1", now=_future())
    job = await _get(orphan)
    assert (job.status, job.attempts, job.claimed_by) == ("pending", 0, None)
    assert (await _get(mine)).status == "done"  # positive control


# ── chained events ───────────────────────────────────────────────────────────


async def test_the_run_carries_its_consumer_and_depth(
    world: dict[str, Any], registered: list[str]
) -> None:
    seen: dict[str, tuple[str | None, int]] = {}

    async def _ctx(session: Any, key: str, job: Any) -> dict[str, Any]:
        seen[key] = (outbox.CURRENT_CONSUMER.get(), outbox.CURRENT_DEPTH.get())
        return {}

    c = _add(registered, _ctx)
    cases = {
        "org:": None,  # a request-path event: depth 1
        "system:": {"_depth": 2},  # a consumer-originated event at depth 2
    }
    keys: dict[str, str] = {}
    for kind, payload in cases.items():
        ev = await _event(world["org"], payload)
        key = f"{kind}{world['org'] if kind == 'org:' else world['system']}"
        keys[kind] = key
        await _job(c.name, key, org_id=world["org"], event_id=ev)
    # A bogus depth (not an int in 1..3) counts as a request-path event.
    for bogus in ("2", 7, True):
        async with session_scope() as s:
            org = Organization(name=f"worker-d-{uuid.uuid4().hex[:6]}")
            s.add(org)
            await s.flush()
            oid = org.id
        ev = await _event(oid, {"_depth": bogus})
        keys[repr(bogus)] = f"org:{oid}"
        await _job(c.name, f"org:{oid}", org_id=oid, event_id=ev)

    await worker.drain_once(worker="w1", limit=20, now=_future())
    assert seen[keys["org:"]] == (c.name, 1)
    assert seen[keys["system:"]] == (c.name, 3)
    for bogus in ("2", 7, True):
        assert seen[keys[repr(bogus)]] == (c.name, 1), bogus
    assert outbox.CURRENT_CONSUMER.get() is None
    assert outbox.CURRENT_DEPTH.get() == 0
