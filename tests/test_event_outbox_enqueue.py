"""``emit`` queues outbox jobs in the caller's transaction; nothing leaves before commit.

Assertions about which organization a job belongs to are read back on an
UNSCOPED session: a tenant session's RLS would hide a job filed under the wrong
organization and make the check pass vacuously.

The test DB is shared, so other modules may have left active global webhooks
behind. Every assertion is therefore pinned to this test's own event ids and
webhook ids, and every webhook created here is deleted in ``finally`` so no
leftover subscription reaches another module's drain.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
import structlog
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, select, text

from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.events import consumers, outbox
from ccf.events.consumers import Consumer, register
from ccf.governance import bus, webhook_url
from ccf.models import Event, Organization, System, Webhook
from ccf.models_outbox import OutboxJob

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


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


@pytest.fixture
def posted(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every outbound webhook POST, from any code path, lands here.

    DNS is stubbed to a public address so a dispatch would not be refused by the
    SSRF guard -- otherwise "nothing was posted" could not fail.
    """
    calls: list[str] = []

    async def _post(self: Any, url: Any, *a: Any, **k: Any) -> httpx.Response:
        calls.append(str(url))
        return httpx.Response(200, request=httpx.Request("POST", str(url)))

    monkeypatch.setattr(httpx.AsyncClient, "post", _post)
    monkeypatch.setattr(webhook_url, "_resolve", lambda host: ["93.184.216.34"])
    return calls


async def _noop(session: Any, scope_key: str, job: Any) -> dict[str, Any]:
    return {}


@pytest.fixture
def entity() -> str:
    """An entity type no real emit site uses, so test consumers match only us."""
    return f"t{uuid.uuid4().hex[:10]}"


@pytest.fixture
def registered() -> Iterator[list[str]]:
    names: list[str] = []
    yield names
    for n in names:
        consumers.REGISTRY.pop(n, None)


def _add(
    registered: list[str], entity: str, scope: Any, *, name: str | None = None, settle: int = 15
) -> Consumer:
    c = Consumer(
        name=name or f"c{uuid.uuid4().hex[:10]}",
        matches=lambda e, v: e == entity,
        scope=scope,
        run=_noop,
        settle_seconds=settle,
    )
    register(c)
    registered.append(c.name)
    return c


@pytest.fixture
async def world() -> AsyncIterator[dict[str, Any]]:
    """An org with a system, plus a list webhooks can be registered on for cleanup."""
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"outbox-{tag}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"outbox {tag}", certification_class="C")
        s.add(sysm)
        await s.flush()
        w: dict[str, Any] = {"org": org.id, "system": sysm.id, "hooks": []}
    try:
        yield w
    finally:
        if w["hooks"]:
            async with session_scope() as s:
                await s.execute(delete(Webhook).where(Webhook.id.in_(w["hooks"])))


async def _hook(world: dict[str, Any], org_id: int | None, events: list[str] | None = None) -> int:
    async with session_scope() as s:
        h = Webhook(
            organization_id=org_id,
            url=f"https://hooks.example/{uuid.uuid4().hex[:6]}",
            events=events or [],
            active=True,
        )
        s.add(h)
        await s.flush()
        world["hooks"].append(h.id)
        return h.id


async def _jobs(event_id: int) -> list[OutboxJob]:
    async with session_scope() as s:
        return list(
            (
                await s.execute(
                    select(OutboxJob)
                    .where(OutboxJob.trigger_event_id == event_id)
                    .order_by(OutboxJob.id)
                )
            )
            .scalars()
            .all()
        )


def _webhook_ids(jobs: list[OutboxJob]) -> set[int]:
    return {j.result["webhook_id"] for j in jobs if j.consumer == "webhook"}


# ── nothing leaves the database before commit ────────────────────────────────


async def test_a_rolled_back_transaction_queues_and_sends_nothing(
    world: dict[str, Any], posted: list[str], entity: str
) -> None:
    hook = await _hook(world, world["org"])

    class _AbortError(Exception):
        pass

    ev_id: int | None = None
    with pytest.raises(_AbortError):
        async with session_scope() as s:
            ev = await bus.emit(
                s, verb="created", entity_type=entity, summary="x", org_id=world["org"]
            )
            ev_id = ev.id
            raise _AbortError
    assert ev_id is not None
    assert await _jobs(ev_id) == []

    # Positive control: the same emit, committed, queues the delivery.
    async with session_scope() as s:
        ev = await bus.emit(s, verb="created", entity_type=entity, summary="x", org_id=world["org"])
        kept = ev.id
    assert hook in _webhook_ids(await _jobs(kept))
    assert posted == []


async def test_emit_no_longer_posts_during_the_request(
    world: dict[str, Any], posted: list[str], entity: str
) -> None:
    hook = await _hook(world, world["org"])
    async with session_scope() as s:
        ev = await bus.emit(s, verb="created", entity_type=entity, summary="x", org_id=world["org"])
        # Still inside the request's transaction.
        assert posted == []
        mine = [
            j
            for j in (
                await s.execute(select(OutboxJob).where(OutboxJob.trigger_event_id == ev.id))
            ).scalars()
            if j.consumer == "webhook" and j.result.get("webhook_id") == hook
        ]
        assert len(mine) == 1
        job = mine[0]
        assert job.status == "pending"
        assert job.scope_key == f"event:{ev.id}"
        assert job.max_attempts == 8
        assert job.organization_id == world["org"]
    assert posted == []


async def test_dispatch_false_queues_no_webhook_job(
    world: dict[str, Any], posted: list[str], entity: str, registered: list[str]
) -> None:
    hook = await _hook(world, world["org"])
    c = _add(registered, entity, lambda ev: f"org:{ev.organization_id}")
    async with session_scope() as s:
        quiet = await bus.emit(
            s, verb="updated", entity_type=entity, summary="x", org_id=world["org"], dispatch=False
        )
        loud = await bus.emit(
            s, verb="updated", entity_type=entity, summary="x", org_id=world["org"]
        )
    quiet_jobs = await _jobs(quiet.id)
    assert hook not in _webhook_ids(quiet_jobs)
    assert [j.consumer for j in quiet_jobs] == [c.name]  # internal consumers still match
    assert hook in _webhook_ids(await _jobs(loud.id))  # positive control


# ── which organization a job belongs to ──────────────────────────────────────


async def test_an_orgless_event_takes_its_scopes_org(
    world: dict[str, Any], entity: str, registered: list[str]
) -> None:
    c = _add(registered, entity, lambda ev: ev.payload["scope"], settle=15)
    async with session_scope() as s:
        live = await bus.emit(
            s,
            verb="updated",
            entity_type=entity,
            summary="x",
            payload={"scope": f"system:{world['system']}"},
        )
        gone = await bus.emit(
            s,
            verb="updated",
            entity_type=entity,
            summary="x",
            payload={"scope": "system:999999999"},
        )
    [job] = [j for j in await _jobs(live.id) if j.consumer == c.name]
    assert job.organization_id == world["org"]
    assert job.scope_key == f"system:{world['system']}"
    assert job.next_attempt_at - job.created_at >= timedelta(seconds=14)
    # A scope that no longer exists is still queued (the worker skips it), unowned.
    [dead] = [j for j in await _jobs(gone.id) if j.consumer == c.name]
    assert dead.organization_id is None


async def test_a_consumer_that_ignores_an_event_queues_nothing(
    world: dict[str, Any], entity: str, registered: list[str]
) -> None:
    c = _add(registered, entity, lambda ev: ev.payload.get("scope"))
    async with session_scope() as s:
        ignored = await bus.emit(
            s, verb="updated", entity_type=entity, summary="x", org_id=world["org"]
        )
        taken = await bus.emit(
            s,
            verb="updated",
            entity_type=entity,
            summary="x",
            org_id=world["org"],
            payload={"scope": f"org:{world['org']}"},
        )
        other = await bus.emit(
            s,
            verb="updated",
            entity_type=entity + "x",
            summary="x",
            org_id=world["org"],
            payload={"scope": f"org:{world['org']}"},
        )
    assert [j.consumer for j in await _jobs(ignored.id)] == []
    assert [j.consumer for j in await _jobs(other.id)] == []  # matches() said no
    assert [j.consumer for j in await _jobs(taken.id)] == [c.name]


async def test_webhook_jobs_take_the_events_org_else_the_hooks(
    world: dict[str, Any], entity: str
) -> None:
    org_hook = await _hook(world, world["org"])
    global_hook = await _hook(world, None, events=[entity])
    async with session_scope() as s:
        scoped = await bus.emit(
            s, verb="created", entity_type=entity, summary="x", org_id=world["org"]
        )
        orgless = await bus.emit(s, verb="created", entity_type=entity, summary="x")
    by_hook = {j.result["webhook_id"]: j for j in await _jobs(scoped.id) if j.consumer == "webhook"}
    # A global webhook delivering an org's event belongs to that org.
    assert by_hook[global_hook].organization_id == world["org"]
    assert by_hook[org_hook].organization_id == world["org"]
    by_hook = {
        j.result["webhook_id"]: j for j in await _jobs(orgless.id) if j.consumer == "webhook"
    }
    # Org-less event: an org webhook's delivery is still that org's; only a
    # global webhook's delivery of an org-less event is platform-only.
    assert by_hook[org_hook].organization_id == world["org"]
    assert by_hook[global_hook].organization_id is None
    assert by_hook[global_hook].next_attempt_at == by_hook[global_hook].created_at


async def test_a_webhook_subscription_filters_by_verb_or_entity(
    world: dict[str, Any], entity: str
) -> None:
    by_verb = await _hook(world, world["org"], events=["approved"])
    by_entity = await _hook(world, world["org"], events=[entity])
    async with session_scope() as s:
        created = await bus.emit(
            s, verb="created", entity_type=entity, summary="x", org_id=world["org"]
        )
        approved = await bus.emit(
            s, verb="approved", entity_type="other", summary="x", org_id=world["org"]
        )
    assert _webhook_ids(await _jobs(created.id)) & {by_verb, by_entity} == {by_entity}
    assert _webhook_ids(await _jobs(approved.id)) & {by_verb, by_entity} == {by_verb}


async def test_another_orgs_webhook_is_not_queued(world: dict[str, Any], entity: str) -> None:
    async with session_scope() as s:
        other = Organization(name=f"outbox-other-{uuid.uuid4().hex[:8]}")
        s.add(other)
        await s.flush()
        other_id = other.id
    theirs = await _hook(world, other_id)
    ours = await _hook(world, world["org"])
    async with session_scope() as s:
        ev = await bus.emit(s, verb="created", entity_type=entity, summary="x", org_id=world["org"])
    ids = _webhook_ids(await _jobs(ev.id))
    assert ours in ids
    assert theirs not in ids


async def test_emit_in_a_tenant_session_queues_under_that_tenant(
    world: dict[str, Any], entity: str, registered: list[str]
) -> None:
    """The WITH CHECK on outbox_jobs refuses a row outside the session's tenant."""
    org_hook = await _hook(world, world["org"])
    global_hook = await _hook(world, None)
    c = _add(registered, entity, lambda ev: f"system:{world['system']}")
    async with session_scope() as s:
        await set_session_tenant(s, world["org"])
        ev = await bus.emit(s, verb="created", entity_type=entity, summary="x", org_id=world["org"])
        ev_id = ev.id
    jobs = await _jobs(ev_id)  # read back unscoped
    assert {j.organization_id for j in jobs} == {world["org"]}
    assert c.name in {j.consumer for j in jobs}
    assert org_hook in _webhook_ids(jobs)
    # Unchanged from the pre-outbox dispatcher: the webhooks policy hides an
    # org-less row from a tenant session, so a global webhook is not selected
    # for an event emitted under a tenant. Recorded here so changing it is a
    # deliberate decision, not a side effect.
    assert global_hook not in _webhook_ids(jobs)


# ── chained events (spec 6.3a) ───────────────────────────────────────────────


async def test_a_consumers_own_event_does_not_retrigger_it_or_reach_webhooks(
    world: dict[str, Any], entity: str, registered: list[str]
) -> None:
    hook = await _hook(world, world["org"])
    a = _add(registered, entity, lambda ev: f"org:{world['org']}")
    b = _add(registered, entity, lambda ev: f"org:{world['org']}")
    async with session_scope() as s:
        tok_c = outbox.CURRENT_CONSUMER.set(a.name)
        tok_d = outbox.CURRENT_DEPTH.set(1)
        try:
            chained = await bus.emit(
                s,
                verb="updated",
                entity_type=entity,
                summary="x",
                org_id=world["org"],
                payload={"k": "v"},
            )
        finally:
            outbox.CURRENT_DEPTH.reset(tok_d)
            outbox.CURRENT_CONSUMER.reset(tok_c)
        plain = await bus.emit(
            s, verb="updated", entity_type=entity, summary="x", org_id=world["org"]
        )
    chained_jobs = await _jobs(chained.id)
    assert {j.consumer for j in chained_jobs} == {b.name}
    assert hook not in _webhook_ids(chained_jobs)
    assert chained.payload == {"k": "v", "_depth": 1}
    # Positive control: the same event outside a consumer reaches all three.
    plain_jobs = await _jobs(plain.id)
    assert {a.name, b.name} <= {j.consumer for j in plain_jobs}
    assert hook in _webhook_ids(plain_jobs)
    assert "_depth" not in plain.payload


async def test_depth_three_queues_nothing(
    world: dict[str, Any], entity: str, registered: list[str]
) -> None:
    a = _add(registered, entity, lambda ev: f"org:{world['org']}")
    b = _add(registered, entity, lambda ev: f"org:{world['org']}")
    ids: dict[int, int] = {}
    async with session_scope() as s:
        for depth in (2, 3, 4):
            tok_c = outbox.CURRENT_CONSUMER.set(a.name)
            tok_d = outbox.CURRENT_DEPTH.set(depth)
            try:
                ev = await bus.emit(
                    s, verb="updated", entity_type=entity, summary="x", org_id=world["org"]
                )
            finally:
                outbox.CURRENT_DEPTH.reset(tok_d)
                outbox.CURRENT_CONSUMER.reset(tok_c)
            ids[depth] = ev.id
            assert ev.payload["_depth"] == depth
    assert [j.consumer for j in await _jobs(ids[2])] == [b.name]  # positive control
    assert await _jobs(ids[3]) == []
    assert await _jobs(ids[4]) == []


async def test_the_contextvars_default_to_a_request() -> None:
    assert outbox.CURRENT_CONSUMER.get() is None
    assert outbox.CURRENT_DEPTH.get() == 0


async def test_a_webhook_job_is_queued_whether_or_not_the_consumer_is_registered(
    world: dict[str, Any], entity: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Webhook selection happens at enqueue, not through the consumer registry."""
    hook = await _hook(world, world["org"])
    for registered_now in (True, False):
        if not registered_now:
            monkeypatch.delitem(consumers.REGISTRY, "webhook")
        assert ("webhook" in consumers.REGISTRY) is registered_now
        async with session_scope() as s:
            ev = await bus.emit(
                s, verb="created", entity_type=entity, summary="x", org_id=world["org"]
            )
        jobs = [j for j in await _jobs(ev.id) if j.consumer == "webhook"]
        assert [j.result["webhook_id"] for j in jobs] == [hook]  # exactly one


async def test_emit_still_returns_the_flushed_event(world: dict[str, Any], entity: str) -> None:
    async with session_scope() as s:
        ev = await bus.emit(s, verb="created", entity_type=entity, summary="x", org_id=world["org"])
        assert isinstance(ev, Event) and ev.id is not None


# ── a broken consumer costs its own job, never the request ───────────────────


def _failures(cap: list[dict[str, Any]], msg: str) -> list[dict[str, Any]]:
    return [r for r in cap if r.get("event") == msg]


async def test_a_broken_consumer_costs_only_its_own_job(
    world: dict[str, Any], entity: str, registered: list[str]
) -> None:
    hook = await _hook(world, world["org"])

    def bad_scope(ev: Any) -> str:
        return ev.payload["missing"]  # KeyError

    def bad_matches(e: str, v: str) -> bool:
        if e == entity:
            raise RuntimeError("matches exploded")
        return False

    broken_scope = _add(registered, entity, bad_scope)
    broken_matches = Consumer(
        name=f"c{uuid.uuid4().hex[:10]}", matches=bad_matches, scope=lambda ev: "org:1", run=_noop
    )
    register(broken_matches)
    registered.append(broken_matches.name)
    good = _add(registered, entity, lambda ev: f"org:{world['org']}")

    with structlog.testing.capture_logs() as cap:
        async with session_scope() as s:
            ev = await bus.emit(
                s, verb="created", entity_type=entity, summary="x", org_id=world["org"]
            )
            assert isinstance(ev, Event) and ev.id is not None
            ev_id = ev.id
    jobs = await _jobs(ev_id)
    names = {j.consumer for j in jobs}
    assert good.name in names  # positive control: the healthy consumer still queued
    assert hook in _webhook_ids(jobs)  # and so did the webhook
    assert broken_scope.name not in names and broken_matches.name not in names
    logged = _failures(cap, "event_outbox.consumer_scope_failed")
    assert {r["consumer"] for r in logged} == {broken_scope.name, broken_matches.name}
    assert all(r["event_id"] == ev_id for r in logged)
    errors = {r["consumer"]: r["error"] for r in logged}
    assert errors[broken_scope.name].startswith("KeyError")
    assert errors[broken_matches.name] == "RuntimeError: matches exploded"


async def test_a_failed_scope_org_read_leaves_the_session_usable(
    world: dict[str, Any], entity: str, registered: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def failing_scope_org(session: Any, key: str) -> int:
        await session.execute(text("SELECT 1/0"))  # aborts the transaction it runs in
        raise AssertionError("unreachable")

    monkeypatch.setattr(consumers, "scope_org", failing_scope_org)
    broken = _add(registered, entity, lambda ev: f"system:{world['system']}")
    with structlog.testing.capture_logs() as cap:
        async with session_scope() as s:
            ev = await bus.emit(s, verb="updated", entity_type=entity, summary="x")  # org-less
            ev_id = ev.id
            # The caller's transaction is still alive after the failed read.
            assert (await s.execute(text("SELECT 1"))).scalar_one() == 1
    async with session_scope() as s:
        assert await s.get(Event, ev_id) is not None  # committed
    assert broken.name not in {j.consumer for j in await _jobs(ev_id)}
    [r] = _failures(cap, "event_outbox.consumer_scope_failed")
    assert r["consumer"] == broken.name and r["error"].startswith("DBAPIError")


async def test_one_broken_webhook_job_does_not_stop_the_others(
    world: dict[str, Any], entity: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = await _hook(world, world["org"])
    second = await _hook(world, world["org"])
    real = outbox._webhook_job

    def flaky(ev: Any, hook: Any) -> OutboxJob:
        if hook.id == first:
            raise RuntimeError("cannot build")
        return real(ev, hook)

    monkeypatch.setattr(outbox, "_webhook_job", flaky)
    with structlog.testing.capture_logs() as cap:
        async with session_scope() as s:
            ev = await bus.emit(
                s, verb="created", entity_type=entity, summary="x", org_id=world["org"]
            )
    ids = _webhook_ids(await _jobs(ev.id))
    assert second in ids and first not in ids
    [r] = _failures(cap, "event_outbox.webhook_job_failed")
    assert r["webhook_id"] == first and r["event_id"] == ev.id


async def test_a_failed_webhook_selection_leaves_the_session_usable(
    world: dict[str, Any], entity: str, registered: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def failing_select(session: Any, ev: Any) -> list[Any]:
        await session.execute(text("SELECT 1/0"))
        raise AssertionError("unreachable")

    monkeypatch.setattr(outbox, "_subscribed_webhooks", failing_select)
    good = _add(registered, entity, lambda ev: f"org:{world['org']}")
    with structlog.testing.capture_logs() as cap:
        async with session_scope() as s:
            ev = await bus.emit(
                s, verb="created", entity_type=entity, summary="x", org_id=world["org"]
            )
            assert (await s.execute(text("SELECT 1"))).scalar_one() == 1
    assert [j.consumer for j in await _jobs(ev.id)] == [good.name]  # consumers unaffected
    assert len(_failures(cap, "event_outbox.webhook_select_failed")) == 1
