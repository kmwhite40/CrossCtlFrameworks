"""The webhook consumer: signed, SSRF-pinned, event-identified delivery from the outbox.

No test reaches the network: DNS is stubbed and ``httpx.AsyncClient`` is
replaced by a recorder. Job rows are read back on an UNSCOPED session.

The test DB is shared, so each test starts by clearing the live jobs other
modules left behind (the worker would claim them), and removes its own on exit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, select, update

from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.events import consumers, webhooks, worker
from ccf.governance import bus, webhook_url
from ccf.models import Event, Organization, Webhook
from ccf.models_outbox import OutboxJob

pytestmark = pytest.mark.usefixtures("fresh_engine")

LATER = datetime.now(UTC) + timedelta(days=1)
SECRET = "s3cret-value"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
async def _no_live_jobs_left_behind() -> AsyncIterator[None]:
    async with session_scope() as s:
        # Every consumer's, not only the webhook's: the derived views are
        # registered too, and a leftover job of theirs takes a drain's slot.
        await s.execute(delete(OutboxJob).where(OutboxJob.status.in_(("pending", "claimed"))))
        mark = (await s.execute(select(func.coalesce(func.max(OutboxJob.id), 0)))).scalar_one()
    yield
    async with session_scope() as s:
        await s.execute(
            delete(OutboxJob).where(
                OutboxJob.id > mark, OutboxJob.status.in_(("pending", "claimed"))
            )
        )


class Net:
    """Records every request; ``respond`` decides the answer (status or exception)."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.client_kwargs: list[dict[str, Any]] = []
        self.respond: Callable[[dict[str, Any]], int] = lambda call: 200


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch) -> Net:
    n = Net()

    class _Client:
        def __init__(self, *a: Any, **k: Any) -> None:
            n.client_kwargs.append(k)

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *a: Any) -> None:
            return None

        async def post(self, url: str, **k: Any) -> httpx.Response:
            call = {"url": url, **k}
            n.calls.append(call)
            return httpx.Response(n.respond(call), request=httpx.Request("POST", url))

    monkeypatch.setattr(webhooks.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(webhook_url, "_resolve", lambda host: ["93.184.216.34"])
    return n


@pytest.fixture
async def world() -> AsyncIterator[dict[str, Any]]:
    async with session_scope() as s:
        org = Organization(name=f"whk-{uuid.uuid4().hex[:8]}")
        s.add(org)
        await s.flush()
        w: dict[str, Any] = {"org": org.id, "hooks": []}
    yield w
    if w["hooks"]:
        async with session_scope() as s:
            await s.execute(delete(Webhook).where(Webhook.id.in_(w["hooks"])))


async def _hook(
    world: dict[str, Any], *, url: str = "https://hooks.example/in", secret: str | None = SECRET
) -> int:
    async with session_scope() as s:
        h = Webhook(organization_id=world["org"], url=url, secret=secret, events=[], active=True)
        s.add(h)
        await s.flush()
        world["hooks"].append(h.id)
        return h.id


async def _emit(
    world: dict[str, Any], org: int | str | None = "org", entity_type: str | None = None
) -> int:
    org_id = world["org"] if org == "org" else org
    async with session_scope() as s:
        ev = await bus.emit(
            s,
            verb="created",
            entity_type=entity_type or f"t{uuid.uuid4().hex[:8]}",
            summary="a summary",
            org_id=org_id,  # type: ignore[arg-type]
            entity_id="42",
            payload={"k": "v"},
        )
        return ev.id


async def _job(event_id: int, hook_id: int) -> OutboxJob:
    async with session_scope() as s:
        jobs = (
            (
                await s.execute(
                    select(OutboxJob).where(
                        OutboxJob.trigger_event_id == event_id, OutboxJob.consumer == "webhook"
                    )
                )
            )
            .scalars()
            .all()
        )
        (j,) = [j for j in jobs if j.result.get("webhook_id") == hook_id]
        s.expunge(j)
        return j


async def _drain(now: datetime | None = None, passes: int = 1) -> dict[str, int]:
    """Deliveries of one event are serialized (one claim per scope per pass), so
    N webhooks on one event take N passes."""
    total: dict[str, int] = {}
    for _ in range(passes):
        for k, v in (await worker.drain_once(worker="t", limit=10, now=now)).items():
            total[k] = total.get(k, 0) + v
    return total


async def test_the_webhook_consumer_is_registered_and_never_routed_by_matches() -> None:
    c = consumers.REGISTRY["webhook"]
    assert c.matches("poam", "created") is False
    assert c.max_attempts == 8


async def test_one_job_per_webhook_even_with_the_consumer_registered(
    world: dict[str, Any], net: Net
) -> None:
    hook = await _hook(world)
    ev = await _emit(world)
    async with session_scope() as s:
        n = (
            await s.execute(
                select(func.count())
                .select_from(OutboxJob)
                .where(OutboxJob.trigger_event_id == ev, OutboxJob.consumer == "webhook")
            )
        ).scalar_one()
    assert n == 1
    assert (await _job(ev, hook)).status == "pending"


async def test_delivery_carries_the_event_id_and_signature(world: dict[str, Any], net: Net) -> None:
    signed = await _hook(world, url="https://hooks.example/signed")
    plain = await _hook(world, url="https://hooks.example/plain", secret=None)
    ev_id = await _emit(world)
    await _drain(passes=2)

    assert len(net.calls) == 2
    s_call = next(c for c in net.calls if c["url"].endswith("/signed"))
    p_call = next(c for c in net.calls if c["url"].endswith("/plain"))
    assert s_call["url"].startswith("https://93.184.216.34/")
    assert s_call["headers"]["Host"] == "hooks.example"

    body = s_call["content"]
    expected = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    assert s_call["headers"]["X-CCF-Signature"] == f"sha256={expected}"
    assert s_call["headers"]["X-CCF-Event-Id"] == str(ev_id)
    assert "X-CCF-Signature" not in p_call["headers"]  # positive control: no secret, no sig
    assert p_call["headers"]["X-CCF-Event-Id"] == str(ev_id)

    async with session_scope() as s:
        ev = await s.get(Event, ev_id)
        created = ev.created_at
    doc = json.loads(body)
    assert doc == {
        "verb": "created",
        "entity_type": ev.entity_type,
        "entity_id": "42",
        "summary": "a summary",
        "payload": {"k": "v"},
        "event_id": ev_id,
        "occurred_at": created.isoformat(),
    }
    for hook in (signed, plain):
        j = await _job(ev_id, hook)
        assert j.status == "done" and j.result["webhook_id"] == hook
        assert [e["status"] for e in j.result["attempts_log"]] == [200]


async def test_a_500_is_retried_and_logged(world: dict[str, Any], net: Net) -> None:
    hook = await _hook(world)
    ev = await _emit(world)
    net.respond = lambda call: 500

    assert (await _drain())["retried"] == 1
    j = await _job(ev, hook)
    assert j.status == "pending" and j.attempts == 1
    assert j.result["webhook_id"] == hook
    log = j.result["attempts_log"]
    assert len(log) == 1
    assert log[0]["status"] == 500 and log[0]["error"] == "HTTP 500"
    assert set(log[0]) == {"at", "status", "ms", "error"}

    # A second failure: the log keeps one entry per attempt.
    await _drain(LATER)
    j = await _job(ev, hook)
    assert j.status == "pending" and j.attempts == 2
    assert [e["status"] for e in j.result["attempts_log"]] == [500, 500]

    # Recovery: delivered, and the log shows all three attempts.
    net.respond = lambda call: 204
    assert (await _drain(LATER + timedelta(days=1)))["done"] == 1
    j = await _job(ev, hook)
    assert j.status == "done" and j.attempts == 3
    assert [e["status"] for e in j.result["attempts_log"]] == [500, 500, 204]
    assert len(net.calls) == 3


async def test_a_transport_error_is_retried_and_logged(world: dict[str, Any], net: Net) -> None:
    hook = await _hook(world)
    ev = await _emit(world)

    def boom(call: dict[str, Any]) -> int:
        raise httpx.ConnectError("no route")

    net.respond = boom
    assert (await _drain())["retried"] == 1
    j = await _job(ev, hook)
    (entry,) = j.result["attempts_log"]
    assert entry["status"] is None and "ConnectError" in entry["error"]
    assert j.status == "pending"


async def test_a_redirect_is_not_followed(world: dict[str, Any], net: Net) -> None:
    hook = await _hook(world)
    ev = await _emit(world)
    net.respond = lambda call: 302
    await _drain()
    assert len(net.calls) == 1  # the Location is never requested
    assert net.client_kwargs and all(k["follow_redirects"] is False for k in net.client_kwargs)
    j = await _job(ev, hook)
    assert j.status == "pending"  # a 3xx is not a delivery
    assert j.result["attempts_log"][0]["status"] == 302


async def test_a_url_that_now_resolves_inward_is_refused_and_not_retried(
    world: dict[str, Any], net: Net, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = await _hook(world, url="https://rebind.example/x")
    good = await _hook(world, url="https://hooks.example/ok")  # positive control
    ev = await _emit(world)
    monkeypatch.setattr(
        webhook_url,
        "_resolve",
        lambda host: ["10.9.9.9"] if host == "rebind.example" else ["93.184.216.34"],
    )
    out = await _drain(passes=2)
    assert out["done"] == 2 and out["retried"] == 0

    j = await _job(ev, bad)
    assert j.status == "done" and j.attempts == 1
    assert j.result["refused"]
    assert [c["url"] for c in net.calls] == ["https://93.184.216.34/ok"]
    assert (await _job(ev, good)).status == "done"
    # Final: another pass has nothing left to retry.
    assert (await _drain(LATER))["retried"] == 0


async def test_a_deactivated_or_deleted_webhook_is_skipped(world: dict[str, Any], net: Net) -> None:
    off = await _hook(world, url="https://hooks.example/off")
    gone = await _hook(world, url="https://hooks.example/gone")
    live = await _hook(world, url="https://hooks.example/live")  # positive control
    ev = await _emit(world)
    async with session_scope() as s:
        await s.execute(update(Webhook).where(Webhook.id == off).values(active=False))
        await s.execute(delete(Webhook).where(Webhook.id == gone))
    world["hooks"].remove(gone)

    await _drain(passes=3)
    for h in (off, gone):
        j = await _job(ev, h)
        assert (
            j.status == "done"
            and j.result["skipped"]
            == {
                off: "webhook deactivated",
                gone: "webhook deleted",
            }[h]
        )
    assert [c["url"] for c in net.calls] == ["https://93.184.216.34/live"]
    assert (await _job(ev, live)).status == "done"


async def test_an_org_less_platform_broadcast_reaches_an_organizations_webhook(
    world: dict[str, Any], net: Net
) -> None:
    hook = await _hook(world)
    ev = await _emit(world, org=None, entity_type="ksi_catalog")
    j = await _job(ev, hook)
    assert j.organization_id == world["org"]
    for _ in range(50):  # every org's webhook in the shared DB gets one, serially
        if (await _job(ev, hook)).status == "done":
            break
        await _drain()
    assert (await _job(ev, hook)).status == "done"
    assert any(c["url"] == "https://93.184.216.34/in" for c in net.calls)


async def test_an_already_queued_org_less_event_is_refused_at_an_orgs_webhook(
    world: dict[str, Any], net: Net
) -> None:
    """Delivery re-checks the rule: a job queued before it (or forged) for an
    org-less, non-broadcast event never reaches an organization's webhook."""
    hook = await _hook(world)
    ev = await _emit(world, org=None, entity_type="ai_agent")
    jid = await _forged_job(ev, hook, world["org"])
    await _drain()
    assert net.calls == []
    assert (await _result(jid)).result.get("refused") == (
        "an org-less event is not a platform broadcast"
    )


async def _forged_job(ev_id: int, hook_id: int, org: int | None, *, uniq: str | None = None) -> int:
    async with session_scope() as s:
        j = OutboxJob(
            organization_id=org,
            consumer="webhook",
            scope_key=f"event:{ev_id}",
            trigger_event_id=ev_id,
            max_attempts=8,
            next_attempt_at=func.now(),
            result={"webhook_id": hook_id},
        )
        s.add(j)
        await s.flush()
        return j.id


async def _result(job_id: int) -> OutboxJob:
    async with session_scope() as s:
        return await s.get(OutboxJob, job_id)  # type: ignore[return-value]


async def test_a_global_webhook_receives_an_org_event(world: dict[str, Any], net: Net) -> None:
    async with session_scope() as s:
        h = Webhook(organization_id=None, url="https://hooks.example/g", events=[], active=True)
        s.add(h)
        await s.flush()
        gid = h.id
        world["hooks"].append(gid)
    ev = await _emit(world)  # unscoped emitter: the global hook is selected
    j = await _job(ev, gid)
    assert j.organization_id == world["org"]
    await _drain()
    assert [c["url"] for c in net.calls] == ["https://93.184.216.34/g"]
    assert (await _job(ev, gid)).status == "done"


async def test_a_job_naming_another_organizations_webhook_is_refused(
    world: dict[str, Any], net: Net
) -> None:
    async with session_scope() as s:
        other = Organization(name=f"whk-other-{uuid.uuid4().hex[:6]}")
        s.add(other)
        await s.flush()
        b = Webhook(organization_id=other.id, url="https://hooks.example/b", events=[], active=True)
        s.add(b)
        await s.flush()
        bid, other_org = b.id, other.id
        world["hooks"].append(bid)
    ev = await _emit(world)  # org A event
    jid = await _forged_job(ev, bid, world["org"])
    await _drain()
    j = await _result(jid)
    assert j.status == "done" and j.result["refused"] == "webhook belongs to another organization"
    assert net.calls == []
    # Positive control: the same hook under its own organization's event delivers.
    ev_b = await _emit(world, org=other_org)
    jb = await _forged_job(ev_b, bid, other_org)
    await _drain(passes=2)
    assert (await _result(jb)).status == "done" and net.calls  # the real job also delivers


async def test_a_job_naming_another_organizations_event_is_refused(
    world: dict[str, Any], net: Net
) -> None:
    hook = await _hook(world)
    async with session_scope() as s:
        other = Organization(name=f"whk-other-{uuid.uuid4().hex[:6]}")
        s.add(other)
        await s.flush()
        other_org = other.id
    ev_other = await _emit(world, org=other_org)
    jid = await _forged_job(ev_other, hook, world["org"])
    await _drain()
    j = await _result(jid)
    assert j.status == "done" and j.result["refused"] == "event belongs to another organization"
    assert net.calls == []


async def test_a_gone_event_is_its_own_skip(world: dict[str, Any]) -> None:
    """The FK keeps a queued job's event alive, so run() is called directly."""
    from types import SimpleNamespace  # noqa: PLC0415

    hook = await _hook(world)
    job = SimpleNamespace(
        result={"webhook_id": hook}, trigger_event_id=2_000_000_000, organization_id=world["org"]
    )
    async with session_scope() as s:
        out = await webhooks.run(s, "event:2000000000", job)  # type: ignore[arg-type]
    assert out == {"skipped": "event gone"}


async def test_the_tenant_is_restored_after_the_unscoped_reads(
    world: dict[str, Any], net: Net
) -> None:
    from sqlalchemy import text  # noqa: PLC0415

    hook = await _hook(world)
    ev = await _emit(world)
    job = await _job(ev, hook)
    async with session_scope() as s:
        await set_session_tenant(s, world["org"])
        await webhooks.run(s, job.scope_key, job)
        tenant = (await s.execute(text("SELECT ccf.current_tenant()"))).scalar()
    assert tenant == world["org"]


async def test_a_requeued_dead_letter_is_delivered_to_its_webhook(
    world: dict[str, Any], net: Net
) -> None:
    """A requeue keeps the job's ``webhook_id``: without it the consumer reads the
    delivery as "webhook deleted", marks it done, and the dead letter vanishes."""
    from ccf.events import retention  # noqa: PLC0415

    hook = await _hook(world)
    ev = await _emit(world)
    jid = (await _job(ev, hook)).id
    async with session_scope() as s:  # one attempt short of the cap
        await s.execute(update(OutboxJob).where(OutboxJob.id == jid).values(attempts=7))
    net.respond = lambda call: 500
    assert (await _drain())["failed"] == 1
    j = await _result(jid)
    assert j.status == "failed" and j.result["webhook_id"] == hook

    async with session_scope() as s:
        await set_session_tenant(s, None)
        assert await retention.requeue_failed(s, consumer="webhook", org_id=world["org"]) == 1
    j = await _result(jid)
    assert j.status == "pending" and j.attempts == 0
    assert j.result["webhook_id"] == hook
    assert j.result["requeued_from_error"] == "DeliveryError: HTTP 500"

    net.respond = lambda call: 200
    assert (await _drain(LATER))["done"] == 1
    j = await _result(jid)
    assert j.status == "done" and "skipped" not in j.result
    assert [e["status"] for e in j.result["attempts_log"]][-1] == 200
    assert len(net.calls) == 2  # the failed attempt, then the requeued delivery
