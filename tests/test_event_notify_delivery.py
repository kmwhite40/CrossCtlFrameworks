"""Slack/Teams notification posts go out after commit, through the outbox.

``bus.notify`` used to ``await delivery.deliver(n)`` inside the caller's
transaction, so an alert raised by a change that then rolled back was still
announced. It now queues a ``notify_delivery`` job; the worker posts it.

No test reaches the network: ``httpx.AsyncClient`` is replaced by a recorder.
Job rows are read back on an UNSCOPED session; tenant assertions read
``ccf.current_tenant()`` off the consumer's own connection.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, select, text

from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.events import consumers, notify_delivery, outbox, retention, worker
from ccf.governance import bus, delivery
from ccf.models import Notification, Organization
from ccf.models_outbox import OutboxJob

pytestmark = pytest.mark.usefixtures("fresh_engine")

URL = "https://hooks.slack.example/services/T/B/x"
LATER = datetime.now(UTC) + timedelta(days=1)


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
async def _no_live_jobs_left_behind() -> AsyncIterator[None]:
    async with session_scope() as s:
        await s.execute(delete(OutboxJob).where(OutboxJob.status.in_(("pending", "claimed"))))
        mark = (await s.execute(select(func.coalesce(func.max(OutboxJob.id), 0)))).scalar_one()
    yield
    async with session_scope() as s:
        # Every status: a dead letter left here would FAIL other modules'
        # reliability checks on the shared DB.
        await s.execute(delete(OutboxJob).where(OutboxJob.id > mark))


def _configure(monkeypatch: pytest.MonkeyPatch, *, url: str | None, min_severity: str) -> None:
    if url is None:
        monkeypatch.delenv("CCF_NOTIFY_WEBHOOK_URL", raising=False)
    else:
        monkeypatch.setenv("CCF_NOTIFY_WEBHOOK_URL", url)
    monkeypatch.setenv("CCF_NOTIFY_MIN_SEVERITY", min_severity)
    get_settings.cache_clear()


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., None]]:
    def _set(url: str | None = URL, min_severity: str = "critical") -> None:
        _configure(monkeypatch, url=url, min_severity=min_severity)

    _set()
    yield _set
    monkeypatch.delenv("CCF_NOTIFY_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("CCF_NOTIFY_MIN_SEVERITY", raising=False)
    get_settings.cache_clear()


class Net:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.respond: Callable[[dict[str, Any]], int] = lambda call: 200


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch) -> Net:
    n = Net()

    class _Client:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *a: Any) -> None:
            return None

        async def post(self, url: str, **k: Any) -> httpx.Response:
            call = {"url": url, **k}
            n.calls.append(call)
            return httpx.Response(n.respond(call), request=httpx.Request("POST", url))

    monkeypatch.setattr(delivery.httpx, "AsyncClient", _Client)
    return n


@pytest.fixture
async def org() -> int:
    async with session_scope() as s:
        o = Organization(name=f"ntf-{uuid.uuid4().hex[:8]}")
        s.add(o)
        await s.flush()
        return o.id


async def _notify(
    org_id: int | None,
    *,
    severity: str = "critical",
    title: str = "Boundary drift",
    body: str | None = "3 checks failed",
    dedupe_key: str | None = None,
    tenant: bool = True,
) -> int | None:
    async with session_scope() as s:
        if tenant and org_id is not None:
            await set_session_tenant(s, org_id)
        n = await bus.notify(
            s,
            category="test",
            title=title,
            body=body,
            org_id=org_id,
            severity=severity,
            dedupe_key=dedupe_key,
        )
        return n.id if n is not None else None


async def _jobs(nid: int) -> list[OutboxJob]:
    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(OutboxJob)
                    .where(
                        OutboxJob.consumer == outbox.NOTIFY_CONSUMER,
                        OutboxJob.scope_key == f"notification:{nid}",
                    )
                    .order_by(OutboxJob.id)
                )
            )
            .scalars()
            .all()
        )
        for r in rows:
            s.expunge(r)
        return list(rows)


async def _drain(passes: int = 1, now: datetime | None = None) -> dict[str, int]:
    total: dict[str, int] = {}
    for _ in range(passes):
        for k, v in (await worker.drain_once(worker="t", limit=10, now=now)).items():
            total[k] = total.get(k, 0) + v
    return total


# ── after commit, never before ────────────────────────────────────────────────


async def test_the_consumer_is_registered_never_routed_and_at_least_once() -> None:
    c = consumers.REGISTRY[outbox.NOTIFY_CONSUMER]
    assert c.matches("notification", "created") is False
    assert c.settle_seconds == 0
    assert c.max_attempts == outbox.WEBHOOK_MAX_ATTEMPTS == 8
    assert outbox.NOTIFY_CONSUMER in outbox.AT_LEAST_ONCE


async def test_a_rolled_back_alert_is_never_posted(org: int, configured: Any, net: Net) -> None:
    marker = f"rolled-back {uuid.uuid4().hex[:8]}"
    nid: int | None = None
    with pytest.raises(RuntimeError, match="abort"):
        async with session_scope() as s:
            await set_session_tenant(s, org)
            n = await bus.notify(s, category="test", title=marker, org_id=org, severity="critical")
            assert n is not None
            nid = n.id
            raise RuntimeError("abort")
    assert net.calls == []  # nothing during the request
    assert nid is not None
    assert await _jobs(nid) == []
    await _drain()
    assert all(marker not in c["json"]["text"] for c in net.calls)


async def test_after_commit_a_drain_posts_what_deliver_posted(
    org: int, configured: Any, net: Net
) -> None:
    nid = await _notify(org, title="Boundary drift", body="3 checks failed")
    assert nid is not None
    assert net.calls == []  # queued, not posted in the request
    (job,) = await _jobs(nid)
    assert (job.status, job.organization_id, job.trigger_event_id) == ("pending", org, None)

    counts = await _drain()
    assert counts["done"] == 1
    assert len(net.calls) == 1
    call = net.calls[0]
    assert call["url"] == URL
    assert call["json"] == {"text": "[CRITICAL] Boundary drift\n3 checks failed"}
    (job,) = await _jobs(nid)
    assert job.status == "done"
    assert job.result["status_code"] == 200


async def test_without_a_body_the_message_is_the_title_line(
    org: int, configured: Any, net: Net
) -> None:
    nid = await _notify(org, title="Just a title", body=None)
    assert nid is not None
    await _drain()
    assert [c["json"]["text"] for c in net.calls] == ["[CRITICAL] Just a title"]


async def test_policy_below_threshold_or_unconfigured_queues_nothing(
    org: int, configured: Any, net: Net
) -> None:
    configured(min_severity="critical")
    quiet = await _notify(org, severity="warning")
    configured(url=None)
    unconfigured = await _notify(org, severity="critical")
    configured(min_severity="warning")
    loud = await _notify(org, severity="warning")
    assert quiet is not None and unconfigured is not None and loud is not None
    assert await _jobs(quiet) == []
    assert await _jobs(unconfigured) == []
    assert len(await _jobs(loud)) == 1  # positive control
    await _drain()
    assert [c["json"]["text"] for c in net.calls] == ["[WARNING] Boundary drift\n3 checks failed"]


async def test_a_worker_without_the_url_dead_letters_the_alert_loudly(
    org: int, configured: Any, net: Net
) -> None:
    """Queued where the URL was set (the api), drained where it is not (an
    event-worker with different settings): a FAILED job naming the setting,
    once, so the reliability check shows it. Never a quiet "done"."""
    nid = await _notify(org)
    assert nid is not None
    configured(url=None)
    counts = await _drain()
    assert net.calls == []
    assert counts["failed"] == 1 and counts["retried"] == 0
    (job,) = await _jobs(nid)
    assert (job.status, job.attempts) == ("failed", 1)
    assert "CCF_NOTIFY_WEBHOOK_URL" in (job.last_error or "")
    assert job.result["text"].startswith("[CRITICAL]")  # kept for a requeue


# ── dedupe and escalation ─────────────────────────────────────────────────────


async def test_an_escalation_is_posted_once_and_a_refresh_is_not(
    org: int, configured: Any, net: Net
) -> None:
    key = f"ntf-test:{uuid.uuid4().hex}"
    # Below the (critical) threshold: never posted.
    nid = await _notify(org, severity="warning", title="Drift (warning)", dedupe_key=key)
    assert nid is not None
    assert await _jobs(nid) == []

    # Escalated to critical: news again, posted once.
    again = await _notify(org, severity="critical", title="Drift (critical)", dedupe_key=key)
    assert again == nid
    assert len(await _jobs(nid)) == 1

    # A refresh at the same severity: not posted again.
    await _notify(org, severity="critical", title="Drift (critical, refreshed)", dedupe_key=key)
    # And a de-escalation is not news either.
    await _notify(org, severity="warning", title="Drift (calmer)", dedupe_key=key)
    assert len(await _jobs(nid)) == 1

    await _drain(passes=2)
    assert [c["json"]["text"] for c in net.calls] == [
        "[CRITICAL] Drift (critical)\n3 checks failed"
    ]


async def test_a_raising_and_its_escalation_are_two_posts_never_merged(
    org: int, configured: Any, net: Net
) -> None:
    configured(min_severity="warning")
    key = f"ntf-test:{uuid.uuid4().hex}"
    nid = await _notify(org, severity="warning", title="First", dedupe_key=key)
    await _notify(org, severity="critical", title="Second", dedupe_key=key)
    assert nid is not None
    assert len(await _jobs(nid)) == 2

    counts = await _drain(passes=2)
    assert counts["merged"] == 0
    # Each post says what that raising said, not the row's current state.
    assert [c["json"]["text"] for c in net.calls] == [
        "[WARNING] First\n3 checks failed",
        "[CRITICAL] Second\n3 checks failed",
    ]
    assert [j.status for j in await _jobs(nid)] == ["done", "done"]


# ── retries, at the webhook's policy ──────────────────────────────────────────


async def test_a_500_backs_off_on_the_webhook_schedule_then_dead_letters(
    org: int, configured: Any, net: Net
) -> None:
    net.respond = lambda call: 500
    nid = await _notify(org)
    assert nid is not None
    before = datetime.now(UTC)
    counts = await _drain()
    assert counts["retried"] == 1
    (job,) = await _jobs(nid)
    assert (job.status, job.attempts, job.max_attempts) == ("pending", 1, 8)
    assert job.last_error == "DeliveryError: HTTP 500"
    wait = (job.next_attempt_at - before).total_seconds()
    assert worker.WEBHOOK_BACKOFF_SECONDS - 5 <= wait <= worker.WEBHOOK_BACKOFF_SECONDS + 30
    assert [a["status"] for a in job.result["attempts_log"]] == [500]
    assert job.result["text"].startswith("[CRITICAL]")  # the message survives the retry

    for i in range(7):  # backoff counts from each failure's ``now``: step past it
        await _drain(now=datetime.now(UTC) + timedelta(days=i + 1))
    (job,) = await _jobs(nid)
    assert (job.status, job.attempts) == ("failed", 8)
    assert len(job.result["attempts_log"]) == 8
    assert len(net.calls) == 8


async def test_a_transport_error_is_retried(org: int, configured: Any, net: Net) -> None:
    def _boom(call: dict[str, Any]) -> int:
        raise httpx.ConnectError("refused")

    net.respond = _boom
    nid = await _notify(org)
    assert nid is not None
    await _drain()
    (job,) = await _jobs(nid)
    assert (job.status, job.attempts) == ("pending", 1)
    assert "ConnectError" in (job.last_error or "")


# ── tenant ────────────────────────────────────────────────────────────────────


@pytest.fixture
def seen_tenant(monkeypatch: pytest.MonkeyPatch) -> dict[int, tuple[int | None, str]]:
    seen: dict[int, tuple[int | None, str]] = {}
    real = consumers.REGISTRY[outbox.NOTIFY_CONSUMER]

    async def _wrapped(session: Any, key: str, job: Any) -> dict[str, Any]:
        out = await real.run(session, key, job)
        row = (await session.execute(text("SELECT ccf.current_tenant(), current_user"))).one()
        seen[job.id] = (row[0], row[1])
        return out

    monkeypatch.setitem(
        consumers.REGISTRY, outbox.NOTIFY_CONSUMER, dataclasses.replace(real, run=_wrapped)
    )
    return seen


async def test_the_post_runs_under_the_notifications_org(
    org: int, configured: Any, net: Net, seen_tenant: dict[int, Any]
) -> None:
    nid = await _notify(org)
    assert nid is not None
    (job,) = await _jobs(nid)
    await _drain()
    assert seen_tenant[job.id] == (org, "ccf_app")
    assert len(net.calls) == 1


async def test_an_orgless_notification_is_posted_platform_only(
    configured: Any, net: Net, seen_tenant: dict[int, Any]
) -> None:
    nid = await _notify(None, title=f"platform {uuid.uuid4().hex[:6]}")
    assert nid is not None
    (job,) = await _jobs(nid)
    assert job.organization_id is None
    await _drain()
    tenant, role = seen_tenant[job.id]
    assert tenant is None and role != "ccf_app"
    assert len(net.calls) == 1


async def _forged_job(nid: int, org_id: int | None) -> int:
    async with session_scope() as s:
        j = OutboxJob(
            organization_id=org_id,
            consumer=outbox.NOTIFY_CONSUMER,
            scope_key=f"notification:{nid}",
            trigger_event_id=None,
            max_attempts=8,
            result={"text": "[CRITICAL] forged"},
        )
        s.add(j)
        await s.flush()
        return j.id


async def test_a_job_filed_under_another_org_is_refused(
    org: int, configured: Any, net: Net
) -> None:
    configured(url=None)  # queue nothing real; the forged rows are the test
    other = await _notify(org)
    orgless = await _notify(None)
    async with session_scope() as s:
        o2 = Organization(name=f"ntf2-{uuid.uuid4().hex[:8]}")
        s.add(o2)
        await s.flush()
        org2 = o2.id
    configured()
    assert other is not None and orgless is not None
    cross = await _forged_job(other, org2)  # an org's alert, filed under another org
    unscoped = await _forged_job(other, None)  # an org's alert, filed to run unscoped
    claimed = await _forged_job(orgless, org)  # a platform alert, filed under an org

    await _drain(passes=2)  # two jobs share one notification's scope
    assert net.calls == []
    async with session_scope() as s:  # unscoped: RLS would hide a mis-filed row
        for jid in (cross, unscoped, claimed):
            job = await s.get(OutboxJob, jid)
            assert job is not None
            assert job.status == "done", jid
            assert job.result.get("refused") == "notification belongs to another organization"


async def test_a_deleted_notification_is_skipped(org: int, configured: Any, net: Net) -> None:
    nid = await _notify(org)
    assert nid is not None
    async with session_scope() as s:
        await s.execute(delete(Notification).where(Notification.id == nid))
    # The job cascades with nothing (no FK to notifications): it must skip.
    await _drain()
    assert net.calls == []
    (job,) = await _jobs(nid)
    assert (job.status, job.result.get("skipped")) == ("done", "notification gone")


async def test_done_posts_are_kept_as_delivery_records(org: int, configured: Any, net: Net) -> None:
    nid = await _notify(org)
    assert nid is not None
    await _drain()
    async with session_scope() as s:
        await retention.purge_outbox(s, now=datetime.now(UTC) + timedelta(days=2))
    assert [j.status for j in await _jobs(nid)] == ["done"]  # 30 days, like webhooks
    async with session_scope() as s:
        await retention.purge_outbox(s, now=datetime.now(UTC) + timedelta(days=31))
    assert await _jobs(nid) == []


def test_the_scope_parser_takes_only_notification_keys() -> None:
    assert notify_delivery.notification_id("notification:12") == 12
    for bad in ("event:12", "notification:", "notification:1a", "notification:\uff11"):
        assert notify_delivery.notification_id(bad) is None, bad


async def test_only_the_notify_consumer_may_run_a_notification_scope_unscoped(
    org: int,
) -> None:
    """``notification:N`` carries its own tenant for ``notify_delivery`` only:
    any other consumer filed org-less on such a key must fail, never run with
    RLS bypassed."""
    ran: list[str] = []

    async def _rec(session: Any, key: str, job: Any) -> dict[str, Any]:
        ran.append(key)
        return {}

    name = f"n{uuid.uuid4().hex[:10]}"
    consumers.register(
        consumers.Consumer(name=name, matches=lambda e, v: False, scope=lambda ev: None, run=_rec)
    )
    try:
        async with session_scope() as s:
            j = OutboxJob(
                organization_id=None,
                consumer=name,
                scope_key="notification:1",
                trigger_event_id=None,
                result={},
            )
            s.add(j)
            await s.flush()
            jid = j.id
        await _drain()
        assert ran == []
        async with session_scope() as s:
            job = await s.get(OutboxJob, jid)
            assert job is not None
            assert (job.status, job.last_error) == ("failed", "unresolvable scope: notification:1")
            await s.execute(delete(OutboxJob).where(OutboxJob.id == jid))
    finally:
        consumers.REGISTRY.pop(name, None)
