"""The operator's ops channel: tagged webhook posts, or Slack threads per org.

Spec 2026-11-09, sections 3 and 5. Every HTTP call goes through a REAL
``httpx.AsyncClient`` on a ``MockTransport`` -- a fake Slack that records each
request -- so the request URL, headers and body are what httpx would send, and
httpx's own logging is exercised. Job rows and thread rows are read on
UNSCOPED sessions.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import structlog
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import DBAPIError
from structlog.testing import capture_logs

from ccf import logging as ccf_logging
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.events import outbox, worker
from ccf.governance import bus, delivery, ops_threads, org_channel, webhook_url
from ccf.models import Event, OpsNotifyThread, Organization, OrgNotifyChannel
from ccf.models_outbox import OutboxJob
from ccf.reliability import checks

pytestmark = pytest.mark.usefixtures("fresh_engine")

TOKEN = "xoxb-TESTTOKEN-4242-sekret"
CHANNEL = "C0OPS"
OPS_URL = "https://hooks.slack.example/services/T/B/opssecret"
ORG_HOST = "a-hooks.example"
#: Spelled out, not slack.SLACK_POST_MESSAGE: the test must not trust the constant.
SLACK_URL = "https://slack.com/api/chat.postMessage"


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
        await s.execute(delete(OutboxJob).where(OutboxJob.id > mark))


class Env:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.mp = monkeypatch

    def set(
        self,
        *,
        webhook: str | None = OPS_URL,
        token: str | None = None,
        channel: str | None = None,
        min_severity: str = "critical",
    ) -> None:
        for name, value in (
            ("CCF_NOTIFY_WEBHOOK_URL", webhook),
            ("CCF_NOTIFY_SLACK_BOT_TOKEN", token),
            ("CCF_NOTIFY_SLACK_CHANNEL", channel),
        ):
            if value is None:
                self.mp.delenv(name, raising=False)
            else:
                self.mp.setenv(name, value)
        self.mp.setenv("CCF_NOTIFY_MIN_SEVERITY", min_severity)
        get_settings.cache_clear()

    def slack(self, channel: str = CHANNEL) -> None:
        self.set(token=TOKEN, channel=channel)


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "unit-test-master-key-32-chars-xx")
    monkeypatch.setattr(
        webhook_url, "_resolve", lambda host: ["93.184.216.34"] if host == ORG_HOST else []
    )
    e = Env(monkeypatch)
    e.set()
    yield e
    get_settings.cache_clear()


class FakeSlack:
    """``slack.com`` and every webhook receiver, behind one MockTransport."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.messages: list[dict[str, Any]] = []
        self._ts = 1000
        #: Optional override: (request, body) -> httpx.Response | None.
        self.answer: Callable[[httpx.Request, dict[str, Any]], httpx.Response | None] = (
            lambda r, b: None
        )
        self.delay = 0.0

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        body = json.loads(request.content or b"{}")
        forced = self.answer(request, body)
        if forced is not None:
            return forced
        if request.url.host != "slack.com":
            return httpx.Response(200)  # an incoming webhook
        self._ts += 1
        ts = f"1700000000.{self._ts:06d}"
        msg = {"ts": ts, **body}
        self.messages.append(msg)
        message = {"ts": ts, "text": body.get("text")}
        if body.get("thread_ts"):
            message["thread_ts"] = body["thread_ts"]
        return httpx.Response(200, json={"ok": True, "channel": body["channel"], "ts": ts,
                                         "message": message})  # fmt: skip

    def slack_posts(self) -> list[dict[str, Any]]:
        return self.messages

    def parents(self) -> list[dict[str, Any]]:
        return [m for m in self.messages if not m.get("thread_ts")]

    def webhook_texts(self) -> list[str]:
        return [json.loads(r.content)["text"] for r in self.requests if r.url.host != "slack.com"]


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeSlack:
    f = FakeSlack()

    class _Real(httpx.AsyncClient):
        def __init__(self, **k: Any) -> None:
            super().__init__(transport=httpx.MockTransport(f.handle), **k)

    for mod in ("ccf.governance.slack", "ccf.governance.delivery"):
        monkeypatch.setattr(f"{mod}.httpx.AsyncClient", _Real)
    return f


def _slack_error(code: str, **headers: str) -> Callable[..., httpx.Response | None]:
    def answer(request: httpx.Request, body: dict[str, Any]) -> httpx.Response | None:
        if request.url.host != "slack.com":
            return None
        return httpx.Response(200, json={"ok": False, "error": code}, headers=headers)

    return answer


async def _org(name: str | None = None) -> int:
    async with session_scope() as s:
        o = Organization(name=name or f"ops-{uuid.uuid4().hex[:8]}")
        s.add(o)
        await s.flush()
        return o.id


async def _name(org_id: int) -> str:
    async with session_scope() as s:
        o = await s.get(Organization, org_id)
        assert o is not None
        return o.name


async def _notify(org_id: int | None, *, title: str = "Drift", severity: str = "critical") -> int:
    async with session_scope() as s:
        if org_id is not None:
            await set_session_tenant(s, org_id)
        n = await bus.notify(s, category="test", title=title, org_id=org_id, severity=severity)
        assert n is not None
        return n.id


async def _jobs(nid: int) -> dict[str, OutboxJob]:
    async with session_scope() as s:
        rows = list(
            (
                await s.execute(
                    select(OutboxJob).where(
                        OutboxJob.consumer == outbox.NOTIFY_CONSUMER,
                        OutboxJob.scope_key == f"notification:{nid}",
                    )
                )
            ).scalars()
        )
        for r in rows:
            s.expunge(r)
    return {str(r.result.get("destination")): r for r in rows}


async def _drain(passes: int = 2, now: datetime | None = None) -> None:
    for _ in range(passes):
        await worker.drain_once(worker="t", limit=10, now=now)


async def _threads(org_id: int) -> list[tuple[str, str]]:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        return [
            (r.channel, r.thread_ts)
            for r in (
                await s.execute(
                    select(OpsNotifyThread).where(OpsNotifyThread.organization_id == org_id)
                )
            ).scalars()
        ]


# ── webhook mode: every post tagged ──────────────────────────────────────────


async def test_a_webhook_only_deployment_gets_every_alert_tagged(env: Env, fake: FakeSlack) -> None:
    a = await _org()
    org_alert = await _notify(a, title="Drift")
    platform_alert = await _notify(None, title=f"platform {uuid.uuid4().hex[:6]}")
    await _drain()
    texts = fake.webhook_texts()
    assert f"[{await _name(a)}] [CRITICAL] Drift" in texts
    assert any(t.startswith("[Platform] [CRITICAL] platform") for t in texts)
    assert fake.slack_posts() == []
    assert (await _jobs(org_alert))["ops"].status == "done"
    assert (await _jobs(platform_alert))["ops"].status == "done"


async def test_the_tag_is_the_name_at_send_time(env: Env, fake: FakeSlack) -> None:
    a = await _org()
    nid = await _notify(a)
    renamed = f"renamed-{uuid.uuid4().hex[:6]}"
    async with session_scope() as s:
        await s.execute(update(Organization).where(Organization.id == a).values(name=renamed))
    await _drain()
    assert fake.webhook_texts() == [f"[{renamed}] [CRITICAL] Drift"]
    assert (await _jobs(nid))["ops"].result["text"] == "[CRITICAL] Drift"  # untagged in the job


async def test_a_tag_cannot_page_the_channel(env: Env, fake: FakeSlack) -> None:
    a = await _org(f"<!channel> {uuid.uuid4().hex[:6]}")
    await _notify(a)
    await _drain()
    (posted,) = fake.webhook_texts()
    left, right = chr(0x2039), chr(0x203A)  # what < and > become in a tag
    assert "<!channel>" not in posted and posted.startswith(f"[{left}!channel{right} ")


# ── mode selection and the startup warning ───────────────────────────────────


async def test_with_both_slack_settings_ops_goes_to_slack_not_the_webhook(
    env: Env, fake: FakeSlack
) -> None:
    env.slack()
    a = await _org()
    await _notify(a)
    await _drain()
    assert fake.webhook_texts() == []
    assert [str(r.url) for r in fake.requests] == [SLACK_URL] * 2


@pytest.mark.parametrize("missing", ["token", "channel"])
async def test_with_one_slack_setting_the_webhook_is_used_and_startup_names_the_other(
    env: Env, fake: FakeSlack, missing: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.set(
        token=None if missing == "token" else TOKEN,
        channel=None if missing == "channel" else CHANNEL,
    )
    from ccf.api import main  # noqa: PLC0415

    # main's module logger may already be cached by an earlier module on a
    # processor list capture_logs() cannot see (tests/test_csrf_origin.py
    # documents this), so it is replaced with a recorder for this call.
    logs: list[dict[str, Any]] = []

    class _Recorder:
        def warning(self, event: str, **kw: Any) -> None:
            logs.append({"event": event, **kw})

        def info(self, event: str, **kw: Any) -> None:
            logs.append({"event": event, **kw})

    monkeypatch.setattr(main, "log", _Recorder())
    main.create_app()
    named = "CCF_NOTIFY_SLACK_BOT_TOKEN" if missing == "token" else "CCF_NOTIFY_SLACK_CHANNEL"
    warned = [e for e in logs if e.get("event") == "config.notify_incomplete"]
    assert len(warned) == 1 and named in warned[0]["detail"]
    assert TOKEN not in json.dumps(logs, default=str)
    a = await _org()
    await _notify(a)
    await _drain()
    assert len(fake.webhook_texts()) == 1 and fake.slack_posts() == []


async def test_a_complete_or_empty_slack_configuration_warns_nothing(env: Env) -> None:
    for kwargs in ({}, {"token": TOKEN, "channel": CHANNEL}):
        env.set(**kwargs)
        assert delivery.config_warnings() == []


def test_the_token_is_a_secret_in_the_settings(env: Env) -> None:
    env.slack()
    s = get_settings()
    assert TOKEN not in repr(s) and TOKEN not in str(s.model_dump())


# ── Slack threads ────────────────────────────────────────────────────────────


async def test_an_orgs_first_alert_opens_its_thread_and_later_ones_reply_in_it(
    env: Env, fake: FakeSlack
) -> None:
    env.slack()
    a = await _org()
    first = await _notify(a, title="one")
    await _drain()
    second = await _notify(a, title="two")
    await _drain()
    parents = fake.parents()
    assert [p["text"] for p in parents] == [f"Alerts for {await _name(a)}"]
    ts = parents[0]["ts"]
    replies = [m for m in fake.slack_posts() if m.get("thread_ts")]
    assert [(m["thread_ts"], m["text"]) for m in replies] == [
        (ts, "[CRITICAL] one"),
        (ts, "[CRITICAL] two"),
    ]
    assert await _threads(a) == [(CHANNEL, ts)]
    for nid in (first, second):
        assert (await _jobs(nid))["ops"].status == "done"
    # The request Slack received: the right URL, a Bearer token, JSON.
    req = fake.requests[-1]
    assert str(req.url) == SLACK_URL
    assert req.headers["authorization"] == f"Bearer {TOKEN}"
    assert json.loads(req.content) == {
        "channel": CHANNEL,
        "text": "[CRITICAL] two",
        "thread_ts": ts,
    }


async def test_each_org_gets_its_own_thread_and_platform_alerts_go_top_level(
    env: Env, fake: FakeSlack
) -> None:
    env.slack()
    a, b = await _org(), await _org()
    await _notify(a)
    await _notify(b)
    await _notify(None, title="platform-wide")
    await _drain(3)
    parent_texts = sorted(p["text"] for p in fake.parents())
    assert parent_texts == sorted(
        [
            f"Alerts for {await _name(a)}",
            f"Alerts for {await _name(b)}",
            "[Platform] [CRITICAL] platform-wide",
        ]
    )
    (ta,), (tb,) = await _threads(a), await _threads(b)
    assert ta[1] != tb[1]


async def test_a_changed_channel_starts_new_threads(env: Env, fake: FakeSlack) -> None:
    env.slack()
    a = await _org()
    await _notify(a, title="old")
    await _drain()
    env.slack(channel="C0NEWOPS")
    await _notify(a, title="new")
    await _drain()
    rows = dict(await _threads(a))
    assert set(rows) == {CHANNEL, "C0NEWOPS"} and rows[CHANNEL] != rows["C0NEWOPS"]
    new_reply = [m for m in fake.slack_posts() if m.get("text") == "[CRITICAL] new"]
    assert new_reply[0]["channel"] == "C0NEWOPS" and new_reply[0]["thread_ts"] == rows["C0NEWOPS"]


async def test_two_first_alerts_at_once_open_one_thread(env: Env, fake: FakeSlack) -> None:
    env.slack()
    a = await _org()
    fake.delay = 0.2  # the first parent post is slow; the second must wait, not race
    got = await asyncio.wait_for(
        asyncio.gather(
            ops_threads.thread_for(org_id=a, org_name="x", channel=CHANNEL, token=TOKEN),
            ops_threads.thread_for(org_id=a, org_name="x", channel=CHANNEL, token=TOKEN),
        ),
        30,
    )
    assert got[0] == got[1]
    assert len(fake.parents()) == 1
    assert await _threads(a) == [(CHANNEL, got[0])]


async def test_the_consumer_writes_the_thread_unscoped_and_a_tenant_cannot_touch_it(
    env: Env, fake: FakeSlack
) -> None:
    env.slack()
    a = await _org()
    await _notify(a)
    await _drain()
    assert len(await _threads(a)) == 1  # written by the consumer
    factory = get_session_factory()
    async with factory() as s:
        await set_session_tenant(s, a)
        with pytest.raises(DBAPIError, match="permission denied"):
            await s.execute(select(OpsNotifyThread))
    async with factory() as s:
        await set_session_tenant(s, a)
        with pytest.raises(DBAPIError, match="permission denied"):
            await s.execute(
                text(
                    "INSERT INTO ccf.ops_notify_threads (organization_id, channel, thread_ts) "
                    "VALUES (:o, 'C', '1')"
                ),
                {"o": a},
            )
    async with session_scope() as s:
        rls = (
            await s.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE oid = 'ccf.ops_notify_threads'::regclass"
                )
            )
        ).one()
    assert tuple(rls) == (True, True)


# ── Slack errors ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "code",
    ["invalid_auth", "token_revoked", "missing_scope", "channel_not_found", "not_in_channel",
     "is_archived", "account_inactive"],
)  # fmt: skip
async def test_a_refusal_a_retry_cannot_fix_is_final_and_named(
    env: Env, fake: FakeSlack, code: str
) -> None:
    env.slack()
    fake.answer = _slack_error(code)
    a = await _org()
    nid = await _notify(a)
    await _drain()
    job = (await _jobs(nid))["ops"]
    assert (job.status, job.attempts) == ("failed", 1)
    assert code in (job.last_error or "") and TOKEN not in (job.last_error or "")
    assert await _threads(a) == []  # the parent failed: nothing stored


@pytest.mark.parametrize(
    "code", ["ratelimited", "internal_error", "service_unavailable", "brand_new_code"]
)
async def test_a_busy_or_unknown_slack_answer_is_retried(
    env: Env, fake: FakeSlack, code: str
) -> None:
    env.slack()
    fake.answer = _slack_error(code)
    nid = await _notify(None)
    await _drain()
    job = (await _jobs(nid))["ops"]
    assert (job.status, job.attempts) == ("pending", 1) and code in (job.last_error or "")


@pytest.mark.parametrize("status", [429, 500, 503])
async def test_http_429_and_5xx_are_retried(env: Env, fake: FakeSlack, status: int) -> None:
    env.slack()
    fake.answer = lambda r, b: httpx.Response(status) if r.url.host == "slack.com" else None
    nid = await _notify(None)
    await _drain()
    assert (await _jobs(nid))["ops"].status == "pending"


async def test_retry_after_holds_the_retry_back(env: Env, fake: FakeSlack) -> None:
    env.slack()
    fake.answer = lambda r, b: (
        httpx.Response(429, headers={"Retry-After": "3600"}) if r.url.host == "slack.com" else None
    )
    nid = await _notify(None)
    before = datetime.now(UTC)
    await _drain(1)
    job = (await _jobs(nid))["ops"]
    wait = (job.next_attempt_at - before).total_seconds()
    assert 3590 <= wait <= 3700, wait  # not the 170 s backoff


async def test_a_short_retry_after_never_shortens_the_backoff(env: Env, fake: FakeSlack) -> None:
    env.slack()
    fake.answer = lambda r, b: (
        httpx.Response(429, headers={"Retry-After": "1"}) if r.url.host == "slack.com" else None
    )
    nid = await _notify(None)
    before = datetime.now(UTC)
    await _drain(1)
    wait = ((await _jobs(nid))["ops"].next_attempt_at - before).total_seconds()
    assert wait >= worker.WEBHOOK_BACKOFF_SECONDS - 5


@pytest.mark.parametrize("code", ["thread_not_found", "invalid_thread_ts", "message_not_found"])
async def test_a_gone_parent_is_replaced_once_and_the_reply_lands(
    env: Env, fake: FakeSlack, code: str
) -> None:
    env.slack()
    a = await _org()
    await _notify(a, title="first")
    await _drain()
    ((_, old_ts),) = await _threads(a)

    def answer(request: httpx.Request, body: dict[str, Any]) -> httpx.Response | None:
        if body.get("thread_ts") == old_ts:
            return httpx.Response(200, json={"ok": False, "error": code})
        return None

    fake.answer = answer
    nid = await _notify(a, title="second")
    await _drain()
    job = (await _jobs(nid))["ops"]
    assert job.status == "done" and job.result.get("thread_reopened") is True
    ((_, new_ts),) = await _threads(a)
    assert new_ts != old_ts
    assert [m["thread_ts"] for m in fake.slack_posts() if m.get("text") == "[CRITICAL] second"] == [
        new_ts
    ]
    assert len(fake.parents()) == 2


async def test_a_parent_that_keeps_vanishing_is_reopened_only_once_per_attempt(
    env: Env, fake: FakeSlack
) -> None:
    env.slack()
    fake.answer = lambda r, b: (
        httpx.Response(200, json={"ok": False, "error": "thread_not_found"})
        if b.get("thread_ts")
        else None
    )
    a = await _org()
    nid = await _notify(a)
    await _drain(1)
    job = (await _jobs(nid))["ops"]
    assert (job.status, job.attempts) == ("pending", 1)  # retried, not looped
    assert len(fake.parents()) == 2
    assert len([r for r in fake.requests if json.loads(r.content).get("thread_ts")]) == 2


async def test_a_reply_slack_silently_posted_at_top_level_resets_the_thread(
    env: Env, fake: FakeSlack
) -> None:
    """If Slack accepts a reply to a deleted parent by posting it at the top
    level (the docs do not say which it does), the thread is forgotten so the
    next alert opens a new one."""
    env.slack()
    a = await _org()
    await _notify(a, title="first")
    await _drain()
    ((_, old_ts),) = await _threads(a)

    def answer(request: httpx.Request, body: dict[str, Any]) -> httpx.Response | None:
        if body.get("thread_ts") == old_ts:
            return httpx.Response(
                200, json={"ok": True, "ts": "1.2", "message": {"ts": "1.2", "text": "x"}}
            )
        return None

    fake.answer = answer
    nid = await _notify(a, title="second")
    await _drain()
    assert (await _jobs(nid))["ops"].result.get("thread_reset") is True
    assert await _threads(a) == []
    fake.answer = lambda r, b: None
    await _notify(a, title="third")
    await _drain()
    ((_, newest),) = await _threads(a)
    assert newest != old_ts


async def test_a_redirect_is_not_followed(env: Env, fake: FakeSlack) -> None:
    env.slack()
    fake.answer = lambda r, b: httpx.Response(302, headers={"Location": "https://evil.example/x"})
    nid = await _notify(None)
    await _drain(1)
    assert [r.url.host for r in fake.requests] == ["slack.com"]
    assert "HTTP 302" in ((await _jobs(nid))["ops"].last_error or "")


# ── independence, rollback ───────────────────────────────────────────────────


async def _org_channel(org_id: int) -> str:
    url = f"https://{ORG_HOST}/services/T0/B0/orgsecret{uuid.uuid4().hex}"
    async with session_scope() as s:
        s.add(
            OrgNotifyChannel(
                organization_id=org_id,
                encrypted_url=org_channel.cipher().encrypt(url),
                url_hint=org_channel.url_hint(url),
            )
        )
    return url


async def test_a_slack_ops_failure_never_blocks_the_org_post(env: Env, fake: FakeSlack) -> None:
    env.slack()
    a = await _org()
    await _org_channel(a)
    fake.answer = _slack_error("invalid_auth")
    nid = await _notify(a)
    await _drain(3)
    jobs = await _jobs(nid)
    assert (jobs["ops"].status, jobs["org"].status) == ("failed", "done")


async def test_an_org_failure_never_blocks_the_slack_ops_post(env: Env, fake: FakeSlack) -> None:
    env.slack()
    a = await _org()
    await _org_channel(a)
    fake.answer = lambda r, b: httpx.Response(410) if r.url.host != "slack.com" else None
    nid = await _notify(a)
    await _drain(3)
    jobs = await _jobs(nid)
    assert (jobs["ops"].status, jobs["org"].status) == ("done", "failed")


async def test_a_rollback_queues_nothing_in_slack_mode(env: Env, fake: FakeSlack) -> None:
    env.slack()
    a = await _org()
    nid: int | None = None
    with pytest.raises(RuntimeError, match="abort"):
        async with session_scope() as s:
            await set_session_tenant(s, a)
            n = await bus.notify(s, category="test", title="rb", org_id=a, severity="critical")
            assert n is not None
            nid = n.id
            raise RuntimeError("abort")
    assert nid is not None and await _jobs(nid) == {}
    await _drain()
    assert fake.requests == [] and await _threads(a) == []


# ── the token never leaks ────────────────────────────────────────────────────


@pytest.fixture
def production_logging() -> Iterator[None]:
    """As tests/test_http_logging_keeps_secrets_out.py: root at DEBUG here."""
    root, names = logging.getLogger(), ("httpx", "httpcore")
    saved = (
        root.level,
        {n: (logging.getLogger(n).level, logging.getLogger(n).disabled) for n in names},
    )
    for n in names:
        logging.getLogger(n).disabled = False
        logging.getLogger(n).setLevel(logging.NOTSET)
    # Only its stdlib side (the root and httpx levels) is wanted here. Its
    # structlog.configure() would leave every logger first used during the
    # test cached on a processor list the suite then drops, so later
    # capture_logs() blocks elsewhere would see nothing.
    saved_structlog = dict(structlog.get_config())
    ccf_logging.configure_logging()
    structlog.configure(**saved_structlog)
    root.setLevel(logging.DEBUG)
    yield
    root.setLevel(saved[0])
    for n, (lvl, disabled) in saved[1].items():
        logging.getLogger(n).setLevel(lvl)
        logging.getLogger(n).disabled = disabled


async def test_the_token_appears_in_no_log_result_event_or_error(
    env: Env,
    fake: FakeSlack,
    production_logging: None,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    env.slack()
    a = await _org()
    async with session_scope() as s:
        mark = (await s.execute(select(func.coalesce(func.max(Event.id), 0)))).scalar_one()
    seen: list[str] = []
    with capture_logs() as logs:
        await _notify(a, title="ok")
        await _drain()
        fake.answer = _slack_error("invalid_auth")
        failed = await _notify(a, title="refused")
        await _drain()

        def boom(request: httpx.Request, body: dict[str, Any]) -> httpx.Response | None:
            # As a library might: the exception text carries the request's
            # credentials (httpx itself masks Authorization in repr()).
            auth = request.headers.get("authorization")
            raise httpx.ConnectError(f"cannot reach {request.url} with {auth}")

        fake.answer = boom
        crashed = await _notify(None, title="transport")
        await _drain(1)
    logging.getLogger("ccf.control").debug("debug control line")
    assert "debug control line" in caplog.text  # DEBUG records are captured at all
    assert any(r.headers.get("authorization") == f"Bearer {TOKEN}" for r in fake.requests)
    for nid in (failed, crashed):
        job = (await _jobs(nid))["ops"]
        seen += [job.last_error or "", json.dumps(job.result)]
    assert "invalid_auth" in seen[0] and "ConnectError" in seen[2]
    async with session_scope() as s:
        evs = (await s.execute(select(Event).where(Event.id > mark))).scalars()
        seen += [f"{e.summary} {json.dumps(e.payload)}" for e in evs]
    out = capsys.readouterr()
    seen += [caplog.text, out.out, out.err, json.dumps(logs, default=str)]
    leaks = [x[:200] for x in seen if TOKEN in x or "TESTTOKEN" in x]
    assert leaks == []


# ── whose delivery failed ────────────────────────────────────────────────────


async def test_the_outbox_check_names_whose_delivery_failed(env: Env, fake: FakeSlack) -> None:
    a = await _org()
    await _org_channel(a)
    # Ops (webhook) refused, and A's own channel refused.
    fake.answer = lambda r, b: httpx.Response(404)
    nid = await _notify(a)
    await _drain(3)
    jobs = await _jobs(nid)
    assert (jobs["ops"].status, jobs["org"].status) == ("failed", "failed")
    async with session_scope() as s:
        await set_session_tenant(s, None)
        check = await checks._check_event_outbox(s)
    assert check.status == checks.FAIL  # the verdict rule is unchanged
    assert "notify_delivery:" in check.message
    assert "ops: 1 (oldest error: DeliveryError: HTTP 404)" in check.message
    assert f"org {a} ({await _name(a)}): 1 (oldest error: DeliveryError: HTTP 404)" in check.message


async def test_a_tenant_sees_its_own_failures_but_not_the_ops_error(
    env: Env, fake: FakeSlack
) -> None:
    a, b = await _org(), await _org()
    await _org_channel(a)
    await _org_channel(b)
    fake.answer = lambda r, b_: httpx.Response(404)
    await _notify(a)
    await _notify(b)
    await _drain(4)
    async with session_scope() as s:
        await set_session_tenant(s, a)
        detail = (await checks._check_event_outbox(s)).message
    assert f"org {a} (" in detail and f"org {b} (" not in detail
    assert await _name(b) not in detail
    assert "ops: 1" in detail and "ops: 1 (oldest error" not in detail


async def test_a_legacy_failed_job_counts_as_ops(env: Env) -> None:
    a = await _org()
    async with session_scope() as s:
        s.add(
            OutboxJob(
                organization_id=a,
                consumer=outbox.NOTIFY_CONSUMER,
                scope_key="notification:1",
                status="failed",
                last_error="DeliveryError: HTTP 410",
                result={"text": "x"},
                next_attempt_at=datetime.now(UTC) - timedelta(days=1),
            )
        )
    async with session_scope() as s:
        await set_session_tenant(s, None)
        detail = (await checks._check_event_outbox(s)).message
    assert "ops: 1 (oldest error: DeliveryError: HTTP 410)" in detail


def test_the_event_worker_also_names_the_missing_setting(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The event-worker is what posts, so its own start says so, not only the api's."""
    from typer.testing import CliRunner  # noqa: PLC0415

    from ccf import cli  # noqa: PLC0415

    env.set(token=TOKEN, channel=None)
    monkeypatch.setenv("CCF_EVENT_WORKER_ENABLED", "true")
    get_settings.cache_clear()

    async def _no_drain(**kw: Any) -> None:
        return None

    monkeypatch.setattr(cli, "_event_drain_loop", _no_drain)
    result = CliRunner().invoke(cli.app, ["event-worker", "--once"])
    assert result.exit_code == 0, result.output
    assert "CCF_NOTIFY_SLACK_CHANNEL" in result.output and TOKEN not in result.output


async def test_a_slack_4xx_other_than_429_is_final(env: Env, fake: FakeSlack) -> None:
    env.slack()
    fake.answer = lambda r, b: httpx.Response(404) if r.url.host == "slack.com" else None
    nid = await _notify(None)
    await _drain(1)
    job = (await _jobs(nid))["ops"]
    assert (job.status, job.attempts) == ("failed", 1) and "HTTP 404" in (job.last_error or "")


async def test_an_error_code_that_is_not_a_code_is_not_echoed(env: Env, fake: FakeSlack) -> None:
    env.slack()
    fake.answer = _slack_error("<b>please paste your token at evil.example</b>")
    nid = await _notify(None)
    await _drain(1)
    err = (await _jobs(nid))["ops"].last_error or ""
    assert "unrecognised_error" in err and "evil.example" not in err


async def test_an_org_name_cannot_page_the_ops_channel_from_its_thread_parent(
    env: Env, fake: FakeSlack
) -> None:
    env.slack()
    a = await _org(f"<!channel> & co {uuid.uuid4().hex[:6]}")
    await _notify(a)
    await _drain()
    (parent,) = fake.parents()
    assert parent["text"].startswith("Alerts for &lt;!channel&gt; &amp; co ")


async def test_a_webhook_transport_error_does_not_record_the_ops_url(
    env: Env, fake: FakeSlack
) -> None:
    def boom(request: httpx.Request, body: dict[str, Any]) -> httpx.Response | None:
        raise httpx.ConnectError(f"cannot reach {request.url}")

    fake.answer = boom
    nid = await _notify(None)
    await _drain(1)
    job = (await _jobs(nid))["ops"]
    assert job.last_error == "DeliveryError: ConnectError"
    assert "opssecret" not in json.dumps(job.result)
