"""An organization's own alert channel (spec 2026-11-09, sections 4-6).

No test reaches the network: ``httpx.AsyncClient`` in ``ccf.governance.delivery``
is replaced by a recorder, and DNS (``webhook_url._resolve``) by a table, so a
post to an organization's channel is seen as the pinned address plus the
``Host`` header naming the channel's host. Job rows and org guards are read on
UNSCOPED sessions: RLS would otherwise hide a missing organization filter.
"""

from __future__ import annotations

import dataclasses
import json
import os
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select, text, update
from structlog.testing import capture_logs

from ccf.ai.cipher import AAD_CREDENTIAL, AAD_NOTIFY_CHANNEL, build_cipher
from ccf.api.deps import get_session
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.events import consumers, notify_delivery, outbox, worker
from ccf.governance import bus, delivery, org_channel, webhook_url
from ccf.models import AuditLog, Event, Organization, OrgNotifyChannel, User, Webhook
from ccf.models_outbox import OutboxJob

pytestmark = pytest.mark.usefixtures("fresh_engine")

OPS_URL = "https://hooks.slack.example/services/T/B/ops"
HOSTS = {"a-hooks.example": "93.184.216.34", "b-hooks.example": "93.184.216.35"}
ROLES = ("admin", "control_owner", "assessor", "viewer")


def _url(host: str) -> str:
    """A channel URL whose path is a unique, greppable secret."""
    return f"https://{host}/services/T0/B0/sekrit{uuid.uuid4().hex}"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "unit-test-master-key-32-chars-xx")
    monkeypatch.setenv("CCF_NOTIFY_WEBHOOK_URL", OPS_URL)
    monkeypatch.setenv("CCF_NOTIFY_MIN_SEVERITY", "critical")
    monkeypatch.setattr(
        webhook_url, "_resolve", lambda host: [HOSTS[host]] if host in HOSTS else []
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
async def _no_live_jobs_left_behind() -> AsyncIterator[None]:
    async with session_scope() as s:
        await s.execute(delete(OutboxJob).where(OutboxJob.status.in_(("pending", "claimed"))))
        mark = (await s.execute(select(func.coalesce(func.max(OutboxJob.id), 0)))).scalar_one()
    yield
    async with session_scope() as s:
        await s.execute(delete(OutboxJob).where(OutboxJob.id > mark))


class Net:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.clients: list[dict[str, Any]] = []
        self.respond: Callable[[dict[str, Any]], int] = lambda call: 200

    def to(self, host: str) -> list[dict[str, Any]]:
        """Posts addressed to an org channel on ``host`` (pinned IP + Host header)."""
        return [
            c
            for c in self.calls
            if c["url"].startswith(f"https://{HOSTS[host]}/")
            and c.get("headers", {}).get("Host") == host
        ]

    def ops(self) -> list[dict[str, Any]]:
        return [c for c in self.calls if c["url"] == OPS_URL]


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch) -> Net:
    n = Net()

    class _Client:
        def __init__(self, *a: Any, **k: Any) -> None:
            n.clients.append(k)

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *a: Any) -> None:
            return None

        async def post(self, url: str, **k: Any) -> httpx.Response:
            call = {"url": url, **k}
            n.calls.append(call)
            return httpx.Response(n.respond(call), request=httpx.Request("POST", url))

    monkeypatch.setattr("ccf.governance.delivery.httpx.AsyncClient", _Client)
    return n


async def _org(label: str = "nch") -> int:
    async with session_scope() as s:
        o = Organization(name=f"{label}-{uuid.uuid4().hex[:8]}")
        s.add(o)
        await s.flush()
        return o.id


async def _seed_channel(
    org_id: int, url: str, *, min_severity: str = "critical", enabled: bool = True
) -> None:
    async with session_scope() as s:
        s.add(
            OrgNotifyChannel(
                organization_id=org_id,
                encrypted_url=org_channel.cipher().encrypt(url),
                url_hint=org_channel.url_hint(url),
                min_severity=min_severity,
                enabled=enabled,
            )
        )


async def _notify(org_id: int | None, *, severity: str = "critical", title: str = "Drift") -> int:
    async with session_scope() as s:
        if org_id is not None:
            await set_session_tenant(s, org_id)
        n = await bus.notify(
            s,
            category="test",
            title=title,
            body="3 checks failed",
            org_id=org_id,
            severity=severity,
        )
        assert n is not None
        return n.id


async def _jobs(nid: int) -> list[OutboxJob]:
    async with session_scope() as s:  # unscoped: RLS would hide a mis-filed job
        rows = list(
            (
                await s.execute(
                    select(OutboxJob)
                    .where(
                        OutboxJob.consumer == outbox.NOTIFY_CONSUMER,
                        OutboxJob.scope_key == f"notification:{nid}",
                    )
                    .order_by(OutboxJob.id)
                )
            ).scalars()
        )
        for r in rows:
            s.expunge(r)
        return rows


def _by_dest(jobs: list[OutboxJob]) -> dict[str, OutboxJob]:
    return {str(j.result.get("destination")): j for j in jobs}


async def _drain(passes: int = 2) -> dict[str, int]:
    total: dict[str, int] = {}
    for _ in range(passes):
        for k, v in (await worker.drain_once(worker="t", limit=10)).items():
            total[k] = total.get(k, 0) + v
    return total


# ── sealing ──────────────────────────────────────────────────────────────────


def test_the_url_is_sealed_under_its_own_context() -> None:
    url = _url("a-hooks.example")
    sealed = org_channel.cipher().encrypt(url)
    assert url not in sealed
    assert org_channel.cipher().decrypt(sealed) == url
    assert AAD_NOTIFY_CHANNEL not in (AAD_CREDENTIAL, b"ccf-mfa")
    # A connector credential's ciphertext does not open as a channel URL, nor
    # the reverse: the contexts are not interchangeable.
    cred = build_cipher(get_settings(), aad=AAD_CREDENTIAL)
    with pytest.raises(Exception, match="did not authenticate"):
        org_channel.cipher().decrypt(cred.encrypt(url))
    with pytest.raises(Exception, match="did not authenticate"):
        cred.decrypt(sealed)


def test_the_hint_shows_scheme_and_host_only() -> None:
    slack = "https://hooks.slack.com/services/T000/B000/abcdefWXYZ"
    teams = "https://x.webhook.office.com/webhookb2/a/IncomingWebhook/b/c?sig=QWERTYsig1234"
    assert org_channel.url_hint(slack) == "https://hooks.slack.com"
    assert org_channel.url_hint(teams) == "https://x.webhook.office.com"


LONG_HOST = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 53, "example"])  # 253 chars


def test_a_long_host_is_cut_to_fit_the_column() -> None:
    assert len(LONG_HOST) == 253
    hint = org_channel.url_hint(f"https://{LONG_HOST}/services/x")
    assert len(hint) == org_channel.MAX_HINT_LENGTH == 160
    assert hint.startswith("https://aaaa") and hint.endswith("…")


async def test_a_long_host_saves_instead_of_failing_after_the_test_post(
    net: Net, auth_on: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = await _tenant("nclong")
    monkeypatch.setattr(webhook_url, "_resolve", lambda host: ["93.184.216.34"])
    async with _client() as c:
        r = await c.put(
            API,
            json={"webhook_url": f"https://{LONG_HOST}/services/T/B/x"},
            headers=_h(a.tokens["admin"]),
        )
    assert r.status_code == 200, r.text
    assert len(r.json()["url_hint"]) <= 160


# ── queueing ─────────────────────────────────────────────────────────────────


async def test_a_tenant_alert_reaches_its_own_channel_and_never_another_orgs(net: Net) -> None:
    a, b = await _org("ncha"), await _org("nchb")
    url_a, url_b = _url("a-hooks.example"), _url("b-hooks.example")
    await _seed_channel(a, url_a)
    await _seed_channel(b, url_b)
    nid = await _notify(a)
    jobs = _by_dest(await _jobs(nid))
    assert set(jobs) == {"ops", "org"}
    assert jobs["org"].organization_id == a
    assert jobs["org"].result["text"] == "[CRITICAL] Drift\n3 checks failed"
    await _drain()
    posted = net.to("a-hooks.example")
    assert len(posted) == 1
    assert posted[0]["url"] == f"https://{HOSTS['a-hooks.example']}/" + url_a.split("/", 3)[3]
    assert posted[0]["extensions"] == {"sni_hostname": "a-hooks.example"}
    assert posted[0]["json"] == {"text": "[CRITICAL] Drift\n3 checks failed"}
    assert {"timeout": delivery.TIMEOUT_SECONDS, "follow_redirects": False} in net.clients
    assert net.to("b-hooks.example") == []
    assert len(net.ops()) == 1
    assert {j.status for j in await _jobs(nid)} == {"done"}


async def test_the_queue_time_lookup_filters_the_org_without_rls(net: Net) -> None:
    """B and C have channels, A has none. On an UNSCOPED session (RLS shows
    every row), A's notification must still find no channel and C's must find
    C's: the org filter is the guard. Two other channels, so a dropped filter
    cannot pass by an error being swallowed or by a lucky single row."""
    a, b, c = await _org(), await _org(), await _org()
    await _seed_channel(b, _url("b-hooks.example"), min_severity="info")
    await _seed_channel(c, _url("a-hooks.example"), min_severity="critical")
    async with session_scope() as s:
        await set_session_tenant(s, None)
        n = await bus.notify(s, category="test", title="unscoped", org_id=a, severity="critical")
        assert n is not None
        nid = n.id
        assert await org_channel.org_job_text(s, n) is None
        nc = await bus.notify(s, category="test", title="c's", org_id=c, severity="warning")
        assert nc is not None
        # C's channel wants critical: B's (info) would have said yes.
        assert await org_channel.org_job_text(s, nc) is None
        nc.severity = "critical"
        assert await org_channel.org_job_text(s, nc) == "[CRITICAL] c's"
    assert set(_by_dest(await _jobs(nid))) == {"ops"}


async def test_a_database_error_in_the_lookup_costs_only_the_org_post(
    net: Net, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy.exc import OperationalError  # noqa: PLC0415

    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"))

    async def _down(session: Any, org_id: int) -> None:
        raise OperationalError("SELECT", {}, Exception("lock timeout"))

    monkeypatch.setattr(org_channel, "get", _down)
    with capture_logs() as logs:
        nid = await _notify(a)
    assert set(_by_dest(await _jobs(nid))) == {"ops"}
    assert any(e.get("event") == "org_channel.lookup_failed" for e in logs)


async def test_any_other_lookup_error_is_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy.exc import MultipleResultsFound  # noqa: PLC0415

    a = await _org()

    async def _broken(session: Any, org_id: int) -> None:
        raise MultipleResultsFound("two channels for one org")

    monkeypatch.setattr(org_channel, "get", _broken)
    with pytest.raises(MultipleResultsFound):
        await _notify(a)


async def test_the_send_time_lookup_filters_the_org_without_rls(net: Net) -> None:
    """A job for A, run on an UNSCOPED session while only B has a channel:
    skipped as removed, and B's channel is never posted to."""
    a, b, c = await _org(), await _org(), await _org()
    await _seed_channel(b, _url("b-hooks.example"), min_severity="info")
    await _seed_channel(c, _url("b-hooks.example"), min_severity="info")
    nid = await _notify(a)  # A has no channel: no org job is queued
    factory = get_session_factory()
    async with factory() as s:
        await set_session_tenant(s, None)
        job = OutboxJob(
            organization_id=a,
            consumer=outbox.NOTIFY_CONSUMER,
            scope_key=f"notification:{nid}",
            result={"destination": "org", "text": "[CRITICAL] forged"},
        )
        out = await notify_delivery._run_org(s, nid, job, dict(job.result), "[CRITICAL] forged")
    assert out == {"skipped": "organization channel removed"}
    assert net.to("b-hooks.example") == []


async def test_an_orgless_alert_queues_no_org_job(net: Net) -> None:
    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"), min_severity="info")
    nid = await _notify(None, title=f"platform {uuid.uuid4().hex[:6]}")
    jobs = await _jobs(nid)
    assert [j.result.get("destination") for j in jobs] == ["ops"]
    await _drain()
    assert net.to("a-hooks.example") == []


async def test_a_forged_orgless_org_job_is_refused(net: Net) -> None:
    nid = await _notify(None)
    async with session_scope() as s:
        s.add(
            OutboxJob(
                organization_id=None,
                consumer=outbox.NOTIFY_CONSUMER,
                scope_key=f"notification:{nid}",
                result={"destination": "org", "text": "x"},
            )
        )
    await _drain(3)
    org_jobs = [j for j in await _jobs(nid) if j.result.get("destination") == "org"]
    assert [j.result.get("refused") for j in org_jobs] == [
        "an organization-less notification has no organization channel"
    ]


async def test_each_channel_has_its_own_minimum_severity(net: Net) -> None:
    a, b = await _org(), await _org()
    await _seed_channel(a, _url("a-hooks.example"), min_severity="warning")
    await _seed_channel(b, _url("b-hooks.example"), min_severity="critical")
    a_warn, a_info = await _notify(a, severity="warning"), await _notify(a, severity="info")
    b_warn, b_crit = await _notify(b, severity="warning"), await _notify(b, severity="critical")
    dests = {nid: set(_by_dest(await _jobs(nid))) for nid in (a_warn, a_info, b_warn, b_crit)}
    # Ops stays at CCF_NOTIFY_MIN_SEVERITY=critical, independently.
    assert dests == {a_warn: {"org"}, a_info: set(), b_warn: set(), b_crit: {"ops", "org"}}


async def test_a_disabled_channel_queues_nothing(net: Net) -> None:
    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"), min_severity="info", enabled=False)
    nid = await _notify(a)
    assert set(_by_dest(await _jobs(nid))) == {"ops"}


async def test_a_rollback_queues_nothing(net: Net) -> None:
    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"), min_severity="info")
    nid: int | None = None
    with pytest.raises(RuntimeError, match="abort"):
        async with session_scope() as s:
            await set_session_tenant(s, a)
            n = await bus.notify(s, category="test", title="rb", org_id=a, severity="critical")
            assert n is not None
            nid = n.id
            raise RuntimeError("abort")
    assert nid is not None
    assert await _jobs(nid) == []
    await _drain()
    assert net.calls == []


# ── delivery ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("change", ["disable", "remove"])
async def test_a_channel_turned_off_after_queueing_is_skipped_not_failed(
    net: Net, change: str
) -> None:
    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"))
    nid = await _notify(a)
    async with session_scope() as s:
        if change == "disable":
            await s.execute(
                update(OrgNotifyChannel)
                .where(OrgNotifyChannel.organization_id == a)
                .values(enabled=False)
            )
        else:
            await s.execute(delete(OrgNotifyChannel).where(OrgNotifyChannel.organization_id == a))
    await _drain()
    job = _by_dest(await _jobs(nid))["org"]
    assert job.status == "done" and job.attempts == 1 and job.last_error is None
    want = "disabled" if change == "disable" else "removed"
    assert job.result["skipped"] == f"organization channel {want}"
    assert net.to("a-hooks.example") == []
    assert len(net.ops()) == 1  # the ops post is unaffected


async def test_an_undecryptable_url_is_a_final_failure(net: Net) -> None:
    a = await _org()
    url = _url("a-hooks.example")
    async with session_scope() as s:
        s.add(
            OrgNotifyChannel(
                organization_id=a,
                # Sealed under the connector context: must not open here.
                encrypted_url=build_cipher(get_settings(), aad=AAD_CREDENTIAL).encrypt(url),
                url_hint=org_channel.url_hint(url),
                min_severity="critical",
            )
        )
    nid = await _notify(a)
    await _drain()
    job = _by_dest(await _jobs(nid))["org"]
    assert (job.status, job.attempts) == ("failed", 1)
    assert "could not be decrypted" in (job.last_error or "")
    assert net.to("a-hooks.example") == []


async def test_the_destinations_fail_independently(net: Net) -> None:
    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"))
    net.respond = lambda call: 500 if call["url"] == OPS_URL else 200
    first = await _notify(a)
    await _drain()
    jobs = _by_dest(await _jobs(first))
    assert (jobs["ops"].status, jobs["org"].status) == ("pending", "done")

    net.respond = lambda call: 200 if call["url"] == OPS_URL else 404
    second = await _notify(a, title="again")
    await _drain()
    jobs = _by_dest(await _jobs(second))
    assert (jobs["ops"].status, jobs["org"].status) == ("done", "failed")


async def test_an_org_post_retries_a_transient_failure(net: Net) -> None:
    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"))
    net.respond = lambda call: 200 if call["url"] == OPS_URL else 503
    nid = await _notify(a)
    await _drain()
    job = _by_dest(await _jobs(nid))["org"]
    assert (job.status, job.attempts) == ("pending", 1)
    assert job.result["destination"] == "org"  # kept for the retry


async def test_an_org_post_goes_only_where_the_guard_allows(
    net: Net, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The channel's name now resolves inward (DNS rebinding): nothing is sent."""
    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"))
    nid = await _notify(a)
    monkeypatch.setattr(webhook_url, "_resolve", lambda host: ["10.0.0.7"])
    await _drain()
    job = _by_dest(await _jobs(nid))["org"]
    assert job.status == "pending" and "URL guard" in (job.last_error or "")
    assert not [c for c in net.calls if c.get("headers", {}).get("Host") == "a-hooks.example"]


async def test_ops_jobs_carry_their_destination_and_legacy_jobs_are_ops(net: Net) -> None:
    a = await _org()
    nid = await _notify(a)
    (job,) = await _jobs(nid)
    assert job.result == {"destination": "ops", "text": "[CRITICAL] Drift\n3 checks failed"}
    async with session_scope() as s:  # queued before destinations existed
        s.add(
            OutboxJob(
                organization_id=a,
                consumer=outbox.NOTIFY_CONSUMER,
                scope_key=f"notification:{nid}",
                result={"text": "[CRITICAL] legacy"},
            )
        )
    await _drain(3)
    assert sorted(c["json"]["text"] for c in net.ops()) == [
        "[CRITICAL] Drift\n3 checks failed",
        "[CRITICAL] legacy",
    ]


async def test_an_unknown_destination_posts_nowhere(net: Net) -> None:
    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"))
    nid = await _notify(a, severity="info")  # nothing real queued
    async with session_scope() as s:
        s.add(
            OutboxJob(
                organization_id=a,
                consumer=outbox.NOTIFY_CONSUMER,
                scope_key=f"notification:{nid}",
                result={"destination": "elsewhere", "text": "x"},
            )
        )
    await _drain()
    (job,) = await _jobs(nid)
    assert job.result["refused"] == "unknown destination: elsewhere"
    assert net.calls == []


def test_enqueue_refuses_an_unknown_destination() -> None:
    import asyncio  # noqa: PLC0415

    with pytest.raises(ValueError, match="unknown notification destination"):
        asyncio.run(outbox.enqueue_notification(None, None, "x", destination="nope"))  # type: ignore[arg-type]


# ── the API ──────────────────────────────────────────────────────────────────


@pytest.fixture
def auth_on() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _unscoped_session() -> AsyncIterator[Any]:
    """RLS tenant cleared: only the code's own org predicates keep tenants apart."""
    async with get_session_factory()() as session:
        await set_session_tenant(session, None)
        yield session


def _client(*, unscoped: bool = True) -> AsyncClient:
    app = create_app()
    if unscoped:
        app.dependency_overrides[get_session] = _unscoped_session
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


async def _tenant(label: str) -> SimpleNamespace:
    t = SimpleNamespace(org=await _org(label), tokens={})
    async with session_scope() as s:
        for role in ROLES:
            u = User(
                email=f"{role}-{uuid.uuid4().hex[:6]}@{label}.test",
                organization_id=t.org,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            await s.flush()
            t.tokens[role] = u.api_token
    return t


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


API = "/api/org/notify-channel"


async def _stored(org_id: int) -> OrgNotifyChannel | None:
    async with session_scope() as s:
        ch = await org_channel.get(s, org_id)
        if ch is not None:
            s.expunge(ch)
        return ch


async def test_an_admin_sets_tests_reads_and_removes_the_channel(net: Net, auth_on: None) -> None:
    a = await _tenant("ncapi")
    url = _url("a-hooks.example")
    async with _client() as c:
        put = await c.put(
            API, json={"webhook_url": url, "min_severity": "warning"}, headers=_h(a.tokens["admin"])
        )
        assert put.status_code == 200, put.text
        assert len(net.to("a-hooks.example")) == 1  # the test post, before saving
        got = await c.get(API, headers=_h(a.tokens["admin"]))
        tested = await c.post(f"{API}/test", headers=_h(a.tokens["admin"]))
        # Settings only: the stored URL is kept.
        flip = await c.put(
            API, json={"min_severity": "critical", "enabled": False}, headers=_h(a.tokens["admin"])
        )
        gone = await c.delete(API, headers=_h(a.tokens["admin"]))
        after = await c.get(API, headers=_h(a.tokens["admin"]))
    body = got.json()
    assert set(body) == {
        "configured", "organization_id", "url_hint", "min_severity", "enabled",
        "created_by", "created_at", "updated_by", "updated_at",
    }  # fmt: skip
    assert body["configured"] is True and body["organization_id"] == a.org
    assert body["url_hint"] == org_channel.url_hint(url)
    assert body["min_severity"] == "warning" and body["enabled"] is True
    assert body["created_by"].startswith("admin-")
    assert tested.json() == {"ok": True, "status_code": 200}
    assert len(net.to("a-hooks.example")) == 2
    assert flip.status_code == 200 and flip.json()["enabled"] is False
    assert flip.json()["url_hint"] == body["url_hint"]
    assert gone.status_code == 200 and after.json() == {"configured": False}
    assert await _stored(a.org) is None


@pytest.mark.parametrize(
    ("url", "why"),
    [
        ("http://a-hooks.example/services/x", "must use https"),
        ("https://127.0.0.1/services/x", "does not send to"),
        ("https://localhost/services/x", "addresses the server itself"),
        ("https://user:pw@a-hooks.example/x", "credentials may not be embedded"),
        ("", "a channel URL is required"),
        ("https://a-hooks.example/" + "x" * 2100, "at most 2048"),
    ],
)
async def test_put_refuses_a_url_the_guard_refuses(
    net: Net, auth_on: None, url: str, why: str
) -> None:
    a = await _tenant("ncref")
    async with _client() as c:
        r = await c.put(API, json={"webhook_url": url}, headers=_h(a.tokens["admin"]))
    assert r.status_code == 400 and why in r.json()["detail"], r.text
    assert "test post" not in r.json()["detail"]  # refused before any post is tried
    assert net.calls == []  # nothing posted
    assert await _stored(a.org) is None


async def test_put_refuses_when_rebinding_points_the_name_inward(
    net: Net, auth_on: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = await _tenant("ncreb")
    monkeypatch.setattr(webhook_url, "_resolve", lambda host: ["169.254.169.254"])
    async with _client() as c:
        r = await c.put(
            API, json={"webhook_url": _url("a-hooks.example")}, headers=_h(a.tokens["admin"])
        )
    assert r.status_code == 400 and "does not send to" in r.json()["detail"]
    assert "test post" not in r.json()["detail"]
    assert net.calls == [] and await _stored(a.org) is None


@pytest.mark.parametrize("code", [404, 403, 500])
async def test_put_refuses_to_save_when_the_test_post_fails(
    net: Net, auth_on: None, code: int
) -> None:
    a = await _tenant("nctp")
    net.respond = lambda call: code
    async with _client() as c:
        r = await c.put(
            API, json={"webhook_url": _url("a-hooks.example")}, headers=_h(a.tokens["admin"])
        )
    assert r.status_code == 400
    assert f"HTTP {code}" in r.json()["detail"] and "not saved" in r.json()["detail"]
    assert await _stored(a.org) is None


async def test_put_refuses_an_unknown_severity(net: Net, auth_on: None) -> None:
    a = await _tenant("ncsev")
    async with _client() as c:
        r = await c.put(
            API,
            json={"webhook_url": _url("a-hooks.example"), "min_severity": "loud"},
            headers=_h(a.tokens["admin"]),
        )
    assert r.status_code == 400 and "min_severity" in r.json()["detail"]
    assert net.calls == []


@pytest.mark.parametrize("role", ["viewer", "control_owner", "assessor"])
async def test_only_admins_reach_the_api(net: Net, auth_on: None, role: str) -> None:
    a = await _tenant("ncrb")
    url = _url("a-hooks.example")
    await _seed_channel(a.org, url)
    async with _client() as c:
        h = _h(a.tokens[role])
        answers = [
            await c.get(API, headers=h),
            await c.put(API, json={"webhook_url": _url("a-hooks.example")}, headers=h),
            await c.post(f"{API}/test", headers=h),
            await c.delete(API, headers=h),
        ]
    assert [r.status_code for r in answers] == [403, 403, 403, 403]
    assert net.calls == []
    ch = await _stored(a.org)
    assert ch is not None and org_channel.cipher().decrypt(ch.encrypted_url) == url


async def test_a_tenant_admin_cannot_act_on_another_org(net: Net, auth_on: None) -> None:
    a, b = await _tenant("ncxa"), await _tenant("ncxb")
    await _seed_channel(b.org, _url("b-hooks.example"))
    async with _client() as c:
        h = _h(a.tokens["admin"])
        q = f"?organization_id={b.org}"
        answers = [
            await c.get(API + q, headers=h),
            await c.put(API + q, json={"webhook_url": _url("a-hooks.example")}, headers=h),
            await c.post(f"{API}/test{q}", headers=h),
            await c.delete(API + q, headers=h),
        ]
        own = await c.get(API, headers=h)
    assert [r.status_code for r in answers] == [403, 403, 403, 403]
    assert own.json() == {"configured": False}  # A's own, not B's, on an unscoped session
    assert net.calls == []
    assert await _stored(b.org) is not None


async def test_a_platform_admin_names_the_org(net: Net) -> None:
    """Auth off is the system principal: global, a platform administrator."""
    a = await _org()
    url = _url("a-hooks.example")
    async with _client() as c:
        unnamed = await c.get(API)
        put = await c.put(f"{API}?organization_id={a}", json={"webhook_url": url})
        got = await c.get(f"{API}?organization_id={a}")
        missing = await c.get(f"{API}?organization_id=999999999")
    assert unnamed.status_code == 400
    assert put.status_code == 200 and got.json()["url_hint"] == org_channel.url_hint(url)
    assert missing.status_code == 404


# ── the URL never leaks ──────────────────────────────────────────────────────


async def test_the_url_appears_in_no_response_log_event_audit_entry_or_error(
    net: Net, auth_on: None
) -> None:
    a = await _tenant("ncleak")
    url = _url("a-hooks.example")
    secret = url.rsplit("/", 1)[1]
    seen: list[str] = []
    async with session_scope() as s:
        audit_mark = (await s.execute(select(func.coalesce(func.max(AuditLog.id), 0)))).scalar_one()
    with capture_logs() as logs:
        async with _client(unscoped=False) as c:
            h = _h(a.tokens["admin"])
            seen.append((await c.put(API, json={"webhook_url": url}, headers=h)).text)
            seen.append((await c.get(API, headers=h)).text)
            seen.append((await c.post(f"{API}/test", headers=h)).text)
            net.respond = lambda call: 410
            seen.append((await c.post(f"{API}/test", headers=h)).text)  # an error
            seen.append(
                (await c.put(API, json={"webhook_url": url + "x"}, headers=h)).text
            )  # a refused save
            seen.append((await c.put(API, json={"webhook_url": 7}, headers=h)).text)  # 422

            def _raise(call: dict[str, Any]) -> int:
                raise httpx.ConnectError(f"cannot reach {call['url']} for {url}")

            net.respond = _raise  # a test post that raises, carrying the URL
            raised = await c.put(API, json={"webhook_url": url + "y"}, headers=h)
            assert raised.status_code == 400 and "ConnectError" in raised.text
            seen.append(raised.text)
            net.respond = lambda call: 200
            seen.append((await c.get("/settings/organization", headers=h)).text)

        # Delivery: a transport error whose message carries the request URL.
        def _boom(call: dict[str, Any]) -> int:
            if call["url"] == OPS_URL:
                return 200
            raise httpx.ConnectError(f"cannot reach {call['url']} for {url}")

        net.respond = _boom
        nid = await _notify(a.org)
        await _drain()
        async with _client(unscoped=False) as c:
            seen.append((await c.delete(API, headers=_h(a.tokens["admin"]))).text)

    org_job = _by_dest(await _jobs(nid))["org"]
    assert org_job.status == "pending" and org_job.last_error == "DeliveryError: ConnectError"
    seen += [org_job.last_error or "", json.dumps(org_job.result)]
    seen.append(json.dumps(logs, default=str))
    assert any(e.get("event") == "notify_delivery.failed" for e in logs)  # logs were captured
    async with session_scope() as s:
        events = (await s.execute(select(Event).where(Event.organization_id == a.org))).scalars()
        ev = [(e.summary, json.dumps(e.payload)) for e in events]
        audits = (await s.execute(select(AuditLog).where(AuditLog.id > audit_mark))).scalars()
        au = [json.dumps(r.diff) for r in audits]
    assert any("notify_channel_set" in x or "webhook_url" in x for x in au)  # audited at all
    assert any(s_ == f"Alert channel set: {org_channel.url_hint(url)}" for s_, _ in ev)
    seen += [x for pair in ev for x in pair] + au
    leaks = [x[:120] for x in seen if secret in x]
    assert leaks == []


async def test_a_settings_change_is_an_event_and_an_audit_entry_but_never_news(
    net: Net, auth_on: None
) -> None:
    a = await _tenant("ncev")
    async with session_scope() as s:  # subscribed to everything this org emits
        s.add(Webhook(organization_id=a.org, url="https://hooks.example/all", events=[]))
    async with _client() as c:
        await c.put(
            API, json={"webhook_url": _url("a-hooks.example")}, headers=_h(a.tokens["admin"])
        )
        await c.delete(API, headers=_h(a.tokens["admin"]))
    async with session_scope() as s:
        evs = list(
            (
                await s.execute(
                    select(Event)
                    .where(
                        Event.organization_id == a.org, Event.entity_type == "org_notify_channel"
                    )
                    .order_by(Event.id)
                )
            ).scalars()
        )
        actions = list(
            (
                await s.execute(
                    select(AuditLog.action).where(
                        AuditLog.organization_id == a.org,
                        AuditLog.entity_type == "org_notify_channel",
                    )
                )
            ).scalars()
        )
        hooks = (
            await s.execute(
                select(func.count())
                .select_from(OutboxJob)
                .where(
                    OutboxJob.consumer == outbox.WEBHOOK_CONSUMER,
                    OutboxJob.trigger_event_id.in_([e.id for e in evs]),
                )
            )
        ).scalar_one()
    assert [e.verb for e in evs] == ["created", "deleted"]
    assert sorted(actions) == ["notify_channel_remove", "notify_channel_set"]
    assert hooks == 0  # dispatch=False: settings, not news


# ── the UI ───────────────────────────────────────────────────────────────────


UI = "/settings/organization/notify-channel"


async def test_the_settings_page_offers_the_form_only_to_admins(net: Net, auth_on: None) -> None:
    a = await _tenant("ncui")
    url = _url("a-hooks.example")
    await _seed_channel(a.org, url, min_severity="warning")
    pages = {}
    async with _client() as c:
        for role in ROLES:
            r = await c.get("/settings/organization", headers=_h(a.tokens[role]))
            assert r.status_code == 200
            pages[role] = r.text
    hint = org_channel.url_hint(url)
    for role, page in pages.items():
        assert "Alert channel" in page, role
        assert url.rsplit("/", 1)[1] not in page
        assert ("data-channel-form" in page) is (role == "admin"), role
        if role == "admin":
            assert hint in page and "<strong>warning</strong> and above" in page
        else:
            # Spec section 6: the read is an admin's. Presence only.
            assert "An alert channel is set" in page, role
            assert "a-hooks.example" not in page, role
            assert "<strong>warning</strong>" not in page and "data-channel-hint" not in page


async def test_a_non_admin_sees_only_that_there_is_no_channel(net: Net, auth_on: None) -> None:
    a = await _tenant("ncui0")
    async with _client() as c:
        page = (await c.get("/settings/organization", headers=_h(a.tokens["viewer"]))).text
    assert "No alert channel" in page and "data-channel-form" not in page


@pytest.mark.parametrize("role", ["viewer", "control_owner", "assessor"])
async def test_every_ui_form_post_refuses_a_non_admin(net: Net, auth_on: None, role: str) -> None:
    a = await _tenant("ncuirb")
    url = _url("a-hooks.example")
    await _seed_channel(a.org, url)
    async with _client() as c:
        h = _h(a.tokens[role])
        answers = [
            await c.post(UI, data={"webhook_url": _url("a-hooks.example")}, headers=h),
            await c.post(f"{UI}/test", headers=h),
            await c.post(f"{UI}/delete", headers=h),
        ]
    assert [r.status_code for r in answers] == [403, 403, 403]
    assert net.calls == []
    assert await _stored(a.org) is not None


async def test_an_admin_manages_the_channel_from_the_page(net: Net, auth_on: None) -> None:
    a = await _tenant("ncuiok")
    url = _url("a-hooks.example")
    async with _client() as c:
        h = _h(a.tokens["admin"])
        bad = await c.post(UI, data={"webhook_url": "http://x.example/a"}, headers=h)
        ok = await c.post(
            UI, data={"webhook_url": url, "min_severity": "warning", "enabled": "1"}, headers=h
        )
        stored = await _stored(a.org)
        page = (await c.get(ok.headers["location"], headers=h)).text
        tested = await c.post(f"{UI}/test", headers=h)
        off = await c.post(UI, data={"min_severity": "info"}, headers=h)  # unchecked: off
        stored_off = await _stored(a.org)
        removed = await c.post(f"{UI}/delete", headers=h)
        foreign = await c.post(UI, data={"organization_id": "999999999"}, headers=h)
    assert bad.status_code == 303 and "channel=refused_scheme" in bad.headers["location"]
    assert ok.status_code == 303 and "channel=saved" in ok.headers["location"]
    assert stored is not None and stored.min_severity == "warning" and stored.enabled
    assert "Alert channel saved" in page and org_channel.url_hint(url) in page
    assert tested.status_code == 303 and "channel=test_sent" in tested.headers["location"]
    assert stored_off is not None and not stored_off.enabled and stored_off.min_severity == "info"
    assert off.status_code == 303
    assert removed.status_code == 303 and await _stored(a.org) is None
    assert foreign.status_code == 403


async def test_a_platform_admin_manages_any_orgs_channel_from_the_page(net: Net) -> None:
    a = await _org("ncplat")
    url = _url("a-hooks.example")
    async with _client() as c:
        listing = (await c.get("/settings/organization")).text
        ok = await c.post(UI, data={"webhook_url": url, "organization_id": str(a), "enabled": "1"})
        page = (await c.get(f"/settings/organization?channel_org={a}")).text
        unnamed = await c.post(UI, data={"webhook_url": url})
    assert f"channel_org={a}" in listing
    assert ok.status_code == 303 and f"channel_org={a}" in ok.headers["location"]
    assert org_channel.url_hint(url) in page and f'name="organization_id" value="{a}"' in page
    assert unnamed.status_code == 400
    assert url.rsplit("/", 1)[1] not in page


# ── schema ───────────────────────────────────────────────────────────────────


async def test_the_table_is_tenant_isolated_and_the_app_cannot_truncate_it() -> None:
    async with session_scope() as s:
        rls = (
            await s.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE oid = 'ccf.org_notify_channels'::regclass"
                )
            )
        ).one()
        privs = (
            (
                await s.execute(
                    text(
                        "SELECT has_table_privilege('ccf_app', 'ccf.org_notify_channels', p) "
                        "FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE']) p"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert tuple(rls) == (True, True)
    assert privs == [True, True, True, True, False]


async def test_a_tenant_session_sees_only_its_own_channel() -> None:
    a, b = await _org(), await _org()
    await _seed_channel(a, _url("a-hooks.example"))
    await _seed_channel(b, _url("b-hooks.example"))
    async with session_scope() as s:
        await set_session_tenant(s, a)
        orgs = (await s.execute(select(OrgNotifyChannel.organization_id))).scalars().all()
    assert set(orgs) == {a}


def test_the_consumer_is_still_one_registered_consumer() -> None:
    c = consumers.REGISTRY[outbox.NOTIFY_CONSUMER]
    assert dataclasses.is_dataclass(c) and c.max_attempts == outbox.WEBHOOK_MAX_ATTEMPTS


async def test_key_rotation_rewraps_the_channel_url(
    net: Net, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The URL is in the rewrap sweep: rotating the master key and dropping the
    old one must not orphan an organization's channel."""
    from ccf.ai import cipher as cipher_mod  # noqa: PLC0415
    from ccf.ai.rotation import rewrap_all  # noqa: PLC0415

    old, new = "rotate-old-key-aaaaaaaaaaaaaaaa", "rotate-new-key-bbbbbbbbbbbbbbbb"
    cipher_mod.reset_key_cache()
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", old)
    get_settings.cache_clear()
    a = await _org()
    url = _url("a-hooks.example")
    await _seed_channel(a, url)

    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", new)
    monkeypatch.setenv("CCF_AI_CREDENTIAL_PREVIOUS_KEYS", json.dumps([old]))
    get_settings.cache_clear()
    async with session_scope() as s:
        report = await rewrap_all(s)
    assert report.rewrapped >= 1
    monkeypatch.delenv("CCF_AI_CREDENTIAL_PREVIOUS_KEYS")
    get_settings.cache_clear()
    ch = await _stored(a)
    assert ch is not None
    assert cipher_mod.token_key_id(ch.encrypted_url) == cipher_mod.key_id(new)
    assert org_channel.cipher().decrypt(ch.encrypted_url) == url
    nid = await _notify(a)
    await _drain()
    assert len(net.to("a-hooks.example")) == 1
    assert _by_dest(await _jobs(nid))["org"].status == "done"
    cipher_mod.reset_key_cache()


# ── fix round 1: a key service outage is retried, not dead-lettered ──────────


class _KmsDown:
    def encrypt(self, plaintext: str) -> str:  # pragma: no cover - not reached
        raise AssertionError("not used")

    def decrypt(self, token: str) -> str:
        from ccf.ai.cipher import KmsUnavailableError  # noqa: PLC0415

        raise KmsUnavailableError("abc123", RuntimeError("ThrottlingException"))


async def test_kms_unavailable_at_send_is_retried(
    net: Net, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"))
    nid = await _notify(a)
    monkeypatch.setattr(org_channel, "cipher", _KmsDown)
    await _drain()
    job = _by_dest(await _jobs(nid))["org"]
    assert (job.status, job.attempts) == ("pending", 1)
    assert "key service" in (job.last_error or "")
    assert net.to("a-hooks.example") == []


@pytest.mark.parametrize("kind", ["payload", "unknown_key"])
async def test_an_unreadable_value_stays_final(
    net: Net, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    from ccf.ai.cipher import PayloadAuthenticationError, UnknownKeyError  # noqa: PLC0415

    class _Bad:
        def decrypt(self, token: str) -> str:
            raise PayloadAuthenticationError("x") if kind == "payload" else UnknownKeyError("k")

    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"))
    nid = await _notify(a)
    monkeypatch.setattr(org_channel, "cipher", _Bad)
    await _drain()
    job = _by_dest(await _jobs(nid))["org"]
    assert (job.status, job.attempts) == ("failed", 1)


async def test_kms_unavailable_on_a_test_post_says_try_later(
    net: Net, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = await _org()
    await _seed_channel(a, _url("a-hooks.example"))
    monkeypatch.setattr(org_channel, "cipher", _KmsDown)
    async with session_scope() as s:
        with pytest.raises(org_channel.ChannelRefusedError) as e:
            await org_channel.send_stored_test(s, a)
    assert "try again later" in str(e.value) and "set it again" not in str(e.value)
    assert net.calls == []


# ── fix round 1: a 422 never echoes the URL ──────────────────────────────────


@pytest.mark.parametrize(
    "shape", ["string", "array", "nested", "wrong_type_severity", "wrong_type_enabled"]
)
async def test_a_malformed_body_is_a_422_without_the_url(
    net: Net, auth_on: None, shape: str
) -> None:
    a = await _tenant("nc422")
    url = _url("a-hooks.example")
    secret = url.rsplit("/", 1)[1]
    body: Any = {
        "string": url,
        "array": [url, {"webhook_url": url}],
        "nested": {"webhook_url": {"url": url}},
        "wrong_type_severity": {"webhook_url": url, "min_severity": [url]},
        "wrong_type_enabled": {"webhook_url": url, "enabled": url},
    }[shape]
    async with _client() as c:
        r = await c.put(API, json=body, headers=_h(a.tokens["admin"]))
    assert r.status_code == 422, r.text
    assert secret not in r.text
    assert net.calls == [] and await _stored(a.org) is None


async def test_the_put_body_is_still_documented() -> None:
    schema = create_app().openapi()
    body = schema["paths"]["/api/org/notify-channel"]["put"]["requestBody"]
    assert "webhook_url" in json.dumps(body)


# ── fix round 1: two first saves at once ─────────────────────────────────────


async def test_two_concurrent_first_saves_leave_one_channel_and_no_error(
    net: Net, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both read "no channel yet", both test-post, both write: the second
    becomes an update instead of an IntegrityError (a 500)."""
    import asyncio  # noqa: PLC0415

    a = await _org()
    urls = [_url("a-hooks.example"), _url("b-hooks.example")]
    reads: list[int] = []
    real_get = org_channel.get

    async def one(url: str, who: str) -> None:
        async with session_scope() as s:
            await set_session_tenant(s, a)
            await org_channel.save(s, a, actor=who, url=url, min_severity="critical", enabled=True)

    async def get_then_wait(session: Any, org_id: int) -> Any:
        found = await real_get(session, org_id)
        reads.append(org_id)
        while len(reads) < 2:  # both have looked before either writes
            await asyncio.sleep(0.01)
        return found

    monkeypatch.setattr(org_channel, "get", get_then_wait)
    await asyncio.wait_for(asyncio.gather(one(urls[0], "x"), one(urls[1], "y")), 30)
    monkeypatch.undo()
    async with session_scope() as s:
        rows = (
            (await s.execute(select(OrgNotifyChannel).where(OrgNotifyChannel.organization_id == a)))
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert org_channel.cipher().decrypt(rows[0].encrypted_url) in urls
        assert rows[0].updated_by in ("x", "y")
        verbs = (
            (
                await s.execute(
                    select(Event.verb).where(
                        Event.organization_id == a, Event.entity_type == "org_notify_channel"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert sorted(verbs) == ["created", "updated"]  # the second save is told it updated



# ── fix round 1: the page renders fixed messages, never query-string text ────


async def test_free_text_in_the_query_string_is_never_rendered(net: Net, auth_on: None) -> None:
    a = await _tenant("ncspoof")
    bait = "Paste your Slack token at evil.example to continue"
    async with _client() as c:
        h = _h(a.tokens["admin"])
        pages = [
            (await c.get("/settings/organization", params=params, headers=h)).text
            for params in (
                {"channel_error": bait},
                {"channel_notice": bait},
                {"channel": bait},
                {"channel": "saved", "status": bait},
                {"channel": "test_failed", "status": "4044"},
                {"channel": "test_failed", "status": "<b>"},
            )
        ]
        known = (
            await c.get(
                "/settings/organization",
                params={"channel": "test_failed", "status": "404"},
                headers=h,
            )
        ).text
    for page in pages:
        assert "evil.example" not in page and "Paste your" not in page
        assert "4044" not in page and "&lt;b&gt;" not in page
    assert "data-channel-error" not in pages[0] and "data-channel-notice" not in pages[1]
    assert "Alert channel saved." in pages[3] and "HTTP" not in pages[3]
    assert "The receiver refused the test post" in known and "HTTP 404" in known


async def test_a_refused_ui_save_reports_the_receivers_status_as_a_number(
    net: Net, auth_on: None
) -> None:
    a = await _tenant("ncstat")
    net.respond = lambda call: 404
    async with _client() as c:
        h = _h(a.tokens["admin"])
        r = await c.post(UI, data={"webhook_url": _url("a-hooks.example")}, headers=h)
        page = (await c.get(r.headers["location"], headers=h)).text
    assert "channel=test_failed&status=404" in r.headers["location"]
    assert "The receiver refused the test post" in page and "HTTP 404" in page


def test_every_refusal_code_has_a_fixed_message() -> None:
    from ccf.api.routes.ui_govern import CHANNEL_MESSAGES  # noqa: PLC0415

    codes = {
        "url_required", "refused_url", "refused_scheme", "refused_target", "invalid_severity",
        "test_failed", "test_refused", "test_unreachable", "no_channel", "kms_unavailable",
        "undecryptable", "saved", "removed", "test_sent", "storage_unavailable",
    }  # fmt: skip
    assert codes <= set(CHANNEL_MESSAGES)
