"""The seams an independent review of the build-out found, each pinned.

* Register import made decisions the API only makes against an approval
  (accepting a risk, closing a POA&M) and wrote any status at all.
* The AI service read a risk's owner through its system, so an enterprise
  risk (no system) had no owner and passed the cross-tenant guard.
* A webhook URL with an out-of-range port was accepted and then raised on
  every emit in the organization.
* Risk writes by a global principal emitted org-less events, which reach every
  tenant's webhooks.
* Readers that scoped risks through their system left enterprise risks out,
  so the exceptions page, digest, summary, overview, executive report, graph,
  search and AI picker disagreed with the risk pages.
* The dashboard counted audit findings by their own (nullable)
  ``organization_id``, not through the engagement as ``/audit/findings`` does.
* Pages that add records up rendered every tenant's totals to an unscoped
  session.

Queries run on an RLS-cleared session, so only the code's own predicate scopes.
"""

from __future__ import annotations

import itertools
import os
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.ai_actions import service as ai_service
from ccf.analytics import command_center, overview, posture
from ccf.api.main import create_app
from ccf.api.routes import risks as risk_routes
from ccf.api.routes import ui_platform
from ccf.assurance import builder
from ccf.auth import Principal, hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.governance import audit_program, bus, digest, exporter, insights, webhook_url
from ccf.models import POAM, Notification, Organization, Risk, System, Task, User
from ccf.models_grc import AuditEngagement, AuditFinding

pytestmark = pytest.mark.usefixtures("fresh_engine")
_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _tag() -> str:
    return f"rs{next(_SEQ)}x{os.getpid()}{os.urandom(2).hex()}"


async def _org(label: str) -> dict[str, int | str]:
    """An organization with a live and a deleted system, an enterprise risk,
    a cyber risk, a POA&M and an admin."""
    tag = _tag()
    async with session_scope() as s:
        org = Organization(name=f"{label}-{tag}")
        s.add(org)
        await s.flush()
        live = System(organization_id=org.id, name=f"{label}-sys-{tag}")
        gone = System(
            organization_id=org.id, name=f"{label}-gone-{tag}", deleted_at=datetime.now(UTC)
        )
        admin = User(
            email=f"{label.lower()}-admin-{tag}@rs.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add_all([live, gone, admin])
        await s.flush()
        enterprise = Risk(
            organization_id=org.id,
            register="enterprise",
            title=f"{label}-ENTERPRISE-{tag}",
            status="accepted",
            residual_score=20,
            next_review_on=date.today() + timedelta(days=3),
        )
        cyber = Risk(system_id=live.id, title=f"{label}-cyber-{tag}", status="open")
        poam = POAM(system_id=live.id, title=f"{label}-poam-{tag}", severity="low", status="open")
        s.add_all([enterprise, cyber, poam])
        await s.flush()
        return {
            "org": org.id,
            "tag": tag,
            "live": live.id,
            "gone": gone.id,
            "enterprise": enterprise.id,
            "enterprise_title": enterprise.title,
            "cyber": cyber.id,
            "poam": poam.id,
            "token": admin.api_token,
            "email": admin.email,
        }


async def _unscoped():
    async with get_session_factory()() as session:
        await set_session_tenant(session, None)
        yield session


# ── 1. register import does not make gated decisions ─────────────────────────


async def _import(org: int, dataset: str, csv: str) -> dict:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        return await exporter.import_rows(
            s, dataset=dataset, content=csv.encode(), fmt="csv", org_id=org
        )


async def test_import_cannot_accept_a_risk() -> None:
    a = await _org("Imp")
    got = await _import(a["org"], "risks", f"id,title,status\n{a['cyber']},x,accepted\n")
    assert got["updated"] == 0 and got["skipped"] == 1
    assert "approved review" in got["errors"][0]
    new = await _import(a["org"], "risks", "title,status\nfresh,accepted\n")
    assert new["created"] == 0 and new["skipped"] == 1
    async with session_scope() as s:
        assert (await s.get(Risk, a["cyber"])).status == "open"


async def test_import_may_restate_an_unchanged_acceptance() -> None:
    """An exported register round-trips: restating a status is not a decision."""
    a = await _org("Imp")
    got = await _import(
        a["org"], "risks", f"id,title,status\n{a['enterprise']},renamed,accepted\n"
    )
    assert got["updated"] == 1 and got["skipped"] == 0
    async with session_scope() as s:
        assert (await s.get(Risk, a["enterprise"])).title == "renamed"


@pytest.mark.parametrize("status", ["closed", "completed", "risk_accepted"])
async def test_import_cannot_close_or_accept_a_poam(status: str) -> None:
    a = await _org("Imp")
    got = await _import(a["org"], "poams", f"id,title,status\n{a['poam']},x,{status}\n")
    assert got["skipped"] == 1 and "approved review" in got["errors"][0]
    async with session_scope() as s:
        assert (await s.get(POAM, a["poam"])).status == "open"


async def test_import_cannot_reopen_an_accepted_poam() -> None:
    a = await _org("Imp")
    async with session_scope() as s:
        (await s.get(POAM, a["poam"])).status = "risk_accepted"
    got = await _import(a["org"], "poams", f"id,title,status\n{a['poam']},x,open\n")
    assert got["skipped"] == 1
    async with session_scope() as s:
        assert (await s.get(POAM, a["poam"])).status == "risk_accepted"


async def test_import_cannot_extend_an_accepted_poams_expiry() -> None:
    """``due_on`` is the acceptance's expiry: later, or cleared, needs an
    approval through the API; earlier needs nobody's, here as there."""
    a = await _org("Imp")
    held = date.today() + timedelta(days=30)
    async with session_scope() as s:
        p = await s.get(POAM, a["poam"])
        p.status, p.due_on = "risk_accepted", held
    for due in ((held + timedelta(days=90)).isoformat(), ""):
        got = await _import(a["org"], "poams", f"id,title,due_on\n{a['poam']},x,{due}\n")
        assert got["skipped"] == 1 and "expiry" in got["errors"][0], due
    async with session_scope() as s:
        assert (await s.get(POAM, a["poam"])).due_on == held
    sooner = held - timedelta(days=10)
    ok = await _import(a["org"], "poams", f"id,title,due_on\n{a['poam']},x,{sooner.isoformat()}\n")
    assert ok["updated"] == 1
    async with session_scope() as s:
        assert (await s.get(POAM, a["poam"])).due_on == sooner


async def test_import_refuses_a_status_the_register_does_not_have() -> None:
    a = await _org("Imp")
    got = await _import(a["org"], "poams", f"id,title,status\n{a['poam']},x,done\n")
    assert got["skipped"] == 1 and "status must be one of" in got["errors"][0]
    ok = await _import(a["org"], "poams", f"id,title,status\n{a['poam']},x,in_progress\n")
    assert ok["updated"] == 1


# ── 2. the AI guard knows who owns an enterprise risk ────────────────────────


async def test_ai_context_refuses_another_orgs_enterprise_risk() -> None:
    a, b = await _org("AiA"), await _org("AiB")
    async with session_scope() as s:
        await set_session_tenant(s, None)
        with pytest.raises(PermissionError):
            await ai_service._resolve_context(
                s, org_id=a["org"], entity_type="risk", entity_id=str(b["enterprise"])
            )
        own = await ai_service._resolve_context(
            s, org_id=a["org"], entity_type="risk", entity_id=str(a["enterprise"])
        )
    assert own is not None and own["owner_org"] == a["org"]


async def test_ai_context_refuses_a_record_whose_owner_is_unknown(monkeypatch) -> None:
    async def ownerless(*_a, **_k):
        return None, "orphan", {}, []

    monkeypatch.setattr(ai_service, "_load_entity", ownerless)
    async with session_scope() as s:
        with pytest.raises(PermissionError):
            await ai_service._resolve_context(s, org_id=1, entity_type="risk", entity_id="1")


# ── 3. a webhook URL is deliverable or refused, never a crash ────────────────


@pytest.mark.parametrize("url", ["https://example.com:99999/h", "https://example.com:abc/h"])
def test_a_webhook_with_an_invalid_port_is_refused(url: str) -> None:
    assert "port" in (webhook_url.refusal(url) or "")


async def test_dispatch_skips_a_stored_url_that_cannot_be_parsed(monkeypatch) -> None:
    posted: list[str] = []

    class _Client:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a) -> None:
            return None

        async def post(self, url, **k):
            posted.append(url)

    def explode(url: str):
        if "bad" in url:
            raise ValueError("Port out of range 0-65535")
        return None, {"url": url, "headers": {}, "extensions": {}}

    monkeypatch.setattr(bus.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(webhook_url, "pinned_target", explode)
    hooks = [
        SimpleNamespace(id=1, url="https://bad.example/x", events=[], secret=None),
        SimpleNamespace(id=2, url="https://good.example/x", events=[], secret=None),
    ]

    class _Session:
        async def execute(self, stmt):
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: hooks))

    ev = SimpleNamespace(
        organization_id=1, verb="created", entity_type="poam", entity_id="1", summary="s",
        payload={},
    )
    await bus._dispatch_webhooks(_Session(), ev)  # type: ignore[arg-type]
    assert posted == ["https://good.example/x"]


def test_an_ipv6_literal_keeps_its_brackets_in_the_host_header() -> None:
    reason, target = webhook_url.pinned_target("https://[2606:4700:4700::1111]:8443/x")
    assert reason is None
    assert target["headers"] == {"Host": "[2606:4700:4700::1111]:8443"}


# ── 5. a global principal's risk write lands in the risk's organization ──────


async def test_a_global_writers_risk_event_and_task_belong_to_the_risk() -> None:
    a = await _org("Glob")
    principal = Principal(user_id=None, email="platform@rs.test", org_id=None, role="admin")
    async with session_scope() as s:
        await set_session_tenant(s, None)
        risk = await s.get(Risk, a["cyber"])
        risk.treatment, risk.residual_score = "mitigate", 20
        await risk_routes._post_write(s, risk, principal, verb="updated")
        await s.flush()
        from ccf.models import Event  # noqa: PLC0415

        ev = (
            await s.execute(
                select(Event).where(Event.entity_type == "risk", Event.entity_id == str(risk.id))
            )
        ).scalar_one()
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"risk-mitigate:{risk.id}"))
        ).scalar_one()
        note = (
            await s.execute(
                select(Notification).where(Notification.dedupe_key == f"risk-high:{risk.id}")
            )
        ).scalar_one()
    assert ev.organization_id == task.organization_id == note.organization_id == a["org"]


# ── 6. every risk reader includes enterprise risks ───────────────────────────


async def test_risk_readers_include_the_organizations_enterprise_risks() -> None:
    a = await _org("ReadA")
    await _org("ReadB")  # another tenant, so a missing predicate shows
    async with session_scope() as s:
        await set_session_tenant(s, None)
        summary = await posture.org_summary(s, today=date.today(), org_id=a["org"])
        # accepted enterprise risk + open cyber risk; nothing of B's
        assert summary["risks_by_status"] == {"accepted": 1, "open": 1}
        bands = await overview._risk_by_band(s, a["org"])
        assert sum(bands.values()) == 2
        execu = await insights.executive(s, org_id=a["org"])
        assert sum(execu["risk_by_residual_band"].values()) == 2
        picker = (await s.execute(ui_platform._target_stmt("risk", a["org"]))).all()
        assert {r.id for r in picker} == {a["enterprise"], a["cyber"]}
        g = builder._Graph()
        await builder._risks(s, a["org"], g)
        assert {k for k in g.nodes if k[0] == "risk"} == {
            ("risk", str(a["enterprise"])),
            ("risk", str(a["cyber"])),
        }


async def test_the_digest_alerts_an_enterprise_risks_review() -> None:
    a = await _org("Dig")
    async with session_scope() as s:
        r = await s.get(Risk, a["enterprise"])
        r.status = "open"  # reviews are alerted for open/mitigated risks
    async with session_scope() as s:
        await set_session_tenant(s, None)
        await digest.run(s, today=date.today(), org_id=a["org"])
        await s.flush()
        hits = (
            await s.execute(
                select(Notification).where(
                    Notification.dedupe_key.like(f"risk-review:{a['enterprise']}:%")
                )
            )
        ).scalars().all()
    assert [n.organization_id for n in hits] == [a["org"]]


@pytest.fixture
def _auth_enabled():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    from ccf.api.deps import get_session  # noqa: PLC0415

    app = create_app()
    app.dependency_overrides[get_session] = _unscoped
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


@pytest.mark.usefixtures("_auth_enabled")
async def test_exceptions_and_search_list_enterprise_risks_of_the_org_only() -> None:
    a, b = await _org("ExcA"), await _org("ExcB")
    async with _client() as c:
        h = {"Authorization": f"Bearer {a['token']}"}
        page = (await c.get("/exceptions", headers=h)).text
        found = (await c.get("/ui/search", params={"q": "ENTERPRISE"}, headers=h)).json()
    assert a["enterprise_title"] in page and b["enterprise_title"] not in page
    assert f'/risks/{a["enterprise"]}' in page
    assert a["enterprise_title"] in str(found) and b["enterprise_title"] not in str(found)


# ── 7. the dashboard counts audit findings as /audit/findings does ───────────


async def test_dashboard_findings_are_scoped_through_the_engagement() -> None:
    a = await _org("Aud")
    async with session_scope() as s:
        eng = AuditEngagement(organization_id=a["org"], name=f"eng-{a['tag']}", status="fieldwork")
        s.add(eng)
        await s.flush()
        s.add_all(
            [
                # Raised in the UI before ISSM-04: no organization of its own.
                AuditFinding(engagement_id=eng.id, title="null-org", severity="high"),
                AuditFinding(
                    engagement_id=eng.id,
                    title="on a deleted system",
                    severity="high",
                    organization_id=a["org"],
                    system_id=a["gone"],
                ),
                AuditFinding(
                    engagement_id=eng.id, title="closed", severity="low", status="closed"
                ),
            ]
        )
    async with session_scope() as s:
        await set_session_tenant(s, None)
        counts = await command_center._open_audit_findings(s, a["org"])
        page = await audit_program.findings(s, a["org"])
    assert counts == {"high": 1}
    assert page["open_total"] == 1 and page["open_by_severity"]["high"] == 1


# ── 4. pages that add records up refuse an unscoped session ──────────────────

UNSCOPED_PAGES = (
    "/risks/assessments",
    "/risks/treatment",
    "/risks/heatmap",
    "/analytics",
    "/audit/workpapers",
    "/audit/findings",
    "/compensating-controls",
    "/audit/readiness",
)


@pytest.mark.parametrize("path", UNSCOPED_PAGES)
async def test_an_unscoped_session_is_told_rather_than_shown_every_tenant(path: str) -> None:
    a = await _org("Uns")
    async with _client() as c:  # auth off: no principal, no organization
        resp = await c.get(path)
    assert resp.status_code == 200
    assert "No organization in scope" in resp.text
    assert a["enterprise_title"] not in resp.text
    assert '<aside class="sidebar"' in resp.text and 'aria-current="page"' in resp.text


async def test_packages_of_two_organizations_are_not_compared() -> None:
    first = SimpleNamespace(id=1, organization_id=1)
    second = SimpleNamespace(id=2, organization_id=2)
    with pytest.raises(audit_program.RefusalError, match="different organizations"):
        await audit_program.compare_packages(None, first, second)  # type: ignore[arg-type]


async def test_an_audit_program_event_without_an_organization_is_refused() -> None:
    """A NULL-organization audit row is published to every tenant (0044), so
    a package that belongs to no organization is refused, not recorded."""
    from fastapi import HTTPException  # noqa: PLC0415

    from ccf.api.routes import ui_auditprog  # noqa: PLC0415

    principal = Principal(user_id=None, email="p@rs.test", org_id=None, role="admin")
    async with session_scope() as s:
        with pytest.raises(HTTPException) as refused:
            await ui_auditprog._event(
                s,
                principal,
                org=None,
                entity_type="authorization_package",
                entity_id=1,
                action="update",
                diff={},
            )
    assert refused.value.status_code == 409
    assert "belongs to no organization" in str(refused.value.detail)
