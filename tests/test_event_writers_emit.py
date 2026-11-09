"""Writers of the derived views' inputs emit, so their views refresh within a drain.

The event-bus review found writers that changed data the derived views read
(assurance_graph, capability_derive, fedramp20x, cr26_documents) while
emitting nothing, so those views waited for the scheduler. Each test here
performs one write and asserts the consumer's job is queued, with the
entity's organization; most also pin that a write which changes nothing
queues nothing (ruling R26).

Route handlers are called directly with a request carrying the principal, so
an org-scoped UI handler sees a tenant without the auth stack. Job and event
rows are read on an UNSCOPED session: RLS would hide a mis-filed one.
"""

from __future__ import annotations

import ast
import uuid
from collections.abc import AsyncIterator
from datetime import date, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select
from starlette.requests import Request

from ccf.ai_governance import service as ai_gov
from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.api.routes import evidence as evidence_routes
from ccf.api.routes import ui, ui_grc, waivers
from ccf.ato.lifecycle import TRANSITIONS
from ccf.auth import Principal
from ccf.boundary import service as boundary
from ccf.config import get_settings
from ccf.connectors import credentials as connector_credentials
from ccf.db import session_scope
from ccf.events import derived
from ccf.evidence import service as evidence_service
from ccf.governance import collection, control_tests, tprm
from ccf.models import (
    Control,
    ControlImplementation,
    Event,
    Evidence,
    FedRAMP20xProfile,
    Organization,
    System,
    SystemComponent,
    Vendor,
)
from ccf.models_ai_agents import AiAgent
from ccf.models_capability import Capability, CapabilityComponent
from ccf.models_grc import ConnectorConfig, ControlTest
from ccf.models_outbox import OutboxJob
from ccf.models_waivers import Waiver
from tests.test_event_derived_consumers import _SRC, _calls_named, _function

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
async def _no_live_jobs_left_behind() -> AsyncIterator[None]:
    async with session_scope() as s:
        mark = (await s.execute(select(func.coalesce(func.max(OutboxJob.id), 0)))).scalar_one()
    yield
    async with session_scope() as s:
        await s.execute(
            delete(OutboxJob).where(
                OutboxJob.id > mark, OutboxJob.status.in_(("pending", "claimed"))
            )
        )


async def _marks() -> tuple[int, int]:
    async with session_scope() as s:
        job = (await s.execute(select(func.coalesce(func.max(OutboxJob.id), 0)))).scalar_one()
        ev = (await s.execute(select(func.coalesce(func.max(Event.id), 0)))).scalar_one()
        return int(job), int(ev)


async def _jobs(mark: int) -> set[tuple[str, str]]:
    async with session_scope() as s:
        return {
            (c, k)
            for c, k in (
                await s.execute(
                    select(OutboxJob.consumer, OutboxJob.scope_key).where(OutboxJob.id > mark)
                )
            ).all()
        }


async def _events(mark: int, entity_type: str, verb: str | None = None) -> list[Event]:
    async with session_scope() as s:
        stmt = select(Event).where(Event.id > mark, Event.entity_type == entity_type)
        if verb is not None:
            stmt = stmt.where(Event.verb == verb)
        return list((await s.execute(stmt.order_by(Event.id))).scalars())


def _request(org_id: int | None, email: str = "isso@acme.gov") -> Request:
    principal = Principal(user_id=1, email=email, org_id=org_id, role="admin")
    return Request({"type": "http", "state": {"principal": principal}, "headers": []})


def _tag() -> str:
    return uuid.uuid4().hex[:8]


async def _system(*, twentyx: bool = False) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"writers-{_tag()}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"sys-{_tag()}", baseline="moderate")
        s.add(system)
        await s.flush()
        if twentyx:
            s.add(FedRAMP20xProfile(system_id=system.id, service_name="svc"))
        return org.id, system.id


class _Client:
    def __init__(self, org_id: int | None) -> None:
        self.app = create_app()
        self.app.dependency_overrides[get_principal] = lambda: Principal(
            user_id=1, email="isso@acme.gov", org_id=org_id, role="admin"
        )

    def __call__(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")


# ── systems (UI) ───────────────────────────────────────────────────────────────


async def test_the_ui_system_form_emits_created_with_the_systems_org() -> None:
    org_id, _ = await _system()
    jm, em = await _marks()
    name = f"ui-{_tag()}"
    async with session_scope() as s:
        await ui.create_system(
            _request(org_id),
            organization_id=org_id,
            name=name,
            description=None,
            baseline=None,
            session=s,
        )
    (ev,) = await _events(em, "system", "created")
    assert ev.organization_id == org_id
    assert ("assurance_graph", f"org:{org_id}") in await _jobs(jm)


async def test_the_ui_delete_emits_deleted() -> None:
    org_id, system_id = await _system()
    jm, em = await _marks()
    async with session_scope() as s:
        await ui.delete_system_ui(system_id, _request(org_id), session=s)
    (ev,) = await _events(em, "system", "deleted")
    assert (ev.organization_id, ev.entity_id) == (org_id, str(system_id))
    assert ("assurance_graph", f"org:{org_id}") in await _jobs(jm)


async def test_scoring_emits_only_for_a_system_it_creates() -> None:
    org_id, _ = await _system()
    name = f"score-{_tag()}"
    _, em = await _marks()
    for _ in range(2):  # the second submit reuses the system
        async with session_scope() as s:
            await ui.scoring_create_system(
                _request(org_id),
                organization_name="ignored for a tenant",
                system_name=name,
                baseline=None,
                session=s,
            )
    evs = await _events(em, "system", "created")
    assert len(evs) == 1 and evs[0].organization_id == org_id


# ── FedRAMP 20x (UI) ───────────────────────────────────────────────────────────


async def _save_profile(org_id: int, system_id: int, service_name: str) -> None:
    async with session_scope() as s:
        await ui.fedramp20x_save_profile(
            _request(org_id),
            system_id,
            service_name=service_name,
            deployment_model="",
            cloud_environment="",
            boundary_description="",
            cryptographic_boundary="",
            logging_boundary="",
            session=s,
        )


async def test_the_ui_profile_form_emits_when_it_changes_something() -> None:
    org_id, system_id = await _system()
    jm, em = await _marks()
    await _save_profile(org_id, system_id, "Acme Cloud")
    assert ("fedramp20x", f"system:{system_id}") in await _jobs(jm)
    (ev,) = await _events(em, "fedramp20x_profile", "updated")
    assert ev.organization_id == org_id

    jm, em = await _marks()
    await _save_profile(org_id, system_id, "Acme Cloud")  # the same form again
    assert await _events(em, "fedramp20x_profile") == []
    assert await _jobs(jm) == set()

    await _save_profile(org_id, system_id, "Acme Cloud 2")  # positive control
    assert len(await _events(em, "fedramp20x_profile", "updated")) == 1


async def test_the_ui_dependency_form_emits_created() -> None:
    org_id, system_id = await _system()
    jm, em = await _marks()
    async with session_scope() as s:
        await ui.fedramp20x_add_dependency(
            _request(org_id),
            system_id,
            name="Okta",
            provider="Okta",
            service_type="idp",
            fedramp_status="authorized",
            dependency_risk="",
            session=s,
        )
    (ev,) = await _events(em, "fedramp_dependency", "created")
    assert ev.organization_id == org_id and ev.payload["system_id"] == system_id
    assert ("fedramp20x", f"system:{system_id}") in await _jobs(jm)


# ── connectors ─────────────────────────────────────────────────────────────────


async def test_a_new_connector_reaches_the_graph_from_the_api_and_the_ui() -> None:
    api_org, _ = await _system()
    ui_org, _ = await _system()
    jm, em = await _marks()
    async with _Client(api_org)() as c:
        r = await c.post(
            "/api/connector-configs", json={"name": "AWS", "connector_type": "aws_govcloud"}
        )
    assert r.status_code == 201, r.text
    async with session_scope() as s:
        await ui_grc.connectors_create(
            _request(ui_org), name="AWS", connector_type="aws_govcloud", environment="", session=s
        )
    evs = await _events(em, "connector_config", "created")
    assert sorted(e.organization_id for e in evs) == sorted([api_org, ui_org])
    jobs = await _jobs(jm)
    assert {("assurance_graph", f"org:{api_org}"), ("assurance_graph", f"org:{ui_org}")} <= jobs


async def test_a_connector_status_change_emits_and_a_repeat_does_not() -> None:
    """The one helper every connector status writer calls (list below)."""
    org_id, _ = await _system()
    async with session_scope() as s:
        cfg = ConnectorConfig(
            organization_id=org_id, name="m365", connector_type="m365", status="error"
        )
        s.add(cfg)
        await s.flush()
        cfg_id = cfg.id
    jm, em = await _marks()
    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg is not None
        cfg.status = "configured"
        await connector_credentials.emit_connector_changed(s, cfg, status_was="error")
        await connector_credentials.emit_connector_changed(s, cfg, status_was="configured")
    (ev,) = await _events(em, "connector_config")
    assert (ev.verb, ev.organization_id, ev.payload["status"]) == ("updated", org_id, "configured")
    assert ("assurance_graph", f"org:{org_id}") in await _jobs(jm)


CONNECTOR_STATUS_WRITERS = (
    "connectors/credentials.py::set_credential",
    "api/routes/connector_settings.py::remove_credential",
    "api/routes/ui_grc.py::connectors_sync",
    "api/routes/ui_grc.py::connectors_test_credential",
    "api/routes/ui_grc.py::connectors_aws_external_id",
    "api/routes/ui_grc.py::connectors_create",
    "api/routes/grc.py::create_connector",
    "connectors/readiness.py::provider_readiness",
)


def test_every_connector_status_writer_calls_the_helper() -> None:
    for where in CONNECTOR_STATUS_WRITERS:
        path, name = where.split("::")
        fn = _function(_SRC / path, name)
        assert _calls_named(fn, "emit_connector_changed"), where


# ── control tests ──────────────────────────────────────────────────────────────


async def test_a_new_control_test_reaches_the_graph_from_the_api_and_the_ui() -> None:
    api_org, _ = await _system()
    ui_org, _ = await _system()
    jm, em = await _marks()
    async with _Client(api_org)() as c:
        r = await c.post(
            "/api/control-tests", json={"control_id": "AC-2", "name": "MFA", "method": "manual"}
        )
    assert r.status_code == 201, r.text
    async with session_scope() as s:
        await ui_grc.control_tests_create(
            _request(ui_org),
            control_id="AC-2",
            name="MFA",
            method="manual",
            frequency="",
            session=s,
        )
    evs = await _events(em, "control_test", "created")
    assert sorted(e.organization_id for e in evs) == sorted([api_org, ui_org])
    jobs = await _jobs(jm)
    assert {("assurance_graph", f"org:{api_org}"), ("assurance_graph", f"org:{ui_org}")} <= jobs


async def test_an_orgless_control_test_takes_its_systems_org() -> None:
    org_id, system_id = await _system()
    _, em = await _marks()
    async with session_scope() as s:
        t = ControlTest(organization_id=None, system_id=system_id, control_id="AC-2", name="x")
        s.add(t)
        await s.flush()
        await control_tests.emit_control_test_created(s, t, actor=None)
    (ev,) = await _events(em, "control_test", "created")
    assert ev.organization_id == org_id and ev.payload["system_id"] == system_id


def test_the_ai_action_control_test_mutation_calls_the_helper() -> None:
    fn = _function(_SRC / "ai_actions/service.py", "_apply_mutation")
    assert _calls_named(fn, "emit_control_test_created")


# ── AI agents and vendors ──────────────────────────────────────────────────────


async def test_a_global_principals_agent_takes_its_systems_org() -> None:
    org_id, system_id = await _system()
    jm, em = await _marks()
    async with _Client(None)() as c:
        r = await c.post("/api/ai-agents", json={"name": f"bot-{_tag()}", "system_id": system_id})
    assert r.status_code == 201, r.text
    async with session_scope() as s:
        agent = await s.get(AiAgent, r.json()["id"])
        assert agent is not None and agent.organization_id == org_id
    (ev,) = await _events(em, "ai_agent", "created")
    assert ev.organization_id == org_id
    assert ("assurance_graph", f"org:{org_id}") in await _jobs(jm)


async def test_the_ui_agent_form_emits_created() -> None:
    org_id, _ = await _system()
    jm, em = await _marks()
    async with session_scope() as s:
        await ui_grc.ai_agents_create_ui(
            _request(org_id), name=f"bot-{_tag()}", autonomy_level="low", production="", session=s
        )
    (ev,) = await _events(em, "ai_agent", "created")
    assert ev.organization_id == org_id
    assert ("assurance_graph", f"org:{org_id}") in await _jobs(jm)
    assert await _events(em, "ai_agent", "updated") == []  # first rating is not an update


async def test_agent_changes_emit_and_no_ops_do_not() -> None:
    org_id, _ = await _system()
    async with session_scope() as s:
        a = AiAgent(organization_id=org_id, name=f"bot-{_tag()}", autonomy_level="low")
        s.add(a)
        await s.flush()
        await ai_gov.risk_assess(s, a)
        aid = a.id
    jm, em = await _marks()
    async with session_scope() as s:
        a = await s.get(AiAgent, aid)
        assert a is not None
        await ai_gov.review_agent(s, a, decision="approved", reviewer="ao", note=None)
        await ai_gov.review_agent(s, a, decision="approved", reviewer="ao", note=None)
        await ai_gov.risk_assess(s, a)  # same inputs, same rating
    evs = await _events(em, "ai_agent", "updated")
    assert [e.payload["fields"] for e in evs] == [["approval_status"]]
    assert evs[0].organization_id == org_id
    assert ("assurance_graph", f"org:{org_id}") in await _jobs(jm)

    _, em = await _marks()
    async with session_scope() as s:
        a = await s.get(AiAgent, aid)
        assert a is not None
        a.production_access = True
        a.autonomy_level = "full"
        a.regulated_data_access = True
        a.external_action_capability = True
        await ai_gov.risk_assess(s, a)  # positive control: the rating moves
    assert [e.payload["fields"] for e in await _events(em, "ai_agent", "updated")] == [
        ["risk_rating"]
    ]


async def test_an_agent_patch_emits_only_when_it_changes_something() -> None:
    org_id, _ = await _system()
    async with _Client(org_id)() as c:
        r = await c.post("/api/ai-agents", json={"name": f"bot-{_tag()}"})
        aid = r.json()["id"]
        _, em = await _marks()
        await c.patch(f"/api/ai-agents/{aid}", json={"owner": None})  # nothing set
        assert await _events(em, "ai_agent", "updated") == []
        await c.patch(f"/api/ai-agents/{aid}", json={"name": "renamed"})
    (ev,) = await _events(em, "ai_agent", "updated")
    assert ev.payload["fields"] == ["name"] and ev.organization_id == org_id


async def test_a_vendor_created_event_carries_the_vendors_org() -> None:
    org_id, _ = await _system()
    jm, em = await _marks()
    async with _Client(org_id)() as c:
        r = await c.post("/api/vendors", json={"name": f"v-{_tag()}"})
    assert r.status_code == 201, r.text
    (ev,) = await _events(em, "vendor", "created")
    assert ev.organization_id == org_id
    assert ("assurance_graph", f"org:{org_id}") in await _jobs(jm)


async def test_a_vendor_rating_change_reaches_the_graph() -> None:
    org_id, _ = await _system()
    async with session_scope() as s:
        v = Vendor(organization_id=org_id, name=f"v-{_tag()}", risk_rating="low")
        s.add(v)
        await s.flush()
        jm, em = await _marks()
        await tprm.emit_vendor_rated(s, v, "high", actor="reviewer")
    (ev,) = await _events(em, "vendor", "updated")
    assert ev.organization_id == org_id and ev.payload["risk_rating"] == "high"
    assert ("assurance_graph", f"org:{org_id}") in await _jobs(jm)


def test_both_questionnaire_reviews_emit_only_on_a_rating_change() -> None:
    for path, name in (
        ("api/routes/questionnaires.py", "review_questionnaire"),
        ("api/routes/ui_grc.py", "questionnaire_review"),
    ):
        fn = _function(_SRC / path, name)
        assert _calls_named(fn, "emit_vendor_rated"), path
        guarded = [
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.If)
            and "risk_rating" in ast.unparse(n.test)
            and any(_calls_named(b, "emit_vendor_rated") for b in n.body)
        ]
        assert guarded, f"{path}: the emit is not guarded on a rating change"


# ── evidence objects (graph) and evidence records (20x) ────────────────────────


async def test_evidence_object_create_and_status_changes_reach_the_graph() -> None:
    org_id, system_id = await _system()
    jm, em = await _marks()
    async with session_scope() as s:
        obj = await evidence_service.create_object(
            s, org_id=org_id, title="MFA config", system_id=system_id
        )
        obj.current_version_id = None
        await evidence_service.add_version(s, obj, data=b"v1", uploaded_by="a")
        await evidence_service.submit_object(s, obj)
        await evidence_service.submit_object(s, obj)  # already submitted: no change
        await evidence_service.review_object(s, obj, decision="approved", reviewer="b")
    evs = await _events(em, "evidence_object")
    assert [(e.verb, e.payload["status"]) for e in evs] == [
        ("created", "draft"),
        ("updated", "submitted"),
        ("updated", "approved"),
    ]
    assert all(e.organization_id == org_id for e in evs)
    assert ("assurance_graph", f"org:{org_id}") in await _jobs(jm)


async def _implementation(system_id: int) -> int:
    async with session_scope() as s:
        ctrl = (
            await s.execute(select(Control).where(Control.identifier == "AC-2"))
        ).scalar_one_or_none()
        if ctrl is None:
            ctrl = Control(identifier="AC-2", control_name="Account Management")
            s.add(ctrl)
            await s.flush()
        impl = ControlImplementation(system_id=system_id, control_id=ctrl.id, status="planned")
        s.add(impl)
        await s.flush()
        return impl.id


async def test_evidence_records_reach_20x_on_create_and_delete() -> None:
    org_id, system_id = await _system(twentyx=True)
    impl_id = await _implementation(system_id)
    jm, em = await _marks()
    async with _Client(org_id)() as c:
        r = await c.post(
            "/api/evidence",
            json={"implementation_id": impl_id, "kind": "document", "title": "Policy"},
        )
        assert r.status_code == 201, r.text
        eid = r.json()["id"]
        assert (await c.delete(f"/api/evidence/{eid}")).status_code == 204
    evs = await _events(em, "evidence")
    assert [e.verb for e in evs] == ["captured", "deleted"]
    assert all(e.organization_id == org_id and e.payload["system_id"] == system_id for e in evs)
    assert ("fedramp20x", f"system:{system_id}") in await _jobs(jm)


async def test_capability_evidence_enters_no_view_and_emits_nothing() -> None:
    org_id, _ = await _system()
    async with session_scope() as s:
        cap = Capability(organization_id=org_id, key=f"c-{_tag()}", title="C", status="planned")
        s.add(cap)
        await s.flush()
        ev = Evidence(capability_id=cap.id, kind="document", title="shared")
        s.add(ev)
        await s.flush()
        _, em = await _marks()
        await evidence_routes._emit_evidence(s, ev, verb="captured", actor=None)
    assert await _events(em, "evidence") == []


# ── waivers (20x readiness) ────────────────────────────────────────────────────


async def _waiver(org_id: int, system_id: int, **kw: Any) -> int:
    async with session_scope() as s:
        w = Waiver(
            organization_id=org_id,
            system_id=system_id,
            check_key=f"chk-{_tag()}",
            rationale="accepted",
            status=kw.get("status", "requested"),
            requested_by="requester@acme.gov",
            expires_on=kw.get("expires_on"),
        )
        s.add(w)
        await s.flush()
        return w.id


def _approver(org_id: int) -> Principal:
    return Principal(user_id=2, email="ao@acme.gov", org_id=org_id, role="admin")


async def test_a_waiver_entering_or_leaving_force_reaches_20x() -> None:
    org_id, system_id = await _system(twentyx=True)
    wid = await _waiver(org_id, system_id)
    jm, em = await _marks()
    async with session_scope() as s:
        await waivers.approve_waiver(wid, s, _approver(org_id))
    assert ("fedramp20x", f"system:{system_id}") in await _jobs(jm)  # each, on its own
    jm2, _ = await _marks()
    async with session_scope() as s:
        await waivers.revoke_waiver(wid, s, _approver(org_id))
    assert ("fedramp20x", f"system:{system_id}") in await _jobs(jm2)
    evs = await _events(em, "waiver")
    assert [e.verb for e in evs] == ["approved", "revoked"]
    assert all(e.organization_id == org_id and e.payload["system_id"] == system_id for e in evs)


async def test_a_waiver_that_never_was_in_force_emits_nothing() -> None:
    org_id, system_id = await _system(twentyx=True)
    requested = await _waiver(org_id, system_id)
    lapsed = await _waiver(org_id, system_id, expires_on=date.today() - timedelta(days=1))
    _, em = await _marks()
    async with session_scope() as s:
        await waivers.revoke_waiver(requested, s, _approver(org_id))  # a request, revoked
    async with session_scope() as s:
        await waivers.approve_waiver(lapsed, s, _approver(org_id))  # approved already lapsed
    assert await _events(em, "waiver") == []


# ── components (capability derivation) ─────────────────────────────────────────


async def _component(org_id: int, system_id: int, *, bound: bool) -> int:
    async with session_scope() as s:
        comp = SystemComponent(
            organization_id=org_id, system_id=system_id, type="software", title="IdP"
        )
        s.add(comp)
        await s.flush()
        if bound:
            cap = Capability(organization_id=org_id, key=f"c-{_tag()}", title="C", status="planned")
            s.add(cap)
            await s.flush()
            s.add(
                CapabilityComponent(
                    organization_id=org_id, capability_id=cap.id, component_id=comp.id
                )
            )
        return comp.id


async def test_deleting_a_bound_component_rederives_its_system() -> None:
    org_id, system_id = await _system()
    bound = await _component(org_id, system_id, bound=True)
    loose = await _component(org_id, system_id, bound=False)
    jm, em = await _marks()
    async with session_scope() as s:
        await boundary.delete_component(s, component_id=loose)
    assert await _events(em, "system_component") == []  # unbound: no view reads it
    async with session_scope() as s:
        await boundary.delete_component(s, component_id=bound, actor="isso@acme.gov")
    (ev,) = await _events(em, "system_component", "deleted")
    assert ev.organization_id == org_id and ev.payload["system_id"] == system_id
    jobs = await _jobs(jm)
    assert ("capability_derive", f"system:{system_id}") in jobs
    assert ("assurance_graph", f"org:{org_id}") in jobs


# ── connector capture (20x) ────────────────────────────────────────────────────


class _Cap(SimpleNamespace):
    pass


async def test_a_first_time_capture_reaches_each_systems_20x_and_a_repeat_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, sys_a = await _system(twentyx=True)
    async with session_scope() as s:
        other = System(organization_id=org_id, name=f"sys-{_tag()}")
        s.add(other)
        await s.flush()
        sys_b = other.id
    caps = [_Cap(odp_key=f"k-{_tag()}", value="on", nist_id="IA-2")]

    class _Conn:
        key = f"fake{_tag()}"
        label = "Fake"

        def is_configured(self) -> bool:
            return True

        async def capture(self) -> list[Any]:
            return caps

    conn = _Conn()

    async def _cred(session: Any, org: int, key: str) -> dict[str, Any]:
        return {}

    monkeypatch.setattr(collection, "connector_keys", lambda: [conn.key])
    monkeypatch.setattr(collection, "resolve_credential", _cred)
    monkeypatch.setattr(collection, "get_connector", lambda key, credential=None: conn)

    jm, em = await _marks()
    async with session_scope() as s:
        await collection.collect_for_org(s, org_id)
    evs = await _events(em, "capture_snapshot", "created")
    assert sorted(e.payload["system_id"] for e in evs) == sorted([sys_a, sys_b])
    assert all(e.organization_id == org_id for e in evs)
    jobs = await _jobs(jm)
    assert {("fedramp20x", f"system:{sys_a}"), ("fedramp20x", f"system:{sys_b}")} <= jobs

    _, em = await _marks()
    caps[0].value = "off"  # the same key with a new value: validation reads presence only
    async with session_scope() as s:
        await collection.collect_for_org(s, org_id)
    assert await _events(em, "capture_snapshot") == []


# ── authorization packages ─────────────────────────────────────────────────────


def test_a_package_decision_that_moves_ato_status_reaches_the_graph() -> None:
    graph = derived.ASSURANCE_GRAPH_TRIGGERS
    for action, rule in TRANSITIONS.items():
        moves = action == "submit" or rule.authorizes or rule.target in ("returned", "denied")
        assert (("authorization_package", f"package_{action}") in graph) is moves, action
