"""Workstream B -- risk: five-point scale, appetite, KRIs, registers, assessments, treatment.

Spec: ``docs/superpowers/specs/2026-10-20-grc-buildout-design.md`` ("B — risk"
and "B — risk, extended").

Properties, each the shape of a defect this platform has shipped before:

* **Tenant isolation is in the query.** Two organizations, each with a risk on
  a live system, an enterprise (system-less) risk, a risk on a soft-deleted
  system, an appetite statement, a KRI, an assessment and a treatment plan,
  each named ``<Label>-<kind>-<tag>``. Pages are driven through the real auth
  gate on an RLS-bypass session (``_unscoped_session``), so only the code's own
  predicate can keep Bravo's rows off Alpha's page; each page must show
  Alpha's record **and** never Bravo's or the deleted system's.
* **Writes are gated**: a viewer and a role outside each gate get 403; the
  permitted role succeeds; an id belonging to the other organization is 404.
* **A ratio over nothing is None**; a computed KRI with nothing to compute
  over records no reading.
"""

from __future__ import annotations

import itertools
import os
from datetime import UTC, date, datetime, timedelta
from urllib.parse import unquote

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from ccf.analytics.command_center import risk_matrix
from ccf.api.deps import get_session
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.governance import kri as kri_engine
from ccf.governance import risk as rk
from ccf.models import POAM, AuditLog, Organization, Risk, System, User
from ccf.models_evidence import EvidenceObject
from ccf.models_program import (
    KeyRiskIndicator,
    KriReading,
    RiskAppetite,
    RiskAssessment,
    RiskTreatmentAction,
    RiskTreatmentPlan,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
ROLES = ("admin", "control_owner", "assessor", "viewer")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _unscoped_session():
    """RLS tenant cleared: only the code's own org predicate can scope a page."""
    factory = get_session_factory()
    async with factory() as session:
        await set_session_tenant(session, None)
        yield session


def _client() -> AsyncClient:
    app = create_app()
    app.dependency_overrides[get_session] = _unscoped_session
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _org(label: str, tag: str) -> dict[str, object]:
    """One organization with one record of every kind this workstream reads.

    Every reference is same-organization (migration 0101 refuses any other)."""
    today = date.today()
    m = lambda kind: f"{label}-{kind}-{tag}"  # noqa: E731
    async with session_scope() as s:
        org = Organization(name=m("org"))
        s.add(org)
        await s.flush()
        users = {
            role: User(
                email=f"{label.lower()}-{role}-{tag}@rp.test",
                full_name=m(f"user-{role}"),
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            for role in ROLES
        }
        live = System(organization_id=org.id, name=m("system"), baseline="moderate")
        gone = System(
            organization_id=org.id,
            name=f"{label}-DELETED-system-{tag}",
            baseline="moderate",
            deleted_at=datetime.now(UTC),
        )
        s.add_all([*users.values(), live, gone])
        await s.flush()
        cyber = Risk(
            system_id=live.id,
            organization_id=org.id,
            register="cyber",
            title=m("risk"),
            category="technical",
            likelihood="high",
            impact="moderate",
            likelihood_score=4,
            impact_score=3,
            status="open",
            inherent_score=12,
            residual_score=12,
            treatment="accept",
        )
        enterprise = Risk(
            system_id=None,
            organization_id=org.id,
            register="enterprise",
            title=m("enterprise-risk"),
            category="strategic",
            likelihood="moderate",
            impact="high",
            likelihood_score=3,
            impact_score=5,
            status="open",
            inherent_score=15,
            residual_score=15,
            treatment="accept",
        )
        deleted_risk = Risk(
            system_id=gone.id,
            title=f"{label}-DELETED-risk-{tag}",
            category="technical",
            likelihood="high",
            impact="high",
            likelihood_score=5,
            impact_score=5,
            status="open",
            inherent_score=25,
            residual_score=25,
        )
        poam = POAM(
            system_id=live.id,
            title=m("poam"),
            severity="high",
            status="open",
            identified_on=today - timedelta(days=10),
            due_on=today - timedelta(days=1),
        )
        gone_poam = POAM(
            system_id=gone.id,
            title=f"{label}-DELETED-poam-{tag}",
            severity="critical",
            status="open",
            identified_on=today,
        )
        s.add_all([cyber, enterprise, deleted_risk, poam, gone_poam])
        await s.flush()
        appetite = RiskAppetite(
            organization_id=org.id,
            category=None,
            statement=m("appetite"),
            max_residual_score=10,
        )
        kri = KeyRiskIndicator(
            organization_id=org.id,
            name=m("kri"),
            direction="higher_is_worse",
            warn_threshold=5,
            critical_threshold=10,
            risk_id=cyber.id,
        )
        assessment = RiskAssessment(
            organization_id=org.id,
            risk_id=enterprise.id,
            assessed_on=today - timedelta(days=5),
            method="quantitative",
            sle=1000.0,
            aro=0.5,
            ale=500.0,
            assessor="seed",
            notes=m("assessment"),
        )
        plan = RiskTreatmentPlan(
            organization_id=org.id,
            risk_id=cyber.id,
            strategy="mitigate",
            description=m("plan"),
            status="planned",
        )
        expired = EvidenceObject(
            organization_id=org.id,
            title=m("evidence"),
            source_type="upload",
            status="approved",
            expires_on=today - timedelta(days=3),
        )
        # A plan on the deleted system's risk: it must surface nowhere.
        gone_plan = RiskTreatmentPlan(
            organization_id=org.id,
            risk_id=deleted_risk.id,
            strategy="avoid",
            description=f"{label}-DELETED-plan-{tag}",
            status="planned",
        )
        s.add_all([appetite, kri, assessment, plan, expired, gone_plan])
        if label == "Bravo":
            # Only Bravo has a 'strategic' statement, and a lenient one: were it
            # to leak into Alpha's rules, Alpha's strategic risk would read as
            # within appetite, and Alpha could not create its own.
            s.add(
                RiskAppetite(
                    organization_id=org.id,
                    category="strategic",
                    statement=m("strategic-appetite"),
                    max_residual_score=25,
                )
            )
        await s.flush()
        action = RiskTreatmentAction(
            organization_id=org.id, plan_id=plan.id, description=m("action"), status="open"
        )
        s.add(action)
        await s.flush()
        return {
            "org_id": org.id,
            "tag": tag,
            "label": label,
            "tokens": {role: u.api_token for role, u in users.items()},
            "user_ids": {role: u.id for role, u in users.items()},
            "system_id": live.id,
            "gone_system_id": gone.id,
            "risk_id": cyber.id,
            "enterprise_risk_id": enterprise.id,
            "deleted_risk_id": deleted_risk.id,
            "poam_id": poam.id,
            "gone_poam_id": gone_poam.id,
            "appetite_id": appetite.id,
            "kri_id": kri.id,
            "plan_id": plan.id,
            "gone_plan_id": gone_plan.id,
            "action_id": action.id,
        }


@pytest.fixture
async def two_orgs() -> tuple[dict[str, object], dict[str, object]]:
    # "rp": other modules build Alpha/Bravo scenes with the same counter and pid.
    tag = f"rp{next(_SEQ)}x{os.getpid()}"
    return await _org("Alpha", tag), await _org("Bravo", tag)


def _tok(o: dict[str, object], role: str) -> dict[str, str]:
    return _auth(o["tokens"][role])  # type: ignore[index]


# ── the pure rules ───────────────────────────────────────────────────────────


def test_scores_and_levels_stay_in_step() -> None:
    assert [rk.score_to_level(n) for n in rk.SCALE] == ["low", "low", "moderate", "high", "high"]
    assert rk.to_score("high") == 5 and rk.to_score(4) == 4
    assert rk.to_score(True) is None and rk.to_score(6) is None
    # A score wins and sets the level; a disagreeing pair is refused.
    assert rk.resolve_axis(axis="likelihood", score=4, level=None) == (4, "high")
    with pytest.raises(rk.AxisConflict):
        rk.resolve_axis(axis="likelihood", score=4, level="low")
    # A level alone keeps a current score already in that level ...
    assert rk.resolve_axis(axis="impact", score=None, level="high", current_score=4) == (4, "high")
    # ... and otherwise stands for 1/3/5.
    assert rk.resolve_axis(axis="impact", score=None, level="low", current_score=4) == (1, "low")
    assert rk.compute_scores(4, 3, "mitigate") == (12, 5)
    assert rk.compute_scores("high", "high", "mitigate") == (25, 10)  # unchanged from levels


def test_appetite_matching_and_placement() -> None:
    rules = [rk.AppetiteRule(1, None, 10), rk.AppetiteRule(2, "Technical", 6)]
    assert rk.appetite_for(" technical ", rules).id == 2
    assert rk.appetite_for("strategic", rules).id == 1
    assert rk.appetite_for(None, rules).id == 1
    assert rk.appetite_for("x", [rk.AppetiteRule(2, "Technical", 6)]) is None
    assert rk.place(9, "technical", 7, rules).state == "breach"
    assert rk.place(9, "technical", 7, rules).over_by == 1
    assert rk.place(9, "technical", 6, rules).state == "within"  # at appetite is within
    assert rk.place(9, "technical", None, rules).state == "unscored"
    assert rk.place(9, "x", 20, [rk.AppetiteRule(2, "Technical", 6)]).state == "no_appetite"


def test_kri_status_respects_direction() -> None:
    s = kri_engine.status
    assert s(None, "higher_is_worse", 5, 10) == "no_reading"
    assert s(3, "higher_is_worse", None, None) == "no_threshold"
    assert s(4, "higher_is_worse", 5, 10) == "ok"
    assert s(5, "higher_is_worse", 5, 10) == "warn"
    assert s(10, "higher_is_worse", 5, 10) == "critical"
    assert s(80, "lower_is_worse", 70, 50) == "ok"
    assert s(70, "lower_is_worse", 70, 50) == "warn"
    assert s(40, "lower_is_worse", 70, 50) == "critical"
    assert kri_engine.threshold_problem("higher_is_worse", 10, 5)
    assert kri_engine.threshold_problem("lower_is_worse", 50, 70)
    assert kri_engine.threshold_problem("sideways", None, None)
    assert kri_engine.threshold_problem("lower_is_worse", 70, 50) is None


def test_ratios_over_nothing_are_none() -> None:
    assert rk.plan_progress(0, 0) is None
    assert rk.plan_progress(1, 4) == 25
    assert rk.ale(1000, None) is None
    assert rk.ale(1000.0, 0.25) == 250.0
    assert kri_engine.sparkline_points([3.0]) is None
    assert kri_engine.sparkline_points([2.0, 2.0]) == "0.0,14.0 120.0,14.0"


# ── the services, on an unscoped session ─────────────────────────────────────


async def test_the_matrix_is_five_by_five_and_scoped(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        await set_session_tenant(s, None)
        m = await risk_matrix(s, int(a["org_id"]))
    assert set(m["cells"]) == set(rk.SCALE) and all(
        set(r) == set(rk.SCALE) for r in m["cells"].values()
    )
    # Alpha's cyber risk (4x3) and enterprise risk (3x5); not the deleted
    # system's (5x5) and not Bravo's.
    assert m["total"] == 2
    assert m["cells"][4][3] == 1 and m["cells"][3][5] == 1 and m["cells"][5][5] == 0
    assert sum(sum(r.values()) for r in m["cells"].values()) + m["unplaced"] == m["total"]


async def test_appetite_breaches_are_the_orgs_own(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        await set_session_tenant(s, None)
        placements = await rk.appetite_placements(s, int(a["org_id"]))
    # Default appetite 10: the cyber risk (12) and enterprise risk (15) breach;
    # the deleted system's risk (25) is not Alpha's to count.
    assert set(placements) == {a["risk_id"], a["enterprise_risk_id"]}
    assert all(p.state == "breach" for p in placements.values())


async def test_computed_readings_count_only_the_orgs_live_records(two_orgs) -> None:
    a, b = two_orgs
    async with session_scope() as s:
        await set_session_tenant(s, None)
        kri = KeyRiskIndicator(
            organization_id=int(a["org_id"]), name="ccx", metric_key="poams_open_critical_high"
        )
        ratio = KeyRiskIndicator(
            organization_id=int(a["org_id"]), name="ratio", metric_key="controls_passing_pct"
        )
        above = KeyRiskIndicator(
            organization_id=int(a["org_id"]), name="above", metric_key="risks_above_appetite"
        )
        expired = KeyRiskIndicator(
            organization_id=int(a["org_id"]), name="exp", metric_key="evidence_expired"
        )
        s.add_all([kri, ratio, above, expired])
        await s.flush()
        out = await kri_engine.record_computed_readings(s, int(a["org_id"]), date.today())
        values = {r["kri_id"]: r["value"] for r in out["recorded"]}
        # One high open POA&M on the live system; the deleted system's
        # critical one and Bravo's are not counted.
        assert values[kri.id] == 1.0
        assert values[above.id] == 2.0
        assert values[expired.id] == 1.0  # Alpha's one expired item; not Bravo's
        # No control has a test result: the ratio has no value and no reading.
        assert ratio.id not in values
        assert any(x["kri_id"] == ratio.id for x in out["skipped"])
        # Bravo's KRIs were not touched.
        n_b = (
            await s.execute(
                select(func.count())
                .select_from(KriReading)
                .where(KriReading.organization_id == int(b["org_id"]))
            )
        ).scalar_one()
        assert n_b == 0


# ── pages: isolation through the real gate ───────────────────────────────────

PAGES = (
    "/risks",
    "/risks?register=enterprise",
    "/risks?register=cyber",
    "/risks/heatmap",
    "/risk-appetite",
    "/kri",
    "/risks/assessments",
    "/risks/treatment",
    "/dashboard",
)


@pytest.mark.parametrize("path", PAGES)
async def test_no_page_shows_another_organizations_or_a_deleted_systems_risk(
    two_orgs, path: str
) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.get(path, headers=_tok(a, "viewer"))
    assert resp.status_code == 200, resp.text[:400]
    assert "Bravo" not in resp.text, f"{path} shows Bravo's records to Alpha"
    assert "DELETED" not in resp.text, f"{path} shows a soft-deleted system's records"


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("/risks", "risk"),
        ("/risks", "enterprise-risk"),
        ("/risks?register=enterprise", "enterprise-risk"),
        ("/risks?register=cyber", "risk"),
        ("/risks/heatmap", "risk"),
        ("/risks/heatmap", "enterprise-risk"),
        ("/risk-appetite", "appetite"),
        ("/risk-appetite", "enterprise-risk"),
        ("/kri", "kri"),
        ("/risks/assessments", "enterprise-risk"),
        ("/risks/treatment", "risk"),
    ],
)
async def test_each_page_shows_its_own_organizations_record(two_orgs, path: str, kind: str) -> None:
    a, _ = two_orgs
    async with _client() as c:
        body = (await c.get(path, headers=_tok(a, "viewer"))).text
    assert f"Alpha-{kind}-{a['tag']}" in body, f"{path} does not show the caller's own {kind}"


async def test_registers_split_one_table(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        ent = (await c.get("/risks?register=enterprise", headers=_tok(a, "viewer"))).text
        cyb = (await c.get("/risks?register=cyber", headers=_tok(a, "viewer"))).text
    assert f"Alpha-risk-{a['tag']}<" not in ent and f"Alpha-enterprise-risk-{a['tag']}" in ent
    assert f"Alpha-enterprise-risk-{a['tag']}" not in cyb and f"Alpha-risk-{a['tag']}" in cyb


async def test_the_risk_detail_is_the_orgs_own(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        own = await c.get(f"/risks/{a['enterprise_risk_id']}", headers=_tok(a, "viewer"))
        other = await c.get(f"/risks/{b['enterprise_risk_id']}", headers=_tok(a, "viewer"))
        other_cyber = await c.get(f"/risks/{b['risk_id']}", headers=_tok(a, "viewer"))
        deleted = await c.get(f"/risks/{a['deleted_risk_id']}", headers=_tok(a, "viewer"))
        # The cyber risk has a plan, so its page offers POA&Ms to link.
        with_plan = await c.get(f"/risks/{a['risk_id']}", headers=_tok(a, "viewer"))
    assert own.status_code == 200 and f"Alpha-assessment-{a['tag']}" in own.text
    # Its owner and POA&M choices are Alpha's live ones only.
    assert "Bravo" not in own.text and "DELETED" not in own.text
    assert "500.00" in own.text  # the seeded ALE
    assert with_plan.status_code == 200 and f"Alpha-poam-{a['tag']}" in with_plan.text
    assert "Bravo" not in with_plan.text and "DELETED" not in with_plan.text
    assert other.status_code == 404 and other_cyber.status_code == 404
    assert deleted.status_code == 404


async def test_the_heat_map_drills_down_by_score_and_by_level(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        hit = (await c.get("/risks/heatmap?l=4&i=3", headers=_tok(a, "viewer"))).text
        miss = (await c.get("/risks/heatmap?l=3&i=3", headers=_tok(a, "viewer"))).text
        old = (
            await c.get("/risks/heatmap?likelihood=high&impact=moderate", headers=_tok(a, "viewer"))
        ).text
        junk = await c.get("/risks/heatmap?l=9&i=x", headers=_tok(a, "viewer"))
    assert f"Alpha-risk-{a['tag']}" in hit and f"Alpha-enterprise-risk-{a['tag']}" not in hit
    assert "No open risks sit in this cell." in miss
    assert f"Alpha-risk-{a['tag']}" in old
    assert junk.status_code == 200 and "All open risks" in junk.text
    assert 'href="/risks/heatmap?l=5&amp;i=5"' in hit  # the grid is 5x5


async def test_api_lists_enterprise_risks_and_never_others(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        listed = await c.get("/api/risks", headers=_tok(a, "viewer"))
        heat = await c.get("/api/risks/heatmap", headers=_tok(a, "viewer"))
        foreign = await c.get(f"/api/risks/{b['enterprise_risk_id']}", headers=_tok(a, "viewer"))
        gone = await c.get(f"/api/risks/{a['deleted_risk_id']}", headers=_tok(a, "viewer"))
    ids = {r["id"] for r in listed.json()}
    assert ids == {a["risk_id"], a["enterprise_risk_id"]}
    assert heat.json()["matrix_5x5"]["3"]["5"] == 1
    assert foreign.status_code == 404 and gone.status_code == 404


# ── the risk API: five-point input ───────────────────────────────────────────


async def test_api_accepts_either_form_and_keeps_them_in_step(two_orgs) -> None:
    a, _ = two_orgs
    h = _tok(a, "control_owner")
    async with _client() as c:
        by_score = await c.post(
            "/api/risks",
            json={
                "title": "s",
                "system_id": a["system_id"],
                "likelihood_score": 4,
                "impact_score": 2,
            },
            headers=h,
        )
        by_level = await c.post(
            "/api/risks",
            json={"title": "l", "system_id": a["system_id"], "likelihood": "moderate"},
            headers=h,
        )
        conflict = await c.post(
            "/api/risks",
            json={
                "title": "c",
                "system_id": a["system_id"],
                "likelihood": "low",
                "likelihood_score": 5,
            },
            headers=h,
        )
        out_of_range = await c.post(
            "/api/risks",
            json={"title": "o", "system_id": a["system_id"], "impact_score": 6},
            headers=h,
        )
        rid = by_score.json()["id"]
        resave = await c.patch(f"/api/risks/{rid}", json={"likelihood": "high"}, headers=h)
    assert by_score.status_code == 201, by_score.text
    j = by_score.json()
    assert (j["likelihood"], j["impact"], j["inherent_score"]) == ("high", "low", 8)
    assert by_level.json()["likelihood_score"] == 3
    assert conflict.status_code == 422 and out_of_range.status_code == 422
    assert resave.json()["likelihood_score"] == 4  # same band: the 4 is kept


async def test_an_enterprise_risk_is_owned_by_the_callers_org(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        made = await c.post("/api/risks", json={"title": "board"}, headers=_tok(a, "assessor"))
        naming_b = await c.post(
            "/api/risks",
            json={"title": "x", "organization_id": b["org_id"]},
            headers=_tok(a, "admin"),
        )
        on_b_system = await c.post(
            "/api/risks", json={"title": "x", "system_id": b["system_id"]}, headers=_tok(a, "admin")
        )
        on_deleted = await c.post(
            "/api/risks",
            json={"title": "x", "system_id": a["gone_system_id"]},
            headers=_tok(a, "admin"),
        )
        b_owner = await c.post(
            "/api/risks",
            json={"title": "x", "owner_user_id": b["user_ids"]["admin"]},
            headers=_tok(a, "admin"),
        )
        viewer = await c.post("/api/risks", json={"title": "v"}, headers=_tok(a, "viewer"))
        seen_by_b = await c.get(f"/api/risks/{made.json()['id']}", headers=_tok(b, "admin"))
    assert made.status_code == 201, made.text
    assert made.json()["organization_id"] == a["org_id"]
    assert made.json()["register"] == "enterprise" and made.json()["system_id"] is None
    assert naming_b.status_code == 403
    assert on_b_system.status_code == 404 and on_deleted.status_code == 404
    assert b_owner.status_code == 404
    assert viewer.status_code == 403
    assert seen_by_b.status_code == 404


# ── appetite: admin-only, one statement per category ─────────────────────────


async def test_appetite_writes_are_admin_only_and_scoped(two_orgs) -> None:
    a, b = two_orgs
    form = {"category": "Technical", "statement": "Low tolerance", "max_residual_score": "6"}
    async with _client() as c:
        for role in ("viewer", "control_owner", "assessor"):
            r = await c.post("/risk-appetite", data=form, headers=_tok(a, role))
            assert r.status_code == 403, role
        for role in ("control_owner", "assessor"):
            edit = await c.post(
                f"/risk-appetite/{a['appetite_id']}",
                data={"statement": "x", "max_residual_score": "25"},
                headers=_tok(a, role),
            )
            drop = await c.post(f"/risk-appetite/{a['appetite_id']}/delete", headers=_tok(a, role))
            assert edit.status_code == 403 and drop.status_code == 403, role
        ok = await c.post("/risk-appetite", data=form, headers=_tok(a, "admin"))
        # Only Bravo has a 'strategic' statement; Alpha may still make its own.
        strategic = await c.post(
            "/risk-appetite",
            data={"category": "Strategic", "statement": "Board view", "max_residual_score": "14"},
            headers=_tok(a, "admin"),
        )
        dup = await c.post(
            "/risk-appetite", data={**form, "category": " technical "}, headers=_tok(a, "admin")
        )
        dup_default = await c.post(
            "/risk-appetite",
            data={"statement": "again", "max_residual_score": "9"},
            headers=_tok(a, "admin"),
        )
        bad = await c.post(
            "/risk-appetite",
            data={**form, "category": "ops", "max_residual_score": "30"},
            headers=_tok(a, "admin"),
        )
        foreign_edit = await c.post(
            f"/risk-appetite/{b['appetite_id']}",
            data={"statement": "pwned", "max_residual_score": "25"},
            headers=_tok(a, "admin"),
        )
        foreign_delete = await c.post(
            f"/risk-appetite/{b['appetite_id']}/delete", headers=_tok(a, "admin")
        )
        foreign_owner = await c.post(
            "/risk-appetite",
            data={**form, "category": "people", "owner_user_id": str(b["user_ids"]["admin"])},
            headers=_tok(a, "admin"),
        )
        page = (await c.get("/risk-appetite", headers=_tok(a, "admin"))).text
    assert ok.status_code == 303 and "error" not in ok.headers["location"]
    assert "error" not in strategic.headers["location"]
    assert "error=" in dup.headers["location"] and "error=" in dup_default.headers["location"]
    assert "error=" in bad.headers["location"]
    assert foreign_edit.status_code == 404 and foreign_delete.status_code == 404
    assert foreign_owner.status_code == 404
    async with session_scope() as s:
        await set_session_tenant(s, None)
        mine = (
            (
                await s.execute(
                    select(RiskAppetite.category).where(RiskAppetite.organization_id == a["org_id"])
                )
            )
            .scalars()
            .all()
        )
        theirs = (
            await s.execute(select(RiskAppetite).where(RiskAppetite.id == b["appetite_id"]))
        ).scalar_one()
        events = (
            await s.execute(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.action == "risk_appetite_created",
                    AuditLog.organization_id == a["org_id"],
                )
            )
        ).scalar_one()
    assert sorted(mine, key=str) == sorted([None, "Strategic", "Technical"], key=str)
    assert theirs.statement == f"Bravo-appetite-{b['tag']}"
    assert events == 2  # one per statement created
    # The cyber risk (technical, residual 12) breaches its 6, the enterprise
    # risk (strategic, 15) Alpha's own strategic 14 -- not Bravo's 25.
    assert f'id="breach-{a["risk_id"]}"' in page
    assert f'id="breach-{a["enterprise_risk_id"]}"' in page
    assert 'chip chip--err">6<' in page and 'chip chip--err">1<' in page
    assert f'id="breach-{a["deleted_risk_id"]}"' not in page


# ── KRIs ─────────────────────────────────────────────────────────────────────


async def test_kri_writes_are_gated_and_scoped(two_orgs) -> None:
    a, b = two_orgs
    form = {
        "name": "Overdue",
        "metric_key": "poams_overdue",
        "warn_threshold": "1",
        "critical_threshold": "3",
    }
    async with _client() as c:
        for role in ("viewer", "assessor"):
            refused = [
                await c.post("/kri", data=form, headers=_tok(a, role)),
                await c.post(f"/kri/{a['kri_id']}", data={"name": "x"}, headers=_tok(a, role)),
                await c.post(f"/kri/{a['kri_id']}/compute", headers=_tok(a, role)),
                await c.post("/kri/compute", headers=_tok(a, role)),
            ]
            assert [r.status_code for r in refused] == [403] * 4, role
        made = await c.post("/kri", data=form, headers=_tok(a, "control_owner"))
        backwards = await c.post(
            "/kri",
            data={**form, "warn_threshold": "5", "critical_threshold": "1"},
            headers=_tok(a, "admin"),
        )
        foreign_risk = await c.post(
            "/kri", data={"name": "x", "risk_id": str(b["risk_id"])}, headers=_tok(a, "admin")
        )
        deleted_risk = await c.post(
            "/kri",
            data={"name": "x", "risk_id": str(a["deleted_risk_id"])},
            headers=_tok(a, "admin"),
        )
        foreign_edit = await c.post(
            f"/kri/{b['kri_id']}", data={"name": "pwned"}, headers=_tok(a, "admin")
        )
        foreign_reading = await c.post(
            f"/kri/{b['kri_id']}/readings", data={"value": "1"}, headers=_tok(a, "admin")
        )
        foreign_compute = await c.post(f"/kri/{b['kri_id']}/compute", headers=_tok(a, "admin"))
        viewer_reading = await c.post(
            f"/kri/{a['kri_id']}/readings", data={"value": "7"}, headers=_tok(a, "viewer")
        )
        reading = await c.post(
            f"/kri/{a['kri_id']}/readings", data={"value": "7"}, headers=_tok(a, "assessor")
        )
        computed = await c.post("/kri/compute", headers=_tok(a, "control_owner"))
        page = (await c.get("/kri", headers=_tok(a, "viewer"))).text
    assert made.status_code == 303 and "error" not in made.headers["location"]
    assert "error=" in backwards.headers["location"]
    assert foreign_risk.status_code == 404 and deleted_risk.status_code == 404
    assert foreign_edit.status_code == 404
    assert foreign_reading.status_code == 404 and foreign_compute.status_code == 404
    assert viewer_reading.status_code == 403
    assert reading.status_code == 303 and "error" not in reading.headers["location"]
    assert computed.status_code == 303
    assert "1 reading recorded" in unquote(computed.headers["location"])
    assert 'chip chip--warn">Warning<' in page  # 7 against warn 5 / critical 10
    async with session_scope() as s:
        await set_session_tenant(s, None)
        new = (
            await s.execute(
                select(KeyRiskIndicator).where(
                    KeyRiskIndicator.organization_id == a["org_id"],
                    KeyRiskIndicator.metric_key == "poams_overdue",
                )
            )
        ).scalar_one()
        value = (
            await s.execute(select(KriReading.value).where(KriReading.kri_id == new.id))
        ).scalar_one()
        b_kri = (
            await s.execute(select(KeyRiskIndicator).where(KeyRiskIndicator.id == b["kri_id"]))
        ).scalar_one()
    assert value == 1.0  # Alpha's one overdue POA&M on a live system
    assert b_kri.name == f"Bravo-kri-{b['tag']}"


async def test_a_computed_kri_takes_no_typed_value_and_a_manual_one_no_compute(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        k = KeyRiskIndicator(organization_id=int(a["org_id"]), name="c", metric_key="poams_overdue")
        s.add(k)
        await s.flush()
        kid = k.id
    async with _client() as c:
        typed = await c.post(f"/kri/{kid}/readings", data={"value": "0"}, headers=_tok(a, "admin"))
        manual = await c.post(f"/kri/{a['kri_id']}/compute", headers=_tok(a, "admin"))
    assert "error=" in typed.headers["location"]
    assert "error=" in manual.headers["location"]
    async with session_scope() as s:
        await set_session_tenant(s, None)
        n = (
            await s.execute(
                select(func.count()).select_from(KriReading).where(KriReading.kri_id == kid)
            )
        ).scalar_one()
    assert n == 0


# ── assessments ──────────────────────────────────────────────────────────────


async def test_an_assessment_sets_the_risks_scores_and_computes_ale(two_orgs) -> None:
    a, _ = two_orgs
    rid = a["risk_id"]
    async with _client() as c:
        viewer = await c.post(
            f"/risks/{rid}/assessments",
            data={"likelihood_score": "2", "impact_score": "2"},
            headers=_tok(a, "viewer"),
        )
        r = await c.post(
            f"/risks/{rid}/assessments",
            data={
                "likelihood_score": "2",
                "impact_score": "5",
                "sle": "20000",
                "aro": "0.1",
                "ale": "999999",
            },
            headers=_tok(a, "assessor"),
        )
        older = await c.post(
            f"/risks/{rid}/assessments",
            data={
                "assessed_on": (date.today() - timedelta(days=30)).isoformat(),
                "likelihood_score": "5",
                "impact_score": "5",
            },
            headers=_tok(a, "control_owner"),
        )
        half = await c.post(
            f"/risks/{rid}/assessments", data={"sle": "100"}, headers=_tok(a, "admin")
        )
        future = await c.post(
            f"/risks/{rid}/assessments",
            data={
                "assessed_on": (date.today() + timedelta(days=1)).isoformat(),
                "likelihood_score": "1",
                "impact_score": "1",
            },
            headers=_tok(a, "admin"),
        )
        quant = (await c.get("/risks/assessments", headers=_tok(a, "viewer"))).text
    assert viewer.status_code == 403
    assert r.status_code == 303 and "error" not in r.headers["location"]
    assert older.status_code == 303 and "error" not in older.headers["location"]
    assert "error=" in half.headers["location"] and "error=" in future.headers["location"]
    async with session_scope() as s:
        await set_session_tenant(s, None)
        risk = await s.get(Risk, rid)
        latest = (
            await s.execute(
                select(RiskAssessment)
                .where(RiskAssessment.risk_id == rid)
                .order_by(RiskAssessment.assessed_on.desc())
                .limit(1)
            )
        ).scalar_one()
    # The latest (today's) assessment sets 2 x 5, not the backdated 5 x 5.
    assert (risk.likelihood_score, risk.impact_score, risk.likelihood, risk.impact) == (
        2,
        5,
        "low",
        "high",
    )
    assert risk.inherent_score == 10
    assert latest.method == "both" and latest.ale == 2000.0  # computed, the form's ignored
    # Total ALE over the two risks with one: seeded 500 + 2000.
    assert "2,500.00" in quant


async def test_assessments_plans_and_actions_on_another_orgs_risk_are_404(two_orgs) -> None:
    a, b = two_orgs
    h = _tok(a, "admin")
    async with _client() as c:
        res = [
            await c.post(
                f"/risks/{b['risk_id']}/assessments",
                data={"likelihood_score": "1", "impact_score": "1"},
                headers=h,
            ),
            await c.post(
                f"/risks/{b['enterprise_risk_id']}/assessments",
                data={"likelihood_score": "1", "impact_score": "1"},
                headers=h,
            ),
            await c.post(
                f"/risks/{a['deleted_risk_id']}/assessments",
                data={"likelihood_score": "1", "impact_score": "1"},
                headers=h,
            ),
            await c.post(f"/risks/{b['risk_id']}/plans", data={"strategy": "avoid"}, headers=h),
            await c.post(f"/risks/plans/{b['plan_id']}", data={"strategy": "avoid"}, headers=h),
            await c.post(
                f"/risks/plans/{b['plan_id']}/actions", data={"description": "x"}, headers=h
            ),
            await c.post(f"/risks/actions/{b['action_id']}", data={"status": "done"}, headers=h),
            # A plan on Alpha's own soft-deleted system's risk is gone too.
            await c.post(
                f"/risks/plans/{a['gone_plan_id']}/actions", data={"description": "x"}, headers=h
            ),
            await c.post(
                f"/risks/plans/{a['gone_plan_id']}", data={"strategy": "accept"}, headers=h
            ),
        ]
    assert [r.status_code for r in res] == [404] * len(res)
    async with session_scope() as s:
        await set_session_tenant(s, None)
        action = await s.get(RiskTreatmentAction, b["action_id"])
        plan = await s.get(RiskTreatmentPlan, b["plan_id"])
        n = (
            await s.execute(
                select(func.count())
                .select_from(RiskAssessment)
                .where(RiskAssessment.risk_id.in_([b["risk_id"], b["enterprise_risk_id"]]))
            )
        ).scalar_one()
    assert action.status == "open" and plan.strategy == "mitigate"
    assert n == 1  # Bravo's seeded one only


# ── treatment plans ──────────────────────────────────────────────────────────


async def test_treatment_plans_link_only_the_orgs_live_poams(two_orgs) -> None:
    a, b = two_orgs
    pid = a["plan_id"]
    async with _client() as c:
        for role in ("viewer",):
            r = await c.post(
                f"/risks/{a['risk_id']}/plans", data={"strategy": "avoid"}, headers=_tok(a, role)
            )
            assert r.status_code == 403
        plan = await c.post(
            f"/risks/{a['enterprise_risk_id']}/plans",
            data={
                "strategy": "transfer",
                "owner_user_id": str(a["user_ids"]["control_owner"]),
                "target_residual_score": "6",
            },
            headers=_tok(a, "control_owner"),
        )
        bad_strategy = await c.post(
            f"/risks/{a['risk_id']}/plans", data={"strategy": "ignore"}, headers=_tok(a, "admin")
        )
        foreign_owner = await c.post(
            f"/risks/{a['risk_id']}/plans",
            data={"strategy": "avoid", "owner_user_id": str(b["user_ids"]["admin"])},
            headers=_tok(a, "admin"),
        )
        b_poam = await c.post(
            f"/risks/plans/{pid}/actions",
            data={"description": "x", "poam_id": str(b["poam_id"])},
            headers=_tok(a, "admin"),
        )
        gone_poam = await c.post(
            f"/risks/plans/{pid}/actions",
            data={"description": "x", "poam_id": str(a["gone_poam_id"])},
            headers=_tok(a, "admin"),
        )
        linked = await c.post(
            f"/risks/plans/{pid}/actions",
            data={"description": "Patch it", "poam_id": str(a["poam_id"])},
            headers=_tok(a, "assessor"),
        )
        done = await c.post(
            f"/risks/actions/{a['action_id']}", data={"status": "done"}, headers=_tok(a, "assessor")
        )
        relink_b = await c.post(
            f"/risks/actions/{a['action_id']}",
            data={"status": "done", "poam_id": str(b["poam_id"])},
            headers=_tok(a, "admin"),
        )
        page = (await c.get("/risks/treatment", headers=_tok(a, "viewer"))).text
    assert plan.status_code == 303 and "error" not in plan.headers["location"]
    assert "error=" in bad_strategy.headers["location"]
    assert foreign_owner.status_code == 404
    assert b_poam.status_code == 404 and gone_poam.status_code == 404
    assert linked.status_code == 303 and done.status_code == 303
    assert relink_b.status_code == 404
    async with session_scope() as s:
        await set_session_tenant(s, None)
        acts = (
            (await s.execute(select(RiskTreatmentAction).where(RiskTreatmentAction.plan_id == pid)))
            .scalars()
            .all()
        )
    assert sorted(x.status for x in acts) == ["done", "open"]
    assert {x.poam_id for x in acts} == {None, a["poam_id"]}
    # Progress: 1 of 2 actions done on the seeded plan; the new plan has none.
    assert "50%" in page and "(1 of 2)" in page and "(0 of 0)" in page


async def test_global_pages_render_without_an_organization() -> None:
    """Auth off: the SYSTEM principal has no organization. The pages say so
    rather than aggregate every tenant's statements and indicators."""
    os.environ["CCF_AUTH_ENABLED"] = "false"
    get_settings.cache_clear()
    async with _client() as c:
        for path in ("/kri", "/risk-appetite"):
            r = await c.get(path)
            assert r.status_code == 200 and "No organization" in r.text, path
        assert (await c.post("/kri", data={"name": "x"})).status_code == 400
