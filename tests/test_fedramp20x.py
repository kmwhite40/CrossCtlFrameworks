"""FedRAMP 20x — unit tests (pure engines) + integration tests (DB + API)."""

from __future__ import annotations

from datetime import date
from types import SimpleNamespace as N

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, update

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.fedramp20x import catalog, monitoring, package, readiness, validation
from ccf.fedramp20x.readiness import compute_readiness
from ccf.fedramp20x.validation import SystemContext, evaluate_rule, normalize_control
from ccf.models import (
    KSI,
    Control,
    ControlImplementation,
    Event,
    FedRAMPDependency,
    KSIState,
    Organization,
    System,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


# --- pure unit tests --------------------------------------------------------


def test_normalize_control_variants() -> None:
    assert normalize_control("AC-06") == "AC-6"
    assert normalize_control("AC-6(1)") == "AC-6"
    assert normalize_control("ac-2") == "AC-2"
    assert normalize_control("SC-7") == "SC-7"


def test_evaluate_control_state_pass_warn_fail() -> None:
    ksi = {"identifier": "KSI-X", "category": "IAM"}
    rule = {"kind": "control_state", "controls": ["IA-2", "AC-2"], "states": ["implemented"]}

    ctx = SystemContext(impl_status={"IA-2": "implemented", "AC-2": "implemented"})
    assert evaluate_rule(rule, ctx, ksi=ksi).status == "pass"

    ctx = SystemContext(impl_status={"IA-2": "implemented"})  # one missing
    assert evaluate_rule(rule, ctx, ksi=ksi).status == "warn"

    ctx = SystemContext(impl_status={})
    v = evaluate_rule(rule, ctx, ksi=ksi)
    assert v.status == "fail" and v.remediation_hint


def test_evaluate_dependency_and_manual() -> None:
    ksi = {"identifier": "KSI-TPR-01", "category": "TPR"}
    # No deps -> manual review required.
    v = evaluate_rule({"kind": "dependency_authorized"}, SystemContext(), ksi=ksi)
    assert v.status == "manual_review_required" and v.assessor_review_required

    ctx = SystemContext(dependencies=[{"name": "S3", "fedramp_status": "authorized"}])
    assert evaluate_rule({"kind": "dependency_authorized"}, ctx, ksi=ksi).status == "pass"

    ctx = SystemContext(dependencies=[{"name": "X", "fedramp_status": "unknown"}])
    assert evaluate_rule({"kind": "dependency_authorized"}, ctx, ksi=ksi).status == "fail"

    assert (
        evaluate_rule({"kind": "manual"}, SystemContext(), ksi=ksi).status
        == "manual_review_required"
    )


def test_compute_readiness_blend_and_status() -> None:
    ksis = [
        N(id=1, automation_level="automated", evidence_required=True),
        N(id=2, automation_level="manual", evidence_required=True),
    ]
    states = [
        N(ksi_id=1, status="pass", next_validation_due=date(2999, 1, 1)),
        N(ksi_id=2, status="fail", next_validation_due=date(2000, 1, 1)),
    ]
    r = compute_readiness(
        ksis=ksis,
        states=states,
        dependencies=[],
        reviews=[],
        open_exceptions=1,
        today=date(2026, 7, 2),
    )
    assert r.ksi_total == 2
    assert r.ksi_pass_rate == 50
    assert r.automation_coverage == 50
    assert r.high_risk_findings == 1  # one failing KSI
    assert r.expired_validations == 1  # one past-due
    assert r.open_exceptions == 1
    assert 0 <= r.readiness_pct <= 100
    assert r.status in {
        "initial_build",
        "evidence_collection",
        "validation_in_progress",
        "assessor_review",
    }


def test_readiness_not_started_when_empty() -> None:
    r = compute_readiness(
        ksis=[], states=[], dependencies=[], reviews=[], open_exceptions=0, today=date(2026, 7, 2)
    )
    assert r.status == "not_started"
    assert r.readiness_pct == 0


def test_oscal_shaped_and_markdown_render() -> None:
    pkg = {
        "system": {"id": 1, "name": "Demo"},
        "generated_at": "2026-07-02T00:00:00Z",
        "disclaimer": "foundation",
        "readiness": {
            "readiness_pct": 42,
            "status": "validation_in_progress",
            "ksi_pass_rate": 50,
            "automation_coverage": 30,
            "evidence_completeness": 20,
            "conmon_coverage": 10,
            "assessor_completion": 0,
            "dependency_readiness": 100,
            "open_exceptions": 0,
            "high_risk_findings": 1,
            "manual_review_burden": 2,
        },
        "cloud_service_offering": {
            "service_name": "Demo",
            "deployment_model": "saas",
            "cloud_environment": "azure_gov",
        },
        "ksis": [
            {
                "identifier": "KSI-IAM-01",
                "name": "MFA",
                "category": "IAM",
                "status": "pass",
                "automation_level": "automated",
                "nist_refs": ["IA-2"],
                "validation": {"evidence_refs": ["IA-2:implemented"]},
                "assessor_review": None,
            },
            {
                "identifier": "KSI-CNA-02",
                "name": "HA",
                "category": "CNA",
                "status": "fail",
                "automation_level": "manual",
                "nist_refs": ["CP-10"],
                "validation": {"failure_reason": "no CP-10"},
                "assessor_review": None,
            },
        ],
        "dependencies": [],
        "poams": [],
    }
    md = package.render_markdown(pkg)
    assert "FedRAMP 20x Package — Demo" in md and "KSI-IAM-01" in md
    oscal = package.to_oscal_shaped(pkg)
    ar = oscal["assessment-results"]
    assert ar["metadata"]["oscal-version"]
    result = ar["results"][0]
    assert len(result["observations"]) == 2
    assert len(result["findings"]) == 1  # only the failing KSI


# --- integration tests ------------------------------------------------------


async def _fresh_system(name: str = "Cso20x") -> int:
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == "Org20x"))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name="Org20x")
            s.add(org)
            await s.flush()
        sys = (
            await s.execute(
                select(System).where(System.organization_id == org.id, System.name == name)
            )
        ).scalar_one_or_none()
        if sys is None:
            sys = System(organization_id=org.id, name=name, baseline="moderate")
            s.add(sys)
            await s.flush()
        # An implemented IA-2 so KSI-IAM-01 (control_state IA-2) validates to pass.
        ctrl = (
            await s.execute(select(Control).where(Control.identifier == "IA-2"))
        ).scalar_one_or_none()
        if ctrl is None:
            ctrl = Control(identifier="IA-2", control_name="Identification and Authentication")
            s.add(ctrl)
            await s.flush()
        await s.execute(
            delete(ControlImplementation).where(ControlImplementation.system_id == sys.id)
        )
        await s.execute(delete(FedRAMPDependency).where(FedRAMPDependency.system_id == sys.id))
        s.add(ControlImplementation(system_id=sys.id, control_id=ctrl.id, status="implemented"))
        return sys.id


@pytest.mark.asyncio
async def test_seed_catalog_is_idempotent() -> None:
    async with session_scope() as s:
        first = await catalog.seed_ksis(s)
        assert first["created"] + first["updated"] == first["total"] > 0
    async with session_scope() as s:
        second = await catalog.seed_ksis(s)
        # Second run updates existing rows rather than creating duplicates.
        assert second["created"] == 0
        assert second["total"] == first["total"]
        rows = (await s.execute(select(KSI))).scalars().all()
        assert len(rows) == first["total"]


@pytest.mark.asyncio
async def test_validate_and_score_via_service() -> None:
    async with session_scope() as s:
        await catalog.seed_ksis(s)
    sid = await _fresh_system()
    async with session_scope() as s:
        results = await validation.validate_system(s, system_id=sid)
        assert results, "expected one result per KSI"
        by_id = {r["ksi_identifier"]: r for r in results}
        # IA-2 implemented -> KSI-IAM-01 passes.
        assert by_id["KSI-IAM-01"]["validation_status"] == "pass"
        # A manual KSI requires assessor review.
        assert by_id["KSI-CNA-02"]["assessor_review_required"] is True

        score = await readiness.score_system(s, system_id=sid, persist=True)
        assert 0 <= score["readiness_pct"] <= 100
        assert score["ksi_pass_rate"] is not None
        # KSIState rows were created for every KSI.
        states = (
            (await s.execute(select(KSIState).where(KSIState.system_id == sid))).scalars().all()
        )
        assert len(states) == len(results)


@pytest.mark.asyncio
async def test_api_flow_end_to_end() -> None:
    async with _client() as c:
        seed = await c.post("/api/fedramp/20x/ksis/seed")
        assert seed.status_code == 200 and seed.json()["total"] > 0

        ksis = (await c.get("/api/fedramp/20x/ksis")).json()
        assert any(k["identifier"] == "KSI-IAM-01" for k in ksis)
        one = (await c.get("/api/fedramp/20x/ksis/KSI-IAM-01")).json()
        assert one["nist_refs"]

        sid = await _fresh_system("ApiCso")

        # Add a dependency, then list with buckets.
        r = await c.post(
            f"/api/fedramp/20x/systems/{sid}/dependencies",
            json={"name": "Blob Storage", "provider": "Azure", "fedramp_status": "authorized"},
        )
        assert r.status_code == 201
        deps = (await c.get(f"/api/fedramp/20x/systems/{sid}/dependencies")).json()
        assert deps["by_status"]["authorized"] == 1

        # Validate -> readiness returned + history recorded.
        v = await c.post(f"/api/fedramp/20x/systems/{sid}/validate")
        assert v.status_code == 200
        assert v.json()["readiness"]["ksi_pass_rate"] is not None
        hist = (await c.get(f"/api/fedramp/20x/systems/{sid}/validations")).json()
        assert len(hist) >= 1

        # Package export in three formats.
        js = await c.get(f"/api/fedramp/20x/systems/{sid}/package")
        assert js.status_code == 200 and "ksis" in js.json()
        md = await c.get(f"/api/fedramp/20x/systems/{sid}/package?format=markdown")
        assert "FedRAMP 20x Package" in md.text
        oscal = await c.get(f"/api/fedramp/20x/systems/{sid}/package?format=oscal")
        assert "assessment-results" in oscal.json()

        # Assessor review creates a record and reflects on state.
        ksi_id = one["id"]
        rv = await c.post(
            "/api/fedramp/20x/assessor-reviews",
            json={"system_id": sid, "ksi_id": ksi_id, "status": "accepted", "assessor": "3PAO"},
        )
        assert rv.status_code == 201
        patched = await c.patch(
            f"/api/fedramp/20x/assessor-reviews/{rv.json()['id']}",
            json={"status": "closed"},
        )
        assert patched.status_code == 200 and patched.json()["status"] == "closed"


@pytest.mark.asyncio
async def test_continuous_monitoring_detects_drift() -> None:
    async with session_scope() as s:
        await catalog.seed_ksis(s)
    sid = await _fresh_system("MonCso")

    # A system enters continuous monitoring once it has KSI state — validate once.
    async with session_scope() as s:
        await validation.validate_system(s, system_id=sid)

    # A clean sweep with the control still implemented shows no regression.
    async with session_scope() as s:
        row = next(r for r in (await monitoring.scan(s))["systems"] if r["system_id"] == sid)
        assert row["regressions"] == 0

    # Regress the supporting control, then the next sweep must flag drift + emit an event.
    async with session_scope() as s:
        await s.execute(
            update(ControlImplementation)
            .where(ControlImplementation.system_id == sid)
            .values(status="not_implemented")
        )
    async with session_scope() as s:
        mine = next(r for r in (await monitoring.scan(s))["systems"] if r["system_id"] == sid)
        assert mine["regressions"] >= 1
    async with session_scope() as s:
        drift = (
            (
                await s.execute(
                    select(Event).where(Event.entity_type == "system", Event.verb == "drift")
                )
            )
            .scalars()
            .all()
        )
        assert any(str(sid) == e.entity_id for e in drift)


@pytest.mark.asyncio
async def test_dependency_context_flows_into_validation() -> None:
    async with session_scope() as s:
        await catalog.seed_ksis(s)
    sid = await _fresh_system("DepCso")
    async with session_scope() as s:
        s.add(FedRAMPDependency(system_id=sid, name="RDS", fedramp_status="not_authorized"))
    async with session_scope() as s:
        results = {
            r["ksi_identifier"]: r for r in await validation.validate_system(s, system_id=sid)
        }
        # A non-authorized dependency fails the dependency KSI.
        assert results["KSI-TPR-01"]["validation_status"] == "fail"
