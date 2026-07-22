"""FedRAMP 20x — unit tests (pure engines) + integration tests (DB + API)."""

from __future__ import annotations

import io
import zipfile
from datetime import date
from types import SimpleNamespace as N

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from prometheus_client import REGISTRY
from sqlalchemy import delete, select, update

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.fedramp20x import (
    CR26_DISPLAY_LABELS,
    catalog,
    cr26_display_label,
    monitoring,
    package,
    readiness,
    validation,
)
from ccf.fedramp20x.readiness import compute_readiness
from ccf.fedramp20x.validation import SystemContext, evaluate_rule, normalize_control
from ccf.models import (
    KSI,
    CaptureSnapshot,
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


def test_cr26_display_label_mapping() -> None:
    """FR-14: the CR26 rename is a display-only mapping, not a value change."""
    assert cr26_display_label("authorized") == "Certified"
    assert cr26_display_label("continuous_monitoring") == "Ongoing Certification"
    # Values CR26 doesn't touch pass through unchanged.
    assert cr26_display_label("not_started") == "not_started"
    assert cr26_display_label("in_process") == "in_process"
    assert cr26_display_label(None) == ""
    assert set(CR26_DISPLAY_LABELS) == {"authorized", "continuous_monitoring"}


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


def test_docx_and_bundle_render() -> None:
    pkg = {
        "system": {"id": 1, "name": "Demo"},
        "generated_at": "2026-07-02T00:00:00Z",
        "disclaimer": "foundation",
        "readiness": {
            "readiness_pct": 42, "status": "validation_in_progress", "ksi_pass_rate": 50,
            "automation_coverage": 30, "evidence_completeness": 20, "conmon_coverage": 10,
            "assessor_completion": 0, "dependency_readiness": 100, "open_exceptions": 0,
            "high_risk_findings": 1, "manual_review_burden": 2,
        },
        "cloud_service_offering": None,
        "ksis": [
            {"identifier": "KSI-IAM-01", "name": "MFA", "category": "IAM", "status": "pass",
             "automation_level": "automated", "nist_refs": ["IA-2"],
             "validation": {"evidence_refs": ["IA-2:implemented"]}, "assessor_review": None},
        ],
        "dependencies": [{"name": "Blob", "provider": "Azure", "fedramp_status": "authorized",
                          "dependency_risk": "low"}],
        "poams": [],
    }
    docx = package.to_docx(pkg)
    assert docx[:2] == b"PK" and len(docx) > 1000  # zip-based OOXML

    bundle = package.to_bundle(pkg)
    with zipfile.ZipFile(io.BytesIO(bundle)) as z:
        names = set(z.namelist())
    assert {"package.json", "package.md", "oscal.json", "evidence-manifest.json"} <= names
    assert package.evidence_manifest(pkg) == [
        {"ksi": "KSI-IAM-01", "evidence_ref": "IA-2:implemented"}
    ]


def test_validate_oscal_accepts_valid_and_flags_broken() -> None:
    pkg = {
        "system": {"id": 1, "name": "Demo"},
        "generated_at": "2026-07-02T00:00:00Z",
        "disclaimer": "foundation",
        "readiness": {"readiness_pct": 0, "status": "not_started"},
        "ksis": [
            {"identifier": "KSI-IAM-01", "name": "MFA", "category": "IAM", "status": "fail",
             "automation_level": "automated", "nist_refs": ["IA-2"],
             "validation": {"failure_reason": "x"}, "assessor_review": None},
        ],
        "dependencies": [],
    }
    good = package.to_oscal_shaped(pkg)
    assert package.validate_oscal(good) == []
    # jsonschema is a core dependency, so schema-mode validation is the active path.
    assert package.validation_mode() == "jsonschema"

    # Break required structure: drop metadata + result uuid.
    del good["assessment-results"]["metadata"]
    good["assessment-results"]["results"][0].pop("uuid")
    errors = package.validate_oscal(good)
    assert any("metadata" in e for e in errors)
    assert any("uuid" in e for e in errors)
    # Wrong top-level shape.
    assert package.validate_oscal({"nope": 1})

    # The structural fallback agrees on a valid document (parity check).
    assert package._validate_oscal_structural(package.to_oscal_shaped(pkg)) == []


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
        # A manual KSI (CNA-06 high availability) requires assessor review.
        assert by_id["KSI-CNA-06"]["assessor_review_required"] is True

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
        # With structural validation requested, the OSCAL export passes + is flagged.
        validated = await c.get(
            f"/api/fedramp/20x/systems/{sid}/package?format=oscal&validate=true"
        )
        assert validated.status_code == 200
        assert validated.headers.get("X-OSCAL-Validation") == "structural-pass"
        # Binary exports: DOCX (OOXML) and a zip bundle with attachment headers.
        docx = await c.get(f"/api/fedramp/20x/systems/{sid}/package?format=docx")
        assert docx.status_code == 200 and docx.content[:2] == b"PK"
        assert "attachment" in docx.headers.get("content-disposition", "")
        bundle = await c.get(f"/api/fedramp/20x/systems/{sid}/package?format=bundle")
        assert bundle.status_code == 200 and bundle.headers["content-type"] == "application/zip"

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
async def test_fedramp20x_ui_pages_and_forms() -> None:
    async with _client() as c:
        await c.post("/api/fedramp/20x/ksis/seed")
        sid = await _fresh_system("UiCso")

        # The dashboard renders the catalog and, for a system, the readiness panel.
        page = await c.get(f"/fedramp20x?system_id={sid}")
        assert page.status_code == 200
        assert "Cloud Service Offering profile" in page.text
        assert "FedRAMP-authorized dependencies" in page.text
        assert "Assessor review" in page.text

        # Profile form persists (303 redirect back to the page).
        r = await c.post(
            f"/fedramp20x/{sid}/profile",
            data={"service_name": "UI CSO", "deployment_model": "saas"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        prof = (await c.get(f"/api/fedramp/20x/systems/{sid}/profile")).json()
        assert prof["service_name"] == "UI CSO" and prof["deployment_model"] == "saas"

        # Dependency add form persists.
        await c.post(
            f"/fedramp20x/{sid}/dependencies",
            data={"name": "UI Blob", "fedramp_status": "authorized"},
            follow_redirects=False,
        )
        deps = (await c.get(f"/api/fedramp/20x/systems/{sid}/dependencies")).json()
        assert any(d["name"] == "UI Blob" for d in deps["dependencies"])

        # Assessor review form records + reflects on KSI state.
        await c.post(f"/api/fedramp/20x/systems/{sid}/validate")
        ksi = (await c.get("/api/fedramp/20x/ksis/KSI-IAM-01")).json()
        await c.post(
            f"/fedramp20x/{sid}/assessor-review",
            data={"ksi_id": str(ksi["id"]), "status": "accepted", "assessor": "3PAO"},
            follow_redirects=False,
        )
        reviewed = await c.get(f"/fedramp20x?system_id={sid}")
        assert "accepted" in reviewed.text


@pytest.mark.asyncio
async def test_fedramp20x_cr26_display_labels() -> None:
    """FR-14: fedramp20x UI shows CR26 labels; stored enum values stay unchanged."""
    async with _client() as c:
        await c.post("/api/fedramp/20x/ksis/seed")
        sid = await _fresh_system("Cr26Cso")

        # profile.readiness_status flows straight through score_system's
        # "submitted" short-circuit (see readiness._derive_status), so this one
        # field drives both the readiness-panel status and the profile status
        # badge on the page.
        prof = await c.put(
            f"/api/fedramp/20x/systems/{sid}/profile",
            json={"readiness_status": "continuous_monitoring"},
        )
        assert prof.status_code == 200
        # Stored value is the raw enum, not the display label.
        assert prof.json()["readiness_status"] == "continuous_monitoring"

        dep = await c.post(
            f"/api/fedramp/20x/systems/{sid}/dependencies",
            json={"name": "CR26 Dep", "fedramp_status": "authorized"},
        )
        assert dep.status_code == 201
        assert dep.json()["fedramp_status"] == "authorized"  # stored value unchanged

        page = await c.get(f"/fedramp20x?system_id={sid}")
        assert page.status_code == 200
        assert "Ongoing Certification" in page.text  # readiness + profile status badges
        assert "Certified" in page.text  # dependency status badge
        # The raw stored value is still surfaced (as a tooltip) for continuity.
        assert 'title="Stored value: continuous_monitoring"' in page.text
        assert 'title="Stored value: authorized"' in page.text

        # Independent confirmation via the API/model layer that the readiness
        # status itself is still the unchanged enum value, not the label.
        readiness_json = (await c.get(f"/api/fedramp/20x/systems/{sid}/readiness")).json()
        assert readiness_json["status"] == "continuous_monitoring"


@pytest.mark.asyncio
async def test_exceptions_traceability_and_findings_poam() -> None:
    async with _client() as c:
        await c.post("/api/fedramp/20x/ksis/seed")
        sid = await _fresh_system("BatchCso")
        ksi = (await c.get("/api/fedramp/20x/ksis/KSI-IAM-01")).json()

        # KSI exception CRUD.
        exc = await c.post(
            "/api/fedramp/20x/exceptions",
            json={"system_id": sid, "ksi_id": ksi["id"], "rationale": "compensating control"},
        )
        assert exc.status_code == 201
        listed = (await c.get(f"/api/fedramp/20x/systems/{sid}/exceptions")).json()
        assert any(e["rationale"] == "compensating control" for e in listed)
        patched = await c.patch(
            f"/api/fedramp/20x/exceptions/{exc.json()['id']}", json={"status": "accepted"}
        )
        assert patched.json()["status"] == "accepted"

        # Reverse traceability: IA-2 supports KSI-IAM-01.
        trace = (await c.get("/api/fedramp/20x/controls/IA-2/ksis")).json()
        assert any(k["identifier"] == "KSI-IAM-01" for k in trace["ksis"])

        # Assessor "finding_opened" auto-opens a POA&M; list endpoint returns history.
        await c.post(f"/api/fedramp/20x/systems/{sid}/validate")
        await c.post(
            "/api/fedramp/20x/assessor-reviews",
            json={
                "system_id": sid, "ksi_id": ksi["id"], "status": "finding_opened",
                "finding": "MFA not enforced for break-glass",
            },
        )
        reviews = (await c.get(f"/api/fedramp/20x/assessor-reviews?system_id={sid}")).json()
        assert any(r["status"] == "finding_opened" for r in reviews)
        poams = (await c.get(f"/api/poams?system_id={sid}")).json()
        assert any("assessor finding" in p["title"] for p in poams)


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


def test_any_of_returns_best_verdict() -> None:
    ksi = {"identifier": "KSI-X", "category": "MLA"}
    rule = {
        "kind": "any_of",
        "rules": [
            {"kind": "connector_capture", "captures": ["audit_retention_period"]},
            {"kind": "control_state", "controls": ["AU-6"], "states": ["implemented"]},
        ],
    }
    # Neither signal present -> best is the control_state fail (beats manual? no: fail<manual).
    v = evaluate_rule(rule, SystemContext(), ksi=ksi)
    assert v.status in ("manual_review_required", "fail")
    # Connector capture present -> passes via the live signal.
    v = evaluate_rule(rule, SystemContext(captures={"audit_retention_period"}), ksi=ksi)
    assert v.status == "pass" and v.source == "connector_capture"
    # No capture but control implemented -> passes via fallback.
    v = evaluate_rule(rule, SystemContext(impl_status={"AU-6": "implemented"}), ksi=ksi)
    assert v.status == "pass" and v.source == "control_state"


@pytest.mark.asyncio
async def test_connector_capture_drives_validation() -> None:
    async with session_scope() as s:
        await catalog.seed_ksis(s)
    sid = await _fresh_system("CapCso")
    # Resolve the system's org and record a connector capture for it.
    async with session_scope() as s:
        org_id = (
            await s.execute(select(System.organization_id).where(System.id == sid))
        ).scalar_one()
        assert (
            await s.execute(select(Organization.id).where(Organization.id == org_id))
        ).scalar_one_or_none() == org_id
        await s.execute(
            delete(CaptureSnapshot).where(CaptureSnapshot.organization_id == org_id)
        )
        for key, val in (
            ("audit_retention_period", "365 days"),
            ("encryption_at_rest", "enabled"),
            ("mfa_enforced", "required"),
        ):
            s.add(
                CaptureSnapshot(
                    organization_id=org_id, connector="aws_govcloud", odp_key=key, value=val
                )
            )
    # Each of these KSIs is any_of[connector_capture(...), control_state(...)]; the live
    # capture drives them to pass — SVC-03 has no SC-28 implementation at all.
    async with session_scope() as s:
        results = {
            r["ksi_identifier"]: r for r in await validation.validate_system(s, system_id=sid)
        }
        for ident in ("KSI-MLA-01", "KSI-SVC-03", "KSI-IAM-01"):
            assert results[ident]["validation_status"] == "pass", ident
            assert results[ident]["source"] == "connector_capture", ident


@pytest.mark.asyncio
async def test_validation_emits_prometheus_metrics() -> None:
    async with session_scope() as s:
        await catalog.seed_ksis(s)
    sid = await _fresh_system("MetricCso")

    def _pass_count() -> float:
        return REGISTRY.get_sample_value("ccf_ksi_validations_total", {"status": "pass"}) or 0.0

    before = _pass_count()
    async with session_scope() as s:
        await validation.validate_system(s, system_id=sid)
    # IA-2 implemented -> at least one KSI passes, so the counter advanced.
    assert _pass_count() > before


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
        # A non-authorized dependency fails the dependency KSI (TPR-02).
        assert results["KSI-TPR-02"]["validation_status"] == "fail"
