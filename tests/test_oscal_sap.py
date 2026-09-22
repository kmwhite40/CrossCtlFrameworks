"""Tests for the OSCAL Assessment-Plan (SAP) export and the ``import-ap`` seam.

Mirrors ``tests/test_oscal_sar.py`` for DB setup (``session_scope``/
``fresh_engine``, module-scoped Alembic migration) and ``tests/
test_oscal_validation.py`` for validating the resulting document.

Every control this module seeds uses the ``ZSAP-`` prefix: ``controls
.identifier`` is globally UNIQUE across the whole test database, so a
collision with another module's fixture fails only in the full suite. Rows
are torn down in ``try/finally`` for the same reason — a leaked
``Control`` row breaks a later file, not this one.
"""

from __future__ import annotations

import os
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.api.routes.oscal import build_sap_doc, build_sar_doc
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    Assessment,
    AssessmentResult,
    Control,
    ControlImplementation,
    Organization,
    SSPProject,
    System,
    User,
)
from ccf.oscal import detect_kind, validate_document
from ccf.oscal.validation import _REQUIRED_CHILDREN, KINDS

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _require_official_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the official-schema gate ON for this module rather than inheriting
    the ambient environment, so "the SAP validates officially" is proven, never
    quietly downgraded to Concord's structural fallback."""
    monkeypatch.setenv("CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA", "1")
    monkeypatch.delenv("CCF_OSCAL_SCHEMA_DIR", raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# The catalog columns this module exercises. ``ZSAP-E`` has all three methods,
# ``ZSAP-I`` has only INTERVIEW, and ``ZSAP-NONE`` has none at all — the third
# is the one that proves nothing is invented where the catalog is silent.
_EXAMINE_TEXT = "[SELECT FROM: Access control policy and procedures; system security plan]."
_INTERVIEW_TEXT = "[SELECT FROM: Organizational personnel with access control responsibilities]."
_TEST_TEXT = "[SELECT FROM: Mechanisms for implementing account management]."

_SEEDED_CONTROLS = {
    "ZSAP-E": {"examine": _EXAMINE_TEXT, "interview": _INTERVIEW_TEXT, "test": _TEST_TEXT},
    "ZSAP-I": {"interview": _INTERVIEW_TEXT},
    "ZSAP-NONE": {},
}


async def _seed(org_name: str, *, with_ssp_project: bool = False) -> tuple[int, int, int]:
    """Organization + System + three ControlImplementations (ZSAP-E, ZSAP-I,
    ZSAP-NONE) + an Assessment with one AssessmentResult each. Returns
    ``(org_id, system_id, assessment_id)``."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"{org_name} system")
        s.add(sysrow)
        await s.flush()

        if with_ssp_project:
            s.add(
                SSPProject(
                    organization_id=org.id,
                    system_id=sysrow.id,
                    customer_name=org_name,
                    system_name=sysrow.name,
                )
            )
            await s.flush()

        impls: list[ControlImplementation] = []
        for identifier, columns in _SEEDED_CONTROLS.items():
            ctrl = (
                await s.execute(select(Control).where(Control.identifier == identifier))
            ).scalar_one_or_none()
            if ctrl is None:
                ctrl = Control(
                    identifier=identifier,
                    control_name=f"{identifier} control title",
                    **columns,
                )
                s.add(ctrl)
                await s.flush()
            impl = ControlImplementation(
                system_id=sysrow.id, control_id=ctrl.id, status="implemented"
            )
            s.add(impl)
            await s.flush()
            impls.append(impl)

        assessment = Assessment(
            system_id=sysrow.id,
            name=f"{org_name} internal assessment",
            kind="internal",
            assessor="Jane 3PAO",
            started_on=date.today() - timedelta(days=10),
            finished_on=date.today(),
            summary="Internal control assessment.",
        )
        s.add(assessment)
        await s.flush()
        for impl in impls:
            s.add(
                AssessmentResult(
                    assessment_id=assessment.id,
                    implementation_id=impl.id,
                    finding="satisfied",
                    rationale="Verified.",
                    observed_on=date.today(),
                )
            )
        await s.flush()
        return org.id, sysrow.id, assessment.id


async def _cleanup() -> None:
    """Drop this module's seeded Control rows. ``controls.identifier`` is
    globally UNIQUE, so leaving them behind is what breaks another file.

    ``control_implementations.control_id`` is ON DELETE RESTRICT, so the
    implementations must go first; their ``assessment_results`` cascade with
    them. Deleting the Control rows directly fails with a foreign-key
    violation — which is itself only visible once something has been seeded.
    """
    async with session_scope() as s:
        control_ids = (
            (
                await s.execute(
                    select(Control.id).where(Control.identifier.in_(_SEEDED_CONTROLS))
                )
            )
            .scalars()
            .all()
        )
        if not control_ids:
            return
        await s.execute(
            delete(ControlImplementation).where(
                ControlImplementation.control_id.in_(control_ids)
            )
        )
        await s.execute(delete(Control).where(Control.id.in_(control_ids)))


def _selection(doc: dict) -> dict:
    return doc["assessment-plan"]["reviewed-controls"]["control-selections"][0]


# --- 1. the SAP validates against the OFFICIAL schema -------------------------


@pytest.mark.asyncio
async def test_sap_validates_against_official_schema() -> None:
    try:
        _org_id, _sys_id, assessment_id = await _seed("SAP Golden Org", with_ssp_project=True)

        transport = ASGITransport(app=create_app())
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.get(f"/api/oscal/sap/{assessment_id}")
            assert r.status_code == 200
            doc = r.json()

        assert "assessment-plan" in doc
        plan = doc["assessment-plan"]
        # Every field the official model REQUIRES is present and derived.
        assert plan["import-ssp"]["href"].startswith("/api/oscal/ssp/")
        assert "remarks" not in plan["import-ssp"]
        assert plan["metadata"]["title"] == "Security Assessment Plan"
        assert plan["metadata"]["parties"][0]["name"] == "Jane 3PAO"
        assert plan["metadata"]["props"] == [{"name": "assessment-kind", "value": "internal"}]

        report = validate_document(doc)
        assert report.kind == "sap"
        assert report.mode == "official", report.warnings
        assert report.ok, report.errors
    finally:
        await _cleanup()


@pytest.mark.asyncio
async def test_sap_without_ssp_project_says_so_and_still_validates() -> None:
    """``import-ssp`` is REQUIRED, so it cannot be omitted when no SSP project
    exists — it must instead say plainly that it is not derived."""
    try:
        _org_id, _sys_id, assessment_id = await _seed("SAP No SSP Org")
        async with session_scope() as s:
            assessment = await s.get(Assessment, assessment_id)
            assert assessment is not None
            doc = await build_sap_doc(s, assessment)

        import_ssp = doc["assessment-plan"]["import-ssp"]
        assert import_ssp["href"] == "#no-system-security-plan"
        assert "UNSPECIFIED" in import_ssp["remarks"]

        report = validate_document(doc)
        assert report.mode == "official", report.warnings
        assert report.ok, report.errors
    finally:
        await _cleanup()


# --- 2. detect_kind recognises an assessment-plan -----------------------------


def test_detect_kind_recognises_assessment_plan() -> None:
    doc = {"assessment-plan": {"uuid": "x", "metadata": {}}}
    assert detect_kind(doc) == "sap"
    # The previously-unrecognised path is gone: validating a SAP no longer
    # returns before ``require_official`` is consulted.
    report = validate_document(doc)
    assert report.kind == "sap"
    assert report.mode != "none"
    assert "unrecognized OSCAL document (no known root key)" not in report.errors
    # ...and a genuinely unknown root key still IS unrecognised.
    assert detect_kind({"nope": {}}) == "unknown"
    assert validate_document({"nope": {}}).errors == [
        "unrecognized OSCAL document (no known root key)"
    ]


def test_sap_kind_aliases_resolve() -> None:
    """The OSCAL model name is one hyphen from the assessment-RESULTS root key;
    passing it explicitly must not fall through to "unknown"."""
    doc = {"assessment-plan": {"uuid": "x", "metadata": {}}}
    for alias in ("sap", "assessment-plan", "assessment_plan", "ap"):
        assert validate_document(doc, kind=alias).kind == "sap", alias
    # The plan alias must not capture the results kind.
    assert validate_document({"assessment-results": {}}, kind="ar").kind == "assessment"


def test_structural_fallback_requires_the_plan_essentials(tmp_path, monkeypatch) -> None:
    """With no official schema resolvable, the structural checks must still
    reject a plan that imports no SSP and reviews no controls — otherwise the
    fallback passes documents the official schema fails."""
    monkeypatch.setenv("CCF_OSCAL_SCHEMA_DIR", str(tmp_path))
    monkeypatch.setenv("CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA", "false")
    get_settings.cache_clear()
    try:
        report = validate_document(
            {
                "assessment-plan": {
                    "uuid": "u",
                    "metadata": {
                        "title": "T",
                        "last-modified": "2026-09-22T00:00:00Z",
                        "oscal-version": "1.1.2",
                    },
                }
            }
        )
        assert report.mode == "structural"
        assert not report.ok
        assert "assessment-plan: missing required 'import-ssp'" in report.errors
        assert "assessment-plan: missing required 'reviewed-controls'" in report.errors
    finally:
        get_settings.cache_clear()


def test_ap_schema_patterns_survive_the_ecma_translation() -> None:
    """The vendored AP schema carries OSCAL's ECMA ``\\p{L}``/``\\p{N}`` classes,
    which Python's ``re`` cannot compile. Validating a token-populated plan must
    not crash — the same regression ``test_oscal_schema_adapter`` pins for SSP."""
    doc = {
        "assessment-plan": {
            "uuid": "33333333-3333-4333-8333-333333333333",
            "metadata": {
                "title": "t",
                "last-modified": "2026-09-22T00:00:00Z",
                "version": "1",
                "oscal-version": "1.1.2",
                "props": [{"name": "assessment-kind", "value": "internal"}],
            },
            "import-ssp": {"href": "#no-system-security-plan"},
            "reviewed-controls": {
                "control-selections": [{"include-controls": [{"control-id": "ac-2"}]}]
            },
        }
    }
    report = validate_document(doc)
    assert report.mode == "official", report.warnings
    assert report.ok, report.errors


# --- 3. reviewed-controls carries the minItems 1 guard ------------------------


@pytest.mark.asyncio
async def test_sap_empty_scope_omits_include_controls_and_validates() -> None:
    """An assessment reviewing nothing must not emit ``"include-controls": []``
    — that is minItems-1-invalid, not an empty-scope signal. Mirrors
    ``test_oscal_sar.test_sar_empty_results_validates_official``."""
    async with session_scope() as s:
        org = Organization(name="SAP Empty Org")
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name="SAP Empty System")
        s.add(sysrow)
        await s.flush()
        assessment = Assessment(
            system_id=sysrow.id, name="Kickoff", kind="internal", assessor="3PAO"
        )
        s.add(assessment)
        await s.flush()
        doc = await build_sap_doc(s, assessment)

    selection = _selection(doc)
    assert "include-controls" not in selection
    assert "UNSPECIFIED" in selection["remarks"]
    # No scope means no activities to plan — and no invented ones.
    assert "local-definitions" not in doc["assessment-plan"]

    report = validate_document(doc)
    assert report.mode == "official", report.warnings
    assert report.ok, report.errors


@pytest.mark.asyncio
async def test_sap_non_empty_scope_lists_every_reviewed_control() -> None:
    try:
        _org_id, _sys_id, assessment_id = await _seed("SAP Scope Org")
        async with session_scope() as s:
            assessment = await s.get(Assessment, assessment_id)
            assert assessment is not None
            doc = await build_sap_doc(s, assessment)

        selection = _selection(doc)
        assert [c["control-id"] for c in selection["include-controls"]] == [
            "zsap-e",
            "zsap-i",
            "zsap-none",
        ]
        # The scope is retrospective; the document must say so rather than
        # presenting recorded coverage as an authored plan scope.
        assert "derived from the control coverage recorded" in selection["description"]
    finally:
        await _cleanup()


# --- 4. EXAMINE / INTERVIEW / TEST reach the document -------------------------


@pytest.mark.asyncio
async def test_catalog_methods_become_activities_and_nothing_is_invented() -> None:
    try:
        _org_id, _sys_id, assessment_id = await _seed("SAP Methods Org")
        async with session_scope() as s:
            assessment = await s.get(Assessment, assessment_id)
            assert assessment is not None
            doc = await build_sap_doc(s, assessment)

        local = doc["assessment-plan"]["local-definitions"]
        activities = local["activities"]

        def methods_for(cid: str) -> list[str]:
            out = []
            for a in activities:
                sel = a["related-controls"]["control-selections"][0]["include-controls"]
                if [c["control-id"] for c in sel] == [cid]:
                    out.extend(p["value"] for p in a["props"] if p["name"] == "method")
            return out

        # All three catalog columns reach the document, in catalog order.
        assert methods_for("zsap-e") == ["EXAMINE", "INTERVIEW", "TEST"]
        # Only the column the catalog actually populates.
        assert methods_for("zsap-i") == ["INTERVIEW"]
        # Where the catalog is silent, NOTHING is invented.
        assert methods_for("zsap-none") == []

        # The activity carries the catalog's own text, not a paraphrase.
        examine = next(
            a
            for a in activities
            if {"name": "method", "value": "EXAMINE"} in a["props"]
            and a["related-controls"]["control-selections"][0]["include-controls"][0][
                "control-id"
            ]
            == "zsap-e"
        )
        assert examine["description"] == _EXAMINE_TEXT
        assert examine["title"] == "EXAMINE — zsap-e"

        # The silence is stated, not merely absent: the reader can tell WHICH
        # reviewed control has no planned activity and why.
        assert "zsap-none" in local["remarks"]
        assert "zsap-e" not in local["remarks"]

        report = validate_document(doc)
        assert report.mode == "official", report.warnings
        assert report.ok, report.errors
    finally:
        await _cleanup()


@pytest.mark.asyncio
async def test_sap_omits_local_definitions_when_catalog_has_no_methods() -> None:
    """A scope whose controls all lack catalog methods yields remarks and no
    ``activities`` key — ``activities`` carries minItems 1, and an empty array
    would be invalid as well as untrue."""
    try:
        async with session_scope() as s:
            org = Organization(name="SAP Silent Catalog Org")
            s.add(org)
            await s.flush()
            sysrow = System(organization_id=org.id, name="SAP Silent Catalog System")
            s.add(sysrow)
            await s.flush()
            ctrl = Control(identifier="ZSAP-NONE", control_name="No methods")
            s.add(ctrl)
            await s.flush()
            impl = ControlImplementation(
                system_id=sysrow.id, control_id=ctrl.id, status="implemented"
            )
            s.add(impl)
            await s.flush()
            assessment = Assessment(
                system_id=sysrow.id, name="Silent", kind="self", assessor="Self"
            )
            s.add(assessment)
            await s.flush()
            s.add(
                AssessmentResult(
                    assessment_id=assessment.id,
                    implementation_id=impl.id,
                    finding="satisfied",
                    rationale="ok",
                )
            )
            await s.flush()
            doc = await build_sap_doc(s, assessment)

        local = doc["assessment-plan"]["local-definitions"]
        assert "activities" not in local
        assert "zsap-none" in local["remarks"]

        report = validate_document(doc)
        assert report.mode == "official", report.warnings
        assert report.ok, report.errors
    finally:
        await _cleanup()


@pytest.mark.asyncio
async def test_sap_does_not_fabricate_optional_assessment_scope() -> None:
    """The four elements Concord holds no data for are absent, not invented."""
    try:
        _org_id, _sys_id, assessment_id = await _seed("SAP No Fabrication Org")
        async with session_scope() as s:
            assessment = await s.get(Assessment, assessment_id)
            assert assessment is not None
            doc = await build_sap_doc(s, assessment)

        plan = doc["assessment-plan"]
        for key in ("terms-and-conditions", "assessment-subjects", "assessment-assets", "tasks"):
            assert key not in plan, f"{key} was fabricated with no data behind it"
    finally:
        await _cleanup()


# --- 5. the SAR's import-ap seam ---------------------------------------------


@pytest.mark.asyncio
async def test_sar_import_ap_resolves_to_the_plan_when_one_exists() -> None:
    try:
        _org_id, _sys_id, assessment_id = await _seed("SAP Seam Org")

        transport = ASGITransport(app=create_app())
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            sar = (await c.get(f"/api/oscal/sar/{assessment_id}")).json()
            import_ap = sar["assessment-results"]["import-ap"]
            assert import_ap["href"] == f"/api/oscal/sap/{assessment_id}"
            assert import_ap["href"] != "#no-assessment-plan"

            # The href actually resolves to a valid plan — not a dangling
            # reference dressed up as a real one.
            plan_resp = await c.get(import_ap["href"])
            assert plan_resp.status_code == 200
            plan_doc = plan_resp.json()

        assert detect_kind(plan_doc) == "sap"
        report = validate_document(plan_doc)
        assert report.mode == "official", report.warnings
        assert report.ok, report.errors

        # The plan and the report agree on scope — the seam joins two views of
        # ONE assessment.
        plan_cids = [
            c["control-id"] for c in _selection(plan_doc)["include-controls"]
        ]
        sar_cids = [
            c["control-id"]
            for c in sar["assessment-results"]["results"][0]["reviewed-controls"][
                "control-selections"
            ][0]["include-controls"]
        ]
        assert plan_cids == sar_cids
    finally:
        await _cleanup()


@pytest.mark.asyncio
async def test_sar_import_ap_keeps_the_honest_placeholder_when_no_plan_exists() -> None:
    """An assessment with no recorded control coverage yields a plan that would
    review nothing, so the SAR keeps the placeholder rather than citing it."""
    async with session_scope() as s:
        org = Organization(name="SAP Seam Placeholder Org")
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name="SAP Seam Placeholder System")
        s.add(sysrow)
        await s.flush()
        assessment = Assessment(
            system_id=sysrow.id, name="Kickoff", kind="internal", assessor="3PAO"
        )
        s.add(assessment)
        await s.flush()
        sar = await build_sar_doc(s, assessment)

    import_ap = sar["assessment-results"]["import-ap"]
    assert import_ap["href"] == "#no-assessment-plan"
    assert "no recorded control coverage" in import_ap["remarks"]
    report = validate_document(sar)
    assert report.mode == "official", report.warnings
    assert report.ok, report.errors


# --- 6. tenant isolation ------------------------------------------------------


@pytest.mark.asyncio
async def test_sap_out_of_org_is_404() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    try:
        _org_id, _sys_id, assessment_id = await _seed("SAP Owner Org")

        async with session_scope() as s:
            other_org = Organization(name="SAP Other Org")
            s.add(other_org)
            await s.flush()
            outsider = User(
                email="outsider@sap-other.test",
                organization_id=other_org.id,
                role="admin",
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(outsider)
            await s.flush()
            token = outsider.api_token

        transport = ASGITransport(app=create_app())
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.get(
                f"/api/oscal/sap/{assessment_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 404

            r_anon = await c.get(f"/api/oscal/sap/{assessment_id}")
            assert r_anon.status_code == 401
    finally:
        os.environ.pop("CCF_AUTH_ENABLED", None)
        os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
        get_settings.cache_clear()
        await _cleanup()


@pytest.mark.asyncio
async def test_sap_route_org_check_rejects_a_foreign_principal_without_rls() -> None:
    """The route's OWN org check, exercised at its own layer.

    ``ccf.assessments`` carries a ``tenant_isolation`` RLS policy, so over HTTP
    an outsider's request 404s at the query before the route's explicit check is
    ever reached — which means the end-to-end test above passes just as happily
    with that check deleted (confirmed by mutation). RLS is documented in
    ``ccf.api.deps.get_session`` as a backstop *beneath* the app-layer scoping,
    so the app-layer scoping needs a test that can actually fail: an unscoped
    ``session_scope`` session (tenant cleared, RLS bypassed) plus a principal
    belonging to another organization.
    """
    from fastapi import HTTPException  # noqa: PLC0415

    from ccf.api.routes.oscal import sap_export  # noqa: PLC0415
    from ccf.auth import Principal  # noqa: PLC0415

    try:
        owner_org_id, _sys_id, assessment_id = await _seed("SAP Layer Owner Org")
        async with session_scope() as s:
            other_org = Organization(name="SAP Layer Other Org")
            s.add(other_org)
            await s.flush()
            other_org_id = other_org.id

        outsider = Principal(
            user_id=None, email="outsider@sap-layer.test", org_id=other_org_id, role="admin"
        )
        async with session_scope() as s:
            with pytest.raises(HTTPException) as excinfo:
                await sap_export(assessment_id, session=s, principal=outsider)
            assert excinfo.value.status_code == 404

            # The same call from the OWNING org succeeds — so the 404 above is
            # the org check, not the assessment being unreachable.
            insider = Principal(
                user_id=None, email="insider@sap-layer.test", org_id=owner_org_id, role="admin"
            )
            doc = await sap_export(assessment_id, session=s, principal=insider)
            assert "assessment-plan" in doc
    finally:
        await _cleanup()


@pytest.mark.asyncio
async def test_sap_unknown_assessment_404() -> None:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/api/oscal/sap/999999999")
        assert r.status_code == 404


# --- 7. the four existing kinds are unaffected -------------------------------


def test_existing_oscal_kinds_unchanged_by_equality() -> None:
    """Adding the plan must not disturb the four kinds already shipping."""
    assert {k: v for k, v in KINDS.items() if k != "sap"} == {
        "ssp": (
            "system-security-plan",
            ("oscal_ssp_schema.json", "oscal_complete_schema.json"),
        ),
        "component": (
            "component-definition",
            ("oscal_component_schema.json", "oscal_complete_schema.json"),
        ),
        "poam": (
            "plan-of-action-and-milestones",
            ("oscal_poam_schema.json", "oscal_complete_schema.json"),
        ),
        "assessment": (
            "assessment-results",
            ("oscal_assessment-results_schema.json", "oscal_complete_schema.json"),
        ),
    }
    assert KINDS["sap"] == (
        "assessment-plan",
        ("oscal_assessment-plan_schema.json", "oscal_complete_schema.json"),
    )
    assert {k: v for k, v in _REQUIRED_CHILDREN.items() if k != "sap"} == {
        "ssp": ("system-characteristics", "control-implementation"),
        "component": ("components",),
        "poam": ("poam-items",),
        "assessment": ("results",),
    }


def test_vendored_ap_schema_matches_its_manifest_hash() -> None:
    """The plan schema is the official NIST v1.1.2 file, pinned by hash
    alongside the other four."""
    import hashlib  # noqa: PLC0415
    import json  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    from ccf.oscal import validation  # noqa: PLC0415

    schema_dir = Path(validation.__file__).with_name("schemas")
    manifest = json.loads((schema_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    name = "oscal_assessment-plan_schema.json"
    digest = hashlib.sha256((schema_dir / name).read_bytes()).hexdigest()
    assert manifest["files"][name] == digest
    assert manifest["oscal_version"] == "1.1.2"

    schema = json.loads((schema_dir / name).read_text(encoding="utf-8"))
    assert schema["$id"] == "http://csrc.nist.gov/ns/oscal/1.1.2/oscal-ap-schema.json"
    # Provenance corroborated offline: the plan model in this file is the same
    # one the ALREADY hash-pinned complete schema carries.
    complete = json.loads(
        (schema_dir / "oscal_complete_schema.json").read_text(encoding="utf-8")
    )
    ours = json.dumps(
        schema["definitions"]["oscal-ap-oscal-ap:assessment-plan"], sort_keys=True
    ).replace("oscal-ap-oscal-", "X-")
    theirs = json.dumps(
        complete["definitions"]["oscal-complete-oscal-ap:assessment-plan"], sort_keys=True
    ).replace("oscal-complete-oscal-", "X-")
    assert ours == theirs
