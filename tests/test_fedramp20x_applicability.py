"""KSI applicability by CR26 Certification Class, derived from FedRAMP's rules.

The first block pins the exact upstream text the derivation parses. If a
re-vendored dataset moves any of it, these fail before a Class A system is
silently scored on 46 KSIs again -- or on none.
"""

from __future__ import annotations

import itertools
import json
import shutil
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.cr26.sdr import seed_sdr
from ccf.db import session_scope
from ccf.fedramp20x import applicability as ap
from ccf.fedramp20x import catalog, package, readiness, rules
from ccf.models import KSI, KSIAssessorReview, KSIException, KSIState, Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine", "isolate_ksi_rows")

_SEQ = itertools.count()
_ENGINE_RULES = Path(__file__).parent / "fixtures" / "ksi_rules_engine.json"

CLASS_A = {
    "KSI-CED-RAT",
    "KSI-CMT-LMC",
    "KSI-CNA-RNT",
    "KSI-IAM-AAM",
    "KSI-IAM-APM",
    "KSI-INR-RIR",
    "KSI-SVC-SIN",
}
VARIES = {"KSI-CNA-EIS", "KSI-MLA-ALA", "KSI-SVC-PRR", "KSI-SVC-RUD", "KSI-SVC-VCM"}


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
async def _shipped_catalog() -> AsyncIterator[None]:
    async with session_scope() as s:
        await catalog.seed_ksis(s)
    yield
    async with session_scope() as s:
        await catalog.seed_ksis(s)


# --- the upstream text this depends on ------------------------------------


def _frr(*path: str) -> dict:
    node = rules.load_rules().data["FRR"]
    for key in path:
        node = node[key]
    return node


def test_class_a_is_frc_cla_mfr_s_seven_ksis() -> None:
    rule = _frr("FRC", "data", "all", "CLA", "FRC-CLA-MFR")
    assert rule["force"] == "MUST"
    assert {r for r in rule["related"] if r.startswith("KSI-")} == CLASS_A
    assert ap.class_a_ksis(rules.load_rules()) == CLASS_A


def test_classes_b_c_d_include_all_ksis_per_ivv_csx_aia() -> None:
    variants = _frr("IVV", "data", "20x", "CSX", "IVV-CSX-AIA")["varies_by_class"]
    assert set(variants) == {"a", "b", "c", "d"}
    for cls in "bcd":
        assert "MUST include all Key Security Indicators" in variants[cls]["statement"]
    # Class A defers to its alternative framework instead -- which is why its
    # scope comes from FRC-CLA-MFR, not from this rule.
    assert "all Key Security Indicators" not in variants["a"]["statement"]
    assert "alternative security framework" in variants["a"]["statement"]


def test_the_five_class_variant_ksis_are_optional_for_b_and_unpublished_for_d() -> None:
    for theme in rules.load_rules().data["KSI"].values():
        for ident, ind in theme["indicators"].items():
            if ident in VARIES:
                assert set(ind["varies_by_class"]) == {"b", "c"}, ident
                assert ind["varies_by_class"]["b"]["statement"].startswith("**Optional:**")
                assert not ind["varies_by_class"]["c"]["statement"].startswith("**Optional")
            else:
                assert "varies_by_class" not in ind, ident


@pytest.mark.parametrize(
    ("cls", "force", "minimum"),
    [("A", "MAY", 0), ("B", "SHOULD", 1), ("C", "MUST", 2), ("D", "MUST", 4)],
)
def test_frc_csx_vvk_automation_minimums(cls: str, force: str, minimum: int) -> None:
    req = ap.automation_requirement(rules.load_rules(), cls)
    assert req is not None and (req.force, req.min_methods) == (force, minimum)


# --- the derivation --------------------------------------------------------


@pytest.mark.parametrize(
    ("cls", "expected"),
    [
        (None, {"unscoped": 46}),
        ("A", {"required": 7, "not_required": 39}),
        ("B", {"required": 41, "optional": 5}),
        ("C", {"required": 46}),
        ("D", {"required": 46}),
    ],
)
def test_counts_per_class(cls: str | None, expected: dict[str, int]) -> None:
    got: dict[str, int] = {}
    for a in ap.for_class(rules.load_rules(), cls).by_identifier.values():
        got[a.status] = got.get(a.status, 0) + 1
    assert got == expected


def test_class_d_says_when_fedramp_published_no_wording() -> None:
    d = ap.for_class(rules.load_rules(), "D").by_identifier
    assert {k for k, v in d.items() if v.note} == VARIES
    assert all(v.rule == "IVV-CSX-AIA" for k, v in d.items() if k in VARIES)


def _tampered(tmp_path: Path, edit) -> rules.ConsolidatedRules:  # type: ignore[no-untyped-def]
    import hashlib  # noqa: PLC0415

    d = tmp_path / "rules_data"
    shutil.copytree(rules.DATA_DIR, d)
    data = json.loads((d / rules.DATASET_FILE).read_text())
    edit(data)
    (d / rules.DATASET_FILE).write_text(json.dumps(data))
    manifest = json.loads((d / "MANIFEST.json").read_text())
    manifest["files"][rules.DATASET_FILE]["sha256"] = hashlib.sha256(
        (d / rules.DATASET_FILE).read_bytes()
    ).hexdigest()
    (d / "MANIFEST.json").write_text(json.dumps(manifest))
    return rules.load_rules(d)


def test_class_a_refuses_a_rule_that_lists_no_ksis(tmp_path: Path) -> None:
    def edit(data: dict) -> None:
        rule = data["FRR"]["FRC"]["data"]["all"]["CLA"]["FRC-CLA-MFR"]
        rule["related"] = [r for r in rule["related"] if not r.startswith("KSI-")]

    with pytest.raises(ap.ApplicabilityError, match="lists no KSIs"):
        ap.for_class(_tampered(tmp_path, edit), "A")


def test_a_class_no_rule_covers_is_refused_not_guessed(tmp_path: Path) -> None:
    def edit(data: dict) -> None:
        v = data["FRR"]["IVV"]["data"]["20x"]["CSX"]["IVV-CSX-AIA"]["varies_by_class"]
        v["c"]["statement"] = "Providers with 20x Class C Certifications MAY do something."

    with pytest.raises(ap.ApplicabilityError, match="Class C"):
        ap.for_class(_tampered(tmp_path, edit), "C")


def test_automated_methods_counts_leaves_not_manual() -> None:
    assert ap.automated_methods({"kind": "manual"}) == 0
    assert ap.automated_methods(None) == 0
    # Reads an operator-entered record: evaluated automatically, but not an
    # automated check of the system (FRC-CSX-VVK's "automated method").
    assert ap.automated_methods({"kind": "control_state", "controls": ["IA-2"]}) == 0
    assert ap.automated_methods({"kind": "connector_capture", "captures": ["x"]}) == 1
    assert ap.automated_methods({"kind": "something_new"}) == 0
    assert (
        ap.automated_methods(
            {
                "kind": "any_of",
                "rules": [
                    {"kind": "connector_capture", "captures": ["x"]},
                    {"kind": "manual"},
                    {"kind": "connector_capture", "captures": ["y"]},
                    {"kind": "control_state", "controls": ["IA-2"]},
                ],
            }
        )
        == 2
    )


# --- consumers --------------------------------------------------------------


async def _system(cls: str | None, path: str | None = None) -> int:
    async with session_scope() as s:
        org = Organization(name=f"Class {cls} Org {next(_SEQ)}")
        s.add(org)
        await s.flush()
        sysm = System(
            organization_id=org.id,
            name=f"Class {cls} {next(_SEQ)}",
            certification_class=cls,
            certification_path=path,
        )
        s.add(sysm)
        await s.flush()
        return sysm.id


async def _state(system_id: int, ident: str, status: str) -> None:
    async with session_scope() as s:
        kid = (await s.execute(select(KSI.id).where(KSI.identifier == ident))).scalar_one()
        s.add(KSIState(system_id=system_id, ksi_id=kid, status=status))


async def test_class_a_readiness_is_scored_on_seven_ksis() -> None:
    sid = await _system("A")
    await _state(sid, "KSI-CNA-OFA", "fail")  # not required of Class A
    await _state(sid, "KSI-CED-RAT", "pass")
    async with session_scope() as s:
        ofa = (await s.execute(select(KSI.id).where(KSI.identifier == "KSI-CNA-OFA"))).scalar_one()
        s.add(KSIException(system_id=sid, ksi_id=ofa, rationale="out of scope", status="open"))
        s.add(KSIAssessorReview(system_id=sid, ksi_id=ofa, status="accepted"))
    async with session_scope() as s:
        score = await readiness.score_system(s, system_id=sid, persist=False)
    # The out-of-scope KSI's exception and review count toward nothing either.
    assert score["open_exceptions"] == 0
    assert score["assessor_completion"] == 0
    assert score["certification_class"] == "A"
    assert score["ksi_total"] == 7
    assert score["ksi_scope"] == {
        "required": 7,
        "optional": 0,
        "not_required": 39,
        "unscoped": 0,
    }
    assert score["high_risk_findings"] == 0  # the CNA-OFA failure is out of scope
    assert score["ksi_pass_rate"] == round(100 / 7)


async def test_class_b_does_not_score_its_optional_ksis() -> None:
    sid = await _system("B")
    await _state(sid, "KSI-SVC-RUD", "fail")  # optional for B
    async with session_scope() as s:
        score = await readiness.score_system(s, system_id=sid, persist=False)
    assert score["ksi_total"] == 41
    assert score["ksi_scope"]["optional"] == 5
    assert score["high_risk_findings"] == 0


async def test_no_class_is_unscoped_and_scores_everything() -> None:
    sid = await _system(None)
    await _state(sid, "KSI-SVC-RUD", "fail")
    async with session_scope() as s:
        score = await readiness.score_system(s, system_id=sid, persist=False)
    assert score["certification_class"] is None
    assert score["ksi_total"] == 46 and score["ksi_scope"]["unscoped"] == 46
    assert score["high_risk_findings"] == 1
    assert score["automation_requirement"] is None


async def test_the_automation_requirement_reports_what_meets_it() -> None:
    sid = await _system("B")
    async with session_scope() as s:
        shipped = await readiness.score_system(s, system_id=sid, persist=False)
    assert shipped["automation_requirement"] == {
        "rule": "FRC-CSX-VVK",
        "force": "SHOULD",
        "min_automated_methods_per_ksi": 1,
        "ksis_meeting": 0,  # the shipped overlay authors no rule
        "ksis_owed": 46,  # 41 required + 5 optional
    }
    c = await _system("C")
    async with session_scope() as s:
        await catalog.seed_ksis(s, overlay_path=_ENGINE_RULES)
        engine_b = await readiness.score_system(s, system_id=sid, persist=False)
        engine_c = await readiness.score_system(s, system_id=c, persist=False)
    # Three test rules are any_of[connector_capture, control_state]: ONE
    # automated method each -- the control_state leaf reads an operator record.
    assert engine_b["automation_requirement"]["ksis_meeting"] == 3
    assert engine_c["automation_requirement"]["ksis_meeting"] == 0  # C needs 2


async def test_a_class_a_sdr_owes_only_the_seven() -> None:
    sid = await _system("A")
    async with session_scope() as s:
        result = await seed_sdr(s, system_id=sid)
    assert set(result.omitted_ksi_ids) == CLASS_A


async def test_a_class_a_package_carries_only_the_seven() -> None:
    sid = await _system("A")
    async with session_scope() as s:
        pkg = await package.build_package(s, system_id=sid)
    entries = pkg["ksis"]
    assert {e["identifier"] for e in entries} == CLASS_A
    assert all(e["applicability"]["status"] == "required" for e in entries)
    assert all(e["applicability"]["rule"] == "FRC-CLA-MFR" for e in entries)


async def test_the_page_says_what_the_score_covers() -> None:
    a = await _system("A")
    none = await _system(None)
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        page_a = (await c.get(f"/fedramp20x?system_id={a}")).text
        page_none = (await c.get(f"/fedramp20x?system_id={none}")).text
    assert "Scored on 7 KSIs: 7 required. 39 not required." in page_a
    assert "Class A certification (20x only)" in page_a
    assert ">not required</span>" in page_a
    assert "No Certification Class is recorded" in page_none
    assert "Scored on 46 KSIs: 46 unscoped." in page_none
    assert "—%" not in page_a and "—%" not in page_none


# --- certification path (review H2) -----------------------------------------


def test_the_agency_path_owes_no_ksis() -> None:
    sc = ap.for_class(rules.load_rules(), "C", "agency")
    assert {a.status for a in sc.by_identifier.values()} == {"not_required"}
    assert {a.rule for a in sc.by_identifier.values()} == {"IVV-CSF-AIA"}
    assert sc.automation is None and not sc.conditional_on_20x
    assert "Rev5 only" in sc.basis


def test_class_a_on_the_agency_path_is_reported_not_resolved() -> None:
    sc = ap.for_class(rules.load_rules(), "A", "agency")
    assert sc.problem is not None and "Program path only" in sc.problem
    assert {a.status for a in sc.by_identifier.values()} == {"unscoped"}


@pytest.mark.parametrize("path", [None, "program"])
def test_program_or_unrecorded_path_is_conditional_on_20x(path: str | None) -> None:
    sc = ap.for_class(rules.load_rules(), "C", path)
    assert sc.conditional_on_20x
    assert "Concord does not record certification type" in sc.basis


def test_the_twentyx_paths_come_from_the_dataset() -> None:
    info = rules.load_rules().data["FRR"]
    assert info["IVV"]["info"]["20x"]["subsets"]["CSX"]["applicability"]["paths"] == ["Program"]
    assert info["FRC"]["info"]["subsets"]["CLA"]["applicability"]["paths"] == ["Program"]


async def test_an_agency_path_system_is_not_scored_on_ksis() -> None:
    sid = await _system("C", "agency")
    await _state(sid, "KSI-CED-RAT", "fail")
    async with session_scope() as s:
        score = await readiness.score_system(s, system_id=sid, persist=False)
        gaps = await readiness.open_gaps(s, system_id=sid)
    assert score["ksi_total"] == 0 and score["high_risk_findings"] == 0
    assert score["automation_requirement"] is None
    assert gaps == []


async def test_unreadable_rules_degrade_to_unscoped_with_the_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise ap.ApplicabilityError("FRC-CLA-MFR is not where it was")

    monkeypatch.setattr(ap, "for_class", boom)
    sid = await _system("A")
    async with session_scope() as s:
        score = await readiness.score_system(s, system_id=sid, persist=False)
    assert score["ksi_scope"]["unscoped"] == 46
    assert "FRC-CLA-MFR is not where it was" in score["ksi_scope_problem"]


# --- consumers agree with readiness (review H1, M1-M5) -----------------------


async def test_an_out_of_scope_sdr_entry_loses_its_frozen_status() -> None:
    from ccf.cr26.store import put_document  # noqa: PLC0415

    sid = await _system("A")
    await _state(sid, "KSI-CED-RAT", "pass")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=sid,
            kind="sdr",
            document={
                "keySecurityIndicators": [
                    {
                        "ksiId": "KSI-CNA-OFA",  # FedRAMP does not ask it of Class A
                        "ksiImplementation": ["Written while unscoped."],
                        "ksiImplementationStatus": "Implemented",
                    },
                    {"ksiId": "KSI-CED-RAT", "ksiImplementation": ["We review training."]},
                ]
            },
        )
    async with session_scope() as s:
        result = await seed_sdr(s, system_id=sid)
    by_id = {e["ksiId"]: e for e in result.document.document["keySecurityIndicators"]}
    assert "ksiImplementationStatus" not in by_id["KSI-CNA-OFA"]
    assert by_id["KSI-CNA-OFA"]["ksiImplementation"] == ["Written while unscoped."]
    assert by_id["KSI-CED-RAT"]["ksiImplementationStatus"] == "Implemented"  # refreshed
    assert result.out_of_scope_ksi_ids == ["KSI-CNA-OFA"]


async def test_an_unseeded_row_is_counted_and_said_to_be_unscoped() -> None:
    sid = await _system("A")
    async with session_scope() as s:
        s.add(KSI(identifier="KSI-IAM-01", category="IAM", name="phase one", sort_order=-1))
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        page = (await c.get(f"/fedramp20x?system_id={sid}")).text
    assert "Scored on 8 KSIs: 7 required, 1 unscoped" in page
    assert "re-seed the catalog" in page


async def test_gaps_onboarding_facts_and_dashboard_count_what_readiness_counts() -> None:
    from ccf.analytics import overview  # noqa: PLC0415
    from ccf.packages import service as packages_service  # noqa: PLC0415

    sid = await _system("A")
    await _state(sid, "KSI-CNA-OFA", "fail")  # not owed by Class A
    await _state(sid, "KSI-CED-RAT", "manual_review_required")
    async with session_scope() as s:
        org_id = (await s.get(System, sid)).organization_id  # type: ignore[union-attr]
        gaps = await readiness.open_gaps(s, system_id=sid)
        facts = await packages_service._ksi_facts(s, sid)
        dash = await overview._ksi_states(s, org_id)
    assert [g["ksi"] for g in gaps] == ["KSI-CED-RAT"]
    assert len(facts) == 1
    assert dash["fail"] == 0 and dash["total"] == 1


async def test_a_class_a_package_drops_out_of_scope_exceptions_and_says_its_scope() -> None:
    sid = await _system("A")
    async with session_scope() as s:
        ofa = (await s.execute(select(KSI.id).where(KSI.identifier == "KSI-CNA-OFA"))).scalar_one()
        s.add(KSIException(system_id=sid, ksi_id=ofa, rationale="out of scope", status="open"))
    async with session_scope() as s:
        pkg = await package.build_package(s, system_id=sid)
    assert pkg["exceptions"] == []
    md = package.render_markdown(pkg)
    assert "**KSI scope:** FedRAMP's KSI rules for a Class A certification (20x only)" in md
    assert "| KSI | Category | Applicability | Status | Assessor |" in md
    assert "| KSI-CED-RAT | CED | required |" in md


async def test_the_page_states_a_should_as_a_should() -> None:
    sid = await _system("B")
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        page = (await c.get(f"/fedramp20x?system_id={sid}")).text
    assert "each KSI SHOULD have at least 1 automated method; 0 of 46 do." in page


async def test_drift_on_a_ksi_the_class_does_not_owe_is_not_alerted() -> None:
    from ccf.fedramp20x import monitoring, validation  # noqa: PLC0415
    from ccf.models import Control, ControlImplementation  # noqa: PLC0415

    sid = await _system("A")
    async with session_scope() as s:
        await catalog.seed_ksis(s, overlay_path=_ENGINE_RULES)
        ctrl = (
            await s.execute(select(Control).where(Control.identifier == "IA-2"))
        ).scalar_one_or_none()
        if ctrl is None:
            ctrl = Control(identifier="IA-2", control_name="Identification and Authentication")
            s.add(ctrl)
            await s.flush()
        s.add(ControlImplementation(system_id=sid, control_id=ctrl.id, status="implemented"))
    async with session_scope() as s:
        # KSI-IAM-ELP's test rule is control_state IA-2: it passes now.
        await validation.validate_system(s, system_id=sid)
    async with session_scope() as s:
        impl = (
            await s.execute(
                select(ControlImplementation).where(ControlImplementation.system_id == sid)
            )
        ).scalar_one()
        impl.status = "not_implemented"
    async with session_scope() as s:
        system = await s.get(System, sid)
        ksi_ident = {k.id: k.identifier for k in (await s.execute(select(KSI))).scalars()}
        row = await monitoring.scan_system(s, system, ksi_ident=ksi_ident)  # type: ignore[arg-type]
    # KSI-IAM-ELP regressed pass -> fail, but Class A does not owe it; the
    # owed KSI-IAM-APM falls to manual review, which is not a regression.
    assert row["regressions"] == 0


def test_class_a_is_not_conditional_on_type() -> None:
    sc = ap.for_class(rules.load_rules(), "A", "program")
    assert not sc.conditional_on_20x  # no Rev5 subset lists Class A
    assert "20x only" in sc.basis


def test_the_agency_path_settles_it_even_without_a_class() -> None:
    sc = ap.for_class(rules.load_rules(), None, "agency")
    assert {a.status for a in sc.by_identifier.values()} == {"not_required"}


async def test_class_a_vvk_counts_ksis_with_any_method_not_all_of_them() -> None:
    sid = await _system("A")
    async with session_scope() as s:
        score = await readiness.score_system(s, system_id=sid, persist=False)
    auto = score["automation_requirement"]
    assert auto["min_automated_methods_per_ksi"] == 0
    assert auto["ksis_meeting"] == 0 and auto["ksis_owed"] == 7
