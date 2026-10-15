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
    for a in ap.for_class(rules.load_rules(), cls).values():
        got[a.status] = got.get(a.status, 0) + 1
    assert got == expected


def test_class_d_says_when_fedramp_published_no_wording() -> None:
    d = ap.for_class(rules.load_rules(), "D")
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
    assert ap.automated_methods({"kind": "control_state", "controls": ["IA-2"]}) == 1
    assert (
        ap.automated_methods(
            {
                "kind": "any_of",
                "rules": [
                    {"kind": "connector_capture", "captures": ["x"]},
                    {"kind": "manual"},
                    {"kind": "control_state", "controls": ["IA-2"]},
                ],
            }
        )
        == 2
    )


# --- consumers --------------------------------------------------------------


async def _system(cls: str | None) -> int:
    async with session_scope() as s:
        org = Organization(name=f"Class {cls} Org {next(_SEQ)}")
        s.add(org)
        await s.flush()
        sysm = System(
            organization_id=org.id, name=f"Class {cls} {next(_SEQ)}", certification_class=cls
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
    sid = await _system("C")
    async with session_scope() as s:
        shipped = await readiness.score_system(s, system_id=sid, persist=False)
    assert shipped["automation_requirement"] == {
        "rule": "FRC-CSX-VVK",
        "force": "MUST",
        "min_automated_methods_per_ksi": 2,
        "ksis_meeting": 0,  # the shipped overlay authors no rule
        "ksis_owed": 46,
    }
    async with session_scope() as s:
        await catalog.seed_ksis(s, overlay_path=_ENGINE_RULES)
        engine = await readiness.score_system(s, system_id=sid, persist=False)
    # Three test rules are any_of[capture, control_state]: two methods each.
    assert engine["automation_requirement"]["ksis_meeting"] == 3


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
    assert "Scored on the 7 KSIs FedRAMP requires of a Class A offering" in page_a
    assert "39 not required for this class" in page_a
    assert "not required, Class A" in page_a
    assert "No Certification Class is recorded" in page_none
    assert "—%" not in page_a and "—%" not in page_none
