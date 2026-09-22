"""Objective-grain findings in the OSCAL SAR.

The docx SAR (``ccf.assessment.sar.generate_sar_docx``) has always rendered
objective-level findings out of ``AssessmentControlResult.objective_findings``;
``build_sar_doc`` was strictly control-level and read a different table
(``AssessmentResult``) entirely, so the *machine-readable* artifact -- the one
an assessor ingests -- was the coarser of the two.

Covers:

- objective-grain findings targeting ``<cid>_smt.<label>``, the same shape
  ``build_ssp_doc`` already emits for sub-statements;
- the control-level fallback for assessments that predate the engine;
- ``insufficient_evidence`` never rendering as a satisfied OSCAL state;
- the ETL's ``#rowN`` de-dup artifact never reaching the document;
- both vocabularies that ``AssessmentControlResult.control_id`` actually
  carries (CMMC ``ZN.L2-9.9.1`` and 800-53 canonical ``ZN-01``) resolving
  against ``Control.identifier``;
- the acceptance projection carrying an assessor-citable rationale while
  deliberately leaving the model's confidence score behind.

Owns the ``ZN-`` identifier prefix (``Control.identifier`` is globally UNIQUE
across the shared test database -- ``ZP-``/``ZK-``/``ZQ-`` are taken by
sibling modules).

No migration: every column read here already exists.
"""

from __future__ import annotations

import json
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.api.routes.oscal import _OSCAL_FINDING_STATE, build_sar_doc
from ccf.assessment.engine.objectives import objective_sha256
from ccf.assessment.engine.service import accept_control_proposal
from ccf.config import get_settings
from ccf.constants import NOT_ASSESSED, OTHER_THAN_SATISFIED, normalize_finding
from ccf.db import session_scope
from ccf.models import (
    Assessment,
    AssessmentControlResult,
    AssessmentResult,
    Control,
    ControlImplementation,
    Organization,
    System,
)
from ccf.models_assessment_engine import (
    AssessmentControlProposal,
    AssessmentObjectiveProposal,
)
from ccf.oscal import validate_document

pytestmark = pytest.mark.usefixtures("fresh_engine")

#: This module's own control-identifier namespace. ``Control.identifier`` is
#: globally UNIQUE, so a collision here fails only under the full suite.
_C80053 = "ZN-1"  # canonicalizes; the ACR row spells it padded, "ZN-01"
_CPLAIN = "ZN-2"  # no objective findings -> control-level fallback
_CCMMC = "ZN.L2-9.9.1"  # does NOT canonicalize; lowercased verbatim


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _control(s, identifier: str) -> Control:
    """Fetch-or-create; ``Control.identifier`` is globally UNIQUE."""
    ctrl = (
        await s.execute(select(Control).where(Control.identifier == identifier))
    ).scalar_one_or_none()
    if ctrl is None:
        ctrl = Control(identifier=identifier, control_name=f"{identifier} control title")
        s.add(ctrl)
        await s.flush()
    return ctrl


async def _build_fixture(org_name: str) -> tuple[int, int]:
    """Org + System + three implemented controls + an Assessment carrying one
    ``AssessmentResult`` each, plus ``AssessmentControlResult`` objective rows
    for two of them (one per ``control_id`` vocabulary). Returns
    ``(system_id, assessment_id)``."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"{org_name} system")
        s.add(sysrow)
        await s.flush()

        impls: dict[str, ControlImplementation] = {}
        for identifier in (_C80053, _CPLAIN, _CCMMC):
            ctrl = await _control(s, identifier)
            impl = ControlImplementation(
                system_id=sysrow.id, control_id=ctrl.id, status="implemented"
            )
            s.add(impl)
            await s.flush()
            impls[identifier] = impl

        assessment = Assessment(
            system_id=sysrow.id,
            name=f"{org_name} assessment",
            kind="internal",
            assessor="Jane 3PAO",
            started_on=date.today() - timedelta(days=5),
            finished_on=date.today(),
            summary="Objective-grain assessment.",
        )
        s.add(assessment)
        await s.flush()

        for identifier, finding in (
            (_C80053, "other_than_satisfied"),
            (_CPLAIN, "satisfied"),
            (_CCMMC, "other_than_satisfied"),
        ):
            s.add(
                AssessmentResult(
                    assessment_id=assessment.id,
                    implementation_id=impls[identifier].id,
                    finding=finding,
                    rationale=f"{identifier} control-level rationale.",
                    observed_on=date.today(),
                )
            )

        # 800-53 vocabulary, spelled PADDED ("ZN-01") against a control whose
        # identifier is unpadded ("ZN-1") -- the join must fold both.
        s.add(
            AssessmentControlResult(
                assessment_id=assessment.id,
                control_id="ZN-01",
                nist_id="ZN-1",
                finding="other_than_satisfied",
                objective_findings=[
                    {
                        "label": "ZN-01a.[01]",
                        "text": "the policy is disseminated to defined personnel;",
                        "finding": "satisfied",
                        "rationale": "Distribution list reviewed against the roster.",
                    },
                    {
                        "label": "ZN-01a.[02]",
                        "text": "an official to manage the policy is designated;",
                        "finding": "not_satisfied",
                        "rationale": "No designated official named in the policy.",
                    },
                    {
                        "label": "ZN-01b.",
                        "text": "the policy is reviewed at a defined frequency;",
                        "finding": "insufficient_evidence",
                        "rationale": "Review cadence could not be determined.",
                    },
                    {
                        # The ETL's de-dup artifact, as it would arrive from a
                        # workbook with a repeated identifier.
                        "label": "ZN-01c.#row417",
                        "text": "the procedures address the policy;",
                        "finding": "not_applicable",
                    },
                ],
            )
        )
        # CMMC vocabulary, matching Control.identifier verbatim.
        s.add(
            AssessmentControlResult(
                assessment_id=assessment.id,
                control_id=_CCMMC,
                nist_id="9.9.1",
                finding="other_than_satisfied",
                objective_findings=[
                    {
                        "label": "[a]",
                        "text": "system use is authorized;",
                        "finding": "satisfied",
                    },
                    {
                        "label": "[b]",
                        "text": "authorizations are documented;",
                        "finding": "not_satisfied",
                    },
                ],
            )
        )
        await s.flush()
        return sysrow.id, assessment.id


async def _sar(assessment_id: int) -> dict:
    async with session_scope() as s:
        assessment = await s.get(Assessment, assessment_id)
        assert assessment is not None
        return await build_sar_doc(s, assessment)


def _findings(doc: dict) -> list[dict]:
    return doc["assessment-results"]["results"][0]["findings"]


def _targets(doc: dict) -> list[str]:
    return [f["target"]["target-id"] for f in _findings(doc)]


# ---------------------------------------------------------------------------
# 1. Objective grain reaches the machine-readable artifact.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_objective_findings_emit_statement_level_targets() -> None:
    _sys_id, assessment_id = await _build_fixture("SAR Objective Grain Org")
    doc = await _sar(assessment_id)

    targets = _targets(doc)
    # ZN-1 has four objectives -> four findings, each at statement grain.
    zn1 = [t for t in targets if t.startswith("zn-1_smt")]
    assert zn1 == [
        "zn-1_smt.ZN-01a.01",
        "zn-1_smt.ZN-01a.02",
        "zn-1_smt.ZN-01b.",
        "zn-1_smt.ZN-01c.",
    ], targets
    # The whole-statement target is GONE for a control that has objectives --
    # the coarse finding is superseded, not duplicated.
    assert "zn-1_smt" not in targets

    # Every objective finding still carries the control's title and its own
    # label, and an assessor-citable description.
    by_target = {f["target"]["target-id"]: f for f in _findings(doc)}
    first = by_target["zn-1_smt.ZN-01a.01"]
    assert "ZN-01a.[01]" in first["title"]
    assert first["description"] == "Distribution list reviewed against the roster."
    assert first["target"]["status"]["state"] == "satisfied"
    assert by_target["zn-1_smt.ZN-01a.02"]["target"]["status"]["state"] == "not-satisfied"

    report = validate_document(doc)
    assert report.mode == "official", report.warnings
    assert report.ok, report.errors


# ---------------------------------------------------------------------------
# 2. No regression for assessments that predate the engine.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_control_without_objective_findings_keeps_control_level_finding() -> None:
    _sys_id, assessment_id = await _build_fixture("SAR Objective Fallback Org")
    doc = await _sar(assessment_id)

    targets = _targets(doc)
    assert "zn-2_smt" in targets, targets
    assert not [t for t in targets if t.startswith("zn-2_smt.")], targets

    finding = next(f for f in _findings(doc) if f["target"]["target-id"] == "zn-2_smt")
    assert finding["description"] == f"{_CPLAIN} control-level rationale."
    assert finding["target"]["status"]["state"] == "satisfied"


@pytest.mark.asyncio
async def test_assessment_with_no_objective_rows_at_all_is_unchanged() -> None:
    """An assessment whose every control predates the engine still emits one
    finding per AssessmentResult, exactly as before."""
    _sys_id, assessment_id = await _build_fixture("SAR Objective NoRows Org")
    async with session_scope() as s:
        await s.execute(
            delete(AssessmentControlResult).where(
                AssessmentControlResult.assessment_id == assessment_id
            )
        )
    doc = await _sar(assessment_id)
    assert sorted(_targets(doc)) == ["zn-1_smt", "zn-2_smt", "zn.l2-9.9.1_smt"]

    report = validate_document(doc)
    assert report.mode == "official", report.warnings
    assert report.ok, report.errors


# ---------------------------------------------------------------------------
# 3. insufficient_evidence is never a satisfied claim.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_insufficient_evidence_never_becomes_a_satisfied_state() -> None:
    _sys_id, assessment_id = await _build_fixture("SAR Objective Insufficient Org")
    doc = await _sar(assessment_id)

    finding = next(f for f in _findings(doc) if f["target"]["target-id"] == "zn-1_smt.ZN-01b.")
    state = finding["target"]["status"]["state"]
    assert state != "satisfied"
    assert state == "not-satisfied"
    # ... and it stays distinguishable from a real failure, rather than being
    # silently laundered into one.
    props = {p["name"]: p["value"] for p in finding.get("props", [])}
    assert props.get("determination") == "insufficient-evidence"
    # A genuine not_satisfied objective carries no such qualifier.
    failed = next(f for f in _findings(doc) if f["target"]["target-id"] == "zn-1_smt.ZN-01a.02")
    assert "determination" not in {p["name"] for p in failed.get("props", [])}


def test_insufficient_evidence_maps_to_no_determination_not_a_pass() -> None:
    """Asserted directly on the normaliser + the OSCAL state map, so the
    guarantee holds for every caller, not just the SAR."""
    assert normalize_finding("insufficient_evidence") == NOT_ASSESSED
    assert _OSCAL_FINDING_STATE[NOT_ASSESSED] != "satisfied"
    assert _OSCAL_FINDING_STATE[normalize_finding("insufficient_evidence")] == "not-satisfied"
    # The other objective-verdict spelling with no DB-enum equivalent.
    assert normalize_finding("not_satisfied") == OTHER_THAN_SATISFIED
    assert _OSCAL_FINDING_STATE[normalize_finding("not_satisfied")] == "not-satisfied"


# ---------------------------------------------------------------------------
# 4. The ETL's de-dup artifact never reaches a federal artifact.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rown_dedup_artifact_never_appears_in_the_document() -> None:
    _sys_id, assessment_id = await _build_fixture("SAR Objective RowN Org")
    doc = await _sar(assessment_id)

    blob = json.dumps(doc)
    assert "#row417" not in blob
    # Not merely the '#': the ETL's row ordinal must not survive sanitization
    # either (``_oscal_token`` alone would turn "#row417" into "row417").
    assert "row417" not in blob
    assert "zn-1_smt.ZN-01c." in _targets(doc)


# ---------------------------------------------------------------------------
# 5. Both control_id vocabularies resolve -- asserted separately.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cmmc_vocabulary_control_id_resolves() -> None:
    _sys_id, assessment_id = await _build_fixture("SAR Objective CMMC Vocab Org")
    targets = _targets(await _sar(assessment_id))
    assert [t for t in targets if t.startswith("zn.l2-9.9.1_smt.")] == [
        "zn.l2-9.9.1_smt.a",
        "zn.l2-9.9.1_smt.b",
    ], targets


@pytest.mark.asyncio
async def test_80053_vocabulary_control_id_resolves_across_padding() -> None:
    """``AssessmentControlResult.control_id`` holds "ZN-01" while
    ``Control.identifier`` holds "ZN-1" -- one canonicalizer must fold both."""
    _sys_id, assessment_id = await _build_fixture("SAR Objective 80053 Vocab Org")
    targets = _targets(await _sar(assessment_id))
    assert [t for t in targets if t.startswith("zn-1_smt.")], targets


# ---------------------------------------------------------------------------
# 6. The acceptance projection: what it carries, and what it leaves behind.
# ---------------------------------------------------------------------------


_ZN3_OBJECTIVES = (
    ("ZN-03a.", "the policy is disseminated;"),
    ("ZN-03b.", "an official is designated;"),
)


@pytest.fixture
async def _zn3_catalog():
    """Catalog rows for ZN-3, so ``accept_control_proposal``'s staleness
    recomputation has a live counterpart for every stored objective. Without
    them every stored label is absent from the catalog and acceptance refuses
    the proposal as stale before the projection ever runs."""
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == "ZN-3"))
        s.add(
            Control(
                identifier="ZN-3",
                sequence_control="ZN-3",
                control_name="Projection Policy",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        for i, (label, text) in enumerate(_ZN3_OBJECTIVES, start=2):
            s.add(
                Control(
                    identifier=label,
                    sequence_control="ZN-3",
                    assessment_objective=text,
                    source_row=i,
                )
            )
    try:
        yield
    finally:
        async with session_scope() as s:
            await s.execute(delete(Control).where(Control.sequence_control == "ZN-3"))


@pytest.mark.asyncio
async def test_accepted_proposal_carries_rationale_and_leaves_confidence_behind(
    _zn3_catalog,
) -> None:
    async with session_scope() as s:
        org = Organization(name="SAR Objective Projection Org")
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name="Projection system")
        s.add(sysrow)
        await s.flush()
        assessment = Assessment(
            system_id=sysrow.id, name="Projection assessment", kind="internal"
        )
        s.add(assessment)
        await s.flush()

        proposal = AssessmentControlProposal(
            organization_id=org.id,
            assessment_id=assessment.id,
            control_identifier="ZN-3",
            state="complete",
            proposed_finding="other_than_satisfied",
            rollup_rationale="2 objective(s): 1 satisfied, 1 not_satisfied.",
        )
        s.add(proposal)
        await s.flush()
        s.add(
            AssessmentObjectiveProposal(
                organization_id=org.id,
                control_proposal_id=proposal.id,
                label=_ZN3_OBJECTIVES[0][0],
                objective_text=_ZN3_OBJECTIVES[0][1],
                objective_text_sha256=objective_sha256(_ZN3_OBJECTIVES[0][1]),
                sort_order=0,
                verdict="not_satisfied",
                rationale="The distribution list omits the contractor staff in scope.",
                gaps=["No evidence of dissemination to contractors."],
                contradictions=["Policy says annual; the log shows one review in three years."],
                cited_unit_ids=[11, 12],
                model_name="test-model",
                model_confidence=0.91,
                primary_verdict="satisfied",
                challenger_verdict="not_satisfied",
                challenger_rationale="The cited passage covers employees only.",
            )
        )
        s.add(
            AssessmentObjectiveProposal(
                organization_id=org.id,
                control_proposal_id=proposal.id,
                label=_ZN3_OBJECTIVES[1][0],
                objective_text=_ZN3_OBJECTIVES[1][1],
                objective_text_sha256=objective_sha256(_ZN3_OBJECTIVES[1][1]),
                sort_order=1,
                verdict="satisfied",
                rationale="Named in section 2.",
                model_confidence=0.55,
            )
        )
        await s.flush()
        proposal_id = proposal.id
        assessment_id = assessment.id

    async with session_scope() as s:
        await accept_control_proposal(s, proposal_id=proposal_id, accepted_by="assessor@test")

    async with session_scope() as s:
        result = (
            await s.execute(
                select(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == assessment_id
                )
            )
        ).scalar_one()
        parts = list(result.objective_findings)

    assert [p["label"] for p in parts] == ["ZN-03a.", "ZN-03b."]
    first = parts[0]

    # Carried: the determination and everything an assessor could cite.
    assert first["finding"] == "not_satisfied"
    assert first["rationale"] == "The distribution list omits the contractor staff in scope."
    assert first["gaps"] == ["No evidence of dissemination to contractors."]
    assert first["contradictions"] == [
        "Policy says annual; the log shows one review in three years."
    ]
    assert first["cited_unit_ids"] == [11, 12]
    # Carried: that a disagreement happened, and what was argued.
    assert first["dissent"] == {
        "primary_verdict": "satisfied",
        "challenger_verdict": "not_satisfied",
        "challenger_rationale": "The cited passage covers employees only.",
    }

    # Deliberately left behind -- asserted absent, both keys, on every part.
    for part in parts:
        assert "model_confidence" not in part
        assert "model_name" not in part
    blob = json.dumps(parts)
    assert "0.91" not in blob
    assert "test-model" not in blob

    # An objective with no dissent and no gaps carries neither key rather than
    # an empty one an assessor could misread as "checked, nothing found".
    second = parts[1]
    assert "dissent" not in second
    assert "gaps" not in second
    assert second["rationale"] == "Named in section 2."


@pytest.mark.asyncio
async def test_carried_rationale_is_what_the_oscal_finding_states() -> None:
    """The projection and the document agree: the rationale an assessor wrote
    is the finding description, and the model's confidence is in neither."""
    _sys_id, assessment_id = await _build_fixture("SAR Objective Rationale Org")
    doc = await _sar(assessment_id)
    finding = next(f for f in _findings(doc) if f["target"]["target-id"] == "zn-1_smt.ZN-01a.02")
    assert finding["description"] == "No designated official named in the policy."
    # An objective with no rationale falls back to the objective text, never
    # to an empty description.
    na = next(f for f in _findings(doc) if f["target"]["target-id"] == "zn-1_smt.ZN-01c.")
    assert na["description"] == "the procedures address the policy;"


@pytest.mark.asyncio
async def test_assessor_ui_save_does_not_erase_the_carried_record() -> None:
    """The assessor form owns one field per objective. Rebuilding each part
    from the form used to drop everything else -- so the first UI save after
    an acceptance silently emptied the row the SAR is built from."""
    _sys_id, assessment_id = await _build_fixture("SAR Objective UI Save Org")
    async with session_scope() as s:
        result = (
            await s.execute(
                select(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == assessment_id,
                    AssessmentControlResult.control_id == "ZN-01",
                )
            )
        ).scalar_one()
        result_id = result.id

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(
            f"/assessments/{assessment_id}/result/{result_id}",
            data={"finding": "other_than_satisfied", "obj::ZN-01a.[01]": "not_satisfied"},
        )
        assert r.status_code == 200

    async with session_scope() as s:
        saved = await s.get(AssessmentControlResult, result_id)
        assert saved is not None
        parts = {p["label"]: p for p in saved.objective_findings}

    # The one field the form owns changed...
    assert parts["ZN-01a.[01]"]["finding"] == "not_satisfied"
    # ...and everything the projection carried survived it.
    assert parts["ZN-01a.[01]"]["rationale"] == "Distribution list reviewed against the roster."
    assert parts["ZN-01b."]["rationale"] == "Review cadence could not be determined."
    assert parts["ZN-01b."]["finding"] == "insufficient_evidence"


@pytest.mark.asyncio
async def test_dedup_stripping_never_produces_two_findings_on_one_target() -> None:
    """Stripping ``#rowN`` can collide a de-duplicated label with the one it
    was de-duplicated from. Two OSCAL findings on one target-id would be two
    determinations about the same objective, which is worse than the suffix."""
    _sys_id, assessment_id = await _build_fixture("SAR Objective Collision Org")
    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == assessment_id,
                    AssessmentControlResult.control_id == "ZN-01",
                )
            )
        ).scalar_one()
        row.objective_findings = [
            {"label": "ZN-01a.", "text": "first", "finding": "satisfied"},
            {"label": "ZN-01a.#row417", "text": "second", "finding": "not_satisfied"},
        ]

    targets = [t for t in _targets(await _sar(assessment_id)) if t.startswith("zn-1_smt.")]
    assert len(targets) == len(set(targets)), targets
    assert targets == ["zn-1_smt.ZN-01a.", "zn-1_smt.ZN-01a.-2"], targets
    assert "row417" not in json.dumps(await _sar(assessment_id))


@pytest.mark.asyncio
async def test_objective_with_no_label_degrades_to_the_statement_target() -> None:
    """A labelless objective targets the whole statement rather than an
    invented ``_unspecified`` sub-statement that no SSP would ever emit."""
    _sys_id, assessment_id = await _build_fixture("SAR Objective NoLabel Org")
    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == assessment_id,
                    AssessmentControlResult.control_id == "ZN-01",
                )
            )
        ).scalar_one()
        row.objective_findings = [{"label": "", "text": "unlabelled", "finding": "satisfied"}]

    doc = await _sar(assessment_id)
    assert "zn-1_smt" in _targets(doc)
    assert "unspecified" not in json.dumps(doc)


# ---------------------------------------------------------------------------
# 7. Official-schema conformance under the CI flag.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_objective_grain_sar_validates_under_required_official_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA", "1")
    get_settings.cache_clear()
    try:
        _sys_id, assessment_id = await _build_fixture("SAR Objective Official Org")
        doc = await _sar(assessment_id)
        report = validate_document(doc)
        assert report.mode == "official", report.warnings
        assert report.ok, report.errors
    finally:
        get_settings.cache_clear()
