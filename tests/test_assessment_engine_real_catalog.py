"""Real-catalog fixture -- the test gap that let all three Criticals ship.

Every other assessment-engine test module seeds a synthetic 3-4 row control
group (``ZQ-``/``AEJ-``/``ZAE-`` prefixes across the sibling test modules).
That is exactly why none of the following surfaced before a whole-branch
review ran the engine against the catalog it actually ships with:

* CRITICAL 1 -- a partially-evaluated control proposed ``satisfied`` -- cannot
  be distinguished from a fully-evaluated one on a 3-row fixture where every
  row is hand-scripted to succeed.
* CRITICAL 2 -- the ``assessment_engine_max_objectives_per_control`` guard
  rejecting the catalog's own largest, highest-value controls -- never
  triggers on 3-4 rows; it only bites at real-catalog scale (AC-4 alone has
  98 sub-clause objectives).
* CRITICAL 3 -- a duplicate ``ap_acronym`` aborting the whole control -- needs
  two rows in the same control group to actually collide on
  ``ap_acronym``, which no hand-written 3-4 row fixture happened to include.

This module seeds a small extracted slice of the real workbook
(``data/NIST Cross Mappings Rev. 1.1.xlsx``), not the whole 27MB file --
ingesting it at test time for the handful of rows this module needs would
make every run of this module slow for no benefit.
``tests/fixtures/assessment_engine_real_catalog.json`` was extracted once,
offline, by replaying ``etl/pipeline.py``'s own column mapping (``Sequence
Control`` -> ``sequence_control``, ``AP Acronym (from IGAP Control Export on
RMF KS)`` -> ``ap_acronym``, ``assessment-objective`` -> ``assessment_objective``,
``control-name`` -> ``control_name``) and ``ccf.assessment.engine.objectives``'s
own definition of a sub-clause row (``control_name`` empty, ``assessment_objective``
populated) against the real workbook -- so what is seeded here is exactly what
a real ingest run produces for these two controls, not a hand-written
approximation of it.

Two controls:

* **AC-1** -- 25 real sub-clause rows. Two of them share the ap_acronym
  "AC-01a" in the real workbook (confirmed live, and this is exactly
  CRITICAL 3's reproduction case).
* **AC-3** -- 65 real sub-clause rows once its numbered enhancements
  (``AC-03(15)`` etc., whose own ``sequence_control`` values normalize down to
  "AC-3" -- see ``ccf.prep.screen.normalize_control_identifier``) are folded
  in by ``objectives_for`` the same way a real evaluation encounters them.
  Comfortably above the old 60-objective default guard (CRITICAL 2) and
  still below the new 150 one -- proof the new default actually clears a
  real, large control, not just a number picked to exceed another number.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import delete

from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.objectives import objectives_for
from ccf.assessment.engine.service import evaluate_control_proposal, open_control_proposal
from ccf.db import session_scope
from ccf.models import Assessment, Control, Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine")

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "assessment_engine_real_catalog.json"
_REAL_ROWS: dict[str, list[dict[str, Any]]] = json.loads(_FIXTURE_PATH.read_text())

#: sequence_control prefixes this module's own seeded rows carry -- used both
#: to seed and to clean up, mirroring every sibling module's own prefix
#: convention (ZQ-/AEJ-/ZAE-) except this one is real, not invented.
_SEQ_PREFIXES = ("AC-01", "AC-03")


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    """Seed the extracted real AC-1 and AC-3 sub-clause rows verbatim."""
    async with session_scope() as s:
        for prefix in _SEQ_PREFIXES:
            await s.execute(delete(Control).where(Control.sequence_control.like(f"{prefix}%")))
        for key in ("AC-1", "AC-3"):
            for i, row in enumerate(_REAL_ROWS[key]):
                s.add(
                    Control(
                        # Real `identifier` values are not guaranteed unique
                        # across the two extracted groups (they are only
                        # guaranteed unique catalog-wide by etl/pipeline.py's
                        # own "#row{idx}" collision handling, which this
                        # fixture -- deliberately not a full ingest -- does
                        # not replay). Suffixed here instead so this module's
                        # own seed can never collide with itself or a
                        # concurrently seeded control from another module.
                        identifier=f"{row['identifier']}#realfixture-{key}-{i}",
                        sequence_control=row["sequence_control"],
                        ap_acronym=row["ap_acronym"],
                        assessment_objective=row["assessment_objective"],
                        source_row=row["row_idx"],
                    )
                )
        await s.flush()
    yield
    async with session_scope() as s:
        for prefix in _SEQ_PREFIXES:
            await s.execute(delete(Control).where(Control.sequence_control.like(f"{prefix}%")))


async def _assessment(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"{name}-system")
        s.add(system)
        await s.flush()
        assessment = Assessment(system_id=system.id, name=f"{name}-assessment", kind="self")
        s.add(assessment)
        await s.flush()
        return int(org.id), int(assessment.id)


def _fake_evaluate_always(verdict: str = "satisfied"):
    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        return ObjectiveEvaluation(verdict=verdict, rationale="ok", confidence=0.5)

    return _fake


# --- objectives_for against the real rows -------------------------------------


async def test_ac1_yields_every_real_sub_clause_row() -> None:
    async with session_scope() as s:
        objectives = await objectives_for(s, "AC-1")
    assert len(objectives) == len(_REAL_ROWS["AC-1"])


async def test_ac1s_duplicate_ap_acronym_does_not_produce_duplicate_labels() -> None:
    """CRITICAL 3's reproduction case, against the real rows, not a synthetic
    stand-in (see test_assessment_objectives.py for the synthetic version).
    """
    async with session_scope() as s:
        objectives = await objectives_for(s, "AC-1")
    labels = [o.label for o in objectives]
    assert len(labels) == len(set(labels)), f"duplicate labels survived: {labels}"
    assert labels.count("AC-01a") == 1, "only one row may keep the catalog-supplied label"


async def test_ac3_exceeds_the_old_default_guard_and_clears_the_new_one() -> None:
    """CRITICAL 2: AC-3's 65 real sub-clause objectives (base control plus its
    numbered enhancements, folded together by normalize_control_identifier)
    exceeded the old 60-objective default -- this control could never be
    evaluated before that default was raised to 150.
    """
    async with session_scope() as s:
        objectives = await objectives_for(s, "AC-3")
    assert len(objectives) == len(_REAL_ROWS["AC-3"])
    assert len(objectives) > 60


# --- evaluate_control_proposal against the real rows --------------------------


async def test_evaluate_control_proposal_completes_for_ac1_despite_the_real_duplicate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The actual regression: without CRITICAL 3's fix, evaluating AC-1
    against the real catalog raised straight out of evaluate_control_proposal
    the moment the second "AC-01a" row's insert violated
    uq_objective_proposal_label -- the whole control failed, not just one
    objective.
    """
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always())
    _, assessment_id = await _assessment("real-catalog-ac1")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="AC-1"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        state = proposal.state
        objectives_total = proposal.objectives_total
        objectives_evaluated = proposal.objectives_evaluated
        proposed_finding = proposal.proposed_finding

    assert state == "complete"
    assert objectives_total == len(_REAL_ROWS["AC-1"])
    assert objectives_evaluated == len(_REAL_ROWS["AC-1"])
    assert proposed_finding == "satisfied"


async def test_evaluate_control_proposal_completes_for_ac3_above_the_old_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRITICAL 2's regression, end to end: AC-3's 65 real objectives must
    reach evaluate_control_proposal and complete, not be rejected by the
    max-objectives guard the way they would have been at the old default.
    """
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always())
    _, assessment_id = await _assessment("real-catalog-ac3")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="AC-3"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        state = proposal.state
        objectives_total = proposal.objectives_total
        objectives_evaluated = proposal.objectives_evaluated

    assert state == "complete"
    assert objectives_total == len(_REAL_ROWS["AC-3"])
    assert objectives_total > 60
    assert objectives_evaluated == objectives_total
