"""ISSM-13 / DATA-05: canonical finding-status vocabulary + cross-source rollup.

"Finding" status is modeled three different ways in the schema:

- ``AssessmentResult.finding`` — a DB enum {satisfied, other_than_satisfied,
  not_applicable}.
- ``AssessmentControlResult.finding`` — a free ``String`` including
  ``not_assessed``.
- ``ScoringStatus.state`` — a free ``String`` SPRS implementation-state
  vocabulary (not_assessed, not_implemented, planned, partial, implemented,
  inherited, not_applicable).

Covers:
- ``ccf.constants.normalize_finding`` maps every known variant from all three
  sources (plus None/unknown) onto the single canonical vocabulary.
- ``ccf.analytics.findings.canonical_finding_counts`` rolls up a
  mixed-vocabulary iterable of raw values into consistent canonical counts
  (pure function, no DB).
- ``ccf.analytics.findings.system_finding_rollup`` does the same against real
  rows across all three DB sources for one system — a row stored as
  ``other_than_satisfied`` (AssessmentControlResult) and a row stored as
  ``not_implemented`` (ScoringStatus) both count as the same canonical
  "other_than_satisfied" bucket, and per-source storage/values are untouched.

No DB migration — this is app-layer normalization only.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.analytics.findings import canonical_finding_counts, system_finding_rollup
from ccf.config import get_settings
from ccf.constants import (
    NOT_APPLICABLE,
    NOT_ASSESSED,
    OTHER_THAN_SATISFIED,
    SATISFIED,
    UNKNOWN,
    normalize_finding,
)
from ccf.db import session_scope
from ccf.models import (
    Assessment,
    AssessmentControlResult,
    AssessmentResult,
    Control,
    ControlImplementation,
    Organization,
    ScoringControl,
    ScoringStatus,
    System,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# --- normalize_finding --------------------------------------------------------


def test_normalize_finding_assessment_result_enum_values() -> None:
    """AssessmentResult's DB enum vocabulary maps to itself."""
    assert normalize_finding("satisfied") == SATISFIED
    assert normalize_finding("other_than_satisfied") == OTHER_THAN_SATISFIED
    assert normalize_finding("not_applicable") == NOT_APPLICABLE


def test_normalize_finding_assessment_control_result_free_string() -> None:
    """AssessmentControlResult's free string vocabulary (adds not_assessed)."""
    assert normalize_finding("satisfied") == SATISFIED
    assert normalize_finding("other_than_satisfied") == OTHER_THAN_SATISFIED
    assert normalize_finding("not_applicable") == NOT_APPLICABLE
    assert normalize_finding("not_assessed") == NOT_ASSESSED


def test_normalize_finding_scoring_status_states() -> None:
    """ScoringStatus.state's SPRS implementation-state vocabulary."""
    assert normalize_finding("implemented") == SATISFIED
    assert normalize_finding("inherited") == SATISFIED
    assert normalize_finding("not_implemented") == OTHER_THAN_SATISFIED
    assert normalize_finding("planned") == OTHER_THAN_SATISFIED
    assert normalize_finding("partial") == OTHER_THAN_SATISFIED
    assert normalize_finding("not_applicable") == NOT_APPLICABLE
    assert normalize_finding("not_assessed") == NOT_ASSESSED


def test_normalize_finding_none_maps_to_not_assessed() -> None:
    assert normalize_finding(None) == NOT_ASSESSED
    assert normalize_finding("") == NOT_ASSESSED
    assert normalize_finding("   ") == NOT_ASSESSED


def test_normalize_finding_unknown_value_maps_to_unknown_not_crash() -> None:
    assert normalize_finding("bogus") == UNKNOWN
    assert normalize_finding("pass") == UNKNOWN


def test_normalize_finding_case_and_whitespace_insensitive() -> None:
    assert normalize_finding(" Satisfied ") == SATISFIED
    assert normalize_finding("IMPLEMENTED") == SATISFIED


# --- canonical_finding_counts (pure rollup) -----------------------------------


def test_canonical_finding_counts_mixed_vocabulary_consistent() -> None:
    """A mixed-vocabulary set rolls up to consistent canonical counts.

    'other_than_satisfied' (assessment vocabulary) and 'not_implemented'
    (scoring vocabulary) both land in the same canonical bucket.
    """
    raw = [
        "satisfied",
        "implemented",  # -> satisfied
        "inherited",  # -> satisfied
        "other_than_satisfied",
        "not_implemented",  # -> other_than_satisfied
        "planned",  # -> other_than_satisfied
        "partial",  # -> other_than_satisfied
        "not_applicable",
        "not_assessed",
        None,  # -> not_assessed
        "totally_bogus",  # -> unknown
    ]
    counts = canonical_finding_counts(raw)
    assert counts[SATISFIED] == 3
    assert counts[OTHER_THAN_SATISFIED] == 4
    assert counts[NOT_APPLICABLE] == 1
    assert counts[NOT_ASSESSED] == 2
    assert counts[UNKNOWN] == 1
    assert sum(counts.values()) == len(raw)


def test_canonical_finding_counts_empty_iterable_zero_fills_all_buckets() -> None:
    counts = canonical_finding_counts([])
    assert counts[SATISFIED] == 0
    assert counts[OTHER_THAN_SATISFIED] == 0
    assert counts[NOT_APPLICABLE] == 0
    assert counts[NOT_ASSESSED] == 0
    assert counts[UNKNOWN] == 0


# --- system_finding_rollup (DB-backed cross-source rollup) --------------------


async def _seed_system(tag: str) -> tuple[int, int, int, int]:
    """One system with a Control/ControlImplementation and a ScoringControl.

    ``tag`` keeps names/identifiers unique across tests sharing a persistent
    test DB (no per-test reset — see ``clean_migrated_db`` in conftest.py).
    """
    async with session_scope() as s:
        org = Organization(name=f"FindingVocabOrg-{tag}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"FindingVocabSys-{tag}", baseline="moderate")
        s.add(sysm)
        ctl = Control(identifier=f"AC-2-fv-{tag}")
        s.add(ctl)
        await s.flush()
        impl = ControlImplementation(system_id=sysm.id, control_id=ctl.id)
        s.add(impl)
        sc = ScoringControl(
            control_id=f"AC.L2-3.1.1-fv-{tag}", domain="AC", point_value="5", title="fv practice"
        )
        s.add(sc)
        await s.flush()
        return sysm.id, ctl.id, impl.id, sc.id


@pytest.mark.asyncio
async def test_system_finding_rollup_combines_mixed_vocabulary_sources() -> None:
    system_id, _ctl_id, impl_id, scoring_control_id = await _seed_system("mixed")

    async with session_scope() as s:
        assessment = Assessment(system_id=system_id, name="FV Assessment", kind="self")
        s.add(assessment)
        await s.flush()

        # AssessmentResult (DB enum) — one satisfied, one other_than_satisfied.
        s.add_all(
            [
                AssessmentResult(
                    assessment_id=assessment.id, implementation_id=impl_id, finding="satisfied"
                ),
            ]
        )

        # AssessmentControlResult (free string) — a differently-sourced
        # 'other_than_satisfied' plus one not_assessed.
        s.add_all(
            [
                AssessmentControlResult(
                    assessment_id=assessment.id,
                    control_id="AC.L2-3.1.1-fv-mixed",
                    finding="other_than_satisfied",
                ),
                AssessmentControlResult(
                    assessment_id=assessment.id,
                    control_id="AC.L2-3.1.2-fv-mixed",
                    finding="not_assessed",
                ),
            ]
        )

        # ScoringStatus (free string, SPRS vocabulary) — 'not_implemented' is
        # a *different spelling* of the same canonical "other_than_satisfied"
        # bucket as the AssessmentControlResult row above.
        s.add(
            ScoringStatus(
                system_id=system_id, scoring_control_id=scoring_control_id, state="not_implemented"
            )
        )

    async with session_scope() as s:
        rollup = await system_finding_rollup(s, system_id)

    assert rollup["system_id"] == system_id
    assert rollup["total"] == 4
    canonical = rollup["canonical"]
    # satisfied: 1 (AssessmentResult)
    assert canonical[SATISFIED] == 1
    # other_than_satisfied: 1 (AssessmentControlResult) + 1 (ScoringStatus,
    # different spelling) == 2 — the whole point of the normalization.
    assert canonical[OTHER_THAN_SATISFIED] == 2
    assert canonical[NOT_ASSESSED] == 1
    assert canonical[NOT_APPLICABLE] == 0
    assert sum(canonical.values()) == rollup["total"]

    # Per-source storage is untouched: raw AssessmentControlResult.finding
    # values are exactly what was written, not normalized in place.
    async with session_scope() as s:
        raw_findings = (
            (
                await s.execute(
                    select(AssessmentControlResult.finding).where(
                        AssessmentControlResult.assessment_id == assessment.id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert set(raw_findings) == {"other_than_satisfied", "not_assessed"}

    # Per-source breakdown in the rollup output still shows each source's own
    # (already-normalized-per-bucket) counts, for visibility.
    by_source = rollup["by_source"]
    assert by_source["assessment_results"][SATISFIED] == 1
    assert by_source["assessment_control_results"][OTHER_THAN_SATISFIED] == 1
    assert by_source["assessment_control_results"][NOT_ASSESSED] == 1
    assert by_source["scoring_statuses"][OTHER_THAN_SATISFIED] == 1


@pytest.mark.asyncio
async def test_system_finding_rollup_empty_system_all_zero() -> None:
    system_id, _ctl_id, _impl_id, _scoring_control_id = await _seed_system("empty")

    async with session_scope() as s:
        rollup = await system_finding_rollup(s, system_id)

    assert rollup["total"] == 0
    assert all(v == 0 for v in rollup["canonical"].values())
