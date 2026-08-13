"""Rejection columns and the calibration snapshot table."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from ccf.db import session_scope
from ccf.models import Assessment, Organization, System
from ccf.models_assessment_engine import (
    CORRECTED_FINDINGS,
    AssessmentControlProposal,
    CalibrationSnapshot,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _assessment(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"{name}-sys")
        s.add(system)
        await s.flush()
        a = Assessment(system_id=system.id, name=f"{name}-a", kind="self")
        s.add(a)
        await s.flush()
        return int(org.id), int(a.id)


def test_corrected_findings_excludes_insufficient_evidence() -> None:
    """An assessor correcting a verdict asserts what is true, never 'could not tell'."""
    assert CORRECTED_FINDINGS == ("satisfied", "other_than_satisfied", "not_applicable")
    assert "insufficient_evidence" not in CORRECTED_FINDINGS


async def test_rejection_columns_default_to_null() -> None:
    org_id, assessment_id = await _assessment("cal-defaults")
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
        )
        s.add(p)
        await s.flush()
        assert p.corrected_finding is None
        assert p.rejected_by is None
        assert p.rejected_at is None
        assert p.rejection_note is None


async def test_rejection_columns_round_trip() -> None:
    org_id, assessment_id = await _assessment("cal-roundtrip")
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id,
            assessment_id=assessment_id,
            control_identifier="AC-2",
            corrected_finding="other_than_satisfied",
            rejected_by="assessor@example.com",
            rejection_note="Policy predates the current boundary.",
        )
        s.add(p)
        await s.flush()
        pid = int(p.id)
    async with session_scope() as s:
        p = (
            await s.execute(
                select(AssessmentControlProposal).where(AssessmentControlProposal.id == pid)
            )
        ).scalar_one()
        assert p.corrected_finding == "other_than_satisfied"
        assert p.rejected_by == "assessor@example.com"
        assert p.rejection_note == "Policy predates the current boundary."


async def test_snapshot_stores_metrics_and_fingerprint() -> None:
    org_id, _ = await _assessment("cal-snapshot")
    async with session_scope() as s:
        snap = CalibrationSnapshot(
            organization_id=org_id,
            config_fingerprint="a" * 64,
            metrics={"decided": 10, "agreed": 8, "missed_findings": 1},
        )
        s.add(snap)
        await s.flush()
        assert snap.metrics["missed_findings"] == 1
        assert snap.computed_at is not None


async def test_snapshot_timestamp_is_not_null_in_live_schema() -> None:
    """Slice 1 shipped nullable timestamps the ORM declared non-null. Not again."""
    async with session_scope() as s:
        row = (
            await s.execute(
                text(
                    "SELECT is_nullable FROM information_schema.columns "
                    "WHERE table_schema='ccf' AND table_name='calibration_snapshots' "
                    "AND column_name='computed_at'"
                )
            )
        ).scalar_one()
    assert row == "NO"
