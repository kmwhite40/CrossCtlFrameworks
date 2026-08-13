"""Configuration fingerprinting and stored calibration snapshots.

A metric is comparable to an earlier one only if what was being measured did
not change underneath it. These tests exercise the fingerprint itself (same
configuration digests identically; each of its five inputs actually moves
the digest) and the snapshot flow built on top of it (storage, org scoping,
and the comparison outcome -- "not comparable" is a distinct result, not a
number, when the fingerprints differ).
"""

from __future__ import annotations

import pytest

from ccf.assessment.engine import calibration
from ccf.assessment.engine.calibration import (
    compare_snapshots,
    config_fingerprint,
    take_snapshot,
)
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal, CalibrationSnapshot

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


async def _decided(
    org_id: int,
    assessment_id: int,
    control: str,
    proposed: str,
    *,
    accepted: bool,
    corrected: str | None = None,
) -> None:
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id,
                assessment_id=assessment_id,
                control_identifier=control,
                state="accepted" if accepted else "rejected",
                proposed_finding=proposed,
                corrected_finding=corrected,
                rejected_by=None if accepted else "assessor@example.com",
                rejection_note=None if accepted else "wrong",
            )
        )


# ---------------------------------------------------------------------------
# The fingerprint itself
# ---------------------------------------------------------------------------


def test_the_same_configuration_fingerprints_identically() -> None:
    assert config_fingerprint(model="claude-sonnet-5") == config_fingerprint(
        model="claude-sonnet-5"
    )


def test_changing_the_screen_threshold_changes_the_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = config_fingerprint(model="claude-sonnet-5")
    monkeypatch.setenv("CCF_PREP_SCREEN_THRESHOLD", "0.91")
    get_settings.cache_clear()
    try:
        after = config_fingerprint(model="claude-sonnet-5")
    finally:
        get_settings.cache_clear()
    assert before != after


def test_changing_the_model_changes_the_fingerprint() -> None:
    a = config_fingerprint(model="claude-sonnet-5")
    b = config_fingerprint(model="claude-opus-5")
    assert a != b


def test_changing_the_rollup_policy_version_changes_the_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = config_fingerprint(model="claude-sonnet-5")
    monkeypatch.setattr(calibration, "ROLLUP_POLICY_VERSION", "v2-test")
    after = config_fingerprint(model="claude-sonnet-5")
    assert before != after


def test_toggling_dissent_enabled_changes_the_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = config_fingerprint(model="claude-sonnet-5")
    monkeypatch.setenv("CCF_ASSESSMENT_DISSENT_ENABLED", "true")
    get_settings.cache_clear()
    try:
        after = config_fingerprint(model="claude-sonnet-5")
    finally:
        get_settings.cache_clear()
    assert before != after


def test_changing_the_dissent_challenge_policy_version_changes_the_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = config_fingerprint(model="claude-sonnet-5")
    monkeypatch.setattr(calibration, "DISSENT_CHALLENGE_POLICY_VERSION", "v2-test")
    after = config_fingerprint(model="claude-sonnet-5")
    assert before != after


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------


async def test_take_snapshot_stores_metrics_and_fingerprint() -> None:
    org_id, aid = await _assessment("snap-store")
    await _decided(org_id, aid, "AC-2", "satisfied", accepted=True)
    await _decided(
        org_id, aid, "SC-7", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    async with session_scope() as s:
        snap = await take_snapshot(s, organization_id=org_id, model="claude-sonnet-5")
        await s.flush()
        snap_id = int(snap.id)
        assert snap.organization_id == org_id
        assert snap.config_fingerprint == config_fingerprint(model="claude-sonnet-5")
        assert snap.metrics["decided"] == 2
        assert snap.metrics["missed_findings"] == 1

    async with session_scope() as s:
        row = await s.get(CalibrationSnapshot, snap_id)
        assert row is not None
        assert row.metrics["decided"] == 2
        assert row.config_fingerprint == config_fingerprint(model="claude-sonnet-5")


async def test_two_snapshots_under_one_configuration_are_comparable() -> None:
    org_id, aid = await _assessment("snap-comparable")
    await _decided(org_id, aid, "AC-2", "satisfied", accepted=True)
    async with session_scope() as s:
        first = await take_snapshot(s, organization_id=org_id, model="claude-sonnet-5")
        await s.flush()
        first_id = int(first.id)

    await _decided(
        org_id, aid, "SC-7", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    async with session_scope() as s:
        second = await take_snapshot(s, organization_id=org_id, model="claude-sonnet-5")
        await s.flush()
        second_id = int(second.id)

    async with session_scope() as s:
        result = await compare_snapshots(s, first_id, second_id, organization_id=org_id)

    assert result["comparable"] is True
    assert result["deltas"]["decided"] == 1
    assert result["deltas"]["missed_findings"] == 1


async def test_snapshots_under_different_configurations_are_not_comparable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-deriving prep_screen_threshold -- which its ~0.03 margin means will
    happen -- must read as an explained configuration change, not drift."""
    org_id, aid = await _assessment("snap-not-comparable")
    await _decided(org_id, aid, "AC-2", "satisfied", accepted=True)
    async with session_scope() as s:
        first = await take_snapshot(s, organization_id=org_id, model="claude-sonnet-5")
        await s.flush()
        first_id = int(first.id)

    monkeypatch.setenv("CCF_PREP_SCREEN_THRESHOLD", "0.75")
    get_settings.cache_clear()
    try:
        async with session_scope() as s:
            second = await take_snapshot(s, organization_id=org_id, model="claude-sonnet-5")
            await s.flush()
            second_id = int(second.id)

        async with session_scope() as s:
            result = await compare_snapshots(s, first_id, second_id, organization_id=org_id)
    finally:
        get_settings.cache_clear()

    assert result["comparable"] is False
    assert "deltas" not in result
    assert "drift" not in str(result).lower()


async def test_two_snapshots_with_dissent_toggled_between_them_are_not_comparable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """This is how the slice actually gets evaluated (design doc, section 4):
    enabling dissent must read as a configuration change, not as an
    unexplained shift in missed_findings.
    """
    org_id, aid = await _assessment("snap-dissent-not-comparable")
    await _decided(org_id, aid, "AC-2", "satisfied", accepted=True)
    async with session_scope() as s:
        first = await take_snapshot(s, organization_id=org_id, model="claude-sonnet-5")
        await s.flush()
        first_id = int(first.id)

    monkeypatch.setenv("CCF_ASSESSMENT_DISSENT_ENABLED", "true")
    get_settings.cache_clear()
    try:
        async with session_scope() as s:
            second = await take_snapshot(s, organization_id=org_id, model="claude-sonnet-5")
            await s.flush()
            second_id = int(second.id)

        async with session_scope() as s:
            result = await compare_snapshots(s, first_id, second_id, organization_id=org_id)
    finally:
        get_settings.cache_clear()

    assert result["comparable"] is False
    assert "deltas" not in result


async def test_snapshots_are_scoped_to_one_organization() -> None:
    org_a, aid_a = await _assessment("snap-org-a")
    org_b, aid_b = await _assessment("snap-org-b")
    await _decided(org_a, aid_a, "AC-2", "satisfied", accepted=True)
    await _decided(
        org_b, aid_b, "AC-2", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    await _decided(
        org_b, aid_b, "SC-7", "satisfied", accepted=False, corrected="other_than_satisfied"
    )

    async with session_scope() as s:
        snap = await take_snapshot(s, organization_id=org_a, model="claude-sonnet-5")
        await s.flush()
        snap_id = int(snap.id)

    async with session_scope() as s:
        row = await s.get(CalibrationSnapshot, snap_id)
        assert row is not None
        assert row.organization_id == org_a
        assert row.metrics["decided"] == 1, "org B's two decisions must not leak into org A"
        assert row.metrics["missed_findings"] == 0, "org B's rejections must not leak into org A"


async def test_a_snapshot_from_another_organization_is_unknown_not_refused() -> None:
    """Cross-tenant comparison must not confirm the id exists.

    compare_snapshots has no route yet. The scoping is asserted here so that
    whoever adds one cannot introduce the leak by omission -- three endpoints
    in an earlier slice of this project leaked exactly that way.
    """
    org_a, aid_a = await _assessment("snap-iso-a")
    org_b, aid_b = await _assessment("snap-iso-b")
    await _decided(org_a, aid_a, "AC-2", "satisfied", accepted=True)
    await _decided(
        org_b, aid_b, "SC-7", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    async with session_scope() as s:
        mine = await take_snapshot(s, organization_id=org_a, model="claude-sonnet-5")
        theirs = await take_snapshot(s, organization_id=org_b, model="claude-sonnet-5")
        await s.flush()
        mine_id, theirs_id = int(mine.id), int(theirs.id)

    async with session_scope() as s:
        with pytest.raises(ValueError) as excinfo:
            await compare_snapshots(s, mine_id, theirs_id, organization_id=org_a)

    assert str(theirs_id) in str(excinfo.value), "org B's snapshot must read as unknown"
    assert "unknown" in str(excinfo.value)
