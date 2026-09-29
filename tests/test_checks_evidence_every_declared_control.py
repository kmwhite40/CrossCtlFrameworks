"""A check is evidence about every control it declares, not only the first.

``PostureCheck.control_ids`` is documented as "what it evidences" -- a tuple.
A scan wrote only ``control_ids[0]`` onto the ``ControlTest``, so every other
control a check bears on was invisible to the rollups. The MFA check declares
``IA-2`` and ``IA-2(1)``; ``IA-2(1)`` never failed, never passed, and showed as
unaddressed. The error ran in the direction that looks better: the platform
reported less coverage than it had, and reported clean controls that a failing
check had something to say about.

Migration 0092 records the full tuple. :mod:`ccf.posture.evidence` decides what
a verdict does with it, and the rule is asymmetric on purpose:

* a **non-passing** verdict (``fail``, ``warn``, ``manual_review_required``)
  reaches every declared control -- none of those is evidence of satisfaction;
* a **passing** verdict credits the primary control only -- one narrow check
  must not mark several controls satisfied.

The asymmetry is the part worth attacking, so it is tested from both sides.
"""

from __future__ import annotations

import itertools

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from ccf.analytics.framework_posture import framework_posture
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Control, Organization, System
from ccf.models_grc import ControlTest
from ccf.posture.evidence import (
    evidenced_controls,
    non_passing_attribution,
    pass_attribution,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# ---------------------------------------------------------------------------
# The rule itself
# ---------------------------------------------------------------------------


def test_a_non_passing_verdict_reaches_every_declared_control() -> None:
    assert non_passing_attribution("AC-3", ["AC-3", "AC-6"]) == ["AC-3", "AC-6"]


def test_a_passing_verdict_credits_only_the_primary_control() -> None:
    """The asymmetry. Restricted guest invites are weak evidence for AC-6."""
    assert pass_attribution("AC-3") == ["AC-3"]


def test_pass_attribution_cannot_be_widened_by_its_caller() -> None:
    """There is no parameter to pass the tuple to, so no call site can."""
    import inspect  # noqa: PLC0415

    assert list(inspect.signature(pass_attribution).parameters) == ["control_id"]


def test_a_null_tuple_means_the_primary_control_alone() -> None:
    """Authored tests and rows written before migration 0092 both land here."""
    assert evidenced_controls("AC-2", None) == ["AC-2"]
    assert evidenced_controls("AC-2", []) == ["AC-2"]


def test_the_primary_control_comes_first_and_repeats_collapse() -> None:
    assert evidenced_controls("IA-2", ["IA-2", "IA-2(1)", "IA-2"]) == ["IA-2", "IA-2(1)"]


def test_a_tuple_that_omits_the_primary_is_reported_not_reconciled() -> None:
    """A scan/registry disagreement is data, not something to quietly fix.

    Dropping either side would hide the disagreement. The caller asked what the
    row is evidence about, not which of two records to believe.
    """
    assert evidenced_controls("AC-2", ["AC-17"]) == ["AC-2", "AC-17"]


def test_blank_entries_are_not_controls() -> None:
    assert evidenced_controls("AC-2", ["", "  ", "AC-6"]) == ["AC-2", "AC-6"]
    assert evidenced_controls(None, ["AC-6"]) == ["AC-6"]
    assert evidenced_controls("", None) == []


# ---------------------------------------------------------------------------
# The rule, reaching the rollup a customer reads
# ---------------------------------------------------------------------------


async def _system_with_test(
    *, control_id: str, control_ids: list[str] | None, status: str
) -> tuple[int, int]:
    """A Moderate-baseline system carrying exactly one recorded control test."""
    tag = f"{next(_SEQ)}"
    async with session_scope() as s:
        for identifier in ("AC-03", "AC-06"):
            if (
                await s.execute(select(Control).where(Control.identifier == identifier))
            ).scalar_one_or_none() is None:
                s.add(Control(identifier=identifier, fisma_mod=True))
        org = Organization(name=f"Evidence Org {tag}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"Evidence Sys {tag}", baseline="moderate")
        s.add(system)
        await s.flush()
        s.add(
            ControlTest(
                organization_id=org.id,
                system_id=system.id,
                control_id=control_id,
                control_ids=control_ids,
                name="guest invitations are restricted",
                method="connector",
                source="generated",
                check_key="m365.policy.guest_invites_restricted",
                last_status=status,
            )
        )
        await s.flush()
        return org.id, system.id


async def _cleanup(org_id: int) -> None:
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id == org_id))


@pytest.mark.asyncio
async def test_a_failing_check_fails_every_control_it_declares() -> None:
    org_id, system_id = await _system_with_test(
        control_id="AC-3", control_ids=["AC-3", "AC-6"], status="fail"
    )
    try:
        async with session_scope() as s:
            posture = await framework_posture(s, org_id=org_id, system_id=system_id)
        assert "AC-3" in posture["failing"]
        assert "AC-6" in posture["failing"], (
            "the second declared control is where the understatement lived"
        )
        assert "AC-6" not in posture["unaddressed"]
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_passing_check_leaves_its_supporting_controls_unaddressed() -> None:
    """The half that must NOT widen.

    If this ever starts passing AC-6, one narrow tenant setting is marking a
    least-privilege control satisfied in a document an assessor samples.
    """
    org_id, system_id = await _system_with_test(
        control_id="AC-3", control_ids=["AC-3", "AC-6"], status="pass"
    )
    try:
        async with session_scope() as s:
            posture = await framework_posture(s, org_id=org_id, system_id=system_id)
        assert "AC-3" in posture["passing"]
        assert "AC-6" not in posture["passing"]
        assert "AC-6" in posture["unaddressed"]
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_check_that_could_not_be_judged_does_not_leave_controls_clean() -> None:
    """`manual_review_required` reaches the whole tuple for the same reason."""
    org_id, system_id = await _system_with_test(
        control_id="AC-3", control_ids=["AC-3", "AC-6"], status="manual_review_required"
    )
    try:
        async with session_scope() as s:
            posture = await framework_posture(s, org_id=org_id, system_id=system_id)
        for control in ("AC-3", "AC-6"):
            assert control not in posture["passing"], control
            assert control not in posture["failing"], control
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_row_written_before_the_column_existed_still_reports() -> None:
    """A null `control_ids` must degrade to the primary control, not to nothing."""
    org_id, system_id = await _system_with_test(
        control_id="AC-3", control_ids=None, status="fail"
    )
    try:
        async with session_scope() as s:
            posture = await framework_posture(s, org_id=org_id, system_id=system_id)
        assert "AC-3" in posture["failing"]
    finally:
        await _cleanup(org_id)
