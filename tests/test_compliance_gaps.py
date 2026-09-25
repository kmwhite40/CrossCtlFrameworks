"""The gap rollup: what a customer has to fix, in one answer.

Everything here was already recorded by a scan; what did not exist was a view
that answered "which controls are failing, on what, and what do I do" without
visiting four pages.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from ccf.analytics.gaps import EXAMPLES_PER_GAP, compliance_gaps
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResourceResult, ControlTestResult

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _seed(*, deleted_system: bool = False) -> tuple[int, int]:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"Gap Org {tag}")
        s.add(org)
        await s.flush()
        system = System(
            organization_id=org.id,
            name=f"Sys {tag}",
            deleted_at=datetime.now(UTC) if deleted_system else None,
        )
        s.add(system)
        await s.flush()

        failing = ControlTest(
            organization_id=org.id, system_id=system.id, control_id="IA-2",
            name="Every user has an MFA method registered", method="automated",
            last_status="fail",
        )
        passing = ControlTest(
            organization_id=org.id, system_id=system.id, control_id="AC-17",
            name="Legacy authentication is blocked", method="automated",
            last_status="pass",
        )
        s.add_all([failing, passing])
        await s.flush()

        now = datetime.now(UTC)
        fail_result = ControlTestResult(
            control_test_id=failing.id, status="fail", run_at=now,
            evaluated=78, failing=6, detail="6 of 78 entra_user(s) failing",
        )
        s.add(fail_result)
        s.add(
            ControlTestResult(
                control_test_id=passing.id, status="pass", run_at=now,
                evaluated=1, failing=0,
            )
        )
        await s.flush()
        for i in range(6):
            s.add(
                ControlTestResourceResult(
                    result_id=fail_result.id, resource_id=f"u{i}",
                    resource_type="entra_user", verdict="fail",
                    observed=f"no MFA method registered: user{i}@x.gov",
                )
            )
        await s.flush()
        return org.id, system.id


@pytest.mark.asyncio
async def test_the_rollup_separates_what_is_failing_from_what_is_not() -> None:
    org_id, _ = await _seed()
    async with session_scope() as s:
        g = await compliance_gaps(s, org_id)

    assert g["assessed"] == 2
    assert g["failing"] == 1
    assert g["passing"] == 1
    assert g["resources_evaluated"] == 79
    assert g["resources_failing"] == 6
    assert [x["control_id"] for x in g["gaps"]] == ["IA-2"]
    assert [x["control_id"] for x in g["clean"]] == ["AC-17"]


@pytest.mark.asyncio
async def test_a_gap_names_what_actually_failed() -> None:
    """A count alone does not tell anyone what to fix."""
    org_id, _ = await _seed()
    async with session_scope() as s:
        g = await compliance_gaps(s, org_id)

    gap = g["gaps"][0]
    assert gap["failing"] == 6
    assert gap["evaluated"] == 78
    assert gap["examples"], "the gap named nothing that failed"
    assert all("no MFA method registered" in e for e in gap["examples"])
    assert len(gap["examples"]) == EXAMPLES_PER_GAP, (
        "a rollup that printed every failing resource would bury the control"
    )


@pytest.mark.asyncio
async def test_a_deleted_systems_failures_are_not_outstanding_work() -> None:
    """Analytics that forgot this once put a deleted system in the headline."""
    org_id, _ = await _seed(deleted_system=True)
    async with session_scope() as s:
        g = await compliance_gaps(s, org_id)
    assert g["assessed"] == 0
    assert g["gaps"] == []


@pytest.mark.asyncio
async def test_another_organizations_gaps_are_never_returned() -> None:
    """The owning org is asserted first, so a query returning nothing at all
    would fail here too."""
    mine, _ = await _seed()
    theirs, _ = await _seed()
    async with session_scope() as s:
        g = await compliance_gaps(s, mine)
        other = await compliance_gaps(s, theirs)

    assert g["assessed"] == 2 and other["assessed"] == 2
    mine_tests = {x["test_id"] for x in g["gaps"] + g["clean"]}
    their_tests = {x["test_id"] for x in other["gaps"] + other["clean"]}
    assert not (mine_tests & their_tests)


@pytest.mark.asyncio
async def test_no_organization_returns_nothing_without_querying_at_all() -> None:
    """This drives a customer-facing page: "no organization" is not a licence
    to show every tenant's gaps.

    Proved with a session that raises if touched. Asserting only that the
    result is empty passed whether or not the guard existed -- with
    ``org_id`` of None the predicate becomes ``organization_id IS NULL``,
    which matches no control test, so the database returned nothing either
    way. The mutation that deleted the guard survived that version.
    """

    class _Unusable:
        async def execute(self, *a, **k):  # pragma: no cover - must not run
            raise AssertionError("queried the database with no organization")

    g = await compliance_gaps(_Unusable(), None)
    assert g["assessed"] == 0
    assert g["gaps"] == []
    assert g["open_tasks"] == 0


@pytest.mark.asyncio
async def test_only_the_latest_result_for_a_test_is_reported() -> None:
    """Re-scanning must move the number, not add a second row for one control."""
    org_id, _ = await _seed()
    async with session_scope() as s:
        test_id = (await compliance_gaps(s, org_id))["gaps"][0]["test_id"]

    async with session_scope() as s:
        s.add(
            ControlTestResult(
                control_test_id=test_id, status="pass",
                run_at=datetime.now(UTC), evaluated=78, failing=0,
            )
        )

    async with session_scope() as s:
        g = await compliance_gaps(s, org_id)
    assert g["failing"] == 0, "an older failing result is still being reported"
    assert g["passing"] == 2
