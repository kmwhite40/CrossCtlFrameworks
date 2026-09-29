"""The gap rollup: what a customer has to fix, in one answer.

Everything here was already recorded by a scan; what did not exist was a view
that answered "which controls are failing, on what, and what do I do" without
visiting four pages.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import select

from ccf.analytics.gaps import EXAMPLES_PER_GAP, compliance_gaps
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResourceResult, ControlTestResult
from ccf.models_waivers import Waiver

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


@pytest.mark.asyncio
async def test_the_executive_rollup_carries_continuous_monitoring() -> None:
    """The one view aimed at people who decide about risk omitted it entirely.

    Every other consumer of a scan saw its results -- the gap report, the work
    queue, the alerts -- but `insights.executive` had no control-test block,
    so a leader could read that page while six of ten continuously-monitored
    controls were failing and see no sign of it.
    """
    from ccf.governance import insights  # noqa: PLC0415

    org_id, _ = await _seed()
    async with session_scope() as s:
        r = await insights.executive(s, org_id=org_id)

    assert "control_tests" in r, "the executive rollup carries no conmon block"
    ct = r["control_tests"]
    assert ct["assessed"] == 2
    assert ct["failing"] == 1
    assert ct["passing"] == 1
    assert ct["resources_failing"] == 6
    # Named, not just counted: a number alone does not say what to look at.
    assert ct["failing_controls"] == ["IA-2"]


@pytest.mark.asyncio
async def test_the_executive_conmon_block_is_scoped_to_one_organization() -> None:
    """The owning org is asserted first, so a block that reported nothing at
    all would fail here too."""
    from ccf.governance import insights  # noqa: PLC0415

    mine, _ = await _seed()
    await _seed()  # another tenant, also with one failing control
    async with session_scope() as s:
        r = await insights.executive(s, org_id=mine)

    assert r["control_tests"]["assessed"] == 2, "another tenant's tests were counted"
    assert r["control_tests"]["failing"] == 1


# ---------------------------------------------------------------------------
# Accepted findings: decided, not outstanding, and never passing
# ---------------------------------------------------------------------------


async def _accept(
    org_id: int,
    system_id: int,
    *,
    control_id: str = "IA-2",
    resource_id: str | None = None,
    status: str = "approved",
    expires_on: date | None = None,
    requested_by: str = "owner@x.gov",
) -> int:
    async with session_scope() as s:
        w = Waiver(
            organization_id=org_id,
            system_id=system_id,
            control_id=control_id,
            resource_id=resource_id,
            rationale="Compensating control: conditional access blocks these six.",
            status=status,
            requested_by=requested_by,
            approved_by="ao@x.gov" if status == "approved" else None,
            expires_on=expires_on,
        )
        s.add(w)
        await s.flush()
        return w.id


@pytest.mark.asyncio
async def test_an_accepted_finding_is_reported_separately_and_never_as_passing() -> None:
    """The queue distinguishes decided work from untouched work.

    An acceptance suppresses the consequence, not the observation -- so the row
    stays in `gaps` with its status `fail`, and `passing` must not move.
    """
    org_id, system_id = await _seed()
    async with session_scope() as s:
        before = await compliance_gaps(s, org_id)
    assert (before["failing"], before["open"], before["accepted"]) == (1, 1, 0)

    await _accept(org_id, system_id)

    async with session_scope() as s:
        after = await compliance_gaps(s, org_id)
    assert after["failing"] == 1, "an acceptance must not remove the finding"
    assert after["open"] == 0, "accepted work is not outstanding work"
    assert after["accepted"] == 1
    assert after["passing"] == before["passing"], "an acceptance is not a pass"
    gap = after["gaps"][0]
    assert gap["status"] == "fail"
    assert gap["accepted"] is True
    assert gap["failing"] == 6, "the failing resource count is untouched"


@pytest.mark.asyncio
async def test_a_requested_acceptance_suppresses_nothing() -> None:
    """If asking were enough, anyone could clear the queue by asking."""
    org_id, system_id = await _seed()
    await _accept(org_id, system_id, status="requested")
    async with session_scope() as s:
        g = await compliance_gaps(s, org_id)
    assert g["open"] == 1
    assert g["accepted"] == 0
    assert g["gaps"][0]["accepted"] is False
    assert g["gaps"][0]["requested_waivers"] == 1


@pytest.mark.asyncio
async def test_a_revoked_acceptance_suppresses_nothing() -> None:
    org_id, system_id = await _seed()
    await _accept(org_id, system_id, status="revoked")
    async with session_scope() as s:
        g = await compliance_gaps(s, org_id)
    assert g["open"] == 1
    assert g["gaps"][0]["accepted"] is False


@pytest.mark.asyncio
async def test_an_expired_acceptance_stops_covering_the_day_after_it_lapses() -> None:
    """Expiry is inclusive: an acceptance runs to the end of its last day."""
    org_id, system_id = await _seed()
    await _accept(org_id, system_id, expires_on=date(2026, 6, 30))

    async with session_scope() as s:
        on_the_day = await compliance_gaps(s, org_id, today=date(2026, 6, 30))
        the_day_after = await compliance_gaps(s, org_id, today=date(2026, 7, 1))
    assert on_the_day["accepted"] == 1
    assert the_day_after["accepted"] == 0
    assert the_day_after["open"] == 1


@pytest.mark.asyncio
async def test_an_acceptance_approved_after_the_last_scan_takes_effect_immediately() -> None:
    """Acceptance is decided from the waivers, not from the counters a scan stored.

    `ControlTestResult.waived` was computed when the run was recorded. Reading
    it would leave a finding accepted today still reading as untouched work
    until somebody happened to re-scan -- a stale proxy for a live decision.
    """
    org_id, system_id = await _seed()
    async with session_scope() as s:
        stored = (
            await s.execute(
                select(ControlTestResult.waived).where(ControlTestResult.status == "fail")
            )
        ).scalars().all()
    assert all(w == 0 for w in stored), "the fixture's run recorded no waived resources"

    await _accept(org_id, system_id)
    async with session_scope() as s:
        g = await compliance_gaps(s, org_id)
    assert g["accepted"] == 1, "the report read the scan's stale counter instead of the waiver"


@pytest.mark.asyncio
async def test_a_partly_accepted_finding_is_still_outstanding() -> None:
    """One uncovered resource and the finding is not accepted.

    Reporting a partial acceptance as accepted is the one mistake here that
    would actually hide work: five of six users waived reads as clean while a
    sixth has no MFA.
    """
    org_id, system_id = await _seed()
    for i in range(5):
        await _accept(org_id, system_id, resource_id=f"u{i}")

    async with session_scope() as s:
        g = await compliance_gaps(s, org_id)
    gap = g["gaps"][0]
    assert g["open"] == 1
    assert g["accepted"] == 0
    assert gap["accepted"] is False
    assert gap["waived_resources"] == 5
    assert gap["uncovered_resources"] == 1

    # Cover the sixth and it becomes accepted.
    await _accept(org_id, system_id, resource_id="u5")
    async with session_scope() as s:
        g2 = await compliance_gaps(s, org_id)
    assert g2["accepted"] == 1
    assert g2["gaps"][0]["uncovered_resources"] == 0


@pytest.mark.asyncio
async def test_another_tenants_acceptance_never_covers_this_tenants_finding() -> None:
    mine_org, _mine_sys = await _seed()
    theirs_org, theirs_sys = await _seed()
    # Same control id, same resource ids, different organization and system.
    await _accept(theirs_org, theirs_sys)

    async with session_scope() as s:
        mine = await compliance_gaps(s, mine_org)
        theirs = await compliance_gaps(s, theirs_org)
    assert mine["accepted"] == 0, "one tenant's acceptance silenced another's finding"
    assert mine["open"] == 1
    assert theirs["accepted"] == 1


@pytest.mark.asyncio
async def test_an_acceptance_for_a_different_control_does_not_cover_this_one() -> None:
    org_id, system_id = await _seed()
    await _accept(org_id, system_id, control_id="AC-17")
    async with session_scope() as s:
        g = await compliance_gaps(s, org_id)
    assert g["accepted"] == 0
    assert g["open"] == 1


@pytest.mark.asyncio
async def test_outstanding_gaps_sort_ahead_of_accepted_ones() -> None:
    """An operator opening the page should read the undecided rows first."""
    org_id, system_id = await _seed()
    # A second failing control, left unaccepted.
    async with session_scope() as s:
        test = ControlTest(
            organization_id=org_id, system_id=system_id, control_id="AC-6",
            name="Default user permissions are restricted", method="automated",
            last_status="fail",
        )
        s.add(test)
        await s.flush()
        s.add(
            ControlTestResult(
                control_test_id=test.id, status="fail", run_at=datetime.now(UTC),
                evaluated=1, failing=1,
            )
        )
    await _accept(org_id, system_id)

    async with session_scope() as s:
        g = await compliance_gaps(s, org_id)
    assert [x["accepted"] for x in g["gaps"]] == [False, True]


@pytest.mark.asyncio
async def test_the_expiry_shown_is_the_soonest_acceptance_in_force() -> None:
    """The date the row comes back is the earliest one, not an arbitrary waiver's."""
    org_id, system_id = await _seed()
    await _accept(org_id, system_id, resource_id=None, expires_on=date(2027, 1, 31))
    await _accept(org_id, system_id, resource_id="u0", expires_on=date(2026, 11, 30))

    async with session_scope() as s:
        g = await compliance_gaps(s, org_id, today=date(2026, 10, 1))
    gap = g["gaps"][0]
    assert gap["accepted"] is True
    assert gap["accepted_until"] == date(2026, 11, 30)
    assert gap["accepted_indefinitely"] is False


@pytest.mark.asyncio
async def test_a_waiver_whose_organization_does_not_match_the_test_never_covers_it() -> None:
    """The tenant arm of the match, pinned where it can actually fail.

    `test_another_tenants_acceptance_never_covers_this_tenants_finding` above
    uses two organizations *and* two systems, and a system belongs to exactly
    one organization -- so the system arm alone catches it and the tenant arm
    could be deleted with every test still green. Mutation testing said so.

    The case that needs the tenant arm is a waiver on the *right* system
    carrying the wrong (or a NULL) organization: `Waiver.organization_id` is
    nullable, the API always fills it from the principal, and a row written any
    other way would otherwise be honoured against this tenant's finding.
    """
    org_id, system_id = await _seed()
    async with session_scope() as s:
        stranger = Organization(name=f"Stranger {uuid.uuid4().hex[:8]}")
        s.add(stranger)
        await s.flush()
        s.add_all([
            # Right system, wrong organization.
            Waiver(
                organization_id=stranger.id, system_id=system_id, control_id="IA-2",
                rationale="Filed under the wrong tenant.", status="approved",
                requested_by="x@y.gov", approved_by="z@y.gov",
            ),
            # Right system, no organization at all.
            Waiver(
                organization_id=None, system_id=system_id, control_id="IA-2",
                rationale="Filed with no tenant.", status="approved",
                requested_by="x@y.gov", approved_by="z@y.gov",
            ),
        ])

    async with session_scope() as s:
        g = await compliance_gaps(s, org_id)
    assert g["accepted"] == 0, "a waiver from another tenant covered this finding"
    assert g["open"] == 1
    assert g["gaps"][0]["accepted"] is False
