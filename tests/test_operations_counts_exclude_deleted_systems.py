"""A deleted system's verdicts stop being counted, not only stop being listed.

Measured against the dev database, for one real organization:

* ``/dashboard`` (``compliance_gaps``) reported **80** control tests assessed;
* ``/operations`` (``dashboard_overview``) reported **112**.

Both are "this organization's control tests". The difference is a soft-deleted
system called "Nexus" holding 32 of them. ``compliance_gaps`` joins ``System`` and
filters ``deleted_at``; ``_control_tests`` filtered on
``ControlTest.organization_id`` alone, so a customer who deleted that system --
and was told it was gone -- still saw its 32 verdicts shaping the pass / fail /
manual-review proportions on the operational dashboard.

The fix already existed ten lines below in the same file. ``_ksi_states`` scopes
through ``posture.org_system_subq``, whose docstring says why in detail: a deleted
system "kept contributing to every executive number ... and SPRS scores are
reported to DoD". ``_risk_by_band`` and ``_mttr_trend`` use it too.
``_control_tests`` and ``_tasks_by_priority`` did not. One rule, five
implementations, two of them wrong -- the same shape as the deleted-systems *list*
defect and the one before that.

So this guard is a sweep rather than two assertions: it seeds one live and one
deleted system with identical data and requires **every** count in
``dashboard_overview`` to be unchanged by the deleted one.
"""

from __future__ import annotations

import itertools
from datetime import UTC, date, datetime, timedelta

from ccf.analytics.gaps import compliance_gaps
from ccf.analytics.overview import dashboard_overview
from ccf.analytics.posture import poam_aging
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import POAM, Organization, Risk, System, Task
from ccf.models_grc import ControlTest

_SEQ = itertools.count()

#: Keys in the overview payload that count rows and must therefore ignore a
#: deleted system. Walked rather than asserted one at a time, so a block added
#: later is covered without anybody remembering this file.
_COUNTED_BLOCKS = ("control_tests", "risk_by_band", "tasks", "ksi")


async def _system_with_data(session, org_id: int, *, deleted: bool) -> int:
    """One system carrying one of everything the overview counts."""
    n = next(_SEQ)
    system = System(
        organization_id=org_id,
        name=f"{'gone' if deleted else 'live'}-{n}",
        baseline="moderate",
        deleted_at=datetime.now(UTC) if deleted else None,
    )
    session.add(system)
    await session.flush()

    test = ControlTest(
        organization_id=org_id,
        system_id=system.id,
        control_id="AC-3",
        control_ids=["AC-3"],
        name=f"check-{n}",
        method="connector",
        source="generated",
        check_key=f"demo.check.{n}",
        check_source="platform",
    )
    session.add(test)
    await session.flush()
    await record_result(session, test, status="fail", detail="x", open_remediation=False)

    today = date.today()
    session.add(
        POAM(
            system_id=system.id,
            title=f"poam-{n}",
            weakness="w",
            severity="high",
            status="open",
            identified_on=today,
            due_on=today + timedelta(days=30),
            original_due_on=today + timedelta(days=30),
        )
    )
    session.add(
        Task(
            organization_id=org_id,
            system_id=system.id,
            title=f"task-{n}",
            kind="remediation",
            priority="high",
            status="open",
            source="auto",
        )
    )
    await session.flush()
    return system.id


async def test_a_deleted_system_changes_no_count_on_operations() -> None:
    """The sweep: every counted block must read the same with and without it."""
    async with session_scope() as session:
        org = Organization(name=f"DelCountOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        await _system_with_data(session, org.id, deleted=False)
        before = await dashboard_overview(session, org_id=org.id)

        await _system_with_data(session, org.id, deleted=True)
        after = await dashboard_overview(session, org_id=org.id)

    for block in _COUNTED_BLOCKS:
        assert after[block] == before[block], (
            f"{block} changed when a *deleted* system was added:\n"
            f"  before: {before[block]}\n  after:  {after[block]}"
        )


async def test_the_control_test_total_counts_only_live_systems() -> None:
    """Named on its own, because this is the one measured wrong in production:
    80 on /dashboard against 112 on /operations for one real organization."""
    async with session_scope() as session:
        org = Organization(name=f"DelCtOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        await _system_with_data(session, org.id, deleted=False)
        await _system_with_data(session, org.id, deleted=True)
        out = await dashboard_overview(session, org_id=org.id)

    ct = out["control_tests"]
    assert ct["total"] == 1, (
        f"{ct['total']} control tests counted for one live system: {ct}"
    )
    assert ct["fail"] == 1


async def test_tasks_for_a_deleted_system_are_not_outstanding_work() -> None:
    """A remediation task against a system that no longer exists is not work.

    It was opened by that system's failing control test, which is itself no longer
    counted -- so leaving the task in the queue reports work nobody can do.
    """
    async with session_scope() as session:
        org = Organization(name=f"DelTaskOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        await _system_with_data(session, org.id, deleted=True)
        out = await dashboard_overview(session, org_id=org.id)

    assert out["tasks"].get("high", 0) == 0, out["tasks"]


async def test_an_org_level_task_with_no_system_still_counts() -> None:
    """The half a naive join would break.

    ``Task.system_id`` is nullable and an org-wide task is real work. Scoping with
    an inner join or a bare ``IN (live systems)`` would silently drop it, trading
    one wrong number for another.
    """
    async with session_scope() as session:
        org = Organization(name=f"OrgTaskOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        session.add(
            Task(
                organization_id=org.id,
                system_id=None,
                title="org-wide work",
                kind="remediation",
                priority="high",
                status="open",
                source="auto",
            )
        )
        await session.flush()
        out = await dashboard_overview(session, org_id=org.id)

    assert out["tasks"].get("high", 0) == 1, out["tasks"]


async def test_the_two_surfaces_agree_about_the_same_organization() -> None:
    """The defect stated as the question a reader would ask.

    ``/dashboard`` and ``/operations`` both describe this organization's control
    tests. They disagreed by exactly the deleted system's rows; they must not.
    """
    async with session_scope() as session:
        org = Organization(name=f"AgreeOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        await _system_with_data(session, org.id, deleted=False)
        await _system_with_data(session, org.id, deleted=False)
        await _system_with_data(session, org.id, deleted=True)
        gaps = await compliance_gaps(session, org.id)
        ov = await dashboard_overview(session, org_id=org.id)

    assert gaps["assessed"] == ov["control_tests"]["total"], (
        f"/dashboard says {gaps['assessed']} control tests assessed and "
        f"/operations says {ov['control_tests']['total']}; one of them is counting "
        "a deleted system"
    )


async def test_a_live_system_is_still_counted() -> None:
    """So the fix is not "count nothing"."""
    async with session_scope() as session:
        org = Organization(name=f"LiveCountOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        await _system_with_data(session, org.id, deleted=False)
        out = await dashboard_overview(session, org_id=org.id)

    assert out["control_tests"]["total"] == 1
    assert out["tasks"].get("high", 0) == 1
    assert out["risk_by_band"] is not None
    assert isinstance(Risk, type)  # the import is load-bearing for the model registry


async def test_the_unscoped_global_view_also_excludes_deleted_systems() -> None:
    """The platform-admin view, which several of these functions forgot.

    ``org_system_subq(None)`` is "every live system" by design, so applying it
    unconditionally is correct for the global view too. ``poam_aging`` gated it on
    ``org_id is not None`` and therefore counted deleted systems' POA&Ms whenever a
    platform admin looked -- the fourth instance of the shape ``_ksi_states``
    records fixing, and the one surface where nobody would notice because there is
    no tenant to compare against.

    Asserted as a delta rather than an absolute, because the global view sees every
    organization in the database and no test can know that total.
    """
    async with session_scope() as session:
        before = await poam_aging(session, org_id=None, today=date.today())
        org = Organization(name=f"GlobalDelOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        await _system_with_data(session, org.id, deleted=True)
        after = await poam_aging(session, org_id=None, today=date.today())

    assert after["open_total"] == before["open_total"], (
        "a deleted system's POA&M was counted in the global view: "
        f"{before['open_total']} -> {after['open_total']}"
    )


async def test_a_live_poam_still_reaches_the_global_view() -> None:
    """So the unconditional filter is not dropping everything."""
    async with session_scope() as session:
        before = await poam_aging(session, org_id=None, today=date.today())
        org = Organization(name=f"GlobalLiveOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        await _system_with_data(session, org.id, deleted=False)
        after = await poam_aging(session, org_id=None, today=date.today())

    assert after["open_total"] == before["open_total"] + 1


async def test_the_poam_sla_blocks_ignore_a_deleted_system() -> None:
    """The overview's SLA block reads poam_aging, so it inherits the fix -- and
    the invariant on_track + overdue + no_due_date == open must still hold."""
    async with session_scope() as session:
        org = Organization(name=f"SlaDelOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        await _system_with_data(session, org.id, deleted=False)
        await _system_with_data(session, org.id, deleted=True)
        out = await dashboard_overview(session, org_id=org.id)

    sla = out["sla"]
    assert sla["open"] == 1, f"a deleted system's POA&M reached the SLA block: {sla}"
    assert sla["overdue"] + sla["on_track"] + sla["no_due_date"] == sla["open"]


async def test_an_org_wide_control_test_with_no_system_still_counts() -> None:
    """The half a bare ``IN (live systems)`` would silently drop.

    ``ControlTest.system_id`` is nullable, and an org-wide authored test is real
    assessment work -- ``_upsert_poam`` even documents the consequence: "an org-wide
    test (not scoped to one system) has nothing to attach a POA&M to, so it keeps
    the existing Task/Notification alert only".

    Found by mutation: removing the ``system_id IS NULL`` branch from the control
    test query passed every other test in this file, because none of them created
    one. Trading a count that includes deleted systems for one that excludes
    org-wide tests is not a fix.
    """
    async with session_scope() as session:
        org = Organization(name=f"OrgWideCtOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        test = ControlTest(
            organization_id=org.id,
            system_id=None,
            control_id="CA-7",
            name="an org-wide authored test",
            method="manual",
            source="authored",
            last_status="pass",
        )
        session.add(test)
        await session.flush()
        out = await dashboard_overview(session, org_id=org.id)

    ct = out["control_tests"]
    assert ct["total"] == 1, f"an org-wide control test was dropped: {ct}"
    assert ct["pass"] == 1
