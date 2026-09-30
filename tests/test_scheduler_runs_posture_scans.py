"""Posture verdicts refresh on their own, not only when somebody clicks Scan.

Found by making the cycle summary report real numbers. The first honest cycle
logged `tests_evaluated=0` across seven organizations with a working connector,
which sent me looking -- and the first thing I found was wrong.

**The wrong diagnosis, recorded because the right one is only interesting beside
it.** All 28 generated control tests had `frequency = NULL`, and `_is_due` reads
a null frequency as "on-demand only". So: set a default frequency, backfill the
existing rows, done. Implemented, tested, migrated -- and worthless, because
`run_due` filters `source != "generated"` two lines further on. Generated tests
are excluded from the scheduler's control-test pass regardless of their
schedule, deliberately: its connector-freshness evaluator has nothing useful to
say about a posture check and would bury the real verdict under a spurious warn.
The frequency fix would have displayed "daily" on tests that never ran daily,
which is a worse defect than the one it was aimed at. Reverted.

The real gap: **nothing re-ran posture scans at all.** The orchestration lived
inside the `POST /systems/{id}/scan-all` route handler, so a person asking was
the only way to refresh a verdict. A tenant scanned once in September still
showed September's verdicts in November, while the SSP cited them as automated
evidence carrying their original observed-on dates -- and `tests_evaluated=0` was
an honest answer, because that field counts `run_due`, which rightly excludes
these. Zero was correct and the gap was elsewhere.

So the orchestration moved to `posture.scan_all`, and the scheduler gained a
per-tenant step that calls it for every live system.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.governance import scheduler
from ccf.models import Organization, System
from ccf.models_grc import ControlTest

_SEQ = itertools.count()


async def _org_with_systems(count: int, *, deleted: int = 0) -> tuple[int, list[int]]:
    tag = f"{next(_SEQ)}"
    async with session_scope() as session:
        org = Organization(name=f"PostureSchedOrg-{tag}")
        session.add(org)
        await session.flush()
        ids: list[int] = []
        for i in range(count):
            sys_ = System(organization_id=org.id, name=f"live-{tag}-{i}")
            session.add(sys_)
            await session.flush()
            ids.append(sys_.id)
        for i in range(deleted):
            from datetime import UTC, datetime  # noqa: PLC0415

            gone = System(
                organization_id=org.id,
                name=f"retired-{tag}-{i}",
                deleted_at=datetime.now(UTC),
            )
            session.add(gone)
            await session.flush()
        return org.id, ids


@pytest.fixture
def recording_scan(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture what the scheduler asks `scan_all_providers` to do.

    Patched on `ccf.posture.scan_all`, which is where the scheduler imports it
    from at call time. Patching the scheduler module would not work -- the import
    is inside the function, deliberately, to avoid an import cycle.
    """
    calls: list[dict[str, Any]] = []

    async def _fake(session: object, **kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"checks_run": 3, "checks_expected": 4, "connectors": []}

    import ccf.posture.scan_all as scan_all_module  # noqa: PLC0415

    monkeypatch.setattr(scan_all_module, "scan_all_providers", _fake)
    return calls


# ---------------------------------------------------------------------------
# The step exists and reaches every live system
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_scheduler_scans_every_live_system_in_the_org(recording_scan) -> None:
    org_id, system_ids = await _org_with_systems(3)
    async with session_scope() as session:
        out = await scheduler._scan_org_systems(session, org_id=org_id)

    assert out["systems_scanned"] == 3
    assert out["checks_run"] == 9  # 3 per system
    assert out["checks_expected"] == 12
    assert sorted(c["system_id"] for c in recording_scan) == sorted(system_ids)


@pytest.mark.asyncio
async def test_a_retired_system_is_not_scanned(recording_scan) -> None:
    """Scanning a soft-deleted system makes live API calls for a dead boundary.

    And records evidence against it, which then appears in reports about a system
    somebody deliberately retired.
    """
    org_id, live_ids = await _org_with_systems(1, deleted=2)
    async with session_scope() as session:
        out = await scheduler._scan_org_systems(session, org_id=org_id)

    assert out["systems_scanned"] == 1
    assert [c["system_id"] for c in recording_scan] == live_ids


@pytest.mark.asyncio
async def test_an_org_with_no_systems_scans_nothing_and_does_not_fail(
    recording_scan,
) -> None:
    org_id, _ = await _org_with_systems(0)
    async with session_scope() as session:
        out = await scheduler._scan_org_systems(session, org_id=org_id)
    assert out == {
        "organization_id": org_id,
        "systems_scanned": 0,
        "checks_run": 0,
        "checks_expected": 0,
        "manual_review": 0,
    }
    assert recording_scan == []


# ---------------------------------------------------------------------------
# What it passes, which is as important as that it runs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_scan_is_attributed_to_the_scheduler_not_a_person(
    recording_scan,
) -> None:
    """`actor` lands on every recorded result and reaches the SSP's evidence.

    An assessor reading "verified on" is entitled to know whether a human was
    watching. Recording a scheduled scan under a person's name would be a false
    attribution in an authorization package.
    """
    org_id, _ = await _org_with_systems(1)
    async with session_scope() as session:
        await scheduler._scan_org_systems(session, org_id=org_id)
    assert recording_scan[0]["actor"] == "scheduler"


@pytest.mark.asyncio
async def test_the_scan_does_not_commit_the_cycles_transaction(recording_scan) -> None:
    """The cycle owns the transaction and manages its own savepoints.

    A commit from inside a per-tenant step ends the transaction under the steps
    that follow it -- including the advisory-unlock in `run_cycle`'s `finally`,
    whose failure would leave the lock held and silently stop every later cycle
    on every replica.
    """
    org_id, _ = await _org_with_systems(1)
    async with session_scope() as session:
        await scheduler._scan_org_systems(session, org_id=org_id)
    assert recording_scan[0]["commit"] is False


@pytest.mark.asyncio
async def test_the_scan_is_scoped_to_the_organization_it_was_asked_about(
    recording_scan,
) -> None:
    """Two orgs, and the step must not reach across.

    `organization_id` is passed explicitly rather than read from ambient state,
    so there is no scope a caller can forget to set -- and RLS backstops it.
    """
    org_a, systems_a = await _org_with_systems(2)
    _org_b, systems_b = await _org_with_systems(2)

    async with session_scope() as session:
        await scheduler._scan_org_systems(session, org_id=org_a)

    seen = {c["system_id"] for c in recording_scan}
    assert seen == set(systems_a)
    assert not (seen & set(systems_b))
    assert {c["organization_id"] for c in recording_scan} == {org_a}


# ---------------------------------------------------------------------------
# It is wired into the cycle, and reported
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_cycle_includes_the_posture_scan_and_reports_its_numbers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wiring. A step nothing calls is the same as no step.

    Only `poll_sources` is stubbed, because it fetches upstream catalogs over
    HTTP and the suite refuses network.
    """
    import structlog  # noqa: PLC0415

    import ccf.posture.scan_all as scan_all_module  # noqa: PLC0415

    _org_id, system_ids = await _org_with_systems(2)

    async def _no_upstream_fetch(*_a: object, **_k: object) -> list[object]:
        return []

    scanned: list[int] = []

    async def _fake(session: object, **kwargs: Any) -> dict[str, Any]:
        scanned.append(int(kwargs["system_id"]))
        return {"checks_run": 5, "checks_expected": 5, "connectors": []}

    monkeypatch.setattr(scheduler, "poll_sources", _no_upstream_fetch)
    monkeypatch.setattr(scan_all_module, "scan_all_providers", _fake)

    with structlog.testing.capture_logs() as logs:
        out = await scheduler.run_cycle()

    assert "posture_scan" in out, "run_cycle does not run the posture-scan step"
    assert set(system_ids) <= set(scanned), "the cycle skipped systems it should have scanned"

    line = [entry for entry in logs if entry["event"] == "scheduler.cycle"][-1]
    assert line["posture_systems"] >= 2
    assert line["posture_checks_run"] >= 10
    # Kept apart from `run_due`'s count on purpose: conflating them would make
    # the zero that exposed this gap unreadable in the other direction.
    assert "tests_evaluated" in line
    assert line["posture_checks_run"] != line["tests_evaluated"]


@pytest.mark.asyncio
async def test_a_posture_scan_failure_is_counted_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Savepointed like every other per-tenant step, and named in the summary.

    The savepoint is what stops one organization's failure aborting the shared
    transaction and killing the cycle. The count is what stops the summary
    reporting the resulting silence as success -- the defect this whole line of
    work started from.
    """
    import structlog  # noqa: PLC0415

    import ccf.posture.scan_all as scan_all_module  # noqa: PLC0415

    await _org_with_systems(1)

    async def _no_upstream_fetch(*_a: object, **_k: object) -> list[object]:
        return []

    async def _boom(*_a: object, **_k: object) -> dict[str, Any]:
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(scheduler, "poll_sources", _no_upstream_fetch)
    monkeypatch.setattr(scan_all_module, "scan_all_providers", _boom)

    with structlog.testing.capture_logs() as logs:
        await scheduler.run_cycle()

    line = [entry for entry in logs if entry["event"] == "scheduler.cycle"][-1]
    assert line["failures"] >= 1
    assert any(s.startswith("posture_scan@") for s in line.get("failed_steps", [])), (
        f"a posture-scan failure is not named in the summary: {line}"
    )
    # And the cycle still finished: later steps ran rather than being aborted.
    assert "assurance_nodes" in line


# ---------------------------------------------------------------------------
# The route still works, on the same code
# ---------------------------------------------------------------------------


def test_the_route_and_the_scheduler_share_one_implementation() -> None:
    """Two copies of this orchestration would drift, and the API is the one
    people compare against.

    Asserted structurally: the route module must not carry its own provider loop.
    A second implementation is exactly how the scheduler's scan and the operator's
    scan start producing different evidence for the same system.
    """
    import inspect  # noqa: PLC0415

    from ccf.api.routes import posture as posture_routes  # noqa: PLC0415

    source = inspect.getsource(posture_routes.scan_system_all_connectors)
    assert "scan_all_providers" in source, "the route no longer delegates"
    assert "for key in sorted(known_providers())" not in source, (
        "the route has its own provider loop again; the scheduler calls the other one"
    )


@pytest.mark.asyncio
async def test_generated_tests_are_still_excluded_from_run_due() -> None:
    """The exclusion my first attempt tried to work around, pinned in place.

    Giving generated tests a frequency so `run_due` would pick them up was the
    wrong fix: `run_due` filters them out by source, and its evaluator would
    report connector-freshness noise over the real posture verdict. This asserts
    the filter stays, so nobody re-derives that idea from an empty
    `tests_evaluated`.
    """
    import inspect  # noqa: PLC0415

    from ccf.governance import control_tests  # noqa: PLC0415

    source = inspect.getsource(control_tests.run_due)
    assert 'ControlTest.source != "generated"' in source, (
        "run_due no longer excludes scan-generated tests; its evaluator will "
        "bury real posture verdicts under connector-freshness warnings"
    )
    # And nothing in the scan path sets a frequency, which would make that
    # exclusion the only thing preventing it.
    from ccf.posture import scan as scan_module  # noqa: PLC0415

    assert "frequency=" not in inspect.getsource(scan_module._upsert_generated_test)


@pytest.mark.asyncio
async def test_a_generated_test_still_carries_no_schedule() -> None:
    """Behavioural counterpart to the source check above.

    A generated test showing "daily" in the UI while the scheduler never runs it
    through `run_due` would be a false claim on a page -- the reason the first
    attempt was reverted rather than kept as harmless.
    """
    org_id, system_ids = await _org_with_systems(1)
    async with session_scope() as session:
        session.add(
            ControlTest(
                organization_id=org_id,
                system_id=system_ids[0],
                control_id="AC-3",
                name="generated check",
                method="connector",
                source="generated",
                check_key="demo.bucket.public",
            )
        )
        await session.flush()
        row = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == system_ids[0])
            )
        ).scalars().one()
        assert row.frequency is None


@pytest.mark.asyncio
async def test_checks_ruled_out_of_api_scope_are_counted_not_just_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gap between expected and run has to be explained on the line.

    This is the shape the dev stack is actually in: org 2's msgraph connector is
    `ready` and its fourteen checks all resolve to `manual_scope_review`, because
    the responsibility template answers "unknown" for their domains. So 164
    checks were expected, 0 ran, and nothing failed -- a reading that looks like
    a bug and is the template declining to guess who owns the control.

    Without this count the only way to learn that was to probe
    `provider_readiness` by hand, which is what it took to find it.
    """
    import ccf.posture.scan_all as scan_all_module  # noqa: PLC0415

    org_id, _ = await _org_with_systems(1)

    async def _all_out_of_scope(session: object, **_kw: Any) -> dict[str, Any]:
        return {
            "checks_run": 0,
            "checks_expected": 14,
            "manual_review_total": 14,
            "connectors": [],
        }

    monkeypatch.setattr(scan_all_module, "scan_all_providers", _all_out_of_scope)
    async with session_scope() as session:
        out = await scheduler._scan_org_systems(session, org_id=org_id)

    assert out["checks_expected"] == 14
    assert out["checks_run"] == 0
    assert out["manual_review"] == 14, (
        "a scan that ruled every check out of API scope is indistinguishable "
        "from one that silently did nothing"
    )
