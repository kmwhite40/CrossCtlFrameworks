"""CISO-01 / CISO-06: residual-risk visibility + honest overdue counting.

Exercises the real ``ccf.analytics.posture`` and ``ccf.analytics.overview``
functions against real POA&M rows — no mocking of the DB layer. Covers:

- risk_accepted POA&Ms surface in an explicit residual/accepted bucket instead
  of vanishing from every metric.
- a ``completed`` POA&M with a null ``closed_on`` is a visible data-quality
  signal rather than silently excluded.
- overdue falls back to ``scheduled_completion`` / ``original_due_on`` when
  ``due_on`` is null, and a POA&M with none of the three lands in
  ``no_due_date`` — never defaulted to on-track.
- the aging invariant ``on_track + overdue + no_due_date == open_total`` holds.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config

from ccf.analytics import overview, posture
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine")

TODAY = date(2026, 7, 21)


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _org_and_system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sys = System(organization_id=org.id, name=f"{name}-sys", baseline="moderate")
        s.add(sys)
        await s.flush()
        return org.id, sys.id


async def _make_poams(system_id: int) -> None:
    """Seed one POA&M for every scenario the requirements care about."""
    async with session_scope() as s:
        s.add_all(
            [
                # Ordinary open, overdue via due_on.
                POAM(
                    system_id=system_id,
                    title="overdue-due-on",
                    status="open",
                    severity="high",
                    identified_on=TODAY - timedelta(days=10),
                    due_on=TODAY - timedelta(days=1),
                ),
                # Ordinary open, on track via due_on.
                POAM(
                    system_id=system_id,
                    title="on-track-due-on",
                    status="open",
                    severity="moderate",
                    identified_on=TODAY - timedelta(days=10),
                    due_on=TODAY + timedelta(days=30),
                ),
                # due_on is null but scheduled_completion is in the past — must
                # still count as overdue, not "on track".
                POAM(
                    system_id=system_id,
                    title="overdue-scheduled-completion",
                    status="in_progress",
                    severity="critical",
                    identified_on=TODAY - timedelta(days=10),
                    due_on=None,
                    scheduled_completion=TODAY - timedelta(days=5),
                ),
                # due_on is null, scheduled_completion is null, but
                # original_due_on is in the past — same fallback, one level deeper.
                POAM(
                    system_id=system_id,
                    title="overdue-original-due-on",
                    status="open",
                    severity="high",
                    identified_on=TODAY - timedelta(days=10),
                    due_on=None,
                    scheduled_completion=None,
                    original_due_on=TODAY - timedelta(days=2),
                ),
                # No due date anywhere — must land in no_due_date, not on_track.
                POAM(
                    system_id=system_id,
                    title="no-due-date",
                    status="open",
                    severity="low",
                    identified_on=TODAY - timedelta(days=10),
                    due_on=None,
                    scheduled_completion=None,
                    original_due_on=None,
                ),
                # Risk-accepted: residual risk, must not be invisible.
                POAM(
                    system_id=system_id,
                    title="accepted-1",
                    status="risk_accepted",
                    severity="high",
                    identified_on=TODAY - timedelta(days=40),
                ),
                POAM(
                    system_id=system_id,
                    title="accepted-2",
                    status="risk_accepted",
                    severity="moderate",
                    identified_on=TODAY - timedelta(days=5),
                ),
                # Completed with no closed_on: a data-quality gap, not a clean close.
                POAM(
                    system_id=system_id,
                    title="completed-missing-closure",
                    status="completed",
                    severity="moderate",
                    identified_on=TODAY - timedelta(days=20),
                    closed_on=None,
                ),
                # Completed with a real closed_on: not a data-quality problem.
                POAM(
                    system_id=system_id,
                    title="completed-clean",
                    status="completed",
                    severity="low",
                    identified_on=TODAY - timedelta(days=20),
                    closed_on=TODAY - timedelta(days=1),
                ),
            ]
        )


@pytest.mark.asyncio
async def test_poam_aging_surfaces_residual_and_data_quality() -> None:
    org_id, sys_id = await _org_and_system("ResidualOrg")
    await _make_poams(sys_id)

    # Scoped to this test's own org — the DB is shared across the whole test
    # session (see conftest.clean_migrated_db), so an unscoped query would pick
    # up POA&Ms seeded by other tests/modules and break the exact-count asserts.
    async with session_scope() as s:
        aging = await posture.poam_aging(s, today=TODAY, org_id=org_id)

    # Open set is the four open/in_progress POA&Ms with a due-date scenario plus
    # the one with no due date at all — five total. risk_accepted/completed are
    # NOT "open" work, so they don't inflate open_total.
    assert aging["open_total"] == 5

    # Residual risk bucket: both risk_accepted rows are counted, not dropped.
    assert aging["accepted"] == 2

    # Data-quality signal: exactly the one completed POA&M with a null closed_on.
    assert aging["data_quality"]["completed_missing_closure"] == 1

    # Overdue: due_on, scheduled_completion, and original_due_on fallbacks all count.
    assert aging["overdue"] == 3
    assert aging["no_due_date"] == 1
    assert aging["on_track"] == 1

    # The core honesty invariant: nothing is silently defaulted to on-track.
    assert aging["on_track"] + aging["overdue"] + aging["no_due_date"] == aging["open_total"]

    # Existing aging-bucket keys are unchanged (a regression here breaks
    # test_enterprise.py's exact-set assertion on this same dict).
    assert set(aging["buckets"]) == {"0-30", "31-60", "61-90", "90+", "unknown"}


@pytest.mark.asyncio
async def test_poam_aging_empty_org_has_no_open_and_zero_buckets() -> None:
    org_id, _sys_id = await _org_and_system("EmptyOrg")
    async with session_scope() as s:
        aging = await posture.poam_aging(s, today=TODAY, org_id=org_id)
    assert aging["open_total"] == 0
    assert aging["overdue"] == 0
    assert aging["no_due_date"] == 0
    assert aging["on_track"] == 0
    assert aging["accepted"] == 0
    assert aging["data_quality"]["completed_missing_closure"] == 0


@pytest.mark.asyncio
async def test_poam_aging_scopes_by_org_id() -> None:
    _org_a, sys_a = await _org_and_system("ScopeOrgA")
    org_b, sys_b = await _org_and_system("ScopeOrgB")
    await _make_poams(sys_a)
    # Org B gets just one risk_accepted POA&M — must not see org A's data.
    async with session_scope() as s:
        s.add(
            POAM(
                system_id=sys_b,
                title="b-accepted",
                status="risk_accepted",
                severity="low",
                identified_on=TODAY,
            )
        )

    async with session_scope() as s:
        aging_b = await posture.poam_aging(s, today=TODAY, org_id=org_b)
    assert aging_b["open_total"] == 0
    assert aging_b["accepted"] == 1
    assert sys_a  # sys_a used only to seed org A's data


@pytest.mark.asyncio
async def test_org_summary_surfaces_residual_top_level_additively() -> None:
    org_id, sys_id = await _org_and_system("SummaryOrg")
    await _make_poams(sys_id)

    async with session_scope() as s:
        summary = await posture.org_summary(s, today=TODAY, org_id=org_id)

    # Existing top-level fields keep working.
    assert summary["open_poams"] == summary["poam_aging"]["open_total"] == 5
    assert summary["overdue_poams"] == summary["poam_aging"]["overdue"] == 3

    # New top-level fields are additive, not a replacement.
    assert summary["accepted_poams"] == 2
    assert summary["poam_data_quality"]["completed_missing_closure"] == 1
    assert summary["poam_aging"]["no_due_date"] == 1
    assert summary["poam_aging"]["on_track"] == 1


@pytest.mark.asyncio
async def test_systems_scorecard_overdue_falls_back_to_scheduled_completion() -> None:
    _org_id, sys_id = await _org_and_system("ScorecardOrg")
    async with session_scope() as s:
        s.add(
            POAM(
                system_id=sys_id,
                title="scorecard-overdue-fallback",
                status="open",
                severity="high",
                identified_on=TODAY - timedelta(days=10),
                due_on=None,
                scheduled_completion=TODAY - timedelta(days=3),
            )
        )

    async with session_scope() as s:
        cards = await posture.systems_scorecard(s, today=TODAY, org_id=None)
    card = next(c for c in cards if c["system_id"] == sys_id)
    assert card["open_poams"] == 1
    # Previously this would have been 0 (due_on-only check) — a null-due POA&M
    # tracked via scheduled_completion must not be silently "on track".
    assert card["overdue_poams"] == 1


@pytest.mark.asyncio
async def test_dashboard_overview_sla_excludes_no_due_date_from_on_track() -> None:
    org_id, sys_id = await _org_and_system("DashboardOrg")
    await _make_poams(sys_id)

    async with session_scope() as s:
        dash = await overview.dashboard_overview(s, org_id=org_id)

    sla = dash["sla"]
    assert sla["open"] == 5
    assert sla["overdue"] == 3
    assert sla["no_due_date"] == 1
    assert sla["on_track"] == 1
    assert sla["on_track"] + sla["overdue"] + sla["no_due_date"] == sla["open"]
    # on_track_pct must reflect the honest on_track count, not open - overdue.
    assert sla["on_track_pct"] == pytest.approx(100 * 1 / 5, abs=0.1)

    # Residual risk is surfaced on the dashboard payload, additively.
    assert dash["poam_residual"]["accepted"] == 2
    assert dash["poam_residual"]["data_quality"]["completed_missing_closure"] == 1

    # Existing fields keep working.
    assert dash["findings_total"] == 5
    assert set(dash["poam_buckets"]) == {"0-30", "31-60", "61-90", "90+", "unknown"}


@pytest.mark.asyncio
async def test_dashboard_overview_sla_on_track_pct_defaults_to_100_when_no_open_poams() -> None:
    org_id, _sys_id = await _org_and_system("NoOpenOrg")
    async with session_scope() as s:
        dash = await overview.dashboard_overview(s, org_id=org_id)
    assert dash["sla"]["open"] == 0
    assert dash["sla"]["on_track_pct"] == 100.0
