"""Task 3 — CISO-05 / CISO-11: dashboard population reconciliation + org scoping.

Exercises the real ``ccf.analytics.overview`` and ``ccf.analytics.posture``
functions against real rows — no mocking of the DB layer. Covers:

- the risk heatmap (``_risk_by_band``) and the risk-status breakdown
  (``org_summary.risks_by_status``) agree on population: both treat "open
  risk" as "status != closed", so the heatmap total reconciles exactly to the
  sum of every non-closed status count.
- dashboard ``_block`` functions that own tenant data (risk, tasks, control
  tests, KSI states, MTTR) are filtered by ``org_id`` in the SQL itself —
  provably org-scoped, not only relying on RLS.
- ``findings_by_severity`` is built from the same POA&M rows that produce
  ``findings_total``, with a catch-all "other" bucket, so the two always sum
  to the same total — including for severity values outside the known
  vocabulary.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete

from ccf.analytics import overview, posture
from ccf.analytics.overview import _severity_breakdown
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import KSI, POAM, KSIState, Organization, Risk, System, Task
from ccf.models_grc import ControlTest

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


@pytest.mark.asyncio
async def test_risk_heatmap_reconciles_with_status_breakdown() -> None:
    """Heatmap total == sum of every non-closed risks_by_status count."""
    org_id, sys_id = await _org_and_system("ReconcileOrg")
    async with session_scope() as s:
        s.add_all(
            [
                Risk(system_id=sys_id, title="r-open-high", status="open", residual_score=12),
                Risk(system_id=sys_id, title="r-mitigated", status="mitigated", residual_score=3),
                Risk(system_id=sys_id, title="r-accepted", status="accepted", residual_score=20),
                # Closed risks must not inflate the "open risk" population in
                # either view.
                Risk(system_id=sys_id, title="r-closed-1", status="closed", residual_score=25),
                Risk(system_id=sys_id, title="r-closed-2", status="closed", residual_score=None),
                # No residual_score at all — bands to "unknown", still open.
                Risk(system_id=sys_id, title="r-open-unknown", status="open", residual_score=None),
            ]
        )

    async with session_scope() as s:
        risk_by_band = await overview._risk_by_band(s, org_id=org_id)
        summary = await posture.org_summary(s, today=TODAY, org_id=org_id)

    risks_by_status = summary["risks_by_status"]
    heatmap_total = sum(risk_by_band.values())
    non_closed_status_total = sum(n for status, n in risks_by_status.items() if status != "closed")

    assert heatmap_total == 4  # every seeded risk except the two "closed" ones
    assert heatmap_total == non_closed_status_total
    # closed risks are visible in the status breakdown (not hidden), just
    # excluded from what counts as "open" in both views.
    assert risks_by_status.get("closed", 0) == 2
    # Sanity on the band split itself.
    assert risk_by_band["high"] == 1
    assert risk_by_band["low"] == 1
    assert risk_by_band["critical"] == 1
    assert risk_by_band["unknown"] == 1


@pytest.mark.asyncio
async def test_dashboard_risk_and_ops_blocks_are_org_scoped_in_query() -> None:
    """Scoped dashboard blocks must not see another org's rows — defense in
    depth beyond RLS: this asserts the query itself is filtered, using two
    orgs seeded in the same test run against the same (unfiltered-by-RLS)
    session."""
    ksi_ids: list[int] = []
    try:
        await _dashboard_risk_and_ops_blocks_are_org_scoped_in_query(ksi_ids)
    finally:
        # KSI (``ccf.ksis``) is the GLOBAL FedRAMP 20x catalog table — the
        # suite's DB reset only runs once per session, so leaked rows here
        # inflate test_fedramp20x.py::test_seed_catalog_is_idempotent's exact
        # row count for every test that runs after this one. KSIState rows
        # cascade-delete (ondelete="CASCADE") along with their KSI parent.
        if ksi_ids:
            async with session_scope() as s:
                await s.execute(delete(KSI).where(KSI.id.in_(ksi_ids)))


async def _dashboard_risk_and_ops_blocks_are_org_scoped_in_query(ksi_ids: list[int]) -> None:
    org_a, sys_a = await _org_and_system("DashScopeOrgA")
    org_b, sys_b = await _org_and_system("DashScopeOrgB")

    async with session_scope() as s:
        # Org A: one open risk, one open task, one control test, one KSI state.
        s.add_all(
            [
                Risk(system_id=sys_a, title="a-risk", status="open", residual_score=10),
                Task(organization_id=org_a, title="a-task", status="open", priority="critical"),
                ControlTest(
                    organization_id=org_a,
                    system_id=sys_a,
                    control_id="AC-1",
                    name="a-test",
                    last_status="fail",
                ),
            ]
        )
        # Org B: three open risks, three open tasks, three control tests —
        # deliberately more than org A's counts so an unscoped query would be
        # detectably wrong (not just off-by-a-coincidence).
        s.add_all(
            [
                Risk(system_id=sys_b, title="b-risk-1", status="open", residual_score=10),
                Risk(system_id=sys_b, title="b-risk-2", status="open", residual_score=10),
                Risk(system_id=sys_b, title="b-risk-3", status="open", residual_score=10),
                Task(organization_id=org_b, title="b-task-1", status="open", priority="high"),
                Task(organization_id=org_b, title="b-task-2", status="open", priority="high"),
                Task(organization_id=org_b, title="b-task-3", status="open", priority="high"),
            ]
        )
        for i in range(3):
            s.add(
                ControlTest(
                    organization_id=org_b,
                    system_id=sys_b,
                    control_id=f"AC-{i + 2}",
                    name=f"b-test-{i}",
                    last_status="pass",
                )
            )
        ksi_1 = KSI(identifier="KSI-SCOPE-TEST-1", category="IAM", name="scope-test-ksi-1")
        ksi_2 = KSI(identifier="KSI-SCOPE-TEST-2", category="IAM", name="scope-test-ksi-2")
        s.add_all([ksi_1, ksi_2])
        await s.flush()
        ksi_ids.extend([ksi_1.id, ksi_2.id])
        s.add_all(
            [
                KSIState(system_id=sys_a, ksi_id=ksi_1.id, status="fail"),
                KSIState(system_id=sys_b, ksi_id=ksi_1.id, status="pass"),
                KSIState(system_id=sys_b, ksi_id=ksi_2.id, status="pass"),
            ]
        )

    async with session_scope() as s:
        dash_a = await overview.dashboard_overview(s, org_id=org_a)

    assert sum(dash_a["risk_by_band"].values()) == 1
    assert dash_a["tasks"]["total"] == 1
    assert dash_a["tasks"]["critical"] == 1
    assert dash_a["control_tests"]["total"] == 1
    assert dash_a["control_tests"]["fail"] == 1
    assert dash_a["ksi"]["total"] == 1
    assert dash_a["ksi"]["fail"] == 1

    # An unscoped call sees everything (RLS is bypassed by the raw session in
    # tests, so this proves the SQL filter — not RLS — is what scoped the
    # query above).
    async with session_scope() as s:
        dash_unscoped = await overview.dashboard_overview(s, org_id=None)
    assert sum(dash_unscoped["risk_by_band"].values()) >= 4
    assert dash_unscoped["tasks"]["total"] >= 4
    assert dash_unscoped["control_tests"]["total"] >= 4
    assert dash_unscoped["ksi"]["total"] >= 3


@pytest.mark.asyncio
async def test_dashboard_mttr_trend_is_org_scoped() -> None:
    org_a, sys_a = await _org_and_system("MttrOrgA")
    org_b, sys_b = await _org_and_system("MttrOrgB")
    async with session_scope() as s:
        s.add_all(
            [
                POAM(
                    system_id=sys_a,
                    title="a-closed",
                    status="completed",
                    severity="high",
                    identified_on=TODAY - timedelta(days=20),
                    closed_on=TODAY - timedelta(days=5),
                ),
                POAM(
                    system_id=sys_b,
                    title="b-closed",
                    status="completed",
                    severity="high",
                    identified_on=TODAY - timedelta(days=100),
                    closed_on=TODAY - timedelta(days=5),
                ),
            ]
        )

    async with session_scope() as s:
        mttr_a = await overview._mttr_trend(s, org_id=org_a)
        mttr_b = await overview._mttr_trend(s, org_id=org_b)

    # Org A's POA&M closed after 15 days, org B's after 95 — scoping must keep
    # the two trends distinct rather than blending both orgs' closures.
    assert mttr_a["closed_total"] == 1
    assert mttr_b["closed_total"] == 1
    assert mttr_a["latest"] == pytest.approx(15.0)
    assert mttr_b["latest"] == pytest.approx(95.0)


@pytest.mark.asyncio
async def test_findings_by_severity_sums_to_findings_total_on_real_data() -> None:
    org_id, sys_id = await _org_and_system("SeverityOrg")
    async with session_scope() as s:
        s.add_all(
            [
                POAM(
                    system_id=sys_id,
                    title="crit",
                    status="open",
                    severity="critical",
                    identified_on=TODAY,
                ),
                POAM(
                    system_id=sys_id,
                    title="high-1",
                    status="open",
                    severity="high",
                    identified_on=TODAY,
                ),
                POAM(
                    system_id=sys_id,
                    title="high-2",
                    status="in_progress",
                    severity="high",
                    identified_on=TODAY,
                ),
                POAM(
                    system_id=sys_id,
                    title="low",
                    status="open",
                    severity="low",
                    identified_on=TODAY,
                ),
            ]
        )

    async with session_scope() as s:
        dash = await overview.dashboard_overview(s, org_id=org_id)

    assert dash["findings_total"] == 4
    assert sum(item["count"] for item in dash["findings_by_severity"]) == dash["findings_total"]
    by_key = {item["key"]: item["count"] for item in dash["findings_by_severity"]}
    assert by_key == {"critical": 1, "high": 2, "low": 1}
    assert "other" not in by_key  # every seeded severity is in-vocabulary


@pytest.mark.asyncio
async def test_findings_by_severity_empty_org_still_sums_to_zero() -> None:
    org_id, _sys_id = await _org_and_system("EmptySeverityOrg")
    async with session_scope() as s:
        dash = await overview.dashboard_overview(s, org_id=org_id)
    assert dash["findings_total"] == 0
    assert sum(item["count"] for item in dash["findings_by_severity"]) == 0


def test_severity_breakdown_catches_out_of_vocabulary_severities() -> None:
    """Unit-level proof of the invariant for values the DB enum can't produce
    today but the aggregation must still handle honestly (future/legacy data).
    """
    by_sev = {"critical": 2, "high": 1, "informational": 3, "": 1}
    result = _severity_breakdown(by_sev)
    assert sum(seg["count"] for seg in result) == sum(by_sev.values())
    by_key = {seg["key"]: seg["count"] for seg in result}
    assert by_key["critical"] == 2
    assert by_key["high"] == 1
    assert by_key["other"] == 4  # "informational" (3) + "" (1)


def test_severity_breakdown_sums_correctly_for_known_vocabulary_only() -> None:
    by_sev = {"critical": 1, "high": 2, "moderate": 3, "low": 4}
    result = _severity_breakdown(by_sev)
    assert sum(seg["count"] for seg in result) == 10
    assert {seg["key"] for seg in result} == {"critical", "high", "moderate", "low"}
