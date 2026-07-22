"""Unit tests for the risk + POA&M buildout (pure output/logic helpers)."""

from __future__ import annotations

from datetime import date
from types import SimpleNamespace as N

from ccf.api.routes.poams import _out as poam_out
from ccf.api.routes.risks import HIGH_RESIDUAL
from ccf.governance.risk import band, compute_scores

TODAY = date(2026, 7, 1)


def _poam(**kw):
    base = dict(
        id=1,
        system_id=1,
        control_id=None,
        title="Weakness",
        weakness=None,
        severity="high",
        status="open",
        identified_on=None,
        due_on=None,
        original_due_on=None,
        scheduled_completion=None,
        closed_on=None,
        owner_user_id=None,
        point_of_contact=None,
        source=None,
        source_ref=None,
        remediation_plan=None,
        resources_required=None,
        cost_estimate=None,
        risk_id=None,
        vendor_id=None,
        milestones=[],
    )
    base.update(kw)
    return N(**base)


def test_poam_progress_from_milestones() -> None:
    ms = [
        N(status="completed"),
        N(status="pending"),
        N(status="completed"),
        N(status="in_progress"),
    ]
    ms = [
        N(id=i, description="m", due_on=None, completed_on=None, status=s.status, sort_order=i)
        for i, s in enumerate(ms)
    ]
    d = poam_out(_poam(milestones=ms), TODAY)
    assert d["milestone_total"] == 4
    assert d["milestone_done"] == 2
    assert d["progress_pct"] == 50


def test_poam_overdue_flag() -> None:
    d = poam_out(_poam(due_on=date(2025, 1, 1), status="open"), TODAY)
    assert d["overdue"] is True
    d2 = poam_out(_poam(due_on=date(2099, 1, 1), status="open"), TODAY)
    assert d2["overdue"] is False


def test_poam_deviation_flag() -> None:
    # Due date slipped past the original baseline.
    d = poam_out(_poam(original_due_on=date(2026, 3, 1), due_on=date(2026, 6, 1)), TODAY)
    assert d["deviation"] is True


def test_high_residual_threshold_matches_band() -> None:
    _, residual = compute_scores("high", "high", "accept")  # 25, unchanged
    assert residual >= HIGH_RESIDUAL
    assert band(residual) == "critical"
