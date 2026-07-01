"""Unit tests for the enterprise governance engines (pure logic)."""

from __future__ import annotations

from datetime import date, timedelta
from types import SimpleNamespace as N

from ccf.governance.conmon import assess_health
from ccf.governance.risk import band, compute_scores

TODAY = date(2026, 7, 1)


def _impl(**kw):
    base = dict(
        id=1,
        system_id=1,
        control_id=1,
        status="implemented",
        next_assessment_due=None,
    )
    base.update(kw)
    return N(**base)


def test_health_healthy_when_current() -> None:
    ev = [N(expires_on=TODAY + timedelta(days=200))]
    status, reasons = assess_health(_impl(), ev, [], TODAY)
    assert status == "healthy"
    assert reasons == []


def test_health_overdue_on_expired_evidence() -> None:
    ev = [N(expires_on=TODAY - timedelta(days=1))]
    status, reasons = assess_health(_impl(), ev, [], TODAY)
    assert status == "overdue"
    assert "evidence expired" in reasons


def test_health_due_soon_on_expiring_evidence() -> None:
    ev = [N(expires_on=TODAY + timedelta(days=10))]
    status, _ = assess_health(_impl(), ev, [], TODAY)
    assert status == "due_soon"


def test_health_at_risk_on_open_critical_poam() -> None:
    ev = [N(expires_on=TODAY + timedelta(days=200))]
    poams = [N(severity="critical")]
    status, reasons = assess_health(_impl(), ev, poams, TODAY)
    assert status == "at_risk"
    assert any("POA&M" in r for r in reasons)


def test_health_overdue_beats_at_risk() -> None:
    ev = [N(expires_on=TODAY - timedelta(days=5))]
    status, _ = assess_health(_impl(status="planned"), ev, [N(severity="high")], TODAY)
    assert status == "overdue"  # highest-rank signal wins


def test_no_evidence_flags_due_soon() -> None:
    status, reasons = assess_health(_impl(), [], [], TODAY)
    assert status == "due_soon"
    assert "no evidence on record" in reasons


def test_risk_scoring_and_band() -> None:
    inherent, residual = compute_scores("high", "high", "mitigate")
    assert inherent == 25  # 5 x 5
    assert residual == 10  # 25 * 0.4
    assert band(inherent) == "critical"
    assert band(residual) == "high"  # 10 falls in the 10-15 high band
    assert compute_scores("low", None, "accept") == (None, None)


def test_risk_accept_keeps_inherent() -> None:
    inherent, residual = compute_scores("moderate", "high", "accept")
    assert inherent == residual == 15
