"""Flaw-remediation latency against a declared timeframe."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from ccf.patching.sla import (
    FEDRAMP_TIMEFRAMES,
    SLA_BUCKETS,
    RemediationWindow,
    classify,
    measure,
)

TODAY = date(2026, 9, 15)


@dataclass
class _Poam:
    """Only the fields the calculation reads."""

    severity: str = "high"
    status: str = "open"
    source: str | None = "scan"
    identified_on: date | None = None
    closed_on: date | None = None
    id: int = 1


def _open(severity: str, age_days: int, **kw) -> _Poam:
    return _Poam(
        severity=severity, status="open", identified_on=TODAY - timedelta(days=age_days), **kw
    )


def _closed(severity: str, age_days: int, latency_days: int) -> _Poam:
    identified = TODAY - timedelta(days=age_days)
    return _Poam(
        severity=severity,
        status="completed",
        identified_on=identified,
        closed_on=identified + timedelta(days=latency_days),
    )


WINDOW = RemediationWindow(**FEDRAMP_TIMEFRAMES)


# ── the defaults ─────────────────────────────────────────────────────────────


def test_the_fedramp_defaults_are_pinned() -> None:
    """Inventing different numbers for a federal product would be worse than
    adopting the ones assessors already expect, so a change must be deliberate."""
    assert FEDRAMP_TIMEFRAMES == {
        "critical": 30,
        "high": 30,
        "moderate": 90,
        "low": 180,
    }


def test_the_window_resolves_days_per_severity() -> None:
    assert WINDOW.days_for("critical") == 30
    assert WINDOW.days_for("low") == 180


def test_an_unknown_severity_falls_back_to_the_strictest_window() -> None:
    """A severity this build does not recognise must not get the most generous
    treatment by default."""
    assert WINDOW.days_for("catastrophic") == 30


# ── the boundaries ───────────────────────────────────────────────────────────


def test_exactly_at_the_limit_is_within_sla() -> None:
    """An organization that says 30 days means 30, not 29."""
    assert classify(_open("high", 30), allowed_days=30, today=TODAY) == "within_sla"


def test_one_day_past_the_limit_is_breached() -> None:
    assert classify(_open("high", 31), allowed_days=30, today=TODAY) == "breached"


def test_closed_exactly_at_the_limit_is_on_time() -> None:
    assert classify(_closed("high", 60, 30), allowed_days=30, today=TODAY) == "closed_on_time"


def test_closed_one_day_past_is_late() -> None:
    assert classify(_closed("high", 60, 31), allowed_days=30, today=TODAY) == "closed_late"


# ── the unmeasurable ─────────────────────────────────────────────────────────


def test_no_identified_on_is_unknown_not_on_time() -> None:
    """Latency is unmeasurable, and counting it as on-time would overstate the
    exact number SI-2 is about."""
    assert classify(_Poam(identified_on=None), allowed_days=30, today=TODAY) == "unknown"


def test_a_closed_poam_with_no_closure_date_is_unknown() -> None:
    """A data-quality signal, never on-time -- the stance poam_aging already
    takes toward a completed POA&M with a null closed_on."""
    p = _Poam(status="completed", identified_on=TODAY - timedelta(days=5), closed_on=None)
    assert classify(p, allowed_days=30, today=TODAY) == "unknown"


def test_a_reopened_poam_with_a_stale_closed_on_is_unknown_not_on_time() -> None:
    """CRITICAL 1 (PR #20 review): a POA&M closed fast and then reopened (status
    back to "open") must not still classify as closed_on_time just because a
    stale closed_on was left behind. Before the fix, ``classify`` branched on
    ``closed_on is not None`` before consulting status, so this exact case --
    identified 404 days ago, "closed" in 4 days, still open today -- returned
    "closed_on_time" and vanished from both breaching_ids and the numerator's
    denominator scrutiny, overstating SI-2 compliance for a flaw 374 days
    overdue. It must land in the same ``unknown`` bucket as a closed POA&M
    with no closure date at all -- not a free pass back to within_sla either.
    """
    identified = TODAY - timedelta(days=404)
    p = _Poam(
        status="open",
        identified_on=identified,
        closed_on=identified + timedelta(days=4),
    )
    assert classify(p, allowed_days=30, today=TODAY) == "unknown"


def test_a_closure_before_identification_is_unknown_not_instant() -> None:
    """Negative latency is corrupt data, not perfect performance."""
    identified = TODAY - timedelta(days=5)
    p = _Poam(
        status="completed", identified_on=identified, closed_on=identified - timedelta(days=2)
    )
    assert classify(p, allowed_days=30, today=TODAY) == "unknown"


# ── the report ───────────────────────────────────────────────────────────────


def test_each_severity_uses_its_own_window() -> None:
    """A 60-day-old moderate is fine; a 60-day-old critical is not."""
    report = measure(
        [_open("moderate", 60), _open("critical", 60)], window=WINDOW, today=TODAY
    )
    assert report.buckets["within_sla"] == 1
    assert report.buckets["breached"] == 1


def test_an_assessment_sourced_poam_is_excluded() -> None:
    """It is not a flaw; including it would distort the SI-2 number."""
    report = measure(
        [_open("critical", 60), _open("critical", 60, source="assessment")],
        window=WINDOW,
        today=TODAY,
    )
    assert report.measured == 1
    assert report.excluded == 1


def test_a_poam_with_no_source_is_excluded() -> None:
    report = measure([_open("high", 5, source=None)], window=WINDOW, today=TODAY)
    assert report.measured == 0
    assert report.excluded == 1


def test_the_buckets_sum_to_the_measured_count() -> None:
    """The invariant that makes the report trustworthy: nothing is silently
    dropped, the way poam_aging asserts its own three buckets sum."""
    poams = [
        _open("critical", 10),
        _open("critical", 40),
        _closed("high", 60, 10),
        _closed("high", 60, 45),
        _Poam(identified_on=None),
    ]
    report = measure(poams, window=WINDOW, today=TODAY)
    assert sum(report.buckets.values()) == report.measured == 5
    assert set(report.buckets) == set(SLA_BUCKETS)


def test_the_report_names_the_breaching_poams() -> None:
    """A count nobody can act on is a worse artefact than a list."""
    breaching = _open("critical", 45)
    breaching.id = 77
    report = measure([breaching, _open("low", 5)], window=WINDOW, today=TODAY)
    assert report.breaching_ids == [77]


def test_median_latency_ignores_the_unmeasurable() -> None:
    poams = [
        _closed("high", 60, 10),
        _closed("high", 60, 20),
        _closed("high", 60, 30),
        _Poam(identified_on=None),
    ]
    report = measure(poams, window=WINDOW, today=TODAY)
    assert report.median_closed_latency_days == 20


def test_median_latency_is_none_when_nothing_closed_measurably() -> None:
    report = measure([_open("high", 5)], window=WINDOW, today=TODAY)
    assert report.median_closed_latency_days is None


def test_an_empty_input_reports_zeroes_not_a_perfect_score() -> None:
    """No findings is not 100% compliance with a remediation timeframe."""
    report = measure([], window=WINDOW, today=TODAY)
    assert report.measured == 0
    assert report.compliance_pct is None
    assert sum(report.buckets.values()) == 0


def test_compliance_counts_on_time_closures_and_within_sla_openings() -> None:
    poams = [_open("high", 5), _closed("high", 60, 10), _open("high", 90)]
    report = measure(poams, window=WINDOW, today=TODAY)
    assert report.compliance_pct == round(100 * 2 / 3, 1)


def test_unknowns_count_against_compliance() -> None:
    """They cannot be shown to comply, so they must not be excluded from the
    denominator -- that would make poor record-keeping improve the score."""
    report = measure(
        [_open("high", 5), _Poam(identified_on=None)], window=WINDOW, today=TODAY
    )
    assert report.compliance_pct == 50.0


def test_the_per_severity_breakdown_is_reported() -> None:
    report = measure(
        [_open("critical", 45), _open("low", 45)], window=WINDOW, today=TODAY
    )
    assert report.by_severity["critical"]["breached"] == 1
    assert report.by_severity["low"]["within_sla"] == 1
