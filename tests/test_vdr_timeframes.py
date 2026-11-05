"""The 20x VDR engine: deadlines from the pinned FedRAMP rules, per class.

Every number asserted here was read from fedramp.gov on 2026-11-05
(/2026/providers/20x/rules/vulnerability-detection-and-response/ and
/vulnerability-evaluation-and-reporting/). The engine reads them from the
vendored dataset; these tests pin that dataset to the published text, so a
re-vendor that moves a number fails here instead of silently moving a
deadline.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace

import pytest

from ccf.vdr import timeframes as tf

T0 = datetime(2026, 12, 1, 0, 0, tzinfo=UTC)


def _poam(**kw: object) -> SimpleNamespace:
    base = {"id": 1, "status": "open", "identified_on": date(2026, 12, 1), "closed_on": None}
    base.update(kw)
    return SimpleNamespace(**base)


def _ev(
    pain: int,
    *,
    at: datetime = T0,
    irv: bool = True,
    lev: bool = True,
    fp: bool = False,
) -> tf.Evaluation:
    return tf.Evaluation(
        pain_rating=pain,
        internet_reachable=irv,
        likely_exploitable=lev,
        false_positive=fp,
        evaluated_at=at,
    )


# ── the pinned tables ─────────────────────────────────────────────────────


PVR_DAYS = {
    # class: {N: (LEV+IRV, LEV+NIRV, NLEV)}, from the fedramp.gov tables.
    "A": {5: (4, 8, 32), 4: (8, 32, 64), 3: (32, 64, 192), 2: (96, 160, 192)},
    "B": {5: (4, 8, 32), 4: (8, 32, 64), 3: (32, 64, 192), 2: (96, 160, 192)},
    "C": {5: (2, 4, 16), 4: (4, 8, 64), 3: (16, 32, 128), 2: (48, 128, 192)},
    "D": {5: (0.5, 1, 8), 4: (2, 8, 32), 3: (8, 16, 64), 2: (24, 96, 192)},
}


@pytest.mark.parametrize("cls", ["A", "B", "C", "D"])
def test_mitigation_table_matches_the_published_rule(cls: str) -> None:
    t = tf.class_timeframes(cls)
    assert t is not None
    for pain, (irv_lev, nirv_lev, nlev) in PVR_DAYS[cls].items():
        row = t.mitigation[pain]
        assert row["irv_lev"] == timedelta(days=irv_lev)
        assert row["nirv_lev"] == timedelta(days=nirv_lev)
        assert row["nlev"] == timedelta(days=nlev)


def test_class_d_n5_internet_reachable_is_twelve_hours_not_a_day() -> None:
    t = tf.class_timeframes("D")
    assert t is not None
    assert t.mitigation[5]["irv_lev"] == timedelta(hours=12)


@pytest.mark.parametrize("cls", ["A", "B", "C", "D"])
def test_n1_and_n0_have_no_timeframe(cls: str) -> None:
    t = tf.class_timeframes(cls)
    assert t is not None
    assert 1 not in t.mitigation and 0 not in t.mitigation


@pytest.mark.parametrize(
    ("cls", "evaluate", "sample"),
    [("A", 14, 14), ("B", 7, 7), ("C", 5, 3), ("D", 2, 1)],
)
def test_evaluation_and_sample_detection_windows(cls: str, evaluate: int, sample: int) -> None:
    t = tf.class_timeframes(cls)
    assert t is not None
    assert t.evaluate_within == timedelta(days=evaluate)  # VER-TFR-EVU
    assert t.sample_detection == timedelta(days=sample)  # VDR-TFR-PSD


def test_acceptance_window_is_192_days() -> None:
    assert timedelta(days=192) == tf.ACCEPT_WITHIN  # VER-TFR-MAV


def test_no_class_means_no_class_timeframes() -> None:
    assert tf.class_timeframes(None) is None


def test_an_unknown_class_is_refused_not_defaulted() -> None:
    with pytest.raises(ValueError, match="E"):
        tf.class_timeframes("E")


def test_the_rules_version_is_reported() -> None:
    assert tf.rules_version() == "2026.10.13.01"


# ── one flaw ──────────────────────────────────────────────────────────────


def test_unevaluated_flaw_awaits_evaluation_until_evu_passes() -> None:
    c = tf.class_timeframes("C")
    s = tf.assess(_poam(), [], cls=c, kev_due=None, now=T0 + timedelta(days=5))
    assert s.state == "awaiting_evaluation"
    assert s.evaluation_due == T0 + timedelta(days=5)
    assert s.breaches == []


def test_unevaluated_flaw_past_evu_is_overdue_and_names_the_rule() -> None:
    c = tf.class_timeframes("C")
    s = tf.assess(_poam(), [], cls=c, kev_due=None, now=T0 + timedelta(days=5, seconds=1))
    assert s.state == "overdue"
    assert [b.rule for b in s.breaches] == ["VER-TFR-EVU"]
    assert "5 days" in s.breaches[0].explanation


def test_unevaluated_flaw_without_a_class_is_not_called_on_time() -> None:
    s = tf.assess(_poam(), [], cls=None, kev_due=None, now=T0 + timedelta(days=400))
    assert s.state == "awaiting_evaluation"
    assert s.evaluation_due is None
    assert "class" in s.note.lower()


def test_evaluated_flaw_gets_the_class_c_window_for_its_column() -> None:
    c = tf.class_timeframes("C")
    s = tf.assess(_poam(), [_ev(4, irv=False)], cls=c, kev_due=None, now=T0)
    assert s.mitigation_column == "nirv_lev"
    assert s.mitigation_due == T0 + timedelta(days=8)
    assert s.state == "within"


def test_not_likely_exploitable_uses_nlev_whatever_the_reachability() -> None:
    c = tf.class_timeframes("C")
    s = tf.assess(_poam(), [_ev(5, irv=True, lev=False)], cls=c, kev_due=None, now=T0)
    assert s.mitigation_column == "nlev"
    assert s.mitigation_due == T0 + timedelta(days=16)


def test_mitigation_past_due_is_a_pvr_breach() -> None:
    c = tf.class_timeframes("C")
    s = tf.assess(_poam(), [_ev(5)], cls=c, kev_due=None, now=T0 + timedelta(days=2, seconds=1))
    assert s.state == "overdue"
    assert [b.rule for b in s.breaches] == ["VDR-TFR-PVR"]


def test_at_the_limit_is_within() -> None:
    c = tf.class_timeframes("C")
    s = tf.assess(_poam(), [_ev(5)], cls=c, kev_due=None, now=T0 + timedelta(days=2))
    assert s.state == "within"


def test_n1_has_no_timeframe_and_is_not_called_within() -> None:
    c = tf.class_timeframes("C")
    s = tf.assess(_poam(), [_ev(1)], cls=c, kev_due=None, now=T0)
    assert s.state == "no_timeframe"
    assert s.mitigation_due is None
    assert "VDR-TFR-RMN" in s.note


def test_resaving_the_same_evaluation_does_not_restart_the_clock() -> None:
    c = tf.class_timeframes("C")
    evs = [_ev(5, at=T0), _ev(5, at=T0 + timedelta(days=1))]
    s = tf.assess(_poam(), evs, cls=c, kev_due=None, now=T0 + timedelta(days=3))
    assert s.clock_start == T0
    assert s.state == "overdue"


def test_a_reduced_rating_starts_a_new_window() -> None:
    c = tf.class_timeframes("C")
    later = T0 + timedelta(days=2)
    evs = [_ev(5, at=T0), _ev(3, at=later)]
    s = tf.assess(_poam(), evs, cls=c, kev_due=None, now=later + timedelta(days=10))
    assert s.clock_start == later
    assert s.mitigation_due == later + timedelta(days=16)
    assert s.state == "within"


def test_a_return_to_an_earlier_tuple_is_a_new_run_not_the_old_clock() -> None:
    c = tf.class_timeframes("C")
    evs = [_ev(3, at=T0), _ev(5, at=T0 + timedelta(days=1)), _ev(3, at=T0 + timedelta(days=2))]
    s = tf.assess(_poam(), evs, cls=c, kev_due=None, now=T0 + timedelta(days=3))
    assert s.clock_start == T0 + timedelta(days=2)


def test_evaluations_are_ordered_by_time_not_by_argument_order() -> None:
    c = tf.class_timeframes("C")
    evs = [_ev(3, at=T0 + timedelta(days=2)), _ev(5, at=T0)]
    s = tf.assess(_poam(), evs, cls=c, kev_due=None, now=T0 + timedelta(days=3))
    assert s.current is not None and s.current.pain_rating == 3


def test_kev_due_date_is_a_breach_even_when_fully_mitigated() -> None:
    c = tf.class_timeframes("C")
    s = tf.assess(
        _poam(), [_ev(0)], cls=c, kev_due=date(2026, 12, 10), now=datetime(2026, 12, 11, tzinfo=UTC)
    )
    assert [b.rule for b in s.breaches] == ["VDR-TFR-KEV"]
    assert s.state == "overdue"


def test_kev_due_day_itself_is_not_late() -> None:
    s = tf.assess(
        _poam(),
        [],
        cls=None,
        kev_due=date(2026, 12, 10),
        now=datetime(2026, 12, 10, 23, tzinfo=UTC),
    )
    assert s.breaches == []


def test_kev_applies_without_a_class() -> None:
    s = tf.assess(
        _poam(), [], cls=None, kev_due=date(2026, 12, 10), now=datetime(2026, 12, 11, tzinfo=UTC)
    )
    assert [b.rule for b in s.breaches] == ["VDR-TFR-KEV"]


def test_kev_still_applies_to_an_accepted_vulnerability() -> None:
    s = tf.assess(
        _poam(status="risk_accepted"),
        [_ev(3)],
        cls=tf.class_timeframes("C"),
        kev_due=date(2026, 12, 10),
        now=datetime(2026, 12, 11, tzinfo=UTC),
    )
    assert [b.rule for b in s.breaches] == ["VDR-TFR-KEV"]


def test_an_accepted_vulnerability_without_a_kev_is_accepted() -> None:
    s = tf.assess(
        _poam(status="risk_accepted"),
        [_ev(3)],
        cls=tf.class_timeframes("C"),
        kev_due=None,
        now=T0 + timedelta(days=400),
    )
    assert s.state == "accepted"
    assert s.breaches == []


def test_open_past_192_days_of_first_evaluation_must_be_accepted() -> None:
    c = tf.class_timeframes("A")
    evs = [_ev(2, lev=False, at=T0)]
    s = tf.assess(_poam(), evs, cls=c, kev_due=None, now=T0 + timedelta(days=192, seconds=1))
    assert "VER-TFR-MAV" in [b.rule for b in s.breaches]
    assert s.accept_by == T0 + timedelta(days=192)


def test_mav_clock_is_the_first_evaluation_not_the_latest() -> None:
    evs = [_ev(3, at=T0), _ev(2, at=T0 + timedelta(days=100))]
    s = tf.assess(_poam(), evs, cls=None, kev_due=None, now=T0 + timedelta(days=193))
    assert s.accept_by == T0 + timedelta(days=192)
    assert "VER-TFR-MAV" in [b.rule for b in s.breaches]


def test_a_fully_mitigated_vulnerability_has_no_mav_breach() -> None:
    s = tf.assess(_poam(), [_ev(0)], cls=None, kev_due=None, now=T0 + timedelta(days=400))
    assert s.breaches == []


def test_closed_flaws_are_closed_with_no_breaches() -> None:
    s = tf.assess(
        _poam(status="closed", closed_on=date(2026, 12, 2)),
        [],
        cls=tf.class_timeframes("D"),
        kev_due=date(2026, 12, 1),
        now=T0 + timedelta(days=30),
    )
    assert s.state == "closed"
    assert s.breaches == []


def test_latest_false_positive_awaits_closure_and_carries_no_deadline() -> None:
    s = tf.assess(
        _poam(),
        [_ev(5), _ev(0, fp=True, at=T0 + timedelta(hours=1))],
        cls=tf.class_timeframes("D"),
        kev_due=None,
        now=T0 + timedelta(days=30),
    )
    assert s.state == "false_positive"
    assert s.breaches == []
    assert s.mitigation_due is None


def test_a_flaw_with_no_identification_date_is_not_on_time() -> None:
    s = tf.assess(_poam(identified_on=None), [], cls=tf.class_timeframes("C"), kev_due=None, now=T0)
    assert s.state == "awaiting_evaluation"
    assert s.evaluation_due is None
    assert "identification date" in s.note


def test_naive_now_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone"):
        tf.assess(_poam(), [], cls=None, kev_due=None, now=datetime(2026, 12, 1))


# ── detection cadence ─────────────────────────────────────────────────────


def test_cadence_per_scanner_against_the_class_sample_window() -> None:
    c = tf.class_timeframes("C")
    now = T0 + timedelta(days=10)
    runs = [
        ("nessus", T0 + timedelta(days=8)),
        ("nessus", T0),
        ("inspector", T0 + timedelta(days=6, hours=23)),
    ]
    out = {r.scanner: r for r in tf.detection_cadence(runs, cls=c, now=now)}
    assert out["nessus"].last_at == T0 + timedelta(days=8)
    assert out["nessus"].stale is False
    assert out["inspector"].stale is True
    assert out["inspector"].required == timedelta(days=3)


def test_cadence_without_a_class_reports_age_but_no_verdict() -> None:
    out = tf.detection_cadence([("nessus", T0)], cls=None, now=T0 + timedelta(days=90))
    assert out[0].stale is None
    assert out[0].required is None


# ── which evaluations need a second person ────────────────────────────────


@pytest.mark.parametrize(
    ("previous", "new", "relaxes"),
    [
        (None, _ev(5), False),
        (None, _ev(2), False),
        (None, _ev(1), True),  # a first rating with no timeframe at all
        (None, _ev(0), True),
        (None, _ev(0, fp=True), True),
        (_ev(5), _ev(5), False),
        (_ev(3), _ev(5), False),  # tightening never waits
        (_ev(5), _ev(4), True),
        (_ev(5, irv=True), _ev(5, irv=False), True),  # irv_lev -> nirv_lev
        (_ev(5, irv=False), _ev(5, irv=True), False),
        (_ev(5), _ev(5, lev=False), True),  # -> nlev
        (_ev(5, lev=False), _ev(5), False),
        (_ev(4), _ev(0, fp=True), True),
        (_ev(0, fp=True), _ev(3), False),  # back from a false positive is stricter
        # A false positive over N0 lowers nothing, but it lifts the KEV deadline.
        (_ev(0), _ev(0, fp=True), True),
        # Any real rating after a false positive is stricter, even in a wider column.
        (_ev(0, fp=True), _ev(3, lev=False), False),
    ],
)
def test_relaxes(previous: tf.Evaluation | None, new: tf.Evaluation, relaxes: bool) -> None:
    assert tf.relaxes(previous, new) is relaxes
