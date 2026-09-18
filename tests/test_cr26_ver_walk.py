"""The single walk: which rows are vulnerabilities, and where each one goes."""

from __future__ import annotations

from datetime import UTC, date, datetime

from ccf.cr26.ver import render_all
from ccf.patching.sla import RemediationWindow

TODAY = date(2026, 9, 18)
WINDOW = RemediationWindow()

#: The reporting window the boundary tests below are measured against.
PERIOD = (datetime(2026, 9, 1, tzinfo=UTC), datetime(2026, 12, 1, tzinfo=UTC))


class _Poam:
    def __init__(self, **kw):
        self.id = kw.get("id", 1)
        self.title = kw.get("title", "Outdated OpenSSL")
        self.weakness = kw.get("weakness")
        self.severity = kw.get("severity", "high")
        self.status = kw.get("status", "open")
        self.identified_on = kw.get("identified_on", date(2026, 9, 1))
        self.closed_on = kw.get("closed_on")
        self.scanner = kw.get("scanner", "nessus")
        self.source = kw.get("source", "scan")


def test_a_control_deficiency_is_not_a_vulnerability_and_is_not_a_defect() -> None:
    """`FLAW_SOURCES` is ("scan",) because "an assessment finding is a control
    deficiency" (sla.py:60). A VULNERABILITY report that carried one would tell
    a regulator that an assessor's documentation finding has a detection source
    and a remediation clock.

    It is EXCLUDED, not omitted: nothing is wrong with the row, so it must not
    appear in the to-do list an operator works through.
    """
    out = render_all([_Poam(id=9, source="assessment")], today=TODAY, window=WINDOW)
    assert out.active == []
    assert out.accepted == []
    assert out.omitted == []
    assert out.counts["excluded_not_a_flaw"] == 1
    assert out.counts["rendered"] == 0


def test_an_open_flaw_is_active_and_an_accepted_one_is_accepted() -> None:
    rows = [
        _Poam(id=1, status="open"),
        _Poam(id=2, status="risk_accepted"),
    ]
    out = render_all(rows, today=TODAY, window=WINDOW)
    assert [d["providerTrackingId"] for d in out.active] == ["1"]
    assert [d["providerTrackingId"] for d in out.accepted] == ["2"]


def test_an_unmeasurable_row_reaches_neither_document() -> None:
    """`accepted_weakness_state` returns `unknown` for a row that cannot be
    SHOWN to fall outside the window. Putting it in `active` would assert it is
    NOT accepted -- the favourable answer under a rule obliging providers to
    report their accepted weaknesses.

    This row also has no identification date, which is why it is unmeasurable;
    both reasons are reported.
    """
    out = render_all([_Poam(id=5, identified_on=None)], today=TODAY, window=WINDOW)
    assert out.active == []
    assert out.accepted == []
    assert sorted(out.omitted) == [
        (5, "no identification date"),
        (5, "not measurable as accepted or not"),
    ]


def test_the_counts_partition_every_row_considered() -> None:
    """A partition whose parts do not add up is how a row disappears silently.

    Row 4 is deliberately multi-fault (no identification date on top of the
    blank title/weakness) so the sum genuinely depends on
    ``counts["omitted"]`` counting ROWS rather than reasons -- do not
    simplify it back to a single-fault row, or this test stops exercising the
    invariant it is named for.
    """
    rows = [
        _Poam(id=1, status="open"),
        _Poam(id=2, status="risk_accepted"),
        _Poam(id=3, source="assessment"),
        _Poam(id=4, scanner=None, source="scan", title=" ", weakness=None, identified_on=None),
    ]
    out = render_all(rows, today=TODAY, window=WINDOW)
    assert sum(out.counts.values()) == len(rows)
    assert set(out.counts) == {
        "excluded_not_a_flaw",
        "excluded_outside_period",
        "rendered",
        "omitted",
    }
    assert out.counts["rendered"] == len(out.active) + len(out.accepted)


def test_one_row_with_several_faults_is_counted_once_and_reported_thrice() -> None:
    """`omitted_poam_ids` carries one tuple per (id, reason) pair, so a row
    tripping three rules appears three times -- but `counts["omitted"]` counts
    ROWS, or the sum invariant breaks.
    """
    row = _Poam(id=8, identified_on=None, scanner=None, source="scan", title=" ")
    out = render_all([row], today=TODAY, window=WINDOW)
    assert out.counts["omitted"] == 1
    assert len([pid for pid, _ in out.omitted if pid == 8]) >= 2


def test_an_empty_input_is_an_empty_rendering() -> None:
    out = render_all([], today=TODAY, window=WINDOW)
    assert out.active == [] and out.accepted == [] and out.omitted == []
    assert sum(out.counts.values()) == 0


def test_a_row_on_either_boundary_of_the_period_is_inside_it() -> None:
    """Both ends INCLUSIVE (spec §2.2).

    The lower edge is not a taste question: §3.3's midnight convention renders
    a row identified on the period's first day at that day's midnight, which is
    the window's own `from`. The upper edge is inclusive for symmetry, so a row
    identified on the last day is covered by the report that ends that day
    rather than falling between two reports.

    Dates are the period's exact ends, so an exclusive comparison on either
    side drops one of these rows and fails here.
    """
    rows = [
        _Poam(id=1, identified_on=date(2026, 9, 1)),
        _Poam(id=2, identified_on=date(2026, 12, 1)),
    ]
    out = render_all(rows, today=TODAY, window=WINDOW, period=PERIOD)
    assert [d["providerTrackingId"] for d in out.active] == ["1", "2"]
    assert out.counts["excluded_outside_period"] == 0
    assert out.omitted == []


def test_a_row_a_day_outside_the_period_is_excluded_not_omitted() -> None:
    """One day either side of the window, so this fails if the comparison is
    off by a day in either direction -- and both are EXCLUDED, never omitted:
    nothing is wrong with them, they belong to another reporting period, and
    an operator must not find them in the to-do list `omitted_poam_ids` is
    (§2.1's reasoning, applied to the period).
    """
    rows = [
        _Poam(id=1, identified_on=date(2026, 8, 31)),
        _Poam(id=2, identified_on=date(2026, 12, 2)),
        _Poam(id=3, identified_on=date(2026, 10, 1)),
    ]
    out = render_all(rows, today=TODAY, window=WINDOW, period=PERIOD)
    assert [d["providerTrackingId"] for d in out.active] == ["3"]
    assert out.counts["excluded_outside_period"] == 2
    assert out.omitted == []
    assert sum(out.counts.values()) == len(rows)


def test_no_period_filters_nothing_because_ver_history_says_all() -> None:
    """`ver_history`'s arrays are "**All** non-accepted" / "**All** accepted",
    against VDR's and AVI's "with activity in this period". That contrast only
    means something if one filters and the other does not, so this is the
    deliberately-not-applied rule §9.6 requires an assertion behind.
    """
    rows = [
        # A day either side of PERIOD -- the exact pair the test above sees
        # excluded. Both stay within 192 days of TODAY so neither drifts into
        # `accepted` by elapsed time and changes bucket for an unrelated reason.
        _Poam(id=1, identified_on=date(2026, 8, 31)),
        _Poam(id=2, identified_on=date(2026, 12, 2)),
    ]
    out = render_all(rows, today=TODAY, window=WINDOW)
    assert [d["providerTrackingId"] for d in out.active] == ["1", "2"]
    assert out.counts["excluded_outside_period"] == 0


def test_a_row_with_no_date_is_omitted_and_named_rather_than_excluded() -> None:
    """A row with no `identified_on` cannot be placed in ANY period, and the
    honest answer is that its absence is a DEFECT, not a different report. It
    must reach `omitted` with its reason, never `excluded_outside_period`.
    """
    out = render_all([_Poam(id=4, identified_on=None)], today=TODAY, window=WINDOW, period=PERIOD)
    assert out.counts["excluded_outside_period"] == 0
    assert out.counts["omitted"] == 1
    assert (4, "no identification date") in out.omitted
