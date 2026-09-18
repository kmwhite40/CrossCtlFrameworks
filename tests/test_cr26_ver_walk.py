"""The single walk: which rows are vulnerabilities, and where each one goes."""

from __future__ import annotations

from datetime import date

from ccf.cr26.ver import render_all
from ccf.patching.sla import RemediationWindow

TODAY = date(2026, 9, 18)
WINDOW = RemediationWindow()


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
    """A partition whose parts do not add up is how a row disappears silently."""
    rows = [
        _Poam(id=1, status="open"),
        _Poam(id=2, status="risk_accepted"),
        _Poam(id=3, source="assessment"),
        _Poam(id=4, scanner=None, source="scan", title=" ", weakness=None),
    ]
    out = render_all(rows, today=TODAY, window=WINDOW)
    assert sum(out.counts.values()) == len(rows)
    assert set(out.counts) == {"excluded_not_a_flaw", "rendered", "omitted"}
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
