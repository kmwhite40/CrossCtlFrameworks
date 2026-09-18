"""The POA&M -> vulnerabilityDetail renderer.

Every assertion here checks what the document CLAIMS, not merely that it
validates: `format: date-time` is unenforced in this environment (spec §4), so
the validator is not a backstop for any date this module writes.
"""

from __future__ import annotations

from datetime import date

import pytest

from ccf.cr26.ver import is_blank, render_vulnerability
from ccf.patching.sla import RemediationWindow

TODAY = date(2026, 9, 18)
WINDOW = RemediationWindow()


class _Poam:
    """A POA&M stand-in. Only the columns the renderer reads."""

    def __init__(self, **kw):
        self.id = kw.get("id", 42)
        self.title = kw.get("title", "Outdated OpenSSL on web tier")
        self.weakness = kw.get("weakness")
        self.severity = kw.get("severity", "high")
        self.status = kw.get("status", "open")
        self.identified_on = kw.get("identified_on", date(2026, 9, 1))
        self.closed_on = kw.get("closed_on")
        self.scanner = kw.get("scanner", "nessus")
        self.source = kw.get("source", "scan")


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, True),
        ("", True),
        ("   ", True),
        ("\t\n", True),
        ("x", False),
        (" x ", False),
        (0, True),
        (["a"], True),
    ],
)
def test_is_blank_is_a_blank_test_not_a_none_test(value, expected) -> None:
    """Five omission rules (spec §7) all ask this one question. A `None` test
    would let `""` and `"   "` through, which is how the SDR shipped a
    whitespace description twice. A non-string is blank: this module never
    reprs a value into a federal document.
    """
    assert is_blank(value) is expected


def test_a_complete_poam_renders_every_sourced_field() -> None:
    detail, reasons = render_vulnerability(_Poam(), today=TODAY, window=WINDOW)
    assert reasons == []
    assert detail == {
        "providerTrackingId": "42",
        "detection": {
            "detectedAt": "2026-09-01T00:00:00Z",
            "detectionSource": "nessus",
        },
        "vulnerabilityDescription": "Outdated OpenSSL on web tier",
        "overdueStatus": {"isOverdue": False},
    }


def test_the_tracking_id_is_a_string_because_the_schema_says_so() -> None:
    """Measured: an integer fails with
    "vulnerabilities/0/providerTrackingId: 42 is not of type 'string'".
    """
    detail, _ = render_vulnerability(_Poam(id=7), today=TODAY, window=WINDOW)
    assert detail["providerTrackingId"] == "7"
    assert isinstance(detail["providerTrackingId"], str)


def test_the_detected_date_is_widened_to_midnight_utc_exactly() -> None:
    """`identified_on` is a DATE; `detectedAt` is a date-time. The widening is
    a DECLARED CONVENTION (spec §3.3), not a measured fact -- and since
    `format: date-time` is unenforced here, this exact-string assertion is the
    only thing standing between a malformed value and the deliverable.
    """
    detail, _ = render_vulnerability(
        _Poam(identified_on=date(2026, 3, 4)), today=TODAY, window=WINDOW
    )
    assert detail["detection"]["detectedAt"] == "2026-03-04T00:00:00Z"


def test_weakness_wins_over_title_when_it_has_content() -> None:
    detail, _ = render_vulnerability(
        _Poam(weakness="CVE-2026-1234 in libssl"), today=TODAY, window=WINDOW
    )
    assert detail["vulnerabilityDescription"] == "CVE-2026-1234 in libssl"


def test_a_blank_weakness_falls_through_to_the_title() -> None:
    """`weakness` is nullable and the UI saves `str(...)` with no strip, so a
    cleared textarea persists as "". Blank is as absent as NULL.
    """
    detail, _ = render_vulnerability(
        _Poam(weakness="   "), today=TODAY, window=WINDOW
    )
    assert detail["vulnerabilityDescription"] == "Outdated OpenSSL on web tier"


def test_the_scanner_wins_over_the_source_for_the_detection_source() -> None:
    detail, _ = render_vulnerability(
        _Poam(scanner="qualys", source="scan"), today=TODAY, window=WINDOW
    )
    assert detail["detection"]["detectionSource"] == "qualys"


def test_a_blank_scanner_falls_through_to_the_source() -> None:
    detail, _ = render_vulnerability(
        _Poam(scanner=None, source="scan"), today=TODAY, window=WINDOW
    )
    assert detail["detection"]["detectionSource"] == "scan"


def test_no_identification_date_omits_the_row_and_names_the_reason() -> None:
    """`detection` is required and `updated_at` is when the ROW changed, not
    when the vulnerability was detected. There is no honest fallback.
    """
    detail, reasons = render_vulnerability(
        _Poam(identified_on=None), today=TODAY, window=WINDOW
    )
    assert detail is None
    assert reasons == ["no identification date"]


def test_no_detection_source_at_all_omits_the_row() -> None:
    detail, reasons = render_vulnerability(
        _Poam(scanner=None, source=None), today=TODAY, window=WINDOW
    )
    assert detail is None
    assert reasons == ["no detection source"]


def test_a_blank_description_on_both_columns_omits_the_row() -> None:
    """`title` is NOT NULL, which guarantees the column exists and says nothing
    about its content.
    """
    detail, reasons = render_vulnerability(
        _Poam(title="  ", weakness=""), today=TODAY, window=WINDOW
    )
    assert detail is None
    assert reasons == ["no description"]


def test_every_reason_that_applies_is_reported_not_just_the_first() -> None:
    """Spec §7. Reporting only the first reason sends an operator to fix one
    field and back again for the next.
    """
    detail, reasons = render_vulnerability(
        _Poam(identified_on=None, scanner=None, source=None, title=" ", weakness=None),
        today=TODAY,
        window=WINDOW,
    )
    assert detail is None
    assert reasons == ["no identification date", "no detection source", "no description"]


def test_a_breached_poam_is_overdue() -> None:
    """high severity -> 30 days. Identified 2026-01-01, today 2026-09-18."""
    detail, _ = render_vulnerability(
        _Poam(identified_on=date(2026, 1, 1), severity="high"),
        today=TODAY,
        window=WINDOW,
    )
    assert detail["overdueStatus"] == {"isOverdue": True}


@pytest.mark.parametrize(
    "kw",
    [
        {"status": "risk_accepted"},
        {"status": "closed", "closed_on": date(2026, 9, 10)},
        {"status": "completed", "closed_on": date(2026, 9, 10)},
    ],
)
def test_a_row_with_no_present_tense_answer_omits_overdue_status(kw) -> None:
    """`isOverdue` asks whether the vulnerability IS overdue. A closed one is
    no longer outstanding and `accepted` short-circuits in `classify` ahead of
    every date check, so no date judgment was ever made. `false` would be the
    FAVOURABLE answer -- the defect this programme keeps shipping.
    """
    detail, reasons = render_vulnerability(_Poam(**kw), today=TODAY, window=WINDOW)
    assert reasons == []
    assert "overdueStatus" not in detail


def test_the_nine_unsourced_fields_are_absent() -> None:
    """Spec §3.4. Emitting any of these would assert something the platform
    cannot defend -- `currentRating` most of all, since `nRating` is 1-5 and
    `severity` has four values on a different scale.
    """
    detail, _ = render_vulnerability(_Poam(), today=TODAY, window=WINDOW)
    for field in (
        "currentRating",
        "painReductionEvents",
        "projectedNextReduction",
        "isInternetReachable",
        "isLikelyExploitable",
        "finalDisposition",
        "potentialAgencyImpact",
        "evaluationCompletedAt",
        "supplementaryRiskInformation",
    ):
        assert field not in detail, field


def test_every_rendered_detail_has_a_non_blank_tracking_id() -> None:
    """`merge_accepted`'s ``continue`` on a blank derived ``providerTrackingId``
    relies on this guarantee -- `providerTrackingId` is always
    ``str(poam.id)`` from the non-null primary key, so no detail this
    renderer emits can have a blank one. Checked over every fixture shape
    that reaches a detail at all, so a future change that weakens the
    guarantee fails here rather than downstream in the merge.
    """
    cases = [
        _Poam(),
        _Poam(status="risk_accepted"),
        _Poam(status="closed", closed_on=date(2026, 9, 10)),
        _Poam(weakness="CVE-2026-1234 in libssl"),
        _Poam(scanner=None, source="scan"),
    ]
    for poam in cases:
        detail, _reasons = render_vulnerability(poam, today=TODAY, window=WINDOW)
        if detail is None:
            continue
        assert not is_blank(detail["providerTrackingId"]), poam.id


def test_reasons_are_non_empty_exactly_when_the_detail_is_none() -> None:
    """The invariant Task 2 relies on. Asserted over every fixture shape this
    file uses, so a future branch that returns both or neither fails here.
    """
    cases = [
        _Poam(),
        _Poam(identified_on=None),
        _Poam(scanner=None, source=None),
        _Poam(title=" ", weakness=None),
        _Poam(status="risk_accepted"),
    ]
    for poam in cases:
        detail, reasons = render_vulnerability(poam, today=TODAY, window=WINDOW)
        assert (detail is None) is bool(reasons), (poam.id, detail, reasons)
