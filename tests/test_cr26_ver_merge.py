"""Keep the human's acceptance rationale; refresh everything else."""

from __future__ import annotations

from ccf.cr26.ver import merge_accepted


def _detail(pid: str, desc: str = "Outdated OpenSSL") -> dict:
    return {
        "providerTrackingId": pid,
        "detection": {"detectedAt": "2026-09-01T00:00:00Z", "detectionSource": "nessus"},
        "vulnerabilityDescription": desc,
    }


def test_an_authored_rationale_survives_and_the_detail_refreshes() -> None:
    authored = [
        {
            "vulnerabilityDetail": _detail("1", "STALE description"),
            "acceptanceRationale": "Compensating control: WAF rule 91234.",
        }
    ]
    merged, omitted = merge_accepted(authored, [_detail("1", "Outdated OpenSSL")])
    assert omitted == []
    assert merged == [
        {
            "vulnerabilityDetail": _detail("1", "Outdated OpenSSL"),
            "acceptanceRationale": "Compensating control: WAF rule 91234.",
        }
    ]


def test_a_derived_entry_with_no_authored_rationale_is_omitted_and_named() -> None:
    """`acceptanceRationale` is REQUIRED. Emitting "" would be the CPO's
    empty-description defect: a value that validates and asserts the provider
    gave a blank reason for accepting a vulnerability.
    """
    merged, omitted = merge_accepted([], [_detail("7")])
    assert merged == []
    assert omitted == [(7, "no acceptance rationale")]


def test_a_blank_authored_rationale_is_no_rationale() -> None:
    authored = [{"vulnerabilityDetail": _detail("7"), "acceptanceRationale": "   "}]
    merged, omitted = merge_accepted(authored, [_detail("7")])
    assert merged == []
    assert omitted == [(7, "no acceptance rationale")]


def test_entries_are_ordered_by_tracking_id_not_by_input_order() -> None:
    """Input is deliberately REVERSED. Do not "tidy" it to ascending -- that is
    what makes this test able to fail.
    """
    authored = [
        {"vulnerabilityDetail": _detail(p), "acceptanceRationale": f"r{p}"}
        for p in ("30", "4", "200")
    ]
    derived = [_detail(p) for p in ("30", "4", "200")]
    merged, _ = merge_accepted(authored, derived)
    assert [e["vulnerabilityDetail"]["providerTrackingId"] for e in merged] == [
        "4",
        "30",
        "200",
    ]


def test_an_authored_entry_the_scanner_no_longer_reports_is_dropped_and_named() -> None:
    """A vulnerability that is no longer accepted -- remediated, or reopened --
    must leave the accepted list. Keeping it would report a resolved weakness
    as still accepted.
    """
    authored = [{"vulnerabilityDetail": _detail("99"), "acceptanceRationale": "r"}]
    merged, omitted = merge_accepted(authored, [])
    assert merged == []
    assert omitted == [(99, "no longer an accepted vulnerability")]


def test_a_non_numeric_authored_id_the_source_no_longer_reports_does_not_crash() -> None:
    """`providerTrackingId` is `type: string` with no numeric pattern, so an
    admin-edited id like "POAM-42" is unusual but legitimate. This id is
    orphaned -- the source no longer reports it -- which is exactly the "this
    vulnerability was remediated" path the omission rule exists to report; it
    must not crash the seeder.
    """
    authored = [
        {
            "vulnerabilityDetail": _detail("POAM-42"),
            "acceptanceRationale": "r",
        }
    ]
    merged, omitted = merge_accepted(authored, [])
    assert merged == []
    assert omitted == [("POAM-42", "no longer an accepted vulnerability")]


def test_a_non_numeric_derived_id_with_no_rationale_does_not_crash() -> None:
    """The no-rationale branch also builds an omitted tuple from the tracking
    id, so it needs the same non-numeric-id safety as the orphan branch.
    """
    merged, omitted = merge_accepted([], [_detail("POAM-42")])
    assert merged == []
    assert omitted == [("POAM-42", "no acceptance rationale")]


def test_the_merge_does_not_alias_its_inputs() -> None:
    """Mutating the result must not reach back into the caller's dicts. The SDR
    needed two rounds on exactly this, including the dicts nested inside.
    """
    derived = [_detail("1")]
    authored = [{"vulnerabilityDetail": _detail("1"), "acceptanceRationale": "r"}]
    merged, _ = merge_accepted(authored, derived)
    merged[0]["vulnerabilityDetail"]["detection"]["detectionSource"] = "MUTATED"
    assert derived[0]["detection"]["detectionSource"] == "nessus"
    assert authored[0]["vulnerabilityDetail"]["detection"]["detectionSource"] == "nessus"
