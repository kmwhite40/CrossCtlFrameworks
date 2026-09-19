"""Keep the human's acceptance rationale; refresh everything else."""

from __future__ import annotations

from ccf.cr26.ver import _as_row_id, merge_accepted


def _merge(*args, **kwargs) -> tuple[list[dict], list[tuple]]:
    """`merge_accepted` as `(entries, omitted)`.

    The real return is an :class:`AcceptedMerge`, which also carries the
    figures the seed's `counts` needs; these tests are about the document and
    the reasons, so they read the two fields they are named for.
    """
    result = merge_accepted(*args, **kwargs)
    return result.entries, result.omitted


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
    merged, omitted = _merge(authored, [_detail("1", "Outdated OpenSSL")])
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
    merged, omitted = _merge([], [_detail("7")])
    assert merged == []
    assert omitted == [(7, "no acceptance rationale")]


def test_a_blank_authored_rationale_is_no_rationale() -> None:
    authored = [{"vulnerabilityDetail": _detail("7"), "acceptanceRationale": "   "}]
    merged, omitted = _merge(authored, [_detail("7")])
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
    merged, _ = _merge(authored, derived)
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
    merged, omitted = _merge(authored, [])
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
    merged, omitted = _merge(authored, [])
    assert merged == []
    assert omitted == [("POAM-42", "no longer an accepted vulnerability")]


def test_a_non_numeric_derived_id_with_no_rationale_does_not_crash() -> None:
    """The no-rationale branch also builds an omitted tuple from the tracking
    id, so it needs the same non-numeric-id safety as the orphan branch.
    """
    merged, omitted = _merge([], [_detail("POAM-42")])
    assert merged == []
    assert omitted == [("POAM-42", "no acceptance rationale")]


def test_as_row_id_does_not_raise_on_a_digit_that_int_rejects() -> None:
    """`"²".isdigit()` is `True` while `int("²")` raises `ValueError` --
    `_as_row_id` used to guard with `.isdigit()`, which does not guard this
    at all, it only defers the crash. `try/except ValueError` is the fix,
    not `.isascii() and .isdigit()`: `"٣"` (Arabic-Indic three) is
    non-ASCII, `.isdigit()` is `True` for it too, and `int("٣") == 3` --
    it parses correctly and must keep doing so.
    """
    assert _as_row_id("²") == "²"
    assert _as_row_id("٣") == 3
    assert _as_row_id("42") == 42
    assert _as_row_id("POAM-42") == "POAM-42"


def test_a_superscript_digit_tracking_id_does_not_abort_the_merge() -> None:
    """End to end through `merge_accepted`, not just the helper in isolation
    -- `"²".isdigit()` being `True` is exactly what let this reach `_as_row_id`
    believing it was safe to call `int()` on.
    """
    merged, omitted = _merge([], [_detail("²")])
    assert merged == []
    assert omitted == [("²", "no acceptance rationale")]


def test_omitted_ids_sort_numeric_first_then_string_not_lexically() -> None:
    """Ids are "9", "10" and "POAM-1" -- deliberately chosen so a naive
    ``str(row[0])`` sort key gets them wrong: lexically "10" sorts before
    "9", which is backwards. The real key sorts numeric ids numerically
    (9 before 10) and puts the non-numeric id after both. Do NOT "tidy" these
    to sequential or single-digit ids -- that is what would let a lexical-key
    regression here pass silently, and a bare ``.sort()`` over the resulting
    mix of `int` and `str` ids would raise `TypeError` instead of ordering
    at all.
    """
    authored = [
        {"vulnerabilityDetail": _detail(p), "acceptanceRationale": f"r{p}"}
        for p in ("9", "10", "POAM-1")
    ]
    _, omitted = _merge(authored, [])
    assert omitted == [
        (9, "no longer an accepted vulnerability"),
        (10, "no longer an accepted vulnerability"),
        ("POAM-1", "no longer an accepted vulnerability"),
    ]


def test_the_merge_does_not_alias_its_inputs() -> None:
    """Mutating the result must not reach back into the caller's dicts. The SDR
    needed two rounds on exactly this, including the dicts nested inside.
    """
    derived = [_detail("1")]
    authored = [{"vulnerabilityDetail": _detail("1"), "acceptanceRationale": "r"}]
    merged, _ = _merge(authored, derived)
    merged[0]["vulnerabilityDetail"]["detection"]["detectionSource"] = "MUTATED"
    assert derived[0]["detection"]["detectionSource"] == "nessus"
    assert authored[0]["vulnerabilityDetail"]["detection"]["detectionSource"] == "nessus"


# --- an authored entry must not be dropped for the wrong reason (spec §5.1) --


def test_an_entry_whose_row_could_not_be_rendered_is_kept_and_named_truthfully() -> None:
    """The measured defect. Blanking a `risk_accepted` POA&M's `title` produced
    `[(3, "no description"), (3, "no longer an accepted vulnerability")]` --
    the second is simply FALSE, the row is still `risk_accepted` -- and since
    `put_document` replaces the stored body, the human-written rationale was
    irrecoverably destroyed. Fixing the title did not bring it back.

    So the entry is kept VERBATIM, stored detail and rationale alike, and the
    reason names the real cause. One cycle stale and labelled beats destroyed.
    """
    authored = [
        {
            "vulnerabilityDetail": _detail("3", "Outdated OpenSSL"),
            "acceptanceRationale": "Compensating control: WAF rule 91234.",
        }
    ]
    merged, omitted = _merge(authored, [], unplaced={"3": ["no description"]})
    assert merged == authored
    assert omitted == [(3, "detail not refreshed: no description")]
    assert (3, "no longer an accepted vulnerability") not in omitted


def test_every_reason_the_walk_gave_reaches_the_kept_entrys_report() -> None:
    """A row can trip several rules at once, and §7 requires all of them: an
    operator told about one missing field fixes it and comes straight back.
    """
    authored = [{"vulnerabilityDetail": _detail("3"), "acceptanceRationale": "r"}]
    merged, omitted = _merge(
        authored,
        [],
        unplaced={"3": ["no detection source", "not measurable as accepted or not"]},
    )
    assert len(merged) == 1
    assert omitted == [
        (3, "detail not refreshed: no detection source"),
        (3, "detail not refreshed: not measurable as accepted or not"),
    ]


def test_an_entry_the_walk_never_saw_is_still_dropped_and_named() -> None:
    """The third case, and the ONLY one where "no longer an accepted
    vulnerability" is true: the walk saw the id nowhere at all.
    """
    authored = [{"vulnerabilityDetail": _detail("99"), "acceptanceRationale": "r"}]
    merged, omitted = _merge(authored, [], unplaced={"3": ["no description"]})
    assert merged == []
    assert omitted == [(99, "no longer an accepted vulnerability")]


def test_an_entry_whose_row_a_scoping_filter_excluded_leaves_with_no_reason() -> None:
    """A row outside this report's period -- or one that stopped being
    scanner-derived -- is EXCLUDED, not omitted (spec §7): nothing is wrong
    with it, so no reason is reported. Reporting "no longer an accepted
    vulnerability" here would be the same false claim §5.1 forbids.
    """
    authored = [{"vulnerabilityDetail": _detail("5"), "acceptanceRationale": "r"}]
    merged, omitted = _merge(authored, [], excluded={"5"})
    assert merged == []
    assert omitted == []


def test_a_scoping_excluded_row_still_promotes_its_document_rationale() -> None:
    """Spec §9.1's residual case, closed: a rationale authored only into the
    document, for a row a scoping filter excludes THIS cycle, must still be
    promoted into the column before the entry is dropped -- otherwise the
    document is the only copy, and a later `put_document` overwrite (while
    still excluded) can lose it with nothing left to promote from. The entry
    itself still leaves the document with no reason reported (previous
    test); only `promoted` is new here.
    """
    authored = [
        {"vulnerabilityDetail": _detail("5"), "acceptanceRationale": "Only in the document."}
    ]
    result = merge_accepted(authored, [], excluded={"5"})
    assert result.entries == []
    assert result.omitted == []
    assert result.promoted == [(5, "Only in the document.")]


def test_a_scoping_excluded_row_with_a_fresh_column_value_is_not_re_promoted() -> None:
    """The column already has it -- `_resolve_rationale` resolves from the
    column, not the document, so `from_document` is `False` and nothing is
    re-promoted (there is nothing new to write).
    """
    authored = [
        {"vulnerabilityDetail": _detail("5"), "acceptanceRationale": "Stale document value."}
    ]
    result = merge_accepted(
        authored, [], excluded={"5"}, column_rationale={"5": "Current column value."}
    )
    assert result.entries == []
    assert result.omitted == []
    assert result.promoted == []


def test_a_kept_entry_with_no_rationale_is_omitted_rather_than_emitted_blank() -> None:
    """Keeping an entry verbatim must not smuggle in an entry the schema
    refuses: `acceptanceRationale` is required, and there is nothing to
    preserve when the authored entry never had one.
    """
    authored = [{"vulnerabilityDetail": _detail("3"), "acceptanceRationale": "  "}]
    merged, omitted = _merge(authored, [], unplaced={"3": ["no description"]})
    assert merged == []
    assert omitted == [(3, "no acceptance rationale")]


def test_a_kept_entry_is_not_aliased_to_the_caller_s_document() -> None:
    """The stored document is a dict the caller still holds; the SDR needed two
    rounds on exactly this, including the dicts nested inside.
    """
    authored = [{"vulnerabilityDetail": _detail("3"), "acceptanceRationale": "r"}]
    merged, _ = _merge(authored, [], unplaced={"3": ["no description"]})
    merged[0]["vulnerabilityDetail"]["detection"]["detectionSource"] = "MUTATED"
    assert authored[0]["vulnerabilityDetail"]["detection"]["detectionSource"] == "nessus"


def test_a_non_numeric_id_that_is_still_accepted_sorts_rather_than_crashing() -> None:
    """The ordering path was the one place left on a bare
    `int(...["providerTrackingId"])`, so an admin-edited "POAM-42" that IS
    still accepted -- rationale and all -- raised `ValueError` and took the
    whole seed down, where the omission paths had used `_as_row_id` since
    they were written. Numeric ids sort first, in numeric order.
    """
    ids = ("POAM-42", "30", "4")
    authored = [
        {"vulnerabilityDetail": _detail(p), "acceptanceRationale": f"r{p}"} for p in ids
    ]
    merged, omitted = _merge(authored, [_detail(p) for p in ids])
    assert omitted == []
    assert [e["vulnerabilityDetail"]["providerTrackingId"] for e in merged] == [
        "4",
        "30",
        "POAM-42",
    ]


def test_an_authored_entry_with_no_tracking_id_is_named_not_silently_dropped() -> None:
    """Reachable by hand: `PUT /cr26-documents/avi` takes an unvalidated
    `dict[str, Any]`, so an entry can be stored with no `vulnerabilityDetail`
    at all. It used to vanish with no `omitted` record -- and "omit and name
    it" is this branch's spine, so an unnamed omission contradicts it.

    The position is the only handle an operator has on an entry with no id,
    so the position is what is reported.
    """
    authored = [
        {"acceptanceRationale": "Rationale with nothing to attach it to."},
        {"vulnerabilityDetail": _detail("7"), "acceptanceRationale": "r7"},
    ]
    merged, omitted = _merge(authored, [_detail("7")])
    assert [e["vulnerabilityDetail"]["providerTrackingId"] for e in merged] == ["7"]
    assert omitted == [
        ("acceptedVulnerabilities[0]", "authored entry has no providerTrackingId")
    ]


def test_a_duplicate_authored_entry_is_reported_rather_than_silently_losing() -> None:
    """Two entries for one id means one human-written rationale is discarded.
    Last wins, as it always has; what is new is that the discarded one is
    named -- the document alone cannot show that it ever existed.
    """
    authored = [
        {"vulnerabilityDetail": _detail("7"), "acceptanceRationale": "FIRST"},
        {"vulnerabilityDetail": _detail("7"), "acceptanceRationale": "SECOND"},
    ]
    merged, omitted = _merge(authored, [_detail("7")])
    assert [e["acceptanceRationale"] for e in merged] == ["SECOND"]
    assert omitted == [(7, "duplicate authored entry discarded")]


# --- `POAM.acceptance_rationale` (spec §9.1): the durable source, preferred
# over the authored document -- which stays a fallback for rationales
# authored before the column existed. ----------------------------------------


def test_column_rationale_is_preferred_over_a_stale_authored_document() -> None:
    """The column is the durable source from here on; a stale value still
    sitting in the authored document must not win over it.
    """
    authored = [
        {
            "vulnerabilityDetail": _detail("7"),
            "acceptanceRationale": "Stale, document-authored rationale.",
        }
    ]
    merged, omitted = _merge(
        authored, [_detail("7")], column_rationale={"7": "Current column rationale."}
    )
    assert omitted == []
    assert [e["acceptanceRationale"] for e in merged] == ["Current column rationale."]


def test_column_rationale_alone_is_enough_no_authored_entry_needed() -> None:
    """The §9.1 defect, at the merge layer: a window moved backwards past an
    accepted row and then forward again leaves the authored document with
    NOTHING for that id (`put_document` overwrote it while the row was
    excluded). Before this column existed that meant the rationale was gone
    for good. Now the column alone is enough to keep the row in the document.
    """
    merged, omitted = _merge([], [_detail("7")], column_rationale={"7": "From the column."})
    assert omitted == []
    assert merged == [
        {"vulnerabilityDetail": _detail("7"), "acceptanceRationale": "From the column."}
    ]


def test_a_blank_column_rationale_falls_back_to_the_authored_document() -> None:
    """The column exists but this particular row's is blank -- e.g. a
    rationale authored before the column existed, never re-entered into it.
    The document fallback must still work: it is NEVER removed.
    """
    authored = [
        {"vulnerabilityDetail": _detail("7"), "acceptanceRationale": "From the document."}
    ]
    merged, omitted = _merge(authored, [_detail("7")], column_rationale={"7": "   "})
    assert omitted == []
    assert [e["acceptanceRationale"] for e in merged] == ["From the document."]


def test_neither_source_having_a_rationale_is_still_omitted_and_named() -> None:
    merged, omitted = _merge([], [_detail("7")], column_rationale={"7": "  "})
    assert merged == []
    assert omitted == [(7, "no acceptance rationale")]


def test_column_rationale_reaches_a_kept_verbatim_entry_too() -> None:
    """The column wins even for an entry kept verbatim because its row could
    not be rendered this cycle (spec §5.1) -- the same precedence, not a
    special case for the common path only.
    """
    authored = [
        {
            "vulnerabilityDetail": _detail("3", "Outdated OpenSSL"),
            "acceptanceRationale": "Stale, document-authored rationale.",
        }
    ]
    merged, omitted = _merge(
        authored,
        [],
        unplaced={"3": ["no description"]},
        column_rationale={"3": "Current column rationale."},
    )
    assert len(merged) == 1
    assert merged[0]["acceptanceRationale"] == "Current column rationale."
    assert merged[0]["vulnerabilityDetail"] == _detail("3", "Outdated OpenSSL")
    assert omitted == [(3, "detail not refreshed: no description")]


def test_a_kept_verbatim_entry_resolved_from_the_document_is_promoted() -> None:
    """N5a: the kept-verbatim/`unplaced` branch does real promotion work too,
    not just the common "freshly rendered" branch -- a row whose column is
    still blank but whose title just got blanked (landing it in `unplaced`)
    must still have its document-authored rationale promoted, or it depends
    on the document surviving forever specifically on the one path where the
    detail is already known to be stale.
    """
    authored = [
        {
            "vulnerabilityDetail": _detail("3", "Outdated OpenSSL"),
            "acceptanceRationale": "Only ever authored into the document.",
        }
    ]
    result = merge_accepted(authored, [], unplaced={"3": ["no description"]})
    assert len(result.entries) == 1
    assert result.promoted == [(3, "Only ever authored into the document.")]
