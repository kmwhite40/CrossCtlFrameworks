"""The three seeders, end to end against the database and the real validator."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.api.routes import cr26 as cr26_routes
from ccf.auth import Principal
from ccf.cr26.store import put_document
from ccf.cr26.ver import seed_avi, seed_vdr, seed_ver_history
from ccf.db import session_scope
from ccf.models import POAM, Organization, System

FROM = datetime(2026, 9, 1, tzinfo=UTC)
TO = datetime(2026, 12, 1, tzinfo=UTC)
ONE_ERROR = ["<root>: 'certificationPackageOverviewUri' is a required property"]

#: Fixed rather than the real clock. `accepted_weakness_state` flips a row to
#: `accepted` after `ACCEPTED_WEAKNESS_DAYS = 192` days past `identified_on`,
#: and `_poam`'s default `identified_on` is 2026-09-05 -- a test that reads
#: `datetime.now()` here would start failing, for reasons unrelated to the
#: code, the moment the real clock crosses 192 days past that date.
TODAY = date(2026, 9, 18)


async def _system(name: str) -> tuple[int, int]:
    """``(org_id, system_id)``. The org id is returned because Task 5's route
    tests need it to build a principal, and one helper is better than two."""
    async with session_scope() as s:
        org = Organization(name=f"{name} org")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=name, baseline="moderate")
        s.add(system)
        await s.flush()
        return org.id, system.id


async def _poam(system_id: int, **kw) -> int:
    async with session_scope() as s:
        row = POAM(
            system_id=system_id,
            title=kw.get("title", "Outdated OpenSSL"),
            severity=kw.get("severity", "high"),
            status=kw.get("status", "open"),
            identified_on=kw.get("identified_on", date(2026, 9, 5)),
            scanner=kw.get("scanner", "nessus"),
            source=kw.get("source", "scan"),
        )
        s.add(row)
        await s.flush()
        return row.id


async def test_a_seeded_vdr_is_invalid_for_exactly_one_reason() -> None:
    """The document carries a REAL vulnerability, so every rendered field goes
    through the validator. The SDR asserted this only on empty arrays and its
    whole derived half went unvalidated for three review rounds.
    """
    _org_id, system_id = await _system("vdr-one")
    await _poam(system_id)
    async with session_scope() as s:
        result = await seed_vdr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert len(result.document.document["vulnerabilities"]) == 1
    assert result.document.validation_errors == ONE_ERROR, result.document.validation_errors
    assert result.document.is_valid is False


async def test_a_vdr_records_the_period_the_caller_asked_for() -> None:
    """Nothing in the platform records what a previous report covered, so
    VER-RPT-PER's chaining is the operator's obligation and the period is an
    argument. The document states the window it actually covered.
    """
    _org_id, system_id = await _system("vdr-period")
    # A row INSIDE the window. This test previously ran against a system with
    # no POA&Ms at all, which is why it could not notice that the period it
    # asserts filtered nothing (spec §2.2).
    await _poam(system_id, identified_on=date(2026, 10, 1))
    async with session_scope() as s:
        result = await seed_vdr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.document["reportPeriod"] == {
        "from": "2026-09-01T00:00:00Z",
        "to": "2026-12-01T00:00:00Z",
    }
    assert len(result.document.document["vulnerabilities"]) == 1


async def test_a_vdr_excludes_a_detection_dated_outside_the_period_it_states() -> None:
    """The measured defect (spec §2.2): a VDR stating it covered
    2026-09-01 -> 2026-12-01 listed a detection dated `2027-01-01`. The period
    was decorative -- it reached `_instant` for display and nothing else.

    EXCLUDED, not omitted: nothing is wrong with that row, it belongs to the
    next report, so it must not appear in the operator's to-do list.
    """
    _org_id, system_id = await _system("vdr-period-filter")
    inside = await _poam(system_id, identified_on=date(2026, 10, 1))
    outside = await _poam(system_id, identified_on=date(2027, 1, 1))
    async with session_scope() as s:
        result = await seed_vdr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    body = result.document.document
    assert [v["providerTrackingId"] for v in body["vulnerabilities"]] == [str(inside)]
    assert result.counts["excluded_outside_period"] == 1
    assert [oid for oid, _ in result.omitted_poam_ids] == []
    assert outside not in [oid for oid, _ in result.omitted_poam_ids]


async def test_an_avi_excludes_an_accepted_row_dated_outside_the_period() -> None:
    """AVI's array carries the same "with activity in this period" wording as
    VDR's, so it filters too -- proven on the AVI's own seeder rather than
    inferred from the VDR's.
    """
    _org_id, system_id = await _system("avi-period-filter")
    await _poam(system_id, status="risk_accepted", identified_on=date(2027, 1, 1))
    async with session_scope() as s:
        result = await seed_avi(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.document["acceptedVulnerabilities"] == []
    assert result.counts["excluded_outside_period"] == 1
    assert result.omitted_poam_ids == []


async def test_ver_history_carries_a_row_no_report_period_would_cover() -> None:
    """`ver_history`'s arrays say "**All** non-accepted" / "**All** accepted",
    against VDR's and AVI's "with activity in this period". The same row the
    two tests above exclude must be PRESENT here, or that contrast means
    nothing -- and `seed_ver_history` takes no period at all.
    """
    _org_id, system_id = await _system("hist-no-filter")
    outside = await _poam(system_id, identified_on=date(2027, 1, 1))
    async with session_scope() as s:
        result = await seed_ver_history(s, system_id=system_id, today=TODAY)
    body = result.document.document
    assert [v["providerTrackingId"] for v in body["activeVulnerabilities"]] == [str(outside)]
    assert result.counts["excluded_outside_period"] == 0


async def test_an_accepted_weakness_leaves_the_vdr_and_enters_the_avi() -> None:
    _org_id, system_id = await _system("split")
    open_id = await _poam(system_id, status="open")
    accepted_id = await _poam(system_id, status="risk_accepted")
    async with session_scope() as s:
        vdr = await seed_vdr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    ids = [v["providerTrackingId"] for v in vdr.document.document["vulnerabilities"]]
    assert ids == [str(open_id)]
    assert str(accepted_id) not in ids


async def test_an_avi_omits_a_vulnerability_with_no_authored_rationale() -> None:
    _org_id, system_id = await _system("avi-none")
    poam_id = await _poam(system_id, status="risk_accepted")
    async with session_scope() as s:
        result = await seed_avi(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.document["acceptedVulnerabilities"] == []
    assert (poam_id, "no acceptance rationale") in result.omitted_poam_ids


async def test_an_authored_rationale_survives_a_reseed_and_the_document_validates() -> None:
    """The one place the accepted half reaches the validator with content in
    it. Exact equality, not a membership check: the claim is ONE reason.
    """
    _org_id, system_id = await _system("avi-keep")
    poam_id = await _poam(system_id, status="risk_accepted")
    async with session_scope() as s:
        await seed_avi(s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY)

    async with session_scope() as s:
        row = await put_document(
            s,
            system_id=system_id,
            kind="avi",
            document={
                "reportPeriod": {"from": "2026-09-01T00:00:00Z", "to": "2026-12-01T00:00:00Z"},
                "acceptedVulnerabilities": [
                    {
                        "vulnerabilityDetail": {
                            "providerTrackingId": str(poam_id),
                            "detection": {
                                "detectedAt": "1999-01-01T00:00:00Z",
                                "detectionSource": "STALE",
                            },
                            "vulnerabilityDescription": "STALE",
                        },
                        "acceptanceRationale": "Compensating control: WAF rule 91234.",
                    }
                ],
            },
        )
        assert row is not None

    async with session_scope() as s:
        result = await seed_avi(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )

    entries = result.document.document["acceptedVulnerabilities"]
    assert len(entries) == 1
    assert entries[0]["acceptanceRationale"] == "Compensating control: WAF rule 91234."
    assert entries[0]["vulnerabilityDetail"]["detection"]["detectedAt"] == "2026-09-05T00:00:00Z"
    assert entries[0]["vulnerabilityDetail"]["detection"]["detectionSource"] == "nessus"
    assert result.document.validation_errors == ONE_ERROR, result.document.validation_errors


async def _retitle(poam_id: int, title: str) -> None:
    async with session_scope() as s:
        row = await s.get(POAM, poam_id)
        assert row is not None
        row.title = title


async def test_a_blanked_title_does_not_destroy_the_authored_rationale() -> None:
    """The measured defect, end to end (spec §5.1).

    Blanking a `risk_accepted` POA&M's `title` produced
    `[(id, "no description"), (id, "no longer an accepted vulnerability")]`.
    The second was FALSE -- the row is still `risk_accepted` -- and because
    `put_document` replaces the stored body in place, the human-written
    rationale was irrecoverably destroyed: fixing the title did not bring it
    back.

    The reseed here happens with the title still blank, which is the whole
    point: the rationale must survive the bad cycle, not merely the good one.
    """
    _org_id, system_id = await _system("avi-blanked-title")
    poam_id = await _poam(system_id, status="risk_accepted")
    async with session_scope() as s:
        await seed_avi(s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY)
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="avi",
            document={
                "reportPeriod": {"from": "2026-09-01T00:00:00Z", "to": "2026-12-01T00:00:00Z"},
                "acceptedVulnerabilities": [
                    {
                        "vulnerabilityDetail": {
                            "providerTrackingId": str(poam_id),
                            "detection": {
                                "detectedAt": "2026-09-05T00:00:00Z",
                                "detectionSource": "nessus",
                            },
                            "vulnerabilityDescription": "Outdated OpenSSL",
                        },
                        "acceptanceRationale": "Compensating control: WAF rule 91234.",
                    }
                ],
            },
        )

    await _retitle(poam_id, "   ")
    async with session_scope() as s:
        blanked = await seed_avi(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    entries = blanked.document.document["acceptedVulnerabilities"]
    assert len(entries) == 1, entries
    assert entries[0]["acceptanceRationale"] == "Compensating control: WAF rule 91234."
    assert entries[0]["vulnerabilityDetail"]["vulnerabilityDescription"] == "Outdated OpenSSL"
    # Both reasons, in `_seed`'s order: the walk's own reason for the row,
    # then the merge's note that the stored detail was kept instead.
    assert blanked.omitted_poam_ids == [
        (poam_id, "no description"),
        (poam_id, "detail not refreshed: no description"),
    ], blanked.omitted_poam_ids
    assert (poam_id, "no longer an accepted vulnerability") not in blanked.omitted_poam_ids
    # The kept entry is NOT counted as rendered: its row is one the walk
    # omitted, it is named in `omitted_poam_ids`, and counting it twice would
    # break the partition. So the document holds one more entry than
    # `rendered` -- exactly the stale entries the operator has been told about.
    assert blanked.counts["rendered"] == 0
    assert blanked.counts["omitted"] == 1
    assert _partition_sum(blanked.counts) == 1

    # And the stale detail refreshes once the data is fixed -- "kept verbatim"
    # must mean one cycle behind, not frozen for ever.
    await _retitle(poam_id, "Outdated OpenSSL, retitled")
    async with session_scope() as s:
        fixed = await seed_avi(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    refreshed = fixed.document.document["acceptedVulnerabilities"]
    assert len(refreshed) == 1
    assert refreshed[0]["acceptanceRationale"] == "Compensating control: WAF rule 91234."
    assert (
        refreshed[0]["vulnerabilityDetail"]["vulnerabilityDescription"]
        == "Outdated OpenSSL, retitled"
    )
    assert fixed.omitted_poam_ids == []


async def test_ver_history_carries_both_halves_and_a_generated_at() -> None:
    """Both arrays populated with real content, not one empty and one full:
    `activeVulnerabilities` and `acceptedVulnerabilities` `$ref` the same
    `vulnerabilityDetail` definition, and an empty array validates trivially.
    Only a populated array on *each* side proves both halves of this document
    reach the validator -- the exact gap that cost the sibling SDR three
    review rounds.
    """
    _org_id, system_id = await _system("hist")
    await _poam(system_id, status="open")
    accepted_id = await _poam(system_id, status="risk_accepted")
    async with session_scope() as s:
        # Authored into the `avi`, which is the family's single authoring
        # surface (spec §5.2). This test used to `put_document` the rationale
        # straight into the `ver_history` body -- the workaround that hid the
        # fact that a rationale authored in the AVI never reached here.
        row = await put_document(
            s,
            system_id=system_id,
            kind="avi",
            document={
                "acceptedVulnerabilities": [
                    {
                        "vulnerabilityDetail": {"providerTrackingId": str(accepted_id)},
                        "acceptanceRationale": "Compensating control: WAF rule 91234.",
                    }
                ],
            },
        )
        assert row is not None
    async with session_scope() as s:
        result = await seed_ver_history(s, system_id=system_id, today=TODAY)
    body = result.document.document
    assert len(body["activeVulnerabilities"]) == 1
    assert len(body["acceptedVulnerabilities"]) == 1
    assert (
        body["acceptedVulnerabilities"][0]["acceptanceRationale"]
        == "Compensating control: WAF rule 91234."
    )
    assert body["generatedAt"].endswith("Z")
    assert "reportPeriod" not in body
    assert result.document.validation_errors == ONE_ERROR


async def test_a_rationale_authored_in_the_avi_reaches_ver_history_too() -> None:
    """The measured defect (spec §5.2). Seeded on one system seconds apart, the
    AVI carried the entry and its rationale while
    `ver_history.acceptedVulnerabilities` was `[]` with
    `(id, "no acceptance rationale")`.

    `ver_history`'s array means "**All** accepted vulnerabilities", so empty
    asserts the provider has accepted none -- the favourable answer -- while
    the AVI filed for the same system says otherwise. Two filed deliverables
    contradicting each other is worse than either being incomplete.

    Authored ONCE, into the AVI, and asserted in both documents.
    """
    _org_id, system_id = await _system("one-authoring-surface")
    poam_id = await _poam(system_id, status="risk_accepted")
    async with session_scope() as s:
        await seed_avi(s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY)
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="avi",
            document={
                "reportPeriod": {"from": "2026-09-01T00:00:00Z", "to": "2026-12-01T00:00:00Z"},
                "acceptedVulnerabilities": [
                    {
                        "vulnerabilityDetail": {"providerTrackingId": str(poam_id)},
                        "acceptanceRationale": "Compensating control: WAF rule 91234.",
                    }
                ],
            },
        )
    async with session_scope() as s:
        avi = await seed_avi(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    async with session_scope() as s:
        hist = await seed_ver_history(s, system_id=system_id, today=TODAY)

    for label, result in (("avi", avi), ("ver_history", hist)):
        entries = result.document.document["acceptedVulnerabilities"]
        assert len(entries) == 1, (label, entries)
        assert entries[0]["acceptanceRationale"] == "Compensating control: WAF rule 91234."
        assert entries[0]["vulnerabilityDetail"]["providerTrackingId"] == str(poam_id)
        assert result.omitted_poam_ids == [], (label, result.omitted_poam_ids)


async def test_a_cpo_uri_already_in_the_document_survives_a_reseed() -> None:
    """Never invented, always carried forward -- as in the SDR."""
    _org_id, system_id = await _system("uri")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="vdr",
            document={
                "certificationPackageOverviewUri": "https://example.gov/cpo.json",
                "reportPeriod": {"from": "2026-09-01T00:00:00Z", "to": "2026-12-01T00:00:00Z"},
                "vulnerabilities": [],
            },
        )
    async with session_scope() as s:
        result = await seed_vdr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert (
        result.document.document["certificationPackageOverviewUri"]
        == "https://example.gov/cpo.json"
    )
    assert result.document.validation_errors == []
    assert result.document.is_valid is True


#: The five keys that PARTITION the POA&M rows a seeder considered.
#: `dropped_authored_entries` is deliberately not among them: it counts
#: authored ENTRIES, which need not correspond to any row.
PARTITION_KEYS = (
    "excluded_not_a_flaw",
    "excluded_outside_period",
    "excluded_other_half",
    "rendered",
    "omitted",
)


def _partition_sum(counts: dict[str, int]) -> int:
    assert set(counts) == {*PARTITION_KEYS, "dropped_authored_entries"}, counts
    return sum(counts[k] for k in PARTITION_KEYS)


async def test_counts_partition_every_row_the_seeder_considered() -> None:
    """One row of every kind the VDR can see -- excluded by source, excluded by
    period, rendered, omitted, and rendered into the OTHER half -- so the sum
    genuinely depends on each bucket rather than on one that happens to be
    zero.
    """
    _org_id, system_id = await _system("counts")
    await _poam(system_id, status="open")
    await _poam(system_id, source="assessment")
    await _poam(system_id, identified_on=None)
    await _poam(system_id, identified_on=date(2027, 1, 1))
    await _poam(system_id, status="risk_accepted")
    async with session_scope() as s:
        result = await seed_vdr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert _partition_sum(result.counts) == 5
    assert result.counts == {
        "excluded_not_a_flaw": 1,
        "excluded_outside_period": 1,
        # The accepted row: rendered by the walk, but a VDR covers
        # "non-accepted vulnerabilities only", so it can never appear here.
        "excluded_other_half": 1,
        "rendered": 1,
        "omitted": 1,
        "dropped_authored_entries": 0,
    }


async def test_an_avi_s_counts_describe_the_avi_not_the_walk() -> None:
    """Measured: an AVI returned `omitted_poam_ids: [[id, "no acceptance
    rationale"]]` beside `counts: {"rendered": 1, "omitted": 0}` and an empty
    document. The merge stage's omissions never reached `counts`, and
    `rendered` counted an ACTIVE row that can never appear in an AVI.
    """
    _org_id, system_id = await _system("counts-avi")
    accepted_id = await _poam(system_id, status="risk_accepted")
    await _poam(system_id, status="open")
    async with session_scope() as s:
        result = await seed_avi(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.document["acceptedVulnerabilities"] == []
    assert result.omitted_poam_ids == [(accepted_id, "no acceptance rationale")]
    assert result.counts == {
        "excluded_not_a_flaw": 0,
        "excluded_outside_period": 0,
        "excluded_other_half": 1,
        "rendered": 0,
        "omitted": 1,
        "dropped_authored_entries": 0,
    }
    assert _partition_sum(result.counts) == 2


async def test_a_dropped_authored_entry_is_counted_outside_the_row_partition() -> None:
    """An authored id need not correspond to any POA&M row -- "POAM-X" here is
    stored JSON an admin edited -- so counting it among the rows would break
    the sum. It is reported beside the partition instead, and the partition
    still adds up to the rows the seeder considered.
    """
    _org_id, system_id = await _system("counts-dropped")
    await _poam(system_id, status="open")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="avi",
            document={
                "acceptedVulnerabilities": [
                    {
                        "vulnerabilityDetail": {"providerTrackingId": "POAM-X"},
                        "acceptanceRationale": "Stale, admin-edited tracking id.",
                    }
                ],
            },
        )
    async with session_scope() as s:
        result = await seed_avi(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.omitted_poam_ids == [("POAM-X", "no longer an accepted vulnerability")]
    assert result.counts["dropped_authored_entries"] == 1
    assert _partition_sum(result.counts) == 1


async def test_another_systems_poams_never_reach_this_document() -> None:
    """App-layer scoping is the primary defence: RLS on this table is
    ORG-scoped, so a dropped filter leaks between systems inside one tenant
    regardless, and an unscoped principal bypasses RLS entirely.
    """
    _org_a, a = await _system("tenant-a")
    _org_b, b = await _system("tenant-b")
    mine = await _poam(a, title="MINE")
    await _poam(b, title="THEIRS")
    async with session_scope() as s:
        result = await seed_vdr(s, system_id=a, period_from=FROM, period_to=TO, today=TODAY)
    descriptions = [
        v["vulnerabilityDescription"] for v in result.document.document["vulnerabilities"]
    ]
    assert descriptions == ["MINE"]
    assert [v["providerTrackingId"] for v in result.document.document["vulnerabilities"]] == [
        str(mine)
    ]


async def test_seed_combines_an_int_and_a_str_omitted_id_without_raising() -> None:
    """`_seed` re-combines `[*rendering.omitted, *extra_omitted]` and re-sorts
    the result. `rendering.omitted` ids are always `int` (POA&M primary
    keys); a `str` id arises only through `merge_accepted`'s "no longer an
    accepted vulnerability" rule, when a stored document carries an
    admin-edited, non-numeric `providerTrackingId` the source no longer
    reports. No other test in this file produces both in the same seed call,
    so nothing exercises `_seed`'s own recombination point -- only
    `merge_accepted`'s internal sort is covered, by
    `test_omitted_ids_sort_numeric_first_then_string_not_lexically` in
    `tests/test_cr26_ver_merge.py`. Exact equality: ints first, in the order
    `render_all` produced them, then the string.
    """
    _org_id, system_id = await _system("mixed-omit")
    unmeasurable_id = await _poam(system_id, identified_on=None)
    async with session_scope() as s:
        row = await put_document(
            s,
            system_id=system_id,
            kind="avi",
            document={
                "acceptedVulnerabilities": [
                    {
                        "vulnerabilityDetail": {"providerTrackingId": "POAM-X"},
                        "acceptanceRationale": "Stale, admin-edited tracking id.",
                    }
                ],
            },
        )
        assert row is not None
    async with session_scope() as s:
        result = await seed_avi(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.omitted_poam_ids == [
        (unmeasurable_id, "not measurable as accepted or not"),
        (unmeasurable_id, "no identification date"),
        ("POAM-X", "no longer an accepted vulnerability"),
    ]


# --- the routes --------------------------------------------------------
#
# The route handlers have no `today` parameter -- adding one would put
# test-only surface into a production API -- so they always render against
# the real clock. `_poam`'s own default `identified_on` is the fixed literal
# `date(2026, 9, 5)`; a route test that relied on it would start failing
# once the real clock crosses `ACCEPTED_WEAKNESS_DAYS = 192` days past that
# date, for reasons that have nothing to do with the code under test (see
# `accepted_weakness_state`). Every POA&M a route test creates below is
# therefore dated relative to `date.today()` instead, recent enough that it
# stays "not accepted" -- and so stays in the VDR/`ver_history` "active"
# bucket -- no matter when the suite runs.

RECENT = date.today() - timedelta(days=5)

#: The reporting window posted to the VDR/AVI routes, dated relative to today
#: for the same reason `RECENT` is. The window is no longer decorative: VDR and
#: AVI now SELECT on it (spec §2.2), so a literal window would stop covering
#: `RECENT` the moment the real clock ran past it, and every route test below
#: would start reporting its row as excluded rather than rendered. Wide enough
#: either side of `RECENT` that no boundary question arises here -- the
#: boundaries are pinned in `tests/test_cr26_ver_walk.py`, where the dates can
#: be exact.
PERIOD = {
    "from": f"{date.today() - timedelta(days=30)}T00:00:00Z",
    "to": f"{date.today() + timedelta(days=30)}T00:00:00Z",
}


class _Session:
    """A client whose identity and role can change between calls."""

    def __init__(self, *, org_id: int | None = None, role: str = "admin") -> None:
        self.app = create_app()
        self.org_id = org_id
        self.role = role
        self.app.dependency_overrides[get_principal] = self._principal

    def _principal(self) -> Principal:
        return Principal(user_id=1, email="isso@acme.gov", org_id=self.org_id, role=self.role)

    def client(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")


async def test_the_vdr_route_reports_every_result_field_to_the_caller() -> None:
    """Both result fields must cross the HTTP boundary. They are the ENTIRE
    operator-facing signal that a vulnerability was left out -- nothing in the
    document says so -- and on the SDR, deleting the equivalent two lines from
    the route left every dataclass-level assertion green.
    """
    org_id, system_id = await _system("route-vdr")
    # RECENT: identified 5 days ago, status "open" -- stays "not accepted"
    # under `accepted_weakness_state` for the next 187 days, so this always
    # renders into `vulnerabilities` rather than drifting to the AVI.
    await _poam(system_id, status="open", identified_on=RECENT)
    # Excluded by source before the accepted/not-accepted question is ever
    # asked (see `render_all`), so its date is irrelevant to its bucket --
    # dated anyway for consistency with the rest of this test.
    await _poam(system_id, source="assessment", identified_on=RECENT)
    omitted_id = await _poam(system_id, identified_on=None)
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/vdr/seed", json=PERIOD
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["kind"] == "vdr"
    assert body["counts"]["excluded_not_a_flaw"] == 1
    assert [omitted_id, "no identification date"] in body["omitted_poam_ids"]
    assert len(body["document"]["vulnerabilities"]) == 1


async def test_an_inverted_period_is_refused() -> None:
    """A report whose window runs backwards states an impossible period."""
    org_id, system_id = await _system("route-inverted")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/vdr/seed",
            json={"from": "2026-12-01T00:00:00Z", "to": "2026-09-01T00:00:00Z"},
        )
    assert resp.status_code == 422, resp.text


@pytest.mark.parametrize(
    "body, label",
    [
        ({"from": "2026-09-01T00:00:00", "to": "2026-12-01T00:00:00Z"}, "naive from"),
        ({"from": "2026-09-01T00:00:00Z", "to": "2026-12-01T00:00:00"}, "naive to"),
        ({"from": "2026-09-01T00:00:00", "to": "2026-12-01T00:00:00"}, "both naive"),
    ],
)
async def test_a_naive_period_is_refused_rather_than_read_as_local_time(
    body: dict[str, str], label: str
) -> None:
    """422, not a silently shifted window (spec §6.1.1).

    Measured before the fix with the server in `America/New_York`: a naive
    pair was stored as `2026-09-01T04:00:00Z`/`2026-12-01T05:00:00Z`, because
    `datetime.astimezone` reads a naive value as LOCAL time -- and since that
    pair straddles a DST boundary, the window's LENGTH changed too. `ok: True`,
    no error, nothing downstream able to tell.

    The two MIXED cases matter on their own: a mixed pair reached `_ordered`'s
    comparison and raised `TypeError`, which pydantic does not wrap the way it
    wraps `ValueError`, so the caller got a 500 rather than a 422.
    """
    org_id, system_id = await _system(f"route-naive-{label.replace(' ', '-')}")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/vdr/seed", json=body
        )
    assert resp.status_code == 422, f"{label}: {resp.text}"


async def test_a_naive_period_is_refused_by_the_avi_route_too() -> None:
    """The AVI route depends on `VerPeriod` rather than merely importing it."""
    org_id, system_id = await _system("route-avi-naive")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/avi/seed",
            json={"from": "2026-09-01T00:00:00", "to": "2026-12-01T00:00:00"},
        )
    assert resp.status_code == 422, resp.text


async def test_an_aware_period_in_another_offset_is_stored_as_the_exact_instant() -> None:
    """The other half of the naive rule: an aware value IS an instant, so it is
    converted rather than refused, and the conversion is asserted by exact
    string. `-04:00` rather than `Z` so a route that dropped the offset would
    fail here -- and so this assertion does not depend on the server's zone.
    """
    org_id, system_id = await _system("route-aware-offset")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/vdr/seed",
            json={"from": "2026-09-01T00:00:00-04:00", "to": "2026-12-01T00:00:00-05:00"},
        )
    assert resp.status_code == 200, resp.text
    assert resp.json()["document"]["reportPeriod"] == {
        "from": "2026-09-01T04:00:00Z",
        "to": "2026-12-01T05:00:00Z",
    }


async def test_a_non_admin_cannot_seed_a_vdr() -> None:
    """`control_owner` rather than `viewer`, so this distinguishes the write
    gate from the read gate. Authoring a CR26 deliverable is admin only."""
    org_id, system_id = await _system("route-role")
    async with _Session(org_id=org_id, role="control_owner").client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/vdr/seed", json=PERIOD
        )
    assert resp.status_code == 403, resp.text


#: One case per seed route: its `kind` (the path segment and the
#: attribute name `cr26_routes` imports its seeder under -- they happen to
#: coincide), and the JSON body it takes (`None` for `ver_history`, which
#: has no request model at all).
_ROUTE_SEED_CASES = [
    pytest.param("vdr", PERIOD, id="vdr"),
    pytest.param("avi", PERIOD, id="avi"),
    pytest.param("ver_history", None, id="ver_history"),
]


@pytest.mark.parametrize("kind, body", _ROUTE_SEED_CASES)
async def test_another_tenants_system_is_404_not_403(
    monkeypatch: pytest.MonkeyPatch, kind: str, body: dict[str, str] | None
) -> None:
    """Seeded as the owner first, so this exercises a path that would otherwise
    return 200 -- a 404 against a system that never existed proves nothing.

    The status code alone CANNOT prove `_owned_system` runs before the
    seeder. If a route called its seeder first and `_owned_system` second,
    the response would still be 404: `_owned_system`'s `HTTPException` still
    fires before the route's `session.commit()`, and `get_session` never
    commits on its own, so whatever the seeder had written for the other
    tenant's system is rolled back when the session closes on the way out.
    Rollback makes the two orderings observationally identical over HTTP --
    the spy below, not the status code, is what actually guards the
    invariant that no tenant's data is touched before ownership is checked.

    Parametrized over all three routes rather than testing `vdr` alone: the
    three handlers are hand-mirrored, not generated from one function (see
    the module docstring in `cr26.py`), so each one's call-order can regress
    independently of the others. An earlier version of this test covered
    only `vdr` and a reviewer found the other two routes had this ordering
    completely unguarded -- not even by the weak, status-code-only kind of
    coverage.
    """
    owner_org, system_id = await _system(f"route-other-{kind}")
    other_org, _ = await _system(f"route-intruder-{kind}")
    async with _Session(org_id=owner_org).client() as c:
        first = await c.post(
            f"/api/systems/{system_id}/cr26-documents/{kind}/seed", json=body
        )
    assert first.status_code == 200, f"{kind}: {first.text}"

    calls: list[None] = []
    # `f"seed_{kind}"` names the right attribute for all three kinds --
    # `seed_vdr`, `seed_avi`, `seed_ver_history` -- because `cr26_routes`
    # imports each seeder under its own name (see `cr26.py`'s import block).
    seeder_name = f"seed_{kind}"
    real_seeder = getattr(cr26_routes, seeder_name)

    async def _spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(None)
        return await real_seeder(*args, **kwargs)

    monkeypatch.setattr(cr26_routes, seeder_name, _spy)

    async with _Session(org_id=other_org).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/{kind}/seed", json=body
        )
    assert resp.status_code == 404, f"{kind}: {resp.text}"
    assert calls == [], f"{kind}: {seeder_name} must never run before ownership is checked"


async def test_the_avi_route_reports_every_result_field_to_the_caller() -> None:
    """`/avi/seed` had ZERO HTTP coverage before this test -- it was only
    ever exercised at the seeder level (`seed_avi` called directly). A
    reviewer proved the gap by swapping `seed_avi` for `seed_vdr` inside
    `seed_avi_document`: the full suite stayed green, because nothing over
    HTTP ever posted to this route. Real content, not `[]`/`{}`, so a route
    that hard-coded an empty result would fail this too.
    """
    org_id, system_id = await _system("route-avi")
    # risk_accepted + RECENT: declared-accepted regardless of age, so this
    # is always in scope for the AVI. No authored rationale exists yet, so
    # `merge_accepted` omits it for exactly one reason.
    poam_id = await _poam(system_id, status="risk_accepted", identified_on=RECENT)
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/avi/seed", json=PERIOD
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["kind"] == "avi"
    assert body["omitted_poam_ids"] == [[poam_id, "no acceptance rationale"]]
    # `rendered` describes THIS document: the one accepted row had no
    # authored rationale, so nothing reached the AVI and the row is omitted.
    # Reporting `rendered: 1, omitted: 0` beside an empty document and a
    # populated `omitted_poam_ids` was the measured defect.
    assert body["counts"] == {
        "excluded_not_a_flaw": 0,
        "excluded_outside_period": 0,
        "excluded_other_half": 0,
        "rendered": 0,
        "omitted": 1,
        "dropped_authored_entries": 0,
    }
    assert body["document"]["acceptedVulnerabilities"] == []


async def test_a_non_admin_cannot_seed_an_avi() -> None:
    """`/avi/seed`'s own role gate, not inferred from the VDR route's."""
    org_id, system_id = await _system("route-avi-role")
    async with _Session(org_id=org_id, role="control_owner").client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/avi/seed", json=PERIOD
        )
    assert resp.status_code == 403, resp.text


async def test_an_inverted_period_is_refused_for_the_avi_route() -> None:
    """`VerPeriod` is shared with `/vdr/seed`, but this proves the AVI route
    actually depends on it rather than merely importing the same class."""
    org_id, system_id = await _system("route-avi-inverted")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/avi/seed",
            json={"from": "2026-12-01T00:00:00Z", "to": "2026-09-01T00:00:00Z"},
        )
    assert resp.status_code == 422, resp.text


async def test_the_ver_history_route_takes_no_period() -> None:
    org_id, system_id = await _system("route-hist")
    # RECENT, same reasoning as the VDR route test above: this must stay
    # "not accepted" so it always lands in `activeVulnerabilities`.
    await _poam(system_id, status="open", identified_on=RECENT)
    # Omitted for "no identification date" -- gives `omitted_poam_ids` real
    # content, so a route that hard-coded `[]` for it would fail this test.
    omitted_id = await _poam(system_id, identified_on=None)
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/ver_history/seed"
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "reportPeriod" not in body["document"]
    assert body["document"]["generatedAt"].endswith("Z")
    assert len(body["document"]["activeVulnerabilities"]) == 1
    assert [omitted_id, "no identification date"] in body["omitted_poam_ids"]
    assert body["counts"]["rendered"] == 1
    assert body["counts"]["omitted"] == 1
