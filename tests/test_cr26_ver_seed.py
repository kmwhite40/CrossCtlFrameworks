"""The three seeders, end to end against the database and the real validator."""

from __future__ import annotations

from datetime import UTC, date, datetime

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
    async with session_scope() as s:
        result = await seed_vdr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.document["reportPeriod"] == {
        "from": "2026-09-01T00:00:00Z",
        "to": "2026-12-01T00:00:00Z",
    }


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
        row = await put_document(
            s,
            system_id=system_id,
            kind="ver_history",
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


async def test_counts_partition_every_row_the_seeder_considered() -> None:
    _org_id, system_id = await _system("counts")
    await _poam(system_id, status="open")
    await _poam(system_id, source="assessment")
    await _poam(system_id, identified_on=None)
    async with session_scope() as s:
        result = await seed_vdr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert sum(result.counts.values()) == 3
    assert result.counts["excluded_not_a_flaw"] == 1


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
