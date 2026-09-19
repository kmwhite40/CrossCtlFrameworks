"""The OCR seeder end to end against the database and the real validator.

This deliverable inverts the ones before it (spec §1): eight of its nine
required fields are human statements the platform cannot supply, and only
``acceptedVulnerabilities`` is derived. Every test below traces back to one of
spec §5's six testing requirements, and each requirement gets a mutation that
proves its guard is load-bearing rather than decorative -- see the report
delivered alongside this file for the mutation-by-mutation results.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.api.routes import cr26 as cr26_routes
from ccf.auth import Principal
from ccf.cr26.ocr import seed_ocr
from ccf.cr26.store import put_document
from ccf.cr26.validation import validate_document
from ccf.db import session_scope
from ccf.models import POAM, Organization, System
from ccf.patching.sla import accepted_weakness_state

FROM = date(2026, 9, 1)
TO = date(2026, 12, 1)

#: Fixed rather than the real clock -- same reasoning as `test_cr26_ver_seed`'s
#: `TODAY`: `accepted_weakness_state` flips a row to `accepted` 192 days past
#: `identified_on`, and several POA&Ms below are dated inside `[FROM, TO]`.
TODAY = date(2026, 9, 18)

#: The six required fields spec §3.4 says have no platform source at all, in
#: the exact order `ccf.cr26.validation` reports them (the vendored schema's
#: own `required` array order) -- pinned by
#: `test_a_freshly_seeded_ocr_is_invalid_for_exactly_six_reasons` below.
SIX_REQUIRED = (
    "certificationDataChanges",
    "plannedCertificationDataChanges",
    "transformativeChanges",
    "updatedRecommendations",
    "activeAgencies",
    "reportableIncidents",
)
SIX_ERRORS = [f"<root>: '{name}' is a required property" for name in SIX_REQUIRED]

CPO_URI = "https://example.gov/cpo.json"


async def _system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"{name} org")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=name, baseline="moderate")
        s.add(system)
        await s.flush()
        return org.id, system.id


async def _poam(system_id: int, **kw: object) -> int:
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


async def _with_cpo_uri(system_id: int) -> None:
    """Seed a stored `ocr` document carrying an authored CPO URI and nothing
    else, so a subsequent `seed_ocr` call is invalid for EXACTLY the six
    authored fields -- isolating spec §3.4's six from §3.1's URI, which is
    carried forward by a completely separate mechanism and already covered by
    `tests/test_cr26_ver_seed.py`'s URI tests on its sibling seeders.
    """
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="ocr",
            document={"certificationPackageOverviewUri": CPO_URI},
        )


# --- requirement 1: nothing authored is invalid, named exactly ------------


async def test_a_freshly_seeded_ocr_is_invalid_for_exactly_six_reasons() -> None:
    """Spec §5 requirement 1, exact equality. With the CPO URI already carried
    forward and nothing else ever authored, the document is invalid for
    EXACTLY the six fields spec §3.4 names -- not seven (a URI omission would
    add one), not fewer (an emitted empty value would validate one away).

    MUTATION: replacing any one of the six `_authored_*` guards in `ocr.py`
    with a version that emits `[]`/`{}` instead of omitting shrinks this list
    by one and fails this assertion.
    """
    _org_id, system_id = await _system("nothing-authored")
    await _with_cpo_uri(system_id)
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.validation_errors == SIX_ERRORS, result.document.validation_errors
    assert result.document.is_valid is False
    assert [name for name, _reason in result.missing_fields] == list(SIX_REQUIRED)
    assert result.missing_fields[0][0] == "certificationDataChanges"
    assert result.missing_fields[0][1]  # a real, non-empty reason


async def test_a_freshly_seeded_ocr_with_no_cpo_uri_either_adds_a_seventh_error() -> None:
    """The URI is a SEPARATE omission from the six authored fields (spec
    §3.1 vs §3.4) -- never invented, and not one of `missing_fields`' six,
    exactly like the SDR's own `certificationPackageOverviewUri` handling.
    """
    _org_id, system_id = await _system("no-uri-either")
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert len(result.document.validation_errors) == 7
    assert "certificationPackageOverviewUri" not in result.document.document
    assert len(result.missing_fields) == 6


# --- requirement 2: an authored value survives a re-seed -------------------


_AUTHORED_VALUES: dict[str, object] = {
    "certificationDataChanges": ["Rotated the KMS root key."],
    "plannedCertificationDataChanges": {
        "planningHorizonThrough": "2027-06-01",
        "changes": ["Migrate logging to the new SIEM."],
    },
    "transformativeChanges": ["Adopted a new IAM provider."],
    "updatedRecommendations": ["Rotate API keys quarterly."],
    "activeAgencies": ["GSA", "DHS"],
    "reportableIncidents": {
        "incidents": [{"summary": "Brief outage, no data exposure."}]
    },
}


@pytest.mark.parametrize("field_name", SIX_REQUIRED)
async def test_an_authored_value_survives_a_reseed(field_name: str) -> None:
    """Spec §5 requirement 2, one authored field at a time -- and the derived
    summary refreshes alongside it (checked once, at the end, since it is the
    same code path regardless of which of the six is under test).

    MUTATION: dropping the `document[key] = value` assignment for any one
    field (while keeping its omission-detection guard) makes that field's own
    parametrize case fail, and only that one.
    """
    _org_id, system_id = await _system(f"survives-{field_name}")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="ocr",
            document={
                "certificationPackageOverviewUri": CPO_URI,
                field_name: _AUTHORED_VALUES[field_name],
            },
        )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.document[field_name] == _AUTHORED_VALUES[field_name]
    assert field_name not in [name for name, _reason in result.missing_fields]
    assert result.document.document["acceptedVulnerabilities"].startswith("0 accepted")


# --- requirement 3: reportableIncidents is never emitted empty by the seeder


async def test_reportable_incidents_is_never_emitted_by_the_seeder_when_unauthored() -> None:
    """Spec §5 requirement 3 -- the attestation guard, the most important test
    in this file. A seeder that fabricated `{"incidents": []}` from nothing
    authored would file a FALSE statement to a federal regulator that no
    reportable incident occurred (spec §1.2).

    MUTATION: changing `_authored_reportable_incidents` to return
    `current.get("reportableIncidents") or {"incidents": []}` -- manufacturing
    the attestation instead of omitting it -- makes `reportableIncidents`
    appear in the document here, and this test is the one that catches it.
    """
    _org_id, system_id = await _system("no-incidents-authored")
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert "reportableIncidents" not in result.document.document
    names = [name for name, _reason in result.missing_fields]
    assert "reportableIncidents" in names


async def test_an_authored_empty_incidents_array_is_preserved_as_the_attestation_it_is() -> None:
    """The other half of requirement 3: once a human HAS authored
    `{"incidents": []}`, that IS the favourable attestation the schema
    describes, and the seeder must carry it forward rather than treating an
    empty list as if nobody had touched it.

    MUTATION: `_authored_reportable_incidents` checking
    `len(value.get("incidents")) > 0` instead of `isinstance(..., list)` would
    make this test fail -- exactly the emptiness-based logic that is correct
    for the four plain array fields but WRONG here.
    """
    _org_id, system_id = await _system("authored-empty-incidents")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="ocr",
            document={
                "certificationPackageOverviewUri": CPO_URI,
                "reportableIncidents": {"incidents": []},
            },
        )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.document["reportableIncidents"] == {"incidents": []}
    assert "reportableIncidents" not in [n for n, _r in result.missing_fields]


# --- requirement 4: date, not date-time -------------------------------------


async def test_the_period_renders_as_date_not_date_time() -> None:
    """Spec §5 requirement 4, exact string.

    MUTATION: rendering `reportPeriod` with `ccf.cr26.ver._instant` instead of
    `date.isoformat()` would produce `"2026-09-01T00:00:00Z"` here, not
    `"2026-09-01"`, and this assertion catches it.
    """
    _org_id, system_id = await _system("period-is-date")
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.document["reportPeriod"] == {
        "from": "2026-09-01",
        "to": "2026-12-01",
    }


async def test_a_date_time_value_in_report_period_is_rejected_by_the_validator() -> None:
    """The other half of requirement 4: pinning that `date` IS enforced here
    while `date-time` is not, the measured contrast with the VER family
    (spec §3.2). Built by hand rather than through `seed_ocr`, which can never
    itself produce a date-time value -- this proves what the SCHEMA does, not
    what the seeder does.
    """
    doc = {
        "certificationPackageOverviewUri": CPO_URI,
        "reportPeriod": {"from": "2026-07-01T00:00:00Z", "to": "2026-12-01"},
        "acceptedVulnerabilities": "0 accepted vulnerabilities for this reporting "
        "period. Full records are reported per VER-RPT-AVI.",
        "certificationDataChanges": ["x"],
        "plannedCertificationDataChanges": {
            "planningHorizonThrough": "2027-01-01",
            "changes": [],
        },
        "transformativeChanges": [],
        "updatedRecommendations": [],
        "activeAgencies": [],
        "reportableIncidents": {"incidents": []},
    }
    report = validate_document(doc, "ocr")
    assert report.ok is False
    assert report.errors == ["reportPeriod/from: '2026-07-01T00:00:00Z' is not a 'date'"]


# --- requirement 5: a partially-authored object is treated as unauthored ---


async def test_a_partial_planned_changes_missing_the_horizon_is_treated_as_unauthored() -> None:
    """Spec §5 requirement 5, `plannedCertificationDataChanges` missing its
    `planningHorizonThrough`.

    MUTATION: `_authored_planned_changes` checking only `"changes" in value`
    (ignoring `planningHorizonThrough` entirely) would carry this object
    forward, and this test's `not in document` assertion catches it.
    """
    _org_id, system_id = await _system("planned-missing-horizon")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="ocr",
            document={
                "certificationPackageOverviewUri": CPO_URI,
                "plannedCertificationDataChanges": {"changes": ["Something planned."]},
            },
        )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert "plannedCertificationDataChanges" not in result.document.document
    assert "plannedCertificationDataChanges" in [n for n, _r in result.missing_fields]


async def test_a_partial_planned_changes_missing_changes_is_treated_as_unauthored() -> None:
    """The other required key, same object -- proves the guard checks BOTH,
    not just `planningHorizonThrough`.

    MUTATION: `_authored_planned_changes` returning early as soon as
    `planningHorizonThrough` is non-blank, without checking `changes` at all,
    would carry this object forward too.
    """
    _org_id, system_id = await _system("planned-missing-changes")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="ocr",
            document={
                "certificationPackageOverviewUri": CPO_URI,
                "plannedCertificationDataChanges": {"planningHorizonThrough": "2027-01-01"},
            },
        )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert "plannedCertificationDataChanges" not in result.document.document
    assert "plannedCertificationDataChanges" in [n for n, _r in result.missing_fields]


async def test_planned_changes_with_an_empty_changes_list_is_still_fully_authored() -> None:
    """A human who set a real planning horizon and genuinely has nothing
    planned has still authored this object -- `changes` only has to be a
    LIST, not a non-empty one, unlike the four plain top-level array fields.

    MUTATION: `_authored_planned_changes` requiring `len(changes) > 0` (the
    rule that IS correct for the four plain array fields) would treat this as
    unauthored, and this test's `in document.document` assertion catches it.
    """
    _org_id, system_id = await _system("planned-empty-changes-ok")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="ocr",
            document={
                "certificationPackageOverviewUri": CPO_URI,
                "plannedCertificationDataChanges": {
                    "planningHorizonThrough": "2027-01-01",
                    "changes": [],
                },
            },
        )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.document["plannedCertificationDataChanges"] == {
        "planningHorizonThrough": "2027-01-01",
        "changes": [],
    }
    assert "plannedCertificationDataChanges" not in [n for n, _r in result.missing_fields]


async def test_an_authored_empty_plain_array_is_honoured_not_discarded() -> None:
    """Presence, not length, is the authored signal (spec §3.4, as corrected
    by review). The seeder itself never writes `activeAgencies` when nothing
    was authored, so a stored `[]` under that key can only have come from a
    human's own `PUT` -- exactly the same reasoning already applied to
    `reportableIncidents`'s empty `incidents` array. `activeAgencies` here,
    picked arbitrarily among the four plain array fields; the same guard,
    `_authored_array`, covers all four identically.

    An earlier version of this test asserted the OPPOSITE -- that an authored
    `[]` was discarded -- which was the defect: it made a quiet quarter, where
    an operator has genuinely nothing to report for this field, unfileable.

    MUTATION: `_authored_array` reverting to `len(value) > 0` (discarding an
    authored empty list) makes this field vanish from the document again, and
    this test's `==` assertion catches it. See
    `test_a_quiet_quarter_with_every_field_authored_empty_is_filable` for the
    same guard exercised across all six fields at once.
    """
    _org_id, system_id = await _system("plain-array-empty-authored")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="ocr",
            document={"certificationPackageOverviewUri": CPO_URI, "activeAgencies": []},
        )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.document["activeAgencies"] == []
    assert "activeAgencies" not in [n for n, _r in result.missing_fields]


async def test_a_quiet_quarter_with_every_field_authored_empty_is_filable() -> None:
    """The end-to-end proof that the fix above matters: the OCR's most common
    case -- a quarter where genuinely nothing happened -- must be FILABLE.

    An operator authors an honest `[]`/empty attestation for all six fields:
    the four plain arrays, `reportableIncidents` (the built-in attestation),
    and `plannedCertificationDataChanges` with a real horizon and no planned
    changes. None of that is "nothing authored" -- every key is genuinely
    present, a human decision recorded -- so the resulting document must
    validate, and `missing_fields` must be empty.

    This is the test that would have caught the reviewed defect: the earlier
    `_authored_array` discarded four of these six authored empties, leaving
    the document permanently invalid no matter what an operator did for a
    quiet quarter.

    MUTATION: reverting `_authored_array` to `len(value) > 0` makes
    `missing_fields` non-empty again (the four plain fields reappear) and
    `is_valid` false.
    """
    _org_id, system_id = await _system("quiet-quarter")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="ocr",
            document={
                "certificationPackageOverviewUri": CPO_URI,
                "certificationDataChanges": [],
                "plannedCertificationDataChanges": {
                    "planningHorizonThrough": "2027-01-01",
                    "changes": [],
                },
                "transformativeChanges": [],
                "updatedRecommendations": [],
                "activeAgencies": [],
                "reportableIncidents": {"incidents": []},
            },
        )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.missing_fields == []
    assert result.document.validation_errors == [], result.document.validation_errors
    assert result.document.is_valid is True
    assert result.document.document["certificationDataChanges"] == []
    assert result.document.document["transformativeChanges"] == []
    assert result.document.document["updatedRecommendations"] == []
    assert result.document.document["activeAgencies"] == []
    assert result.document.document["reportableIncidents"] == {"incidents": []}
    assert result.document.document["plannedCertificationDataChanges"] == {
        "planningHorizonThrough": "2027-01-01",
        "changes": [],
    }


async def test_a_reportable_incidents_object_missing_its_incidents_key_is_unauthored() -> None:
    """`reportableIncidents`'s own half of requirement 5: present as an
    object, but missing its one required key, is exactly as unauthored as
    the key never having been touched.
    """
    _org_id, system_id = await _system("incidents-missing-key")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="ocr",
            document={
                "certificationPackageOverviewUri": CPO_URI,
                "reportableIncidents": {"notes": "nothing filled in yet"},
            },
        )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert "reportableIncidents" not in result.document.document
    assert "reportableIncidents" in [n for n, _r in result.missing_fields]


# --- requirement 6: the derived summary agrees with accepted_count ---------


async def test_the_derived_summary_agrees_with_accepted_count_and_with_the_sla_rule() -> None:
    """Spec §5 requirement 6. One `risk_accepted` row inside the period (and
    inside the flaw-source filter) plus one row that must NOT count -- closed
    on time, so `accepted_weakness_state` says `not_accepted` -- so the count
    genuinely depends on the rule rather than on "every row in the period".

    MUTATION: `_accepted_count` counting every row in the period regardless of
    `accepted_weakness_state` (i.e. dropping the `== "accepted"` check) would
    report `2`, not `1`, here.
    """
    _org_id, system_id = await _system("summary-agrees")
    accepted_id = await _poam(
        system_id, status="risk_accepted", identified_on=date(2026, 10, 1)
    )
    not_accepted_id = await _poam(
        system_id, status="open", identified_on=date(2026, 10, 1)
    )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.accepted_count == 1
    assert result.document.document["acceptedVulnerabilities"] == (
        "1 accepted vulnerability for this reporting period. "
        "Full records are reported per VER-RPT-AVI."
    )

    # And it agrees with `accepted_weakness_state` on the SAME rows, directly.
    async with session_scope() as s:
        accepted_row = await s.get(POAM, accepted_id)
        not_accepted_row = await s.get(POAM, not_accepted_id)
        assert accepted_row is not None
        assert not_accepted_row is not None
        assert accepted_weakness_state(accepted_row, today=TODAY) == "accepted"
        assert accepted_weakness_state(not_accepted_row, today=TODAY) == "not_accepted"


async def test_a_zero_accepted_count_is_stated_not_omitted() -> None:
    """Spec §3.3: a derived zero is measured, not assumed, and must be said
    explicitly -- unlike the six authored fields, an empty answer here is not
    ambiguous, because the platform saw the whole population.
    """
    _org_id, system_id = await _system("summary-zero")
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.accepted_count == 0
    assert result.document.document["acceptedVulnerabilities"] == (
        "0 accepted vulnerabilities for this reporting period. "
        "Full records are reported per VER-RPT-AVI."
    )


async def test_the_accepted_count_excludes_a_row_outside_the_period() -> None:
    """Same scoping the AVI applies (spec §3.3) -- a row dated outside the
    window must not inflate the count, proven the same way
    `test_an_avi_excludes_an_accepted_row_dated_outside_the_period` proves it
    for the AVI itself.
    """
    _org_id, system_id = await _system("summary-outside-period")
    await _poam(system_id, status="risk_accepted", identified_on=date(2027, 1, 1))
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.accepted_count == 0


async def test_the_accepted_count_excludes_a_non_flaw_source() -> None:
    """Same flaw-source scoping the AVI applies -- a control deficiency must
    never inflate a summary that is specifically about accepted
    *vulnerabilities*.
    """
    _org_id, system_id = await _system("summary-non-flaw")
    await _poam(
        system_id, status="risk_accepted", source="assessment", identified_on=date(2026, 10, 1)
    )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.accepted_count == 0


# --- carrying the CPO URI, and carrying it only when authored --------------


async def test_a_cpo_uri_already_in_the_document_survives_a_reseed() -> None:
    """Never invented, always carried forward -- as in the VDR and the SDR."""
    _org_id, system_id = await _system("uri-survives")
    await _with_cpo_uri(system_id)
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert result.document.document["certificationPackageOverviewUri"] == CPO_URI


async def test_a_blank_stored_cpo_uri_is_not_carried_forward() -> None:
    """`is_blank`, not `is not None` -- shared with `ccf.cr26.ver`, and this
    is the OCR's own proof that the shared helper is actually being called
    rather than a bespoke, possibly-looser check.
    """
    _org_id, system_id = await _system("ocr-uri-blank")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="ocr",
            document={"certificationPackageOverviewUri": "   "},
        )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system_id, period_from=FROM, period_to=TO, today=TODAY
        )
    assert "certificationPackageOverviewUri" not in result.document.document


# --- tenant isolation -------------------------------------------------------


async def test_another_systems_poams_never_reach_this_summary() -> None:
    _org_a, a = await _system("ocr-tenant-a")
    _org_b, b = await _system("ocr-tenant-b")
    await _poam(a, status="risk_accepted", identified_on=date(2026, 10, 1))
    await _poam(b, status="risk_accepted", identified_on=date(2026, 10, 1))
    async with session_scope() as s:
        result = await seed_ocr(s, system_id=a, period_from=FROM, period_to=TO, today=TODAY)
    assert result.accepted_count == 1


# --- the route ---------------------------------------------------------


class _Session:
    def __init__(self, *, org_id: int | None = None, role: str = "admin") -> None:
        self.app = create_app()
        self.org_id = org_id
        self.role = role
        self.app.dependency_overrides[get_principal] = self._principal

    def _principal(self) -> Principal:
        return Principal(user_id=1, email="isso@acme.gov", org_id=self.org_id, role=self.role)

    def client(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")


#: Dated relative to today, same reasoning as `test_cr26_ver_seed.RECENT`/
#: `PERIOD`: the route has no `today` override, so a literal window would go
#: stale the moment the real clock passes it.
PERIOD = {
    "from": str(date.today() - timedelta(days=30)),
    "to": str(date.today() + timedelta(days=30)),
}


async def test_the_ocr_route_reports_every_result_field_to_the_caller() -> None:
    """Every field of `OcrSeedResult` must cross the HTTP boundary -- on this
    module, deleting result fields from the route left the whole suite green
    (task brief). `missing_fields` and `accepted_count` are the only signal
    an operator gets that six fields are still owed and what the derived
    summary counted; nothing in `document` says either on its own.
    """
    org_id, system_id = await _system("route-ocr")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/ocr/seed", json=PERIOD
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["kind"] == "ocr"
    assert body["accepted_count"] == 0
    assert [name for name, _reason in body["missing_fields"]] == list(SIX_REQUIRED)
    assert body["document"]["reportPeriod"] == PERIOD
    assert body["document"]["acceptedVulnerabilities"].startswith("0 accepted")


async def test_a_non_admin_cannot_seed_an_ocr() -> None:
    org_id, system_id = await _system("route-ocr-role")
    async with _Session(org_id=org_id, role="control_owner").client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/ocr/seed", json=PERIOD
        )
    assert resp.status_code == 403, resp.text


async def test_an_inverted_period_is_refused_for_the_ocr_route() -> None:
    org_id, system_id = await _system("route-ocr-inverted")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/ocr/seed",
            json={"from": "2026-12-01", "to": "2026-09-01"},
        )
    assert resp.status_code == 422, resp.text


async def test_another_tenants_system_is_404_not_403_for_the_ocr_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same ordering guard as the VER family's routes: ownership is checked
    before the seeder ever runs, proven with a spy rather than inferred from
    the status code alone -- see `test_cr26_ver_seed`'s identical test for why
    the status code cannot prove this on its own.
    """
    owner_org, system_id = await _system("route-ocr-other")
    other_org, _sid = await _system("route-ocr-intruder")
    async with _Session(org_id=owner_org).client() as c:
        first = await c.post(
            f"/api/systems/{system_id}/cr26-documents/ocr/seed", json=PERIOD
        )
    assert first.status_code == 200, first.text

    calls: list[None] = []
    real_seeder = cr26_routes.seed_ocr

    async def _spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(None)
        return await real_seeder(*args, **kwargs)

    monkeypatch.setattr(cr26_routes, "seed_ocr", _spy)

    async with _Session(org_id=other_org).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/ocr/seed", json=PERIOD
        )
    assert resp.status_code == 404, resp.text
    assert calls == []
