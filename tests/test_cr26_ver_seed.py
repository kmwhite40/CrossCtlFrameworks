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

#: The reporting window posted to the VDR/AVI routes. No assertion in the
#: route tests below depends on its value -- only on `counts`,
#: `omitted_poam_ids` and array lengths -- so, unlike `identified_on`, this
#: does not need to track `date.today()`: the window is just a value the
#: document records, never an input to `accepted_weakness_state` or
#: `classify`.
PERIOD = {"from": "2026-09-01T00:00:00Z", "to": "2026-12-01T00:00:00Z"}


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
    assert body["counts"] == {"excluded_not_a_flaw": 0, "rendered": 1, "omitted": 0}
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
