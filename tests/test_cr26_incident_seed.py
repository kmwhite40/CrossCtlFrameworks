"""The Incident Report seeder end to end against the database, the real
validator, and the route.

See docs/superpowers/specs/2026-09-19-cr26-incident-design.md. This
deliverable takes the OCR's shape (spec §2): Concord holds no incident data,
so the seeder's only real service is continuity across an incident's own
Initial/Ongoing/Final lifecycle (spec §2.1), keyed by ``document_key =
"{providerTrackingId}/{reportType}"`` so filing a later report never
overwrites an earlier one (spec §1.1) -- the exact loss migration ``0081``
was added to prevent.

Every test below traces back to one of spec §5's seven testing requirements
or one of the task brief's "decisions that matter most", and is written so a
mutation removing its guard turns it red (noted per test).

Every keyed ``cr26_documents`` row this file writes is cleaned up in a
``try``/``finally``, matching ``tests/test_cr26_document_key.py``'s
discipline: a leaked keyed row makes migration ``0081``'s downgrade guard
hard-fail every later pytest session's startup.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.api.routes import cr26 as cr26_routes
from ccf.auth import Principal
from ccf.cr26 import incident as incident_module
from ccf.cr26.incident import seed_incident
from ccf.cr26.store import put_document
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_cr26 import DOCUMENT_KEY_MAX_LENGTH, Cr26Document

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


async def _delete_org(org_id: int) -> None:
    """Cascades to the system and every ``cr26_documents`` row it owns,
    keyed or not. See ``tests/test_cr26_document_key.py``'s identical helper
    for why this must run even when a test fails.
    """
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id == org_id))


async def _author(system_id: int, document_key: str, document: dict[str, Any]) -> None:
    """Directly store content at an exact keyed ``incident`` row, bypassing
    the seeder -- simulating "already authored on this report", exactly as
    ``tests/test_cr26_ocr_seed.py``'s ``_with_cpo_uri`` bypasses ``seed_ocr``
    to set up prior state. There is no keyed PUT route yet (spec is scoped to
    the seed route only), so this is also the only mechanism available to a
    test -- or, today, to any caller -- for putting content at a specific
    incident key.
    """
    async with session_scope() as s:
        await put_document(
            s, system_id=system_id, kind="incident", document_key=document_key, document=document
        )


async def _rows(system_id: int) -> dict[str, Cr26Document]:
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(Cr26Document).where(
                    Cr26Document.system_id == system_id, Cr26Document.kind == "incident"
                )
            )
        ).scalars().all()
        return {row.document_key: row for row in rows if row.document_key is not None}


# --- requirement 1: the chain -----------------------------------------------


async def test_initial_ongoing_final_survive_as_three_distinct_rows_with_initial_unchanged() -> (
    None
):
    """Spec §5 requirement 1 -- the one the task brief singles out. Filing an
    Ongoing, then a Final, must never touch the Initial's own row.

    MUTATION: computing ``document_key`` as ``tracking_id`` alone (dropping
    ``/{report_type}``) collapses all three onto one row; the second and
    third assertions on ``rows["INC-CHAIN/Initial"].document`` would then see
    the Final's body, not the Initial's.
    """
    _org_id, system_id = await _system("incident-chain")
    tid = "INC-CHAIN"
    try:
        await _author(system_id, f"{tid}/Initial", {"incidentDescription": "It started."})
        async with session_scope() as s:
            await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Initial"
            )
        async with session_scope() as s:
            await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        async with session_scope() as s:
            await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Final"
            )

        rows = await _rows(system_id)
        assert set(rows) == {f"{tid}/Initial", f"{tid}/Ongoing", f"{tid}/Final"}
        assert rows[f"{tid}/Initial"].document["incidentDescription"] == "It started."
        assert rows[f"{tid}/Initial"].document["reportType"] == "Initial"
        assert rows[f"{tid}/Ongoing"].document["reportType"] == "Ongoing"
        assert rows[f"{tid}/Final"].document["reportType"] == "Final"
        # Continuity actually carried the description all the way through.
        assert rows[f"{tid}/Ongoing"].document["incidentDescription"] == "It started."
        assert rows[f"{tid}/Final"].document["incidentDescription"] == "It started."
    finally:
        await _delete_org(_org_id)


# --- requirement 2: a Final with no resolvedAt, exact errors, real content -


async def test_a_final_report_with_no_resolved_at_is_invalid_for_exactly_that_reason() -> None:
    """Spec §5 requirement 2, exact equality, against a document with REAL
    content -- not an empty scaffold, so this proves the ONE thing missing
    is ``resolvedAt``, not that everything else happens to be absent too.

    MUTATION: `seed_incident` inventing a `resolvedAt` for a Final report
    (violating spec §3.2) would make `validation_errors` empty instead.
    """
    _org_id, system_id = await _system("incident-final-no-resolved")
    tid = "INC-FINAL-CONTENT"
    key = f"{tid}/Final"
    try:
        await _author(
            system_id,
            key,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "federalIncidentCoordinator": "coordinator@example.gov",
                "incidentDescription": "A detailed account of what happened.",
                "timeline": {
                    "startedAt": "2026-09-01T00:00:00Z",
                    "detectedAt": "2026-09-02T00:00:00Z",
                    "detectionSource": "SIEM alert",
                },
                "potentialImpact": {"currentRating": 2},
                "functionalImpact": "Brief degraded availability.",
                "recoveryPlan": "Failover completed within the hour.",
                "affectedAgencies": ["GSA"],
                "observedActivity": "Anomalous outbound traffic.",
                "indicatorsOfCompromise": ["203.0.113.7"],
                "relatedCveIds": ["CVE-2026-12345"],
                "rootCause": "Misconfigured egress rule.",
                "responseAndRecoveryActivities": "Rule corrected; traffic blocked.",
            },
        )
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Final"
            )
        assert result.document.validation_errors == [
            "<root>: 'resolvedAt' is a required property"
        ], result.document.validation_errors
        assert result.document.is_valid is False
        reasons = dict(result.missing_required)
        assert "resolvedAt" in reasons
        assert "required for a Final report" in reasons["resolvedAt"]
    finally:
        await _delete_org(_org_id)


# --- requirement 3: reportType and resolvedAt are never carried forward ----


async def test_report_type_and_resolved_at_are_never_carried_forward() -> None:
    """Spec §5 requirement 3. Seed a Final with `resolvedAt`, then seed a NEW
    Ongoing for the same tracking id -- it must carry neither the Final's
    `reportType` nor its `resolvedAt`.

    MUTATION: this scenario's own guard is lifecycle order -- a Final is
    never a candidate "prior report" for an Ongoing regardless of
    `_CARRY_FIELDS` (spec §2.1's ordering, not the field-exclusion list, is
    what makes this particular pairing safe). See
    `test_resolved_at_authored_on_a_true_prior_report_is_still_never_carried`
    directly below for the mutation that exercises the field-exclusion list
    itself, using a prior report lifecycle order actually allows to be read.
    """
    _org_id, system_id = await _system("incident-no-leak")
    tid = "INC-NO-LEAK"
    try:
        await _author(
            system_id,
            f"{tid}/Final",
            {
                "certificationPackageOverviewUri": CPO_URI,
                "resolvedAt": "2026-09-10T12:00:00Z",
                "incidentDescription": "Resolved incident.",
            },
        )
        async with session_scope() as s:
            await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Final"
            )
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert result.document.document["reportType"] == "Ongoing"
        assert "resolvedAt" not in result.document.document
        # And the description -- an ordinary carry field -- IS still absent,
        # because lifecycle order never treats a Final as "prior" to an
        # Ongoing regardless of write order (spec §2.1's ordering, not just
        # the field-exclusion list, is what this test also proves).
        assert result.carried_from is None
        assert result.carried_fields == []
    finally:
        await _delete_org(_org_id)


async def test_resolved_at_authored_on_a_true_prior_report_is_still_never_carried() -> None:
    """The field-exclusion half of spec §5 requirement 3, isolated from
    lifecycle order: the Initial genuinely IS a prior report for the
    Ongoing, so it is read for continuity -- but `resolvedAt` must still not
    cross, because copying it would assert this incident is over when
    nothing on the Ongoing itself says so.

    MUTATION: adding `"resolvedAt"` to `incident._CARRY_FIELDS` makes this
    test fail (`test_report_type_and_resolved_at_are_never_carried_forward`
    above does NOT catch that mutation, because a Final is never even a
    lifecycle candidate for an Ongoing's prior report).
    """
    _org_id, system_id = await _system("incident-resolved-at-true-prior")
    tid = "INC-RESOLVED-TRUE-PRIOR"
    try:
        await _author(
            system_id,
            f"{tid}/Initial",
            {"resolvedAt": "2026-09-01T00:00:00Z", "rootCause": "Known cause."},
        )
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert "resolvedAt" not in result.document.document
        assert "resolvedAt" not in result.carried_fields
        # The prior report WAS actually read for continuity -- rootCause,
        # an ordinary carry field, did cross -- so this is not merely
        # re-proving that no prior report was consulted at all.
        assert result.document.document["rootCause"] == "Known cause."
        assert result.carried_from == f"{tid}/Initial"
    finally:
        await _delete_org(_org_id)


# --- requirement 4: authored beats carried ----------------------------------


async def test_authored_field_on_this_report_beats_carried_value_from_prior() -> None:
    """Spec §5 requirement 4. The Ongoing already has its OWN authored
    `incidentDescription`; continuity must not overwrite it with the
    Initial's.

    MUTATION: swapping the `if field_name in current` / `elif field_name in
    prior` branches in `seed_incident`'s carry loop would let the prior
    value win instead.
    """
    _org_id, system_id = await _system("incident-authored-wins")
    tid = "INC-AUTHORED-WINS"
    try:
        await _author(
            system_id, f"{tid}/Initial", {"incidentDescription": "Initial description."}
        )
        await _author(
            system_id,
            f"{tid}/Ongoing",
            {"incidentDescription": "Ongoing's own, different description."},
        )
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert (
            result.document.document["incidentDescription"]
            == "Ongoing's own, different description."
        )
        assert "incidentDescription" not in result.carried_fields
    finally:
        await _delete_org(_org_id)


# --- review round 3, I2: a blank authored field carries no information -----
# --- (found on ccf.cr26.scn, fixed here too -- the identical shape) -------


async def test_a_blank_authored_field_on_this_report_is_treated_as_absent_and_named() -> None:
    """Review round 3, I2. The carry loop used a bare ``field_name in
    current`` test, so a field present but blank -- ``""`` on
    ``rootCause`` here -- was carried into the document as though it were
    genuine content, and named nowhere. ``has_content``, not a bare ``in``
    test, must guard both branches of the carry loop.

    MUTATION: reverting the ``current`` branch of the carry loop in
    ``seed_incident`` to a bare ``field_name in current`` check turns this
    red -- the blank ``rootCause`` would be carried and
    ``missing_advisory`` would not name it.
    """
    _org_id, system_id = await _system("incident-blank-current-field")
    tid = "INC-BLANK-CURRENT"
    try:
        await _author(system_id, f"{tid}/Initial", {"rootCause": "   "})
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Initial"
            )
        assert "rootCause" not in result.document.document
        assert "rootCause" in result.missing_advisory
    finally:
        await _delete_org(_org_id)


async def test_a_blank_field_in_a_prior_report_is_not_carried_forward() -> None:
    """Review round 3, I2, the ``prior`` half of the same fix: a blank
    field in the closest prior report must not be carried into a later
    report either, and must not count as "continuity supplied something"
    for ``carried_from``/``carried_fields``.

    MUTATION: reverting the ``prior`` branch of the carry loop to a bare
    ``field_name in prior`` check turns this red -- the blank ``rootCause``
    would be carried from the Initial into the Ongoing and reported as
    carried.
    """
    _org_id, system_id = await _system("incident-blank-prior-field")
    tid = "INC-BLANK-PRIOR"
    try:
        await _author(system_id, f"{tid}/Initial", {"rootCause": "   "})
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert "rootCause" not in result.document.document
        assert "rootCause" in result.missing_advisory
        assert "rootCause" not in result.carried_fields
        # Nothing carry-worthy was actually found in the prior report, so
        # `carried_from` must stay `None` -- matching
        # `test_carried_from_stays_none_when_a_prior_report_exists_but_has_
        # nothing_to_offer`'s existing pin of this same rule.
        assert result.carried_from is None
    finally:
        await _delete_org(_org_id)


# --- requirement 5: a blank or `/`-containing tracking id is refused -------


async def test_a_blank_tracking_id_is_refused_at_the_seeder() -> None:
    """MUTATION: removing the blank check from `_validate_tracking_id` would
    let this construct a document keyed `"/Initial"` instead of raising.
    """
    _org_id, system_id = await _system("incident-blank-tid")
    try:
        async with session_scope() as s:
            with pytest.raises(ValueError, match="must not be blank"):
                await seed_incident(
                    s, system_id=system_id, provider_tracking_id="   ", report_type="Initial"
                )
    finally:
        await _delete_org(_org_id)


async def test_a_slash_containing_tracking_id_is_refused_at_the_seeder() -> None:
    """MUTATION: removing the `/` check would let two different incidents'
    keys collide, e.g. `"A/Initial"` vs an incident literally tracked as
    `"A/Initial"`.
    """
    _org_id, system_id = await _system("incident-slash-tid")
    try:
        async with session_scope() as s:
            with pytest.raises(ValueError, match="must not contain"):
                await seed_incident(
                    s,
                    system_id=system_id,
                    provider_tracking_id="INC/1",
                    report_type="Initial",
                )
    finally:
        await _delete_org(_org_id)


# --- requirement 6: two incidents on one system do not collide -------------


async def test_two_incidents_on_one_system_do_not_collide() -> None:
    """Spec §5 requirement 6."""
    _org_id, system_id = await _system("incident-two-incidents")
    try:
        await _author(system_id, "INC-A/Initial", {"incidentDescription": "Incident A."})
        await _author(system_id, "INC-B/Initial", {"incidentDescription": "Incident B."})
        async with session_scope() as s:
            result_a = await seed_incident(
                s, system_id=system_id, provider_tracking_id="INC-A", report_type="Initial"
            )
        async with session_scope() as s:
            result_b = await seed_incident(
                s, system_id=system_id, provider_tracking_id="INC-B", report_type="Initial"
            )
        assert result_a.document_key == "INC-A/Initial"
        assert result_b.document_key == "INC-B/Initial"
        assert result_a.document.document["incidentDescription"] == "Incident A."
        assert result_b.document.document["incidentDescription"] == "Incident B."
        assert result_a.carried_from is None
        assert result_b.carried_from is None

        rows = await _rows(system_id)
        assert set(rows) == {"INC-A/Initial", "INC-B/Initial"}
    finally:
        await _delete_org(_org_id)


# --- requirement 7: every result field crosses the HTTP boundary -----------


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


async def test_the_incident_route_reports_every_result_field_to_the_caller() -> None:
    """Every field of `IncidentSeedResult` must cross the HTTP boundary (task
    brief: deleting a result field from the route left the whole suite
    green).
    """
    org_id, system_id = await _system("incident-route-fields")
    tid = "INC-ROUTE-FIELDS"
    try:
        await _author(system_id, f"{tid}/Initial", {"incidentDescription": "Seeded first."})
        async with session_scope() as s:
            await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Initial"
            )

        async with _Session(org_id=org_id).client() as c:
            resp = await c.post(
                f"/api/systems/{system_id}/cr26-documents/incident/seed",
                json={"providerTrackingId": tid, "reportType": "Ongoing"},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["kind"] == "incident"
        assert body["document_key"] == f"{tid}/Ongoing"
        assert body["carried_from"] == f"{tid}/Initial"
        assert body["carried_fields"] == ["incidentDescription"]
        required_names = {name for name, _reason in body["missing_required"]}
        assert "certificationPackageOverviewUri" in required_names
        assert "rootCause" in body["missing_advisory"]
        assert body["document"]["incidentDescription"] == "Seeded first."
    finally:
        await _delete_org(org_id)


async def test_a_non_admin_cannot_seed_an_incident() -> None:
    org_id, system_id = await _system("incident-route-role")
    try:
        async with _Session(org_id=org_id, role="control_owner").client() as c:
            resp = await c.post(
                f"/api/systems/{system_id}/cr26-documents/incident/seed",
                json={"providerTrackingId": "INC-ROLE", "reportType": "Initial"},
            )
        assert resp.status_code == 403, resp.text
    finally:
        await _delete_org(org_id)


async def test_a_blank_tracking_id_is_422_at_the_route() -> None:
    """Spec §5 requirement 5, the route half."""
    org_id, system_id = await _system("incident-route-blank")
    try:
        async with _Session(org_id=org_id).client() as c:
            resp = await c.post(
                f"/api/systems/{system_id}/cr26-documents/incident/seed",
                json={"providerTrackingId": "   ", "reportType": "Initial"},
            )
        assert resp.status_code == 422, resp.text
    finally:
        await _delete_org(org_id)


async def test_a_slash_containing_tracking_id_is_422_at_the_route() -> None:
    org_id, system_id = await _system("incident-route-slash")
    try:
        async with _Session(org_id=org_id).client() as c:
            resp = await c.post(
                f"/api/systems/{system_id}/cr26-documents/incident/seed",
                json={"providerTrackingId": "INC/1", "reportType": "Initial"},
            )
        assert resp.status_code == 422, resp.text
    finally:
        await _delete_org(org_id)


async def test_an_invalid_report_type_is_422_at_the_route() -> None:
    """The route's own `Literal` guard on `reportType`, ahead of the
    vendored schema's `enum` -- a narrower, earlier check than
    `seed_incident` itself performs (see its docstring).
    """
    org_id, system_id = await _system("incident-route-bad-type")
    try:
        async with _Session(org_id=org_id).client() as c:
            resp = await c.post(
                f"/api/systems/{system_id}/cr26-documents/incident/seed",
                json={"providerTrackingId": "INC-BAD-TYPE", "reportType": "Draft"},
            )
        assert resp.status_code == 422, resp.text
    finally:
        await _delete_org(org_id)


async def test_another_tenants_system_is_404_not_403_for_the_incident_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ownership is checked before the seeder ever runs, proven with a spy --
    matching `test_cr26_ocr_seed.py`'s identical test for why the status
    code alone cannot prove this.
    """
    owner_org, system_id = await _system("incident-route-owner")
    other_org, _sid = await _system("incident-route-intruder")
    try:
        async with _Session(org_id=owner_org).client() as c:
            first = await c.post(
                f"/api/systems/{system_id}/cr26-documents/incident/seed",
                json={"providerTrackingId": "INC-TENANT", "reportType": "Initial"},
            )
        assert first.status_code == 200, first.text

        calls: list[None] = []
        real_seeder = cr26_routes.seed_incident

        async def _spy(*args: Any, **kwargs: Any) -> Any:
            calls.append(None)
            return await real_seeder(*args, **kwargs)

        monkeypatch.setattr(cr26_routes, "seed_incident", _spy)

        async with _Session(org_id=other_org).client() as c:
            resp = await c.post(
                f"/api/systems/{system_id}/cr26-documents/incident/seed",
                json={"providerTrackingId": "INC-TENANT", "reportType": "Ongoing"},
            )
        assert resp.status_code == 404, resp.text
        assert calls == []
    finally:
        await _delete_org(owner_org)
        await _delete_org(other_org)


# --- certificationPackageOverviewUri: never invented, carried, authored wins


async def test_cpo_uri_is_never_invented_when_nothing_authored() -> None:
    _org_id, system_id = await _system("incident-uri-never-invented")
    try:
        async with session_scope() as s:
            result = await seed_incident(
                s,
                system_id=system_id,
                provider_tracking_id="INC-NO-URI",
                report_type="Initial",
            )
        assert "certificationPackageOverviewUri" not in result.document.document
        reasons = dict(result.missing_required)
        assert "certificationPackageOverviewUri" in reasons
    finally:
        await _delete_org(_org_id)


async def test_cpo_uri_carried_forward_from_prior_report_when_not_authored_on_this_one() -> None:
    _org_id, system_id = await _system("incident-uri-carried")
    tid = "INC-URI-CARRY"
    try:
        await _author(system_id, f"{tid}/Initial", {"certificationPackageOverviewUri": CPO_URI})
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert result.document.document["certificationPackageOverviewUri"] == CPO_URI
        assert "certificationPackageOverviewUri" in result.carried_fields
    finally:
        await _delete_org(_org_id)


async def test_cpo_uri_authored_on_this_report_wins_over_prior() -> None:
    _org_id, system_id = await _system("incident-uri-authored-wins")
    tid = "INC-URI-WINS"
    other_uri = "https://example.gov/other-cpo.json"
    try:
        await _author(system_id, f"{tid}/Initial", {"certificationPackageOverviewUri": CPO_URI})
        await _author(
            system_id, f"{tid}/Ongoing", {"certificationPackageOverviewUri": other_uri}
        )
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert result.document.document["certificationPackageOverviewUri"] == other_uri
        assert "certificationPackageOverviewUri" not in result.carried_fields
    finally:
        await _delete_org(_org_id)


async def test_a_blank_stored_cpo_uri_is_not_carried_forward() -> None:
    """`is_blank`, not `is not None` -- matching every other CR26 seeder's
    identical URI-carry logic.
    """
    _org_id, system_id = await _system("incident-uri-blank")
    tid = "INC-URI-BLANK"
    try:
        await _author(system_id, f"{tid}/Initial", {"certificationPackageOverviewUri": "   "})
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert "certificationPackageOverviewUri" not in result.document.document
    finally:
        await _delete_org(_org_id)


# --- resolvedAt: never invented, never carried, named when unparseable -----


async def test_seeder_never_writes_resolved_at_itself() -> None:
    """Spec §3.2: a freshly seeded Final with nothing authored has NO
    `resolvedAt` key at all -- not `null`, absent -- and it is named in
    `missing_required`, not silently left to the schema alone.
    """
    _org_id, system_id = await _system("incident-final-no-invent")
    tid = "INC-FINAL-NO-INVENT"
    try:
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Final"
            )
        assert "resolvedAt" not in result.document.document
        reasons = dict(result.missing_required)
        assert "resolvedAt" in reasons
        # M5 (review round 1): a bare `"never" in reasons[...]` disjunct
        # would match almost any prose about resolvedAt, including the
        # unparseable-value reason below -- this pins the specific phrase.
        assert "never invents or carries one forward" in reasons["resolvedAt"]
    finally:
        await _delete_org(_org_id)


async def test_an_unparseable_resolved_at_is_named_not_rewritten() -> None:
    """Spec §3.4.1, measured: `{"reportType":"Final","resolvedAt":"whenever"}`
    validates `ok=True` because the schema's own conditional only checks
    presence. The seeder must report this in `missing_required` and must NOT
    alter the operator's own value.

    MUTATION: `_resolved_at_problem` returning `None` whenever `resolvedAt`
    is merely present (dropping the `_parses_as_iso8601_instant` check)
    would silently accept `"whenever"`.
    """
    _org_id, system_id = await _system("incident-final-unparseable")
    tid = "INC-FINAL-UNPARSEABLE"
    key = f"{tid}/Final"
    try:
        await _author(
            system_id,
            key,
            {"certificationPackageOverviewUri": CPO_URI, "resolvedAt": "whenever"},
        )
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Final"
            )
        # Not rewritten or dropped.
        assert result.document.document["resolvedAt"] == "whenever"
        # The schema itself is satisfied -- measured in the spec.
        assert result.document.is_valid is True
        assert result.document.validation_errors == []
        # But Concord's own obligation names it anyway.
        reasons = dict(result.missing_required)
        assert "resolvedAt" in reasons
        assert "does not parse" in reasons["resolvedAt"]
    finally:
        await _delete_org(_org_id)


async def test_a_well_formed_resolved_at_on_a_final_report_satisfies_the_obligation() -> None:
    """The other half: a real ISO-8601 instant does NOT appear in
    `missing_required` at all.
    """
    _org_id, system_id = await _system("incident-final-good-resolved")
    tid = "INC-FINAL-GOOD"
    key = f"{tid}/Final"
    try:
        await _author(
            system_id,
            key,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "resolvedAt": "2026-09-15T08:00:00Z",
            },
        )
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Final"
            )
        assert result.document.is_valid is True
        assert result.document.validation_errors == []
        reasons = dict(result.missing_required)
        assert "resolvedAt" not in reasons
    finally:
        await _delete_org(_org_id)


# --- timeline / potentialImpact: whole-object carry, never merged ----------


async def test_timeline_carries_whole_when_unauthored_on_this_report() -> None:
    _org_id, system_id = await _system("incident-timeline-whole")
    tid = "INC-TIMELINE-WHOLE"
    prior_timeline = {
        "startedAt": "2026-09-01T00:00:00Z",
        "detectionSource": "SIEM alert",
    }
    try:
        await _author(system_id, f"{tid}/Initial", {"timeline": prior_timeline})
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert result.document.document["timeline"] == prior_timeline
        assert "timeline" in result.carried_fields
    finally:
        await _delete_org(_org_id)


async def test_timeline_authored_on_this_report_is_not_merged_with_priors() -> None:
    """A half-filled `timeline` authored on THIS report must win wholesale,
    never topped up with keys from the prior report's timeline.

    MUTATION: replacing the whole-value carry with
    `{**prior.get("timeline", {}), **current.get("timeline", {})}` (a
    field-by-field merge) would make this test's `==` assertion fail --
    the merged object would also carry `detectionSource` from the prior
    report.
    """
    _org_id, system_id = await _system("incident-timeline-no-merge")
    tid = "INC-TIMELINE-NO-MERGE"
    prior_timeline = {
        "startedAt": "2026-09-01T00:00:00Z",
        "detectionSource": "SIEM alert",
    }
    this_report_timeline = {"detectedAt": "2026-09-05T00:00:00Z"}
    try:
        await _author(system_id, f"{tid}/Initial", {"timeline": prior_timeline})
        await _author(system_id, f"{tid}/Ongoing", {"timeline": this_report_timeline})
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert result.document.document["timeline"] == this_report_timeline
        assert "timeline" not in result.carried_fields
    finally:
        await _delete_org(_org_id)


# --- missing_required and missing_advisory stay separate --------------------


async def test_missing_required_and_missing_advisory_stay_separate() -> None:
    """Spec §4: a missing `rootCause` is advisory only and must not appear
    in `missing_required`; a missing `certificationPackageOverviewUri` (and,
    on a Final, a missing `resolvedAt`) blocks validity and must not appear
    in `missing_advisory`.

    MUTATION: collapsing the two lists (e.g. appending every missing field,
    required or not, to one list) would make one of these assertions fail.
    """
    _org_id, system_id = await _system("incident-missing-separate")
    tid = "INC-MISSING-SEPARATE"
    try:
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Final"
            )
        required_names = {name for name, _reason in result.missing_required}
        assert "certificationPackageOverviewUri" in required_names
        assert "resolvedAt" in required_names
        assert "rootCause" not in required_names

        assert "rootCause" in result.missing_advisory
        assert "certificationPackageOverviewUri" not in result.missing_advisory
        assert "resolvedAt" not in result.missing_advisory
    finally:
        await _delete_org(_org_id)


# --- carried_from: present only when continuity actually supplied something


async def test_carried_from_is_none_when_nothing_is_carried() -> None:
    _org_id, system_id = await _system("incident-carried-from-none")
    try:
        async with session_scope() as s:
            result = await seed_incident(
                s,
                system_id=system_id,
                provider_tracking_id="INC-FROM-NONE",
                report_type="Initial",
            )
        assert result.carried_from is None
        assert result.carried_fields == []
    finally:
        await _delete_org(_org_id)


async def test_carried_from_names_the_prior_report_key_when_something_is_carried() -> None:
    _org_id, system_id = await _system("incident-carried-from-set")
    tid = "INC-FROM-SET"
    try:
        await _author(system_id, f"{tid}/Initial", {"rootCause": "Misconfiguration."})
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert result.carried_from == f"{tid}/Initial"
        assert "rootCause" in result.carried_fields
    finally:
        await _delete_org(_org_id)


async def test_carried_from_stays_none_when_a_prior_report_exists_but_has_nothing_to_offer() -> (
    None
):
    """A prior report can exist (was filed) while contributing nothing this
    report needs -- `carried_from` must reflect what was actually used, not
    merely that a row exists.

    This is also I2's fixture (review round 1): the Initial genuinely DID
    author `rootCause`, but the walk stops at Ongoing (the closest filed
    report), which is empty, and never reaches back past it -- so `rootCause`
    lands in `missing_advisory` despite having been authored somewhere in
    this incident's history. `IncidentSeedResult`'s own docstring on
    `missing_advisory` says exactly this now; it used to claim the opposite.
    """
    _org_id, system_id = await _system("incident-carried-from-empty-prior")
    tid = "INC-FROM-EMPTY-PRIOR"
    try:
        await _author(system_id, f"{tid}/Initial", {"rootCause": "Already known."})
        await _author(system_id, f"{tid}/Ongoing", {})
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Final"
            )
        # Ongoing (the closest filed prior report) had nothing to offer, and
        # the walk must NOT reach back past it to the Initial -- even though
        # the Initial itself DOES have rootCause authored.
        assert result.carried_from is None
        assert result.carried_fields == []
        # I2: rootCause was authored on the Initial, yet it is still
        # "advisory, absent" here -- proving missing_advisory means "not
        # reachable by the walk", not "never authored anywhere".
        assert "rootCause" in result.missing_advisory
    finally:
        await _delete_org(_org_id)


# --- C1 (review round 1): PUT and GET are key-aware ------------------------


async def test_a_keyed_document_written_directly_is_invisible_to_the_null_keyed_get() -> None:
    """Before C1's fix: `PUT .../incident` (no key) always wrote the single
    NULL-keyed `incident` row, and `GET .../incident` (no key) only ever
    read that NULL-keyed row -- so a seeded report at a REAL key was 404
    forever, and a second unkeyed PUT silently overwrote the first (the
    exact loss migration 0081 exists to prevent, reachable through the
    generic route this branch had not yet narrowed).

    This test pins the CURRENT, fixed behaviour: writing at an explicit key
    does not appear under the NULL key, and reading with the SAME key that
    `seed_incident` returned finds it.
    """
    org_id, system_id = await _system("incident-put-get-key-aware")
    tid = "INC-PUT-GET"
    try:
        async with session_scope() as s:
            seeded = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Initial"
            )
        key = seeded.document_key

        async with _Session(org_id=org_id).client() as c:
            # Author content AT that exact key.
            put_resp = await c.put(
                f"/api/systems/{system_id}/cr26-documents/incident",
                params={"document_key": key},
                json={"document": {"reportType": "Initial", "providerTrackingId": tid,
                                    "incidentDescription": "Authored via the keyed PUT."}},
            )
            assert put_resp.status_code == 200, put_resp.text

            # Reading it back with the SAME key finds it.
            get_keyed = await c.get(
                f"/api/systems/{system_id}/cr26-documents/incident",
                params={"document_key": key},
            )
            assert get_keyed.status_code == 200, get_keyed.text
            assert (
                get_keyed.json()["document"]["incidentDescription"]
                == "Authored via the keyed PUT."
            )

            # The NULL-keyed GET (no document_key at all) does NOT see it --
            # it is a different row entirely.
            get_null = await c.get(f"/api/systems/{system_id}/cr26-documents/incident")
            assert get_null.status_code == 404, get_null.text
    finally:
        await _delete_org(org_id)


async def test_a_second_keyed_put_at_a_different_key_does_not_overwrite_the_first() -> None:
    """The core of C1: two DIFFERENT keyed PUTs to the same `kind` must
    produce two rows, not one overwriting the other -- the incident
    equivalent of `tests/test_cr26_document_key.py`'s own coexistence test,
    now proven through the route rather than only through `put_document`
    directly.
    """
    org_id, system_id = await _system("incident-put-two-keys")
    tid = "INC-TWO-KEYS"
    try:
        async with _Session(org_id=org_id).client() as c:
            first = await c.put(
                f"/api/systems/{system_id}/cr26-documents/incident",
                params={"document_key": f"{tid}/Initial"},
                json={"document": {"incidentDescription": "Initial body."}},
            )
            second = await c.put(
                f"/api/systems/{system_id}/cr26-documents/incident",
                params={"document_key": f"{tid}/Ongoing"},
                json={"document": {"incidentDescription": "Ongoing body."}},
            )
            assert first.status_code == 200, first.text
            assert second.status_code == 200, second.text

            get_initial = await c.get(
                f"/api/systems/{system_id}/cr26-documents/incident",
                params={"document_key": f"{tid}/Initial"},
            )
            get_ongoing = await c.get(
                f"/api/systems/{system_id}/cr26-documents/incident",
                params={"document_key": f"{tid}/Ongoing"},
            )
        assert get_initial.json()["document"]["incidentDescription"] == "Initial body."
        assert get_ongoing.json()["document"]["incidentDescription"] == "Ongoing body."
    finally:
        await _delete_org(org_id)


async def test_the_null_keyed_put_and_get_are_unchanged_for_a_single_instance_deliverable() -> (
    None
):
    """C1's own regression guard: omitting `document_key` entirely must
    behave EXACTLY as before this parameter existed, for the six
    single-instance deliverables that always use the NULL key. Two PUTs with
    no key collapse onto one row (unchanged upsert identity), and GET with
    no key reads it back.

    MUTATION: `document_key: str | None = None` defaulting to anything other
    than `None`, or the query filtering `!=` instead of `==`, would make
    this test fail.
    """
    org_id, system_id = await _system("incident-null-key-unchanged")
    try:
        async with _Session(org_id=org_id).client() as c:
            first = await c.put(
                f"/api/systems/{system_id}/cr26-documents/sdr",
                json={"document": {"seed": 1}},
            )
            second = await c.put(
                f"/api/systems/{system_id}/cr26-documents/sdr",
                json={"document": {"seed": 2}},
            )
            assert first.status_code == 200, first.text
            assert second.status_code == 200, second.text

            get_resp = await c.get(f"/api/systems/{system_id}/cr26-documents/sdr")
        assert get_resp.status_code == 200, get_resp.text
        assert get_resp.json()["document"] == {"seed": 2}

        # Still exactly one row for this system+kind.
        async with session_scope() as s:
            rows = (
                await s.execute(
                    select(Cr26Document).where(
                        Cr26Document.system_id == system_id, Cr26Document.kind == "sdr"
                    )
                )
            ).scalars().all()
        assert len(rows) == 1
        assert rows[0].document_key is None
    finally:
        await _delete_org(org_id)


# --- I3 (review round 1): the list view distinguishes keyed rows -----------


async def test_the_list_view_distinguishes_two_incident_filings_by_document_key() -> None:
    """`routes/cr26.py`'s own prior-branch note said this deliverable's
    routes would revisit the list view; C1/I3 do. Before the fix, two
    incident filings both rendered as `{"kind": "incident", ...}` with no
    way to tell them apart in this response.
    """
    org_id, system_id = await _system("incident-list-distinguishes")
    tid = "INC-LIST"
    try:
        async with session_scope() as s:
            await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Initial"
            )
        async with session_scope() as s:
            await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )

        async with _Session(org_id=org_id).client() as c:
            resp = await c.get(f"/api/systems/{system_id}/cr26-documents")
        assert resp.status_code == 200, resp.text
        rows = [row for row in resp.json() if row["kind"] == "incident"]
        keys = {row["document_key"] for row in rows}
        assert keys == {f"{tid}/Initial", f"{tid}/Ongoing"}
    finally:
        await _delete_org(org_id)


# --- C2 (review round 1): re-seeding does not silently re-propagate --------


async def test_reseeding_the_same_key_reports_nothing_carried_even_though_content_is() -> None:
    """C2: a value carried on the FIRST seed becomes this report's own
    stored content -- a re-seed of the SAME key reports
    `carried_fields == []` even though most of the body originated from
    continuity, because nothing needed fetching a second time. Not a bug:
    `carried_fields` describes what THIS seed call did, not the document's
    full provenance -- see `IncidentSeedResult`'s corrected docstring.
    """
    _org_id, system_id = await _system("incident-reseed-same-key")
    tid = "INC-RESEED-SAME-KEY"
    try:
        await _author(system_id, f"{tid}/Initial", {"rootCause": "Original cause."})
        async with session_scope() as s:
            first = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert first.carried_fields == ["rootCause"]
        assert first.carried_from == f"{tid}/Initial"

        async with session_scope() as s:
            second = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        # Same body...
        assert second.document.document["rootCause"] == "Original cause."
        # ...but nothing was carried THIS time, because it was already there.
        assert second.carried_fields == []
        assert second.carried_from is None
    finally:
        await _delete_org(_org_id)


async def test_correcting_a_prior_report_does_not_retroactively_rewrite_an_already_seeded_one() -> (
    None
):
    """The other half of C2: this is deliberate, not a bug. Seed an Ongoing
    from an Initial's `rootCause`, THEN correct the Initial's `rootCause`
    directly, then re-seed the SAME Ongoing again -- its `rootCause` must
    still be the ORIGINAL value, not the correction, because `seed_incident`
    never re-derives an already-filed report's content from a prior report
    that has since changed.

    MUTATION: making `seed_incident` always re-read `prior` and overwrite an
    already-carried field on every re-seed (rather than only filling what
    `current` lacks) would make this test's first assertion fail.
    """
    _org_id, system_id = await _system("incident-no-retroactive-rewrite")
    tid = "INC-NO-RETRO"
    try:
        await _author(system_id, f"{tid}/Initial", {"rootCause": "Original cause."})
        async with session_scope() as s:
            await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        # Correct the Initial after the fact.
        await _author(system_id, f"{tid}/Initial", {"rootCause": "Corrected cause."})

        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Ongoing"
            )
        assert result.document.document["rootCause"] == "Original cause."
        assert result.carried_fields == []
        assert result.carried_from is None
    finally:
        await _delete_org(_org_id)


# --- I1 (review round 1): resolvedAt must be a full instant, not just an ---
# --- ISO-8601-shaped string -------------------------------------------------


_LOOSE_RESOLVED_AT_CASES = [
    ("bare-date", "2026-09-15"),
    ("compact", "20260915"),
    ("week-date", "2026-W01-1"),
    ("hour-only", "2026-09-15T08"),
    ("naive-no-offset", "2026-09-15T08:00:00"),
]


@pytest.mark.parametrize("label,resolved_at", _LOOSE_RESOLVED_AT_CASES)
async def test_a_resolved_at_missing_date_time_or_offset_is_named(
    label: str, resolved_at: str
) -> None:
    """I1: `datetime.fromisoformat` alone accepts all five of these, and
    every one `is_valid=True`s against the schema (date-time is unenforced),
    but NONE of them names a single instant -- and each is a far more
    plausible operator typo than the spec's own `"whenever"` example,
    because each one IS a syntactically real ISO-8601 form, just not an
    instant.

    MUTATION: reverting `_parses_as_iso8601_instant` to `fromisoformat`
    alone (dropping the `_INSTANT_RE` pre-check) makes every one of these
    parametrized cases pass silently instead of being named.
    """
    _org_id, system_id = await _system(f"incident-resolved-loose-{label}")
    tid = "INC-RESOLVED-LOOSE"
    key = f"{tid}/Final"
    try:
        await _author(
            system_id,
            key,
            {"certificationPackageOverviewUri": CPO_URI, "resolvedAt": resolved_at},
        )
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Final"
            )
        assert result.document.document["resolvedAt"] == resolved_at, "not rewritten"
        assert result.document.is_valid is True, "the schema itself is still satisfied"
        reasons = dict(result.missing_required)
        assert "resolvedAt" in reasons, f"{resolved_at!r} should have been named"
        assert "does not parse" in reasons["resolvedAt"]
    finally:
        await _delete_org(_org_id)


_FULL_RESOLVED_AT_CASES = [
    ("z-suffix", "2026-09-15T08:00:00Z"),
    ("numeric-offset", "2026-09-15T08:00:00+00:00"),
]


@pytest.mark.parametrize("label,resolved_at", _FULL_RESOLVED_AT_CASES)
async def test_a_full_resolved_at_instant_is_not_named(label: str, resolved_at: str) -> None:
    """The boundary's other side: a genuine date + time + offset must NOT be
    flagged, in either accepted spelling of "UTC".
    """
    _org_id, system_id = await _system(f"incident-resolved-full-{label}")
    tid = "INC-RESOLVED-FULL"
    key = f"{tid}/Final"
    try:
        await _author(
            system_id,
            key,
            {"certificationPackageOverviewUri": CPO_URI, "resolvedAt": resolved_at},
        )
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Final"
            )
        reasons = dict(result.missing_required)
        assert "resolvedAt" not in reasons, f"{resolved_at!r} should NOT have been named"
    finally:
        await _delete_org(_org_id)


# --- I4 (review round 1): resolvedAt is required for Final alone -----------


async def test_resolved_at_is_never_required_on_an_ongoing_report() -> None:
    """I4: `_resolved_at_problem` is only ever called when
    `report_type == "Final"` -- an Ongoing report with no `resolvedAt` must
    not be told it owes one; a still-open incident does not owe a resolution
    time.

    MUTATION: broadening the caller's guard to
    `if report_type in ("Final", "Ongoing")` leaves every other test in this
    file green (measured -- review round 1) and makes only this one fail.
    """
    _org_id, system_id = await _system("incident-resolved-not-required-ongoing")
    try:
        async with session_scope() as s:
            result = await seed_incident(
                s,
                system_id=system_id,
                provider_tracking_id="INC-ONGOING-NO-RESOLVED",
                report_type="Ongoing",
            )
        required_names = {name for name, _reason in result.missing_required}
        assert "resolvedAt" not in required_names
    finally:
        await _delete_org(_org_id)


# --- M1 (review round 1): the tracking id is stripped before it is keyed ---


async def test_a_tracking_id_with_surrounding_whitespace_joins_the_same_chain() -> None:
    """M1: `"  INC-1 "` and `"INC-1"` must resolve to the SAME document_key,
    or an incident's own reports would split into two chains under two
    different keys -- the whitespace-shaped version of the collision §1.1
    exists to prevent.

    MUTATION: `_validate_tracking_id` returning the unstripped value would
    make the second seed below produce `document_key ==
    "  INC-WHITESPACE  /Ongoing"` instead of joining the first seed's chain,
    and `carried_from` would be `None` instead of naming the Initial.
    """
    _org_id, system_id = await _system("incident-tracking-id-whitespace")
    try:
        async with session_scope() as s:
            first = await seed_incident(
                s,
                system_id=system_id,
                provider_tracking_id="  INC-WHITESPACE  ",
                report_type="Initial",
            )
        assert first.document_key == "INC-WHITESPACE/Initial"

        await _author(system_id, "INC-WHITESPACE/Initial", {"rootCause": "Known cause."})

        async with session_scope() as s:
            second = await seed_incident(
                s, system_id=system_id, provider_tracking_id="INC-WHITESPACE", report_type="Ongoing"
            )
        assert second.document_key == "INC-WHITESPACE/Ongoing"
        assert second.carried_from == "INC-WHITESPACE/Initial"
        assert second.document.document["rootCause"] == "Known cause."
    finally:
        await _delete_org(_org_id)


# --- M2 (review round 1): an overlong tracking id is refused, not a 500 ----


async def test_an_overlong_tracking_id_is_refused_at_the_seeder_not_a_500() -> None:
    """M2: `document_key` is `String(128)`. Before this guard, a
    sufficiently long `providerTrackingId` reached the database as a raw
    `StringDataRightTruncationError` -- an unhandled 500 -- instead of a
    refusal this module controls.
    """
    _org_id, system_id = await _system("incident-tracking-id-overlong")
    overlong = "X" * 125  # 125 + len("/Initial") == 133 > 128
    try:
        async with session_scope() as s:
            with pytest.raises(ValueError, match="too long"):
                await seed_incident(
                    s,
                    system_id=system_id,
                    provider_tracking_id=overlong,
                    report_type="Initial",
                )
    finally:
        await _delete_org(_org_id)


async def test_an_overlong_tracking_id_is_422_at_the_route() -> None:
    org_id, system_id = await _system("incident-tracking-id-overlong-route")
    overlong = "X" * 125
    try:
        async with _Session(org_id=org_id).client() as c:
            resp = await c.post(
                f"/api/systems/{system_id}/cr26-documents/incident/seed",
                json={"providerTrackingId": overlong, "reportType": "Initial"},
            )
        assert resp.status_code == 422, resp.text
    finally:
        await _delete_org(org_id)


async def test_a_tracking_id_at_exactly_the_length_boundary_is_accepted() -> None:
    """The other side of M2's boundary: a tracking id whose resulting
    document_key is exactly 128 characters must be accepted, not refused --
    this is a length LIMIT, not an arbitrary shorter cutoff.
    """
    _org_id, system_id = await _system("incident-tracking-id-at-boundary")
    # len(tid) + 1 ("/") + len("Initial"=7) == 128  =>  len(tid) == 120
    tid = "Y" * 120
    try:
        async with session_scope() as s:
            result = await seed_incident(
                s, system_id=system_id, provider_tracking_id=tid, report_type="Initial"
            )
        assert result.document_key == f"{tid}/Initial"
        assert len(result.document_key) == 128
    finally:
        await _delete_org(_org_id)


# --- M2 at the other door (review round 2): the generic keyed route also ---
# --- bounds document_key, without adopting the incident key's format rules -


async def test_an_overlong_document_key_is_422_on_the_generic_put() -> None:
    """Review round 2: the generic route stays format-agnostic (no
    blank/'/' rule -- a future SCN may key itself differently), but a length
    bound is not a format rule, it is the column's own physical limit.
    Measured before this fix: a 200-character `document_key` on `PUT`
    reached Postgres as `asyncpg.exceptions.StringDataRightTruncationError`
    -- an unhandled 500, not a refusal this route controlled.

    MUTATION: removing the `_checked_document_key` call from
    `put_cr26_document` reintroduces the 500 (verified below via mutation).
    """
    org_id, system_id = await _system("incident-generic-put-key-overlong")
    overlong_key = "K" * (DOCUMENT_KEY_MAX_LENGTH + 1)
    try:
        async with _Session(org_id=org_id).client() as c:
            resp = await c.put(
                f"/api/systems/{system_id}/cr26-documents/incident",
                params={"document_key": overlong_key},
                json={"document": {"incidentDescription": "should never be stored"}},
            )
        assert resp.status_code == 422, resp.text
    finally:
        await _delete_org(org_id)


async def test_an_overlong_document_key_is_422_not_a_500_or_a_silent_miss_on_the_generic_get() -> (
    None
):
    """The other door: `GET` with an overlong `document_key` must also be
    422, not a 500 (the query would otherwise reach Postgres with an
    over-width parameter) and not a silent 404 miss (which would look like
    an ordinary "nothing authored yet" rather than a caller error).
    """
    org_id, system_id = await _system("incident-generic-get-key-overlong")
    overlong_key = "K" * (DOCUMENT_KEY_MAX_LENGTH + 1)
    try:
        async with _Session(org_id=org_id).client() as c:
            resp = await c.get(
                f"/api/systems/{system_id}/cr26-documents/incident",
                params={"document_key": overlong_key},
            )
        assert resp.status_code == 422, resp.text
        assert resp.status_code != 404
    finally:
        await _delete_org(org_id)


async def test_a_document_key_at_exactly_the_column_width_is_accepted_on_the_generic_route() -> (
    None
):
    """The boundary's other side: exactly `DOCUMENT_KEY_MAX_LENGTH`
    characters must be accepted on both doors, not refused -- this is a
    length LIMIT, not an arbitrary shorter cutoff.
    """
    org_id, system_id = await _system("incident-generic-key-at-boundary")
    boundary_key = "K" * DOCUMENT_KEY_MAX_LENGTH
    try:
        async with _Session(org_id=org_id).client() as c:
            put_resp = await c.put(
                f"/api/systems/{system_id}/cr26-documents/incident",
                params={"document_key": boundary_key},
                json={"document": {"incidentDescription": "at the boundary"}},
            )
            assert put_resp.status_code == 200, put_resp.text

            get_resp = await c.get(
                f"/api/systems/{system_id}/cr26-documents/incident",
                params={"document_key": boundary_key},
            )
        assert get_resp.status_code == 200, get_resp.text
        assert get_resp.json()["document"]["incidentDescription"] == "at the boundary"
    finally:
        await _delete_org(org_id)


def test_the_incident_seeders_own_bound_and_the_generic_routes_bound_share_one_source() -> None:
    """Review round 2: confirms `ccf.cr26.incident` and `ccf.api.routes.cr26`
    both import `ccf.models_cr26.DOCUMENT_KEY_MAX_LENGTH` rather than each
    hardcoding `128` -- the exact drift this review round's fix removed.
    A change to the column's width is felt by both call sites automatically,
    or this test's own import would already have failed.
    """
    assert incident_module.DOCUMENT_KEY_MAX_LENGTH is DOCUMENT_KEY_MAX_LENGTH
    assert cr26_routes.DOCUMENT_KEY_MAX_LENGTH is DOCUMENT_KEY_MAX_LENGTH
