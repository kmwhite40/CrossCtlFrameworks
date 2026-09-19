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
from ccf.cr26.incident import seed_incident
from ccf.cr26.store import put_document
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_cr26 import Cr26Document

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
        assert "never invents" in reasons["resolvedAt"] or "never" in reasons["resolvedAt"]
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
        # the walk must NOT reach back past it to Initial (which also has
        # nothing here, but that is not the point being proven).
        assert result.carried_from is None
        assert result.carried_fields == []
    finally:
        await _delete_org(_org_id)
