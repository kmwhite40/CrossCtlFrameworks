"""The Significant Change Notification seeder end to end against the
database, the real validator, and the route.

See docs/superpowers/specs/2026-09-19-cr26-scn-design.md. The SCN has no
identity field at all -- no tracking id, no change id, no date -- so unlike
the Incident Report, ``document_key`` is not derived from anything in the
document: it is the caller's own ``change_ref``, used verbatim (spec §1).
Every field is authored (spec §2), and ``impactedControls`` is the first
field in this programme the platform checks against its own catalog (spec
§2.1) without ever refusing on it.

Every test below traces back to one of spec §5's six testing requirements,
and is written so a mutation removing its guard turns it red (noted per
test).

Every keyed ``cr26_documents`` row this file writes is cleaned up in a
``try``/``finally``, matching ``tests/test_cr26_incident_seed.py``'s
discipline: a leaked keyed row makes migration ``0081``'s downgrade guard
hard-fail every later pytest session's startup. Any ``controls``/``ksis``
row a test adds to the catalog is cleaned up too, for the same reason
``tests/conftest.py``'s ``isolate_ksi_rows`` exists: ``tests/test_fedramp20x.py``
asserts an exact KSI count, and a leaked row would poison it.
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
from ccf.cr26 import scn as scn_module
from ccf.cr26.scn import seed_scn
from ccf.cr26.store import put_document
from ccf.db import session_scope
from ccf.models import KSI, Control, Organization, System
from ccf.models_cr26 import DOCUMENT_KEY_MAX_LENGTH, Cr26Document

pytestmark = pytest.mark.usefixtures("isolate_ksi_rows")

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
    keyed or not. See ``tests/test_cr26_incident_seed.py``'s identical
    helper for why this must run even when a test fails.
    """
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id == org_id))


async def _author(system_id: int, document_key: str, document: dict[str, Any]) -> None:
    """Directly store content at an exact keyed ``scn`` row, bypassing the
    seeder -- simulating "already authored on this SCN", exactly as
    ``tests/test_cr26_incident_seed.py``'s ``_author`` bypasses
    ``seed_incident``. There is no keyed PUT route yet (spec is scoped to
    the seed route only), so this is also the only mechanism available for
    putting content at a specific SCN key.
    """
    async with session_scope() as s:
        await put_document(
            s, system_id=system_id, kind="scn", document_key=document_key, document=document
        )


async def _rows(system_id: int) -> dict[str, Cr26Document]:
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(Cr26Document).where(
                    Cr26Document.system_id == system_id, Cr26Document.kind == "scn"
                )
            )
        ).scalars().all()
        return {row.document_key: row for row in rows if row.document_key is not None}


async def _ensure_control(identifier: str, **kw: Any) -> tuple[int, bool]:
    """Get-or-create a real ``controls`` row, mirroring
    ``tests/test_fedramp20x.py``'s ``_fresh_system``. Returns ``(id,
    created)`` so the caller only deletes what THIS test actually added --
    leaving a row another module already relies on alone.
    """
    async with session_scope() as s:
        row = (
            await s.execute(select(Control).where(Control.identifier == identifier))
        ).scalar_one_or_none()
        if row is not None:
            return row.id, False
        row = Control(identifier=identifier, **kw)
        s.add(row)
        await s.flush()
        return row.id, True


async def _delete_control(control_id: int) -> None:
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.id == control_id))


async def _add_ksi(identifier: str) -> None:
    async with session_scope() as s:
        s.add(KSI(identifier=identifier, category="IAM", name=f"{identifier} test indicator"))


# --- requirement 1: two SCNs on one system do not collide -------------------


async def test_two_scns_on_one_system_do_not_collide() -> None:
    """Spec §5 requirement 1.

    MUTATION: computing ``document_key`` as a constant (e.g. always
    ``"scn"``) rather than ``change_ref`` itself would collapse both onto
    one row; ``set(rows)`` below would then have one member, not two, and
    ``result_b``'s content would be ``result_a``'s.
    """
    _org_id, system_id = await _system("scn-two-changes")
    try:
        await _author(system_id, "CHG-A", {"changeDescription": "Change A description."})
        await _author(system_id, "CHG-B", {"changeDescription": "Change B description."})
        async with session_scope() as s:
            result_a = await seed_scn(
                s, system_id=system_id, change_ref="CHG-A", change_type="Adaptive"
            )
        async with session_scope() as s:
            result_b = await seed_scn(
                s, system_id=system_id, change_ref="CHG-B", change_type="Transformative"
            )
        assert result_a.document_key == "CHG-A"
        assert result_b.document_key == "CHG-B"
        assert result_a.document.document["changeDescription"] == "Change A description."
        assert result_b.document.document["changeDescription"] == "Change B description."
        assert result_a.document.document["changeType"] == "Adaptive"
        assert result_b.document.document["changeType"] == "Transformative"

        rows = await _rows(system_id)
        assert set(rows) == {"CHG-A", "CHG-B"}
    finally:
        await _delete_org(_org_id)


# --- requirement 2: a blank/absent changeDescription is invalid, exactly ---


async def test_a_blank_change_description_is_omitted_and_invalid_for_exactly_that_reason() -> (
    None
):
    """Spec §5 requirement 2, exact equality, against a document with REAL
    content -- not an empty scaffold, so this proves the ONE thing missing
    is ``changeDescription``, not that everything else happens to be absent
    too.

    MUTATION: writing ``current["changeDescription"]`` verbatim instead of
    checking ``is_blank`` first (spec §3.2) would carry the blank string
    through, and ``validation_errors`` would be empty instead -- a blank
    string satisfies the schema, which has no ``minLength``.
    """
    _org_id, system_id = await _system("scn-blank-description")
    ref = "CHG-BLANK-DESC"
    try:
        await _author(
            system_id,
            ref,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "changeDescription": "   ",
                "assessorName": "Jane Assessor",
                "relatedVulnerability": "CVE-2026-99999",
                "changeTypeExplanation": "Escalated after impact review.",
                "reason": "Address a newly disclosed vulnerability.",
                "customerImpact": "Brief maintenance window.",
                "planAndTimeline": {"summary": "Patch and redeploy over a weekend."},
                "impactAnalysis": "Low risk, well-tested patch path.",
            },
        )
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=ref, change_type="Adaptive"
            )
        assert result.document.validation_errors == [
            "<root>: 'changeDescription' is a required property"
        ], result.document.validation_errors
        assert result.document.is_valid is False
        reasons = dict(result.missing_required)
        assert "changeDescription" in reasons
        assert "certificationPackageOverviewUri" not in reasons
    finally:
        await _delete_org(_org_id)


# --- requirement 3: impactedControls entries are kept and named, never -----
# --- refused -----------------------------------------------------------


async def test_impacted_controls_are_never_dropped_and_unrecognised_ones_are_named() -> None:
    """Spec §5 requirement 3 -- one of the two the task brief singles out.
    A real control, a real KSI, an unknown id, and a blank: all four kept
    VERBATIM in the stored document, and only the unknown and the blank
    named in ``unrecognised_controls``.

    MUTATION: dropping the KSI catalog lookup (resolving through
    ``canonicalize`` alone, spec §2.1's central trap) would misreport
    ``"KSI-SCN-IMPACT-1"`` as unrecognised too, since ``canonicalize`` on a
    KSI id returns ``None`` exactly like an unknown string.
    MUTATION: filtering unrecognised entries OUT of the stored document
    instead of only reporting them would make the first assertion below
    fail -- the document must keep all four verbatim regardless of verdict.
    """
    control_id, control_created = await _ensure_control(
        "ZZ-95", control_name="A control seeded only for this test"
    )
    await _add_ksi("KSI-SCN-IMPACT-1")
    _org_id, system_id = await _system("scn-impacted-controls")
    ref = "CHG-IMPACTED"
    try:
        await _author(
            system_id,
            ref,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "changeDescription": "Rotating the primary signing key.",
                "impactedControls": ["ZZ-95", "KSI-SCN-IMPACT-1", "NOT-REAL-ID", ""],
            },
        )
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=ref, change_type="Adaptive"
            )
        assert result.document.document["impactedControls"] == [
            "ZZ-95",
            "KSI-SCN-IMPACT-1",
            "NOT-REAL-ID",
            "",
        ]
        unrecognised = dict(result.unrecognised_controls)
        assert set(unrecognised) == {"NOT-REAL-ID", ""}
        assert unrecognised["NOT-REAL-ID"] == "not a known control or KSI"
        assert unrecognised[""] == "identifies nothing"
    finally:
        await _delete_org(_org_id)
        if control_created:
            await _delete_control(control_id)


# --- requirement 4: a canonicalisable control id is recognised -------------


async def test_ia_02_resolves_where_ia_2_exists_proving_canonicalize_is_applied() -> None:
    """Spec §5 requirement 4 -- the other one the task brief singles out.
    ``IA-02`` must resolve where ``IA-2`` exists in the catalog, proving
    ``canonicalize`` is actually applied rather than a raw-string lookup.

    MUTATION: looking ``impactedControls`` entries up directly against
    ``Control.identifier`` without canonicalizing first would report
    ``"IA-02"`` as unrecognised even though ``"IA-2"`` is seeded --
    ``unrecognised_controls`` would then be non-empty.
    """
    control_id, control_created = await _ensure_control(
        "IA-2", control_name="Identification and Authentication"
    )
    _org_id, system_id = await _system("scn-ia-02-canonicalize")
    ref = "CHG-IA-02"
    try:
        await _author(
            system_id,
            ref,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "changeDescription": "Adding a second MFA factor.",
                "impactedControls": ["IA-02"],
            },
        )
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=ref, change_type="Adaptive"
            )
        assert result.document.document["impactedControls"] == ["IA-02"]
        assert result.unrecognised_controls == []
    finally:
        await _delete_org(_org_id)
        if control_created:
            await _delete_control(control_id)


# --- requirement 5: a blank or overlong change_ref is refused --------------


async def test_a_blank_change_ref_is_refused_at_the_seeder() -> None:
    """MUTATION: removing the blank check from ``_validate_change_ref``
    would let this construct a document keyed ``""`` instead of raising.
    """
    _org_id, system_id = await _system("scn-blank-ref")
    try:
        async with session_scope() as s:
            with pytest.raises(ValueError, match="must not be blank"):
                await seed_scn(
                    s, system_id=system_id, change_ref="   ", change_type="Adaptive"
                )
    finally:
        await _delete_org(_org_id)


async def test_an_overlong_change_ref_is_refused_at_the_seeder() -> None:
    """MUTATION: removing the length check from ``_validate_change_ref``
    would let a ``document_key`` wider than the column through, reaching
    Postgres as a raw ``StringDataRightTruncationError`` instead of a clean
    ``ValueError`` here.
    """
    _org_id, system_id = await _system("scn-overlong-ref")
    overlong = "K" * (DOCUMENT_KEY_MAX_LENGTH + 1)
    try:
        async with session_scope() as s:
            with pytest.raises(ValueError, match="too long"):
                await seed_scn(
                    s, system_id=system_id, change_ref=overlong, change_type="Adaptive"
                )
    finally:
        await _delete_org(_org_id)


def test_the_scn_seeders_own_bound_and_the_generic_routes_bound_share_one_source() -> None:
    """Confirms ``ccf.cr26.scn`` and ``ccf.api.routes.cr26`` both import
    ``ccf.models_cr26.DOCUMENT_KEY_MAX_LENGTH`` rather than either
    restating ``128`` -- see the module docstring and spec's own warning
    against exactly that drift.
    """
    assert scn_module.DOCUMENT_KEY_MAX_LENGTH is DOCUMENT_KEY_MAX_LENGTH
    assert cr26_routes.DOCUMENT_KEY_MAX_LENGTH is DOCUMENT_KEY_MAX_LENGTH


# --- requirement 6: every ScnSeedResult field crosses the HTTP boundary ----


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


async def test_the_scn_route_reports_every_result_field_to_the_caller() -> None:
    """Spec §5 requirement 6 (task brief: deleting a result field from a
    route on this module left the whole suite green). Every field of
    ``ScnSeedResult`` must cross the HTTP boundary: ``document_key``,
    ``missing_required``, ``missing_advisory`` and ``unrecognised_controls``.

    MUTATION: dropping any one key from the route's response dict makes the
    corresponding assertion below ``KeyError``/fail.
    """
    org_id, system_id = await _system("scn-route-fields")
    ref = "CHG-ROUTE-FIELDS"
    try:
        await _author(
            system_id,
            ref,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "changeDescription": "",
                "impactedControls": ["NOT-A-REAL-ID"],
            },
        )
        async with _Session(org_id=org_id).client() as c:
            resp = await c.post(
                f"/api/systems/{system_id}/cr26-documents/scn/seed",
                json={"changeRef": ref, "changeType": "Adaptive"},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["kind"] == "scn"
        assert body["document_key"] == ref
        required_names = {name for name, _reason in body["missing_required"]}
        assert "changeDescription" in required_names
        assert "assessorName" in body["missing_advisory"]
        unrecognised_names = {name for name, _reason in body["unrecognised_controls"]}
        assert "NOT-A-REAL-ID" in unrecognised_names
        assert body["document"]["impactedControls"] == ["NOT-A-REAL-ID"]
    finally:
        await _delete_org(org_id)


async def test_a_non_admin_cannot_seed_an_scn() -> None:
    org_id, system_id = await _system("scn-route-role")
    try:
        async with _Session(org_id=org_id, role="control_owner").client() as c:
            resp = await c.post(
                f"/api/systems/{system_id}/cr26-documents/scn/seed",
                json={"changeRef": "CHG-ROLE", "changeType": "Adaptive"},
            )
        assert resp.status_code == 403, resp.text
    finally:
        await _delete_org(org_id)


async def test_a_blank_change_ref_is_422_at_the_route() -> None:
    """Spec §5 requirement 5, the route half."""
    org_id, system_id = await _system("scn-route-blank-ref")
    try:
        async with _Session(org_id=org_id).client() as c:
            resp = await c.post(
                f"/api/systems/{system_id}/cr26-documents/scn/seed",
                json={"changeRef": "   ", "changeType": "Adaptive"},
            )
        assert resp.status_code == 422, resp.text
    finally:
        await _delete_org(org_id)
