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
from ccf.cr26.scn import ScnSeedResult, seed_scn
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
        # Regression guard for review round 3, I2: `has_content` treats a
        # STRUCTURED authored field (a dict, here) as content whenever it
        # is not literally `None` -- it must never be blank-tested the way
        # a string is, or this real, non-empty `planAndTimeline` would be
        # silently dropped and reported as missing_advisory instead.
        assert result.document.document["planAndTimeline"] == {
            "summary": "Patch and redeploy over a weekend."
        }
        assert "planAndTimeline" not in result.missing_advisory
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


# --- review round 3, C1: changeTypeExplanation cannot outlive its category -


async def test_change_type_explanation_survives_re_seeding_with_the_same_change_type() -> None:
    """The un-broken half of C1: re-seeding with the SAME ``change_type`` as
    what is already stored must still carry a genuinely-matching
    ``changeTypeExplanation`` forward -- the fix must not turn "amend with
    no category change" into "drop the explanation every time".

    MUTATION: requiring ``current.get("changeType") == change_type`` when
    ``current`` never had a stored ``changeType`` in the first place would
    ALSO break this test if the precondition below did not author
    ``changeType`` alongside the explanation -- which is why it does.
    """
    _org_id, system_id = await _system("scn-explanation-same-category")
    ref = "CHG-EXPLANATION-SAME"
    try:
        await _author(
            system_id,
            ref,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "changeDescription": "Rotating an expiring TLS certificate.",
                "changeType": "Adaptive",
                "changeTypeExplanation": "Adaptive because it does not alter the boundary.",
            },
        )
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=ref, change_type="Adaptive"
            )
        assert (
            result.document.document["changeTypeExplanation"]
            == "Adaptive because it does not alter the boundary."
        )
        assert "changeTypeExplanation" not in result.missing_advisory
    finally:
        await _delete_org(_org_id)


async def test_re_categorising_an_scn_drops_its_stale_change_type_explanation() -> None:
    """C1, the Critical the task brief's coordinator found. Measured before
    this fix: re-seeding ``"CHG-FLIP"`` first as ``Adaptive`` (with an
    explanation arguing exactly that) and then as ``Transformative`` --
    the documented way to amend an SCN's category -- carried the OLD
    explanation forward under the NEW category and reported the document
    fully valid: a ``changeType`` of ``"Transformative"`` sitting over a
    sentence arguing ``"Adaptive"``, an internally contradictory federal
    filing with nothing flagged.

    MUTATION: removing the
    ``current.get("changeType") == change_type`` guard (i.e. treating
    ``changeTypeExplanation`` like every other ``_AUTHORED_FIELDS`` member)
    reintroduces exactly that -- the assertions below on
    ``changeTypeExplanation`` and ``missing_advisory`` would fail.
    """
    _org_id, system_id = await _system("scn-recategorise-flip")
    ref = "CHG-FLIP"
    try:
        await _author(
            system_id,
            ref,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "changeDescription": "Reworking the ingress boundary.",
                "changeType": "Adaptive",
                "changeTypeExplanation": "Adaptive because it does not alter the boundary.",
            },
        )
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=ref, change_type="Transformative"
            )
        assert result.document.document["changeType"] == "Transformative"
        assert "changeTypeExplanation" not in result.document.document
        assert "changeTypeExplanation" in result.missing_advisory
        # The document is otherwise complete -- proving the fix reports an
        # honestly-thin filing, not a broken one, and did not just make
        # everything invalid as a side effect.
        assert result.document.document["changeDescription"] == "Reworking the ingress boundary."
    finally:
        await _delete_org(_org_id)


async def test_change_type_explanation_absent_is_named_in_missing_advisory() -> None:
    """M3: ``changeTypeExplanation`` is called out by name in spec §3.3 --
    when nothing was ever authored for it (the ordinary case, distinct from
    C1's stale-explanation case above), it must still be named, not
    silently swallowed by the branch C1 added.

    MUTATION: the C1 branch's ``else`` clause failing to append to
    ``missing_advisory`` turns this red.
    """
    _org_id, system_id = await _system("scn-explanation-never-authored")
    ref = "CHG-NO-EXPLANATION"
    try:
        await _author(
            system_id,
            ref,
            {"certificationPackageOverviewUri": CPO_URI, "changeDescription": "A minor change."},
        )
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=ref, change_type="Adaptive"
            )
        assert "changeTypeExplanation" not in result.document.document
        assert "changeTypeExplanation" in result.missing_advisory
    finally:
        await _delete_org(_org_id)


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


async def test_a_change_ref_padded_to_exactly_the_bound_after_stripping_is_accepted() -> None:
    """I6: the strip in ``_validate_change_ref`` runs BEFORE the length
    check and BEFORE ``document_key`` is built, so a ``change_ref`` that is
    only overlong because of padding -- not because its meaningful content
    exceeds the bound -- is accepted, and accepted at EXACTLY
    ``DOCUMENT_KEY_MAX_LENGTH`` (a length LIMIT, not an arbitrary shorter
    cutoff).

    MUTATION: stripping after measuring length, or not stripping at all
    before building ``document_key``, either wrongly refuses this in-bounds
    ref (if the length check also uses the unstripped value) or -- the more
    serious failure -- lets an over-width ``document_key`` reach Postgres
    as a raw ``StringDataRightTruncationError`` instead of this seeder's own
    clean ``ValueError``, exactly what ``ccf.cr26.incident``'s identical
    check was written to prevent.
    """
    core = "K" * DOCUMENT_KEY_MAX_LENGTH
    padded = f"  {core}  "
    _org_id, system_id = await _system("scn-strip-boundary")
    try:
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=padded, change_type="Adaptive"
            )
        assert result.document_key == core
        assert len(result.document_key) == DOCUMENT_KEY_MAX_LENGTH
    finally:
        await _delete_org(_org_id)


def test_the_scn_seeders_own_bound_matches_the_document_key_columns_declared_width() -> None:
    """I3: a review round 3 finding about the ORIGINAL version of this test,
    which asserted ``scn_module.DOCUMENT_KEY_MAX_LENGTH is
    DOCUMENT_KEY_MAX_LENGTH`` against a second import of the very same
    name. That assertion could never fail: ``DOCUMENT_KEY_MAX_LENGTH`` is
    ``128``, CPython interns every ``int`` in ``-5..256``, and a hardcoded
    ``DOCUMENT_KEY_MAX_LENGTH = 128`` dropped into ``ccf.cr26.scn`` in
    place of the import is measured to leave that identity check passing.

    This version instead asserts against the ACTUAL source of truth -- the
    ``document_key`` column's own declared width,
    ``Cr26Document.__table__.c.document_key.type.length`` -- so the claim
    becomes "this module's bound tracks the column", which is what
    actually matters: if the column's width is ever changed, ``ccf.cr26.
    scn.DOCUMENT_KEY_MAX_LENGTH`` must move with it or Postgres, not this
    module's own check, becomes the thing that refuses an overlong key.

    MUTATION: hardcoding a DIFFERENT number in ``ccf.cr26.scn`` (not merely
    the CURRENT column width, which no test can distinguish from a correct
    import by value alone -- see above) turns this red.
    """
    column_width = Cr26Document.__table__.c.document_key.type.length
    assert column_width == scn_module.DOCUMENT_KEY_MAX_LENGTH
    assert column_width == cr26_routes.DOCUMENT_KEY_MAX_LENGTH


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
    route on this module left the whole suite green).

    The key-presence check is asserted MECHANICALLY against
    ``ScnSeedResult.__dataclass_fields__`` (review round 3, I4) rather than
    a hand-written list of field names: a hand-written list only proves
    that whatever the author remembered to type crosses the boundary, and
    review round 3 measured that dropping the route's explicit
    ``"document_key": result.document_key`` line specifically leaves this
    kind of test green anyway, because ``_full()`` already emits
    ``document_key`` from the row itself -- the two happen to agree, which
    hid the missing wiring rather than proving it present. Asserting
    against the dataclass itself means a FUTURE field added to
    ``ScnSeedResult`` and never wired into the route fails this test
    automatically, without anyone needing to remember to extend a
    hand-maintained set.

    MUTATION: dropping ``"missing_required"`` (a field ``_full()`` has no
    other source for, unlike ``document_key``) from the route's response
    dict turns this red.
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
        missing_keys = set(ScnSeedResult.__dataclass_fields__) - set(body)
        assert not missing_keys, f"ScnSeedResult fields missing from the response: {missing_keys}"
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


# --- review round 3: I1, I2 -- blank authored content is absent content ----


async def test_a_blank_certification_package_overview_uri_is_treated_as_absent() -> None:
    """I1: ``is_blank``, not ``uri is not None``, guards
    ``certificationPackageOverviewUri``. A stored value of all whitespace
    must be treated exactly like an absent one, not carried through as a
    "complete" filing with an empty package overview.

    MUTATION: changing the guard in ``seed_scn`` from ``is_blank(uri)`` to
    ``uri is None`` turns this red -- a whitespace-only stored URI would
    then be carried and this one required field would look satisfied.
    """
    _org_id, system_id = await _system("scn-blank-uri")
    ref = "CHG-BLANK-URI"
    try:
        await _author(
            system_id, ref, {"certificationPackageOverviewUri": "   ", "changeDescription": "x"}
        )
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=ref, change_type="Adaptive"
            )
        assert "certificationPackageOverviewUri" not in result.document.document
        reasons = dict(result.missing_required)
        assert "certificationPackageOverviewUri" in reasons
    finally:
        await _delete_org(_org_id)


async def test_a_blank_authored_optional_field_is_treated_as_absent_and_named() -> None:
    """I2: ``has_content``, not a bare ``field_name in current`` test,
    guards the eight authored-in-practice optional fields. A stored ``""``
    for ``reason`` carries no more information than an absent one, and must
    be named in ``missing_advisory`` rather than silently carried.

    MUTATION: reverting the carry loop to a bare ``field_name in current``
    check turns this red -- the blank ``reason`` would be carried into the
    document and never named.
    """
    _org_id, system_id = await _system("scn-blank-optional-field")
    ref = "CHG-BLANK-REASON"
    try:
        await _author(
            system_id,
            ref,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "changeDescription": "A change.",
                "reason": "   ",
            },
        )
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=ref, change_type="Adaptive"
            )
        assert "reason" not in result.document.document
        assert "reason" in result.missing_advisory
    finally:
        await _delete_org(_org_id)


# --- review round 3: I5 -- the KSI-catalog lookup normalises like control --
# --- ids already do, and M5 -- step 2's wording is non-committal too ------


async def test_a_ksi_id_with_different_casing_or_whitespace_still_resolves() -> None:
    """I5: step 3 originally matched the RAW value byte-for-byte, which
    denied a real catalog KSI over nothing but the author's whitespace or
    casing -- see the module docstring's correction and the design spec's
    own §2.1 correction. Both variants below must resolve.

    MUTATION: removing ``.strip().lower()`` from either side of the
    comparison in ``_resolve_impacted_controls`` turns this red.
    """
    await _add_ksi("KSI-SCN-CASE-1")
    _org_id, system_id = await _system("scn-ksi-case-insensitive")
    ref = "CHG-KSI-CASE"
    try:
        await _author(
            system_id,
            ref,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "changeDescription": "Testing KSI matching normalisation.",
                "impactedControls": [" KSI-SCN-CASE-1 ", "ksi-scn-case-1"],
            },
        )
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=ref, change_type="Adaptive"
            )
        assert result.unrecognised_controls == []
        # Kept verbatim -- only the COMPARISON is normalised, never what is
        # reported or what stays in the stored document.
        assert result.document.document["impactedControls"] == [
            " KSI-SCN-CASE-1 ",
            "ksi-scn-case-1",
        ]
    finally:
        await _delete_org(_org_id)


async def test_a_canonicalisable_but_uncatalogued_control_id_is_named_not_a_known_control() -> (
    None
):
    """M5: step 2's not-found reason is ``"not a known control"``, aligned
    with step 3's deliberately non-committal wording -- see the module
    docstring and the design spec's own correction. ``"YY-01"``
    canonicalizes cleanly (a valid family-number shape) but nothing seeds
    it into the catalog for this test, so it must fall into step 2's
    not-found branch and use step 2's reason, not step 3's.

    MUTATION: reverting the reason string back to ``"no such control"``
    turns this red.
    """
    _org_id, system_id = await _system("scn-uncatalogued-control")
    ref = "CHG-UNCATALOGUED"
    try:
        await _author(
            system_id,
            ref,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "changeDescription": "Testing an uncatalogued but well-formed control id.",
                "impactedControls": ["YY-01"],
            },
        )
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=ref, change_type="Adaptive"
            )
        assert result.unrecognised_controls == [("YY-01", "not a known control")]
    finally:
        await _delete_org(_org_id)


# --- review round 3, M2: a non-string entry is named by position, never ----
# --- by its Python repr -----------------------------------------------


async def test_a_non_string_impacted_controls_entry_is_named_by_position_not_repr() -> None:
    """M2: a non-string entry -- reachable only via the generic PUT route or
    (as here) by authoring the row directly, since the vendored schema's
    own ``items: {"type": "string"}`` already refuses it in
    ``validation_errors`` -- used to be reported as Python's own ``repr``
    (``"None"``, ``"['nested']"``) under the wrong reason ("identifies
    nothing"), text that appears nowhere in the document an operator is
    actually reading. It must be reported by POSITION instead.

    MUTATION: reverting to ``str(entry)`` for a non-string entry, or
    reverting the reason back to ``"identifies nothing"``, turns this red.
    """
    _org_id, system_id = await _system("scn-non-string-entry")
    ref = "CHG-NON-STRING"
    try:
        await _author(
            system_id,
            ref,
            {
                "certificationPackageOverviewUri": CPO_URI,
                "changeDescription": "Testing a malformed impactedControls entry.",
                "impactedControls": [None, ["nested"]],
            },
        )
        async with session_scope() as s:
            result = await seed_scn(
                s, system_id=system_id, change_ref=ref, change_type="Adaptive"
            )
        assert result.unrecognised_controls == [
            ("impactedControls[0]", "not a string -- see validation_errors"),
            ("impactedControls[1]", "not a string -- see validation_errors"),
        ]
        # Still kept verbatim, exactly like every other unrecognised entry.
        assert result.document.document["impactedControls"] == [None, ["nested"]]
    finally:
        await _delete_org(_org_id)
