"""Seeding an SDR: render what is known, omit what is owed, preserve what was written."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.cr26 import sdr as sdr_module
from ccf.cr26.sdr import (
    _evidence,
    _implementation_status,
    seed_sdr,
)
from ccf.cr26.store import put_document
from ccf.db import session_scope
from ccf.fedramp20x import VALIDATION_STATUSES
from ccf.models import (
    KSI,
    KSIAssessorReview,
    KSIState,
    KSIValidationResult,
    Organization,
    SSPControlEntry,
    SSPProject,
    System,
)

_SEQ = itertools.count()

#: ``ksis`` is global reference data -- the seeded FedRAMP 20x catalog -- and
#: ``tests/test_fedramp20x.py`` asserts an exact row count against it. This
#: module invents KSIs, and the suite runs alphabetically, so without this the
#: rows it leaves behind poison that assertion (measured: ``assert 64 == 51``).
#: Declared at module level so a test added here later cannot forget it.
pytestmark = pytest.mark.usefixtures("isolate_ksi_rows")


class _Fixture:
    """What a test needs to talk about one org, one system and one KSI."""

    def __init__(
        self, org_id: int, system_id: int, project_id: int, ksi_id: int, identifier: str
    ) -> None:
        self.org_id = org_id
        self.system_id = system_id
        self.project_id = project_id
        self.ksi_id = ksi_id
        self.identifier = identifier


async def _fixture(name: str) -> _Fixture:
    """An org, a system with one SSP control entry, and one KSI."""
    ident = f"KSI-{name.upper()}-{next(_SEQ)}"
    async with session_scope() as s:
        org = Organization(name=f"{name} Provider")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} Service")
        s.add(sysm)
        await s.flush()
        project = SSPProject(
            organization_id=org.id,
            system_id=sysm.id,
            customer_name=name,
            platform="aws",
            framework="NIST_800_53_R5",
            title=f"{name} SSP",
            version="1.0",
        )
        s.add(project)
        await s.flush()
        s.add(
            SSPControlEntry(
                project_id=project.id,
                control_id="AC-2",
                # Title-cased, as ssp.constants.IMPLEMENTATION_STATUS_OPTIONS
                # actually writes it -- and an exact member of the schema's
                # enum, so it survives the 1.2.1 rule.
                implementation_status=["Implemented"],
                part_narratives=[{"part": "a", "text": "We manage accounts."}],
                odp_values={"ac-2_prm_1": "30 days", "ac-2_prm_2": None},
            )
        )
        ksi = KSI(
            identifier=ident,
            category="IAM",
            name=f"{name} indicator",
            description="The CATALOG description of the requirement.",
            validation_method="automated",
            rule={"kind": "connector_capture", "captures": ["mfa_enforced"]},
        )
        s.add(ksi)
        await s.flush()
        # A passing state, so ksiImplementationStatus is actually DERIVED and
        # reaches the validator in the seed-twice test. Without it the key is
        # omitted and the "every derived field at once" claim there is false.
        s.add(KSIState(system_id=sysm.id, ksi_id=ksi.id, status="pass"))
        await s.flush()
        return _Fixture(org.id, sysm.id, project.id, ksi.id, ident)


def _indicator(document: dict[str, Any], ksi_id: str) -> dict[str, Any]:
    """The merged entry for ``ksi_id``, or a failure that names what is missing.

    A bare ``next(...)`` raises ``StopIteration``, which inside an async test
    surfaces as ``RuntimeError: coroutine raised StopIteration`` and says
    nothing about which indicator went absent -- exactly the case these tests
    exist to catch.
    """
    entries = document["keySecurityIndicators"]
    matches = [entry for entry in entries if entry["ksiId"] == ksi_id]
    assert matches, (
        f"{ksi_id} is absent from keySecurityIndicators: "
        f"{[entry['ksiId'] for entry in entries]}"
    )
    return matches[0]


async def _author_narrative(
    system_id: int, document: dict[str, object], text: str, ksi_id: str
) -> None:
    """Author the one field the platform cannot derive, through the store."""
    doc = dict(document)
    doc["keySecurityIndicators"] = [{"ksiId": ksi_id, "ksiImplementation": [text]}]
    async with session_scope() as s:
        await put_document(s, system_id=system_id, kind="sdr", document=doc)


# --- the seeder ------------------------------------------------------------


async def test_a_seeded_sdr_renders_the_ssp_controls_and_is_invalid() -> None:
    """Two claims at once: the controls carry real content (not []), and the
    document is invalid because certificationPackageOverviewUri is owed."""
    fx = await _fixture("render")
    async with session_scope() as s:
        result = await seed_sdr(s, system_id=fx.system_id)

    doc = result.document.document
    assert doc["securityControls"] == [
        {
            "controlId": "AC-2",
            "controlImplementationStatus": "Implemented",
            "controlImplementationDescription": "We manage accounts.",
            # ac-2_prm_2 is unanswered and must NOT appear as "None".
            "parameterValues": [{"parameterId": "ac-2_prm_1", "parameterValue": "30 days"}],
        }
    ]
    assert doc["fedRampRequirements"] == []
    assert "certificationPackageOverviewUri" not in doc
    assert result.document.is_valid is False
    assert any(
        "certificationPackageOverviewUri" in e for e in result.document.validation_errors
    ), result.document.validation_errors
    assert result.ssp_project_id is not None


async def test_seeding_twice_keeps_the_narrative_and_refreshes_the_derived_fields() -> None:
    """The plan's central risk. BOTH halves matter: asserting only that the
    narrative survives would pass against a seeder that ignores the database
    and echoes the stored document back."""
    fx = await _fixture("twice")

    async with session_scope() as s:
        first = await seed_sdr(s, system_id=fx.system_id)
    assert fx.identifier in first.omitted_ksi_ids, "no narrative yet, so it must be omitted"

    # A human authors the one field the platform cannot derive.
    await _author_narrative(
        fx.system_id,
        first.document.document,
        "We enforce MFA via Conditional Access.",
        fx.identifier,
    )

    async with session_scope() as s:
        second = await seed_sdr(s, system_id=fx.system_id)
    entry = _indicator(second.document.document, fx.identifier)
    assert entry["ksiImplementation"] == ["We enforce MFA via Conditional Access."]
    assert fx.identifier not in second.omitted_ksi_ids
    before = entry["ksiValidation"]

    # A scan runs between seeds -- the derived half must move.
    async with session_scope() as s:
        s.add(
            KSIValidationResult(
                system_id=fx.system_id,
                ksi_id=fx.ksi_id,
                ksi_identifier=fx.identifier,
                status="pass",
                source="scan",
                validated_at=datetime.now(UTC),
                evidence_refs=["s3://ev/1"],
            )
        )

    async with session_scope() as s:
        third = await seed_sdr(s, system_id=fx.system_id)
    entry = _indicator(third.document.document, fx.identifier)
    assert entry["ksiImplementation"] == ["We enforce MFA via Conditional Access."], (
        "the authored narrative must survive a re-seed"
    )
    assert entry["ksiValidation"] != before, (
        "the derived fields must actually refresh -- if they never change, this "
        "test would pass against a seeder that only echoes the stored document"
    )
    assert entry["ksiEvidence"], entry

    # The ONLY place the derived KSI half goes through the real validator.
    # This document carries an authored narrative, a pass-derived status, a
    # validation statement, tests and evidence -- every derived field at once
    # -- so a derived field that renders a schema-invalid shape shows up here
    # and nowhere else. The two other validation_errors assertions in this
    # file run against fixtures with no narrative, where
    # keySecurityIndicators is [] and there is nothing to get wrong.
    #
    # Exact equality, not a membership check: the claim is that a seeded SDR
    # is invalid for exactly ONE reason, and "contains" would pass while the
    # document quietly acquired a second, dishonest one.
    # Pin the comment's claim rather than trusting it: the fixture's KSIState
    # is what makes the status a DERIVED value here, and without this
    # assertion the key could quietly go missing and the "every derived field
    # at once" promise above would become false without any test noticing.
    assert entry["ksiImplementationStatus"] == "Implemented", entry
    assert third.document.validation_errors == [
        "<root>: 'certificationPackageOverviewUri' is a required property"
    ], third.document.validation_errors


async def test_a_seeded_document_never_carries_an_out_of_enum_control_status() -> None:
    """Spec 1.2.1, end to end through the validator.

    Four entries covering every branch of the rule: one schema-valid status,
    one real platform status with no FedRAMP equivalent, two statuses at once,
    and none at all. Only the first may reach the document.

    The second assertion is the one that matters: the seeded SDR is still
    invalid, but ``certificationPackageOverviewUri`` must now be the ONLY
    reason. A ``", ".join(...)`` renderer puts three more errors in this list.
    """
    fx = await _fixture("enum")
    async with session_scope() as s:
        for control_id, statuses in (
            ("AU-2", ["Partially Implemented"]),
            ("AU-6", ["Planned"]),
            ("CM-6", ["Implemented", "Partially Implemented"]),
            ("CP-9", []),
        ):
            s.add(
                SSPControlEntry(
                    project_id=fx.project_id,
                    control_id=control_id,
                    implementation_status=statuses,
                    part_narratives=[{"text": f"About {control_id}."}],
                    odp_values={},
                )
            )

    async with session_scope() as s:
        result = await seed_sdr(s, system_id=fx.system_id)

    by_control = {
        control["controlId"]: control
        for control in result.document.document["securityControls"]
    }
    assert by_control["AC-2"]["controlImplementationStatus"] == "Implemented"
    assert by_control["AU-2"]["controlImplementationStatus"] == "Partially Implemented"
    for control_id in ("AU-6", "CM-6", "CP-9"):
        assert "controlImplementationStatus" not in by_control[control_id], (
            control_id,
            by_control[control_id],
        )

    assert result.document.is_valid is False
    assert not [
        e for e in result.document.validation_errors if "controlImplementationStatus" in e
    ], result.document.validation_errors
    assert [
        e for e in result.document.validation_errors if "certificationPackageOverviewUri" in e
    ], result.document.validation_errors


async def test_an_authored_cpo_uri_survives_a_reseed() -> None:
    """The seeder never invents ``certificationPackageOverviewUri`` -- but once
    someone publishes the CPO and authors it, a re-seed must not throw it away,
    or the SDR could never stop being invalid for that reason.

    This is also what pins that the seeder builds on the STORED document
    rather than starting from ``{}``: a seeder that started fresh would pass
    every other test in this file and fail here.
    """
    fx = await _fixture("cpo-uri")
    async with session_scope() as s:
        first = await seed_sdr(s, system_id=fx.system_id)
    assert "certificationPackageOverviewUri" not in first.document.document

    async with session_scope() as s:
        doc = dict(first.document.document)
        doc["certificationPackageOverviewUri"] = "https://example.gov/cpo.json"
        await put_document(s, system_id=fx.system_id, kind="sdr", document=doc)

    async with session_scope() as s:
        again = await seed_sdr(s, system_id=fx.system_id)
    assert again.document.document["certificationPackageOverviewUri"] == (
        "https://example.gov/cpo.json"
    )
    assert not [
        e for e in again.document.validation_errors if "certificationPackageOverviewUri" in e
    ], again.document.validation_errors


async def test_the_latest_project_is_used() -> None:
    """Both halves: the reported id AND the content rendered from it. An id
    assertion alone would pass if the renderer read the other project.

    The OLDER project is inserted second, so it gets the HIGHER id: under
    ``oscal.py``'s disagreeing ``id.desc()`` precedent this test fails rather
    than passing by insertion-order coincidence.
    """
    fx = await _fixture("latest")
    async with session_scope() as s:
        newer = await s.get(SSPProject, fx.project_id)  # holds AC-2
        assert newer is not None
        newer.updated_at = datetime(2026, 6, 2, tzinfo=UTC)
        older = SSPProject(
            organization_id=fx.org_id,
            system_id=fx.system_id,
            customer_name="latest",
            updated_at=datetime(2026, 6, 1, tzinfo=UTC),
        )
        s.add(older)
        await s.flush()
        s.add(
            SSPControlEntry(
                project_id=older.id,
                control_id="AU-6",
                implementation_status=["Planned"],
                part_narratives=[{"text": "From the older project."}],
                odp_values={},
            )
        )
        assert older.id > fx.project_id  # pin the arrangement the docstring relies on

    async with session_scope() as s:
        result = await seed_sdr(s, system_id=fx.system_id)

    assert result.ssp_project_id == fx.project_id
    # Only the newer project holds AC-2; the older one holds AU-6 alone.
    assert [c["controlId"] for c in result.document.document["securityControls"]] == ["AC-2"]


async def test_an_unknown_system_raises() -> None:
    async with session_scope() as s:
        with pytest.raises(ValueError, match="system"):
            await seed_sdr(s, system_id=-1)


async def test_a_soft_deleted_system_raises() -> None:
    """DATA-04 soft-deletes systems so the CASCADE never fires; a document
    seeded against one would be unreachable and permanent."""
    fx = await _fixture("deleted")
    async with session_scope() as s:
        system = await s.get(System, fx.system_id)
        assert system is not None
        system.deleted_at = datetime.now(UTC)

    async with session_scope() as s:
        with pytest.raises(ValueError, match="system"):
            await seed_sdr(s, system_id=fx.system_id)


# --- the two derived fields that are claims, not renderings (spec 1.3) -----


def test_only_pass_and_fail_become_an_implementation_status() -> None:
    """A validation verdict is not an implementation status. Mapping the whole
    vocabulary would tell FedRAMP "Not Implemented" about something nobody has
    examined, so the four ambiguous verdicts yield no claim at all."""
    assert _implementation_status("pass") == "Implemented"
    assert _implementation_status("fail") == "Not Implemented"
    for verdict in ("warn", "not_tested", "manual_review_required", "not_applicable"):
        assert _implementation_status(verdict) is None, verdict
    assert _implementation_status(None) is None
    # Every member of the real vocabulary is accounted for above, so a status
    # added to VALIDATION_STATUSES later cannot slip through unconsidered.
    assert set(VALIDATION_STATUSES) == {
        "pass",
        "fail",
        "warn",
        "not_tested",
        "manual_review_required",
        "not_applicable",
    }


def test_evidence_carries_a_description_and_a_date_but_no_type() -> None:
    """``evidenceType`` is an enum of Log/Report/Screenshot/Configuration/
    Policy/Procedure/Audit Record -- a classification this platform does not
    hold. ``lastUpdated`` is ``format: date``, not date-time."""
    result = KSIValidationResult(
        system_id=1,
        ksi_id=1,
        ksi_identifier="KSI-IAM-01",
        status="pass",
        evidence_refs=["AC-2:implemented", "s3://bucket/scan.json"],
        validated_at=datetime(2026, 9, 18, 14, 30, tzinfo=UTC),
    )
    assert _evidence(result) == [
        {"evidenceDescription": "AC-2:implemented", "lastUpdated": "2026-09-18"},
        {"evidenceDescription": "s3://bucket/scan.json", "lastUpdated": "2026-09-18"},
    ]
    assert _evidence(None) == []


async def test_a_passing_state_is_implemented_and_an_untested_one_claims_nothing() -> None:
    """End to end through the database: the same seed must make the claim for
    one KSI and stay silent for the other."""
    fx = await _fixture("claims")
    other_ident = f"{fx.identifier}-B"
    async with session_scope() as s:
        other = KSI(
            identifier=other_ident,
            category="IAM",
            name="untested indicator",
            validation_method="manual",
            rule={},
        )
        s.add(other)
        await s.flush()
        # fx's own KSI already has a "pass" state from the fixture; this test
        # only needs the ambiguous counterpart beside it.
        s.add(KSIState(system_id=fx.system_id, ksi_id=other.id, status="not_tested"))

    async with session_scope() as s:
        await put_document(
            s,
            system_id=fx.system_id,
            kind="sdr",
            document={
                "keySecurityIndicators": [
                    {"ksiId": fx.identifier, "ksiImplementation": ["We do A."]},
                    {"ksiId": other_ident, "ksiImplementation": ["We do B."]},
                ]
            },
        )

    async with session_scope() as s:
        result = await seed_sdr(s, system_id=fx.system_id)

    assert _indicator(result.document.document, fx.identifier)["ksiImplementationStatus"] == (
        "Implemented"
    )
    other_entry = _indicator(result.document.document, other_ident)
    assert "ksiImplementationStatus" not in other_entry, other_entry


async def test_the_other_derived_statements_come_from_the_database() -> None:
    """``ksiValidation``, ``ksiAssessment`` and ``ksiTests`` must each carry the
    row that produced them -- an inert seeder emits ``[]`` for all three."""
    fx = await _fixture("statements")
    async with session_scope() as s:
        s.add(
            KSIValidationResult(
                system_id=fx.system_id,
                ksi_id=fx.ksi_id,
                ksi_identifier=fx.identifier,
                status="warn",
                source="connector:entra",
                evidence_refs=[],
                validated_at=datetime(2026, 9, 17, 9, 0, tzinfo=UTC),
            )
        )
        s.add(
            KSIAssessorReview(
                system_id=fx.system_id,
                ksi_id=fx.ksi_id,
                assessor="assessor@3pao.example",
                status="accepted",
                finding="No exceptions observed.",
                reviewed_at=datetime(2026, 9, 17, 12, 0, tzinfo=UTC),
            )
        )

    async with session_scope() as s:
        await put_document(
            s,
            system_id=fx.system_id,
            kind="sdr",
            document={
                "keySecurityIndicators": [
                    {"ksiId": fx.identifier, "ksiImplementation": ["We do the thing."]}
                ]
            },
        )

    async with session_scope() as s:
        result = await seed_sdr(s, system_id=fx.system_id)

    entry = _indicator(result.document.document, fx.identifier)
    assert entry["ksiValidation"] == [
        "warn at 2026-09-17T09:00:00+00:00 (source: connector:entra)"
    ]
    assert entry["ksiAssessment"] == [
        "accepted by assessor@3pao.example: No exceptions observed."
    ]
    assert entry["ksiTests"] == ["automated validation (rule kind: connector_capture)"]


# --- the route -------------------------------------------------------------


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


async def test_the_route_returns_the_document_and_what_was_omitted() -> None:
    fx = await _fixture("route")
    async with _Session(org_id=fx.org_id).client() as c:
        resp = await c.post(f"/api/systems/{fx.system_id}/cr26-documents/sdr/seed")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["kind"] == "sdr"
    assert body["is_valid"] is False
    assert fx.identifier in body["omitted_ksi_ids"]
    assert body["ssp_project_id"] is not None
    assert [c["controlId"] for c in body["document"]["securityControls"]] == ["AC-2"]
    # Both control-gap keys must cross the HTTP boundary. They are the ENTIRE
    # operator-facing remediation for the draft-scaffolding defect -- nothing
    # in the document says a control is unwritten or truncated -- so a route
    # that computed them and forgot to return them would silently restore the
    # invisible gap. Deleting the two lines in the route leaves every
    # dataclass-level assertion in this file green.
    assert body["rendered_control_count"] == 1
    assert body["controls_missing_description"] == []
    assert body["controls_with_dropped_parts"] == []


async def test_the_route_reports_a_draft_control_to_the_caller() -> None:
    """The empty-list assertions above would pass against a route that
    hard-coded ``[]``. This one carries real content across the boundary."""
    fx = await _fixture("route-draft")
    async with session_scope() as s:
        s.add(
            SSPControlEntry(
                project_id=fx.project_id,
                control_id="AU-2",
                implementation_status=["Planned"],
                part_narratives=[
                    {"text": "[DRAFT] Describe the implementation.", "draft": True}
                ],
                odp_values={},
            )
        )
        s.add(
            SSPControlEntry(
                project_id=fx.project_id,
                control_id="SC-13",
                implementation_status=["Implemented"],
                part_narratives=[
                    {"text": "We use AWS KMS."},
                    {"text": "Key custody is [ORGANIZATION-DEFINED: owner]."},
                ],
                odp_values={},
            )
        )

    async with _Session(org_id=fx.org_id).client() as c:
        resp = await c.post(f"/api/systems/{fx.system_id}/cr26-documents/sdr/seed")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["rendered_control_count"] == 3
    assert body["controls_missing_description"] == ["AU-2"]
    # SC-13 kept a description and a status -- it reads complete, and this is
    # the only place its loss is visible.
    assert body["controls_with_dropped_parts"] == ["AU-2", "SC-13"]
    by_control = {c["controlId"]: c for c in body["document"]["securityControls"]}
    assert by_control["SC-13"]["controlImplementationDescription"] == "We use AWS KMS."


async def test_the_seed_route_is_admin_gated() -> None:
    """Deliberately tries ``control_owner``, not ``viewer``: viewer 403s under
    either gate, so it could not tell an admin-only gate from an
    admin+control_owner one."""
    fx = await _fixture("gate")
    async with _Session(org_id=fx.org_id, role="control_owner").client() as c:
        resp = await c.post(f"/api/systems/{fx.system_id}/cr26-documents/sdr/seed")
    assert resp.status_code == 403, resp.text


async def test_another_tenants_system_is_404() -> None:
    """The owning tenant seeds FIRST, so this exercises a path that would
    otherwise return 200 -- a 404 test that can only pass from the branch it
    means to pin."""
    owner = await _fixture("tenant-a")
    other = await _fixture("tenant-b")
    async with _Session(org_id=owner.org_id).client() as c:
        seeded = await c.post(f"/api/systems/{owner.system_id}/cr26-documents/sdr/seed")
    assert seeded.status_code == 200, seeded.text

    async with _Session(org_id=other.org_id).client() as c:
        resp = await c.post(f"/api/systems/{owner.system_id}/cr26-documents/sdr/seed")
    assert resp.status_code == 404, resp.text


# --- scoping, recency and round-trip ---------------------------------------


async def test_another_systems_ksi_facts_never_reach_this_document() -> None:
    """Every KSI query must filter on ``system_id``. All three filters could be
    deleted with the suite green, and RLS is not the backstop here: its
    policies are ORG-scoped, so a dropped filter leaks between systems inside
    one tenant regardless, and an unscoped principal bypasses RLS entirely.
    App-layer scoping is the primary defence.

    Same shape as ``test_cr26_sdr_controls.py``'s
    ``test_a_project_belonging_to_a_different_system_is_not_returned``: system
    B's rows are the ones a dropped ``.where()`` would return, because they are
    added later, so each assertion names B's text as the thing that must NOT
    appear.
    """
    a = await _fixture("scope-a")
    b = await _fixture("scope-b")
    async with session_scope() as s:
        # B records facts against A's catalog KSI -- the only way a dropped
        # system filter shows up as wrong CONTENT rather than merely extra rows.
        # A's own state is "pass", written by the fixture.
        s.add(KSIState(system_id=b.system_id, ksi_id=a.ksi_id, status="fail"))
        s.add(
            KSIValidationResult(
                system_id=b.system_id,
                ksi_id=a.ksi_id,
                ksi_identifier=a.identifier,
                status="fail",
                source="OTHER-SYSTEM-SCAN",
                validated_at=datetime(2026, 9, 18, tzinfo=UTC),
                evidence_refs=["OTHER-SYSTEM-EVIDENCE"],
            )
        )
        s.add(
            KSIAssessorReview(
                system_id=b.system_id,
                ksi_id=a.ksi_id,
                assessor="OTHER-SYSTEM-ASSESSOR",
                status="rejected",
                reviewed_at=datetime(2026, 9, 18, tzinfo=UTC),
            )
        )
        s.add(
            KSIValidationResult(
                system_id=a.system_id,
                ksi_id=a.ksi_id,
                ksi_identifier=a.identifier,
                status="pass",
                source="a-scan",
                validated_at=datetime(2026, 9, 17, tzinfo=UTC),
                evidence_refs=["a-evidence"],
            )
        )
        s.add(
            KSIAssessorReview(
                system_id=a.system_id,
                ksi_id=a.ksi_id,
                assessor="a-assessor",
                status="accepted",
                reviewed_at=datetime(2026, 9, 17, tzinfo=UTC),
            )
        )

    async with session_scope() as s:
        await put_document(
            s,
            system_id=a.system_id,
            kind="sdr",
            document={
                "keySecurityIndicators": [
                    {"ksiId": a.identifier, "ksiImplementation": ["A's narrative."]}
                ]
            },
        )

    async with session_scope() as s:
        result = await seed_sdr(s, system_id=a.system_id)

    entry = _indicator(result.document.document, a.identifier)
    # ksi_states: A's is "pass" (Implemented), B's is "fail" (Not Implemented).
    assert entry["ksiImplementationStatus"] == "Implemented", entry
    assert entry["ksiValidation"] == [
        "pass at 2026-09-17T00:00:00+00:00 (source: a-scan)"
    ]
    assert entry["ksiAssessment"] == ["accepted by a-assessor"]
    assert entry["ksiEvidence"] == [
        {"evidenceDescription": "a-evidence", "lastUpdated": "2026-09-17"}
    ]


async def test_the_latest_validation_run_wins_not_the_first() -> None:
    """``_validation_statements`` claims "the latest run only" and nothing
    pinned it: no fixture created two results for one KSI, so the dict-fold
    that makes the newest win was unreachable as a distinguishing branch.

    Reversing the ordering would report the OLDEST scan as current -- a stale
    ``pass`` outliving a later ``fail``, told to a regulator as the present
    state. The rows are added newest-first so insertion order disagrees with
    the answer.
    """
    fx = await _fixture("recency")
    async with session_scope() as s:
        for status, source, when, ref in (
            ("fail", "newer-scan", datetime(2026, 9, 18, tzinfo=UTC), "newer-evidence"),
            ("pass", "older-scan", datetime(2026, 9, 10, tzinfo=UTC), "older-evidence"),
        ):
            s.add(
                KSIValidationResult(
                    system_id=fx.system_id,
                    ksi_id=fx.ksi_id,
                    ksi_identifier=fx.identifier,
                    status=status,
                    source=source,
                    validated_at=when,
                    evidence_refs=[ref],
                )
            )
        for assessor, status, when in (
            ("newer-assessor", "rejected", datetime(2026, 9, 18, tzinfo=UTC)),
            ("older-assessor", "accepted", datetime(2026, 9, 10, tzinfo=UTC)),
        ):
            s.add(
                KSIAssessorReview(
                    system_id=fx.system_id,
                    ksi_id=fx.ksi_id,
                    assessor=assessor,
                    status=status,
                    reviewed_at=when,
                )
            )

    async with session_scope() as s:
        await put_document(
            s,
            system_id=fx.system_id,
            kind="sdr",
            document={
                "keySecurityIndicators": [
                    {"ksiId": fx.identifier, "ksiImplementation": ["We do it."]}
                ]
            },
        )

    async with session_scope() as s:
        result = await seed_sdr(s, system_id=fx.system_id)

    entry = _indicator(result.document.document, fx.identifier)
    assert entry["ksiValidation"] == [
        "fail at 2026-09-18T00:00:00+00:00 (source: newer-scan)"
    ]
    assert entry["ksiEvidence"] == [
        {"evidenceDescription": "newer-evidence", "lastUpdated": "2026-09-18"}
    ]
    assert entry["ksiAssessment"] == ["rejected by newer-assessor"]


async def test_a_tie_on_the_timestamp_is_broken_by_row_id() -> None:
    """Two runs can share ``validated_at`` exactly -- ``now()`` is
    transaction-scoped in Postgres, so results written in one transaction all
    carry the identical server default. The later ROW is the later run, and the
    answer must not be left to whatever order the scan returns.

    Ids are assigned EXPLICITLY, higher first, so physical order is the
    reverse of id order. That is what makes this test able to fail: inserting
    normally leaves heap order and id order identical, an unordered fold picks
    the right row by accident, and dropping ``.id.asc()`` goes unnoticed
    (measured -- it did). With the rows laid out this way, ordering on the
    timestamp alone folds to the LOWER-id row and this fails.
    """
    fx = await _fixture("tie-run")
    same_moment = datetime(2026, 9, 18, tzinfo=UTC)
    async with session_scope() as s:
        base_result = (
            await s.execute(select(func.coalesce(func.max(KSIValidationResult.id), 0)))
        ).scalar_one() + 100
        base_review = (
            await s.execute(select(func.coalesce(func.max(KSIAssessorReview.id), 0)))
        ).scalar_one() + 100
        # Higher id inserted FIRST -> it sits earlier in the heap.
        for offset, source in ((1, "higher-id"), (0, "lower-id")):
            s.add(
                KSIValidationResult(
                    id=base_result + offset,
                    system_id=fx.system_id,
                    ksi_id=fx.ksi_id,
                    ksi_identifier=fx.identifier,
                    status="pass",
                    source=source,
                    validated_at=same_moment,
                    evidence_refs=[],
                )
            )
            await s.flush()
        for offset, assessor in ((1, "higher-id-review"), (0, "lower-id-review")):
            s.add(
                KSIAssessorReview(
                    id=base_review + offset,
                    system_id=fx.system_id,
                    ksi_id=fx.ksi_id,
                    assessor=assessor,
                    status="accepted",
                    reviewed_at=same_moment,
                )
            )
            await s.flush()

    async with session_scope() as s:
        await put_document(
            s,
            system_id=fx.system_id,
            kind="sdr",
            document={
                "keySecurityIndicators": [
                    {"ksiId": fx.identifier, "ksiImplementation": ["We do it."]}
                ]
            },
        )

    async with session_scope() as s:
        result = await seed_sdr(s, system_id=fx.system_id)

    entry = _indicator(result.document.document, fx.identifier)
    assert entry["ksiValidation"] == [
        "pass at 2026-09-18T00:00:00+00:00 (source: higher-id)"
    ]
    assert entry["ksiAssessment"] == ["accepted by higher-id-review"]


async def test_the_seeder_reads_the_sdr_row_not_whatever_document_exists() -> None:
    """A system with both a CPO and an SDR is the normal case. Without the
    ``kind`` filter, ``_current`` returns whichever row comes back first and
    ``seed_sdr`` builds the SDR on top of the CPO's body -- carrying
    ``serviceIdentification`` into a document that has no such field.

    The CPO is written FIRST so it has the lower id, which is what an
    unfiltered ``.first()`` returns.
    """
    fx = await _fixture("kinds")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=fx.system_id,
            kind="cpo",
            document={"serviceIdentification": {"serviceName": "CPO CONTENT"}},
        )
        await put_document(
            s,
            system_id=fx.system_id,
            kind="sdr",
            document={"certificationPackageOverviewUri": "https://example.gov/cpo.json"},
        )

    async with session_scope() as s:
        result = await seed_sdr(s, system_id=fx.system_id)

    doc = result.document.document
    assert "serviceIdentification" not in doc, doc
    assert doc["certificationPackageOverviewUri"] == "https://example.gov/cpo.json"


async def test_an_authored_fedramp_requirement_survives_a_reseed() -> None:
    """``seed_sdr``'s docstring promises "[] unless already authored". Plain
    assignment instead of ``setdefault`` passes every other test in this file,
    because nothing else ever authors the field -- and it would silently
    destroy the one part of ``fedRampRequirements`` a human can supply."""
    fx = await _fixture("frr")
    authored = [{"frrID": "SDR-CSO-FRR", "frrImplementation": ["We meet it."]}]
    async with session_scope() as s:
        await put_document(
            s, system_id=fx.system_id, kind="sdr", document={"fedRampRequirements": authored}
        )

    async with session_scope() as s:
        result = await seed_sdr(s, system_id=fx.system_id)

    assert result.document.document["fedRampRequirements"] == authored


async def test_a_draft_only_control_is_reported_rather_than_described() -> None:
    """Spec 1.2.2, end to end. A scaffolded SSP entry reaches the document with
    NO ``controlImplementationDescription``, and the control id is named in the
    result -- the only signal there is, since the scaffolded ``Planned`` status
    is omitted as untranslatable.
    """
    fx = await _fixture("draft")
    async with session_scope() as s:
        s.add(
            SSPControlEntry(
                project_id=fx.project_id,
                control_id="AU-2",
                implementation_status=["Planned"],
                part_narratives=[
                    {
                        "label": "",
                        "text": (
                            "[DRAFT] AU control AU-2 is the responsibility of "
                            "System Owner. Describe the implementation."
                        ),
                        "draft": True,
                    }
                ],
                odp_values={},
            )
        )

    async with session_scope() as s:
        result = await seed_sdr(s, system_id=fx.system_id)

    by_control = {
        control["controlId"]: control
        for control in result.document.document["securityControls"]
    }
    assert by_control["AU-2"] == {"controlId": "AU-2", "parameterValues": []}
    # AC-2 from the fixture is genuinely written, so it keeps its description.
    assert by_control["AC-2"]["controlImplementationDescription"] == (
        "We manage accounts."
    )
    assert result.controls_missing_description == ["AU-2"]
    assert result.controls_with_dropped_parts == ["AU-2"]
    assert result.rendered_control_count == 2


async def test_an_empty_ssp_project_reports_zero_controls_rendered() -> None:
    """``ssp_project_id: None`` is documented as the signal that
    ``securityControls: []`` means "no SSP to render from" -- but an EMPTY
    project that happens to be the most recently updated one wins the
    selection, blanks a populated ``securityControls`` and returns a
    non-``None`` id, so that signal does not fire. The rendered count is what
    distinguishes the two.
    """
    fx = await _fixture("empty-project")
    async with session_scope() as s:
        first = await seed_sdr(s, system_id=fx.system_id)
    assert first.rendered_control_count == 1

    async with session_scope() as s:
        empty = SSPProject(
            organization_id=fx.org_id,
            system_id=fx.system_id,
            customer_name="empty",
            updated_at=datetime(2027, 1, 1, tzinfo=UTC),
        )
        s.add(empty)
        await s.flush()
        empty_id = empty.id

    async with session_scope() as s:
        again = await seed_sdr(s, system_id=fx.system_id)

    assert again.document.document["securityControls"] == []
    assert again.ssp_project_id == empty_id  # NOT None -- the gap in that signal
    assert again.rendered_control_count == 0
    assert again.controls_missing_description == []
    assert again.controls_with_dropped_parts == []


def test_a_verdict_mapping_outside_the_schema_enum_is_refused() -> None:
    """M8's other half. ``_IMPLEMENTATION_STATUS_BY_VERDICT`` names its two
    targets as literals; gating them on the schema's enum is what stops a
    NARROWING schema bump leaving this producer emitting a value FedRAMP no
    longer accepts, with nothing saying why."""
    assert _implementation_status("fail") == "Not Implemented"
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sdr_module, "_implementation_status_enum", lambda: frozenset({"Implemented"}))
        with pytest.raises(RuntimeError, match="Not Implemented"):
            _implementation_status("fail")
        # The mapped-to-nothing verdicts still make no claim rather than raising.
        assert _implementation_status("not_tested") is None
