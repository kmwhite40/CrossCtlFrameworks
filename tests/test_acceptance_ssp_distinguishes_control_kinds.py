"""Acceptance: the SSP tells five kinds of control apart.

The fourth acceptance criterion of
``docs/superpowers/plans/2026-09-26-live-audit-compliance-plan.md``:

    SSP output distinguishes passing automated evidence, documented-only
    controls, failed controls with POA&Ms, inherited controls, and manual
    review gaps.

The operative word is **distinguishes**, and it is not the same claim as "can
produce each of these". Tests already exist for the clauses one at a time, and
they would all still pass if the composer emitted the finding sentence on a
control that merely lacked evidence, or the inherited sentence beside an open
finding. What none of them establishes is that the five are mutually exclusive
in one document -- which is the only form in which an assessor meets them.

So this builds **one** SSP project holding one control of each kind and asserts
a matrix: every entry carries its own marker and none of the other four. A
false positive is a worse defect than a missing clause here. "Verified by
automated testing" on a control nothing tested, or "inherited from Microsoft"
on a control the customer owns, is a false statement in an authorization
package, and it validates.

The fifth kind is the one with no marker at all. A documented-only control --
described, believed, never machine-tested -- must read as exactly that, and the
risk is not that it says the wrong thing but that it quietly acquires one of
the other four sentences and becomes indistinguishable from a verified control.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import automation as automation_engine
from ccf.models import POAM, Organization, SSPControlEntry, SSPProject, System, SystemProfile
from ccf.models_grc import ControlTest
from ccf.scoring.seed import seed_scoring_controls

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# ---------------------------------------------------------------------------
# The five markers, as the composer actually writes them
# ---------------------------------------------------------------------------
#
# Substrings of `ccf.ssp.statements`, not paraphrases. If the wording changes
# these break, which is correct: an assessor reads the wording, and a clause
# renamed without anyone noticing is a clause nobody can find.

VERIFIED = "Verified by automated testing against the live environment"
FINDING = "Open finding"
MANUAL = "Not machine-verified"
INHERITED = "is inherited from"

MARKERS = {
    "passing_automated_evidence": VERIFIED,
    "failed_with_poam": FINDING,
    "manual_review_gap": MANUAL,
    "inherited": INHERITED,
}

#: The CMMC practice the m365 GCC High placemat records as Microsoft Coverage,
#: which `_COVERAGE_TO_STATE` maps to (inherited, inherited). Physical
#: protection of a Microsoft datacenter is the honest example: it is genuinely
#: not the customer's control to implement.
INHERITED_PRACTICE = "PE.L2-3.10.1"


async def _scene() -> tuple[int, int, int]:
    """One project, five controls, each engineered into exactly one kind."""
    tag = f"{next(_SEQ)}"
    async with session_scope() as s:
        await seed_scoring_controls(s)
    async with session_scope() as s:
        org = Organization(name=f"Kinds Org {tag}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"Kinds Sys {tag}")
        s.add(system)
        await s.flush()
        s.add(
            SystemProfile(
                system_id=system.id,
                answers={},
                environment_type="cloud",
                # The platform is what makes inheritance derivable at all: with
                # no cloud platform nothing can be inherited, and "customer" is
                # then the correct non-guessed answer for every control.
                cloud_platform="m365_gcc_high",
                frameworks=["NIST_800_171"],
                derivation={},
            )
        )
        project = SSPProject(
            organization_id=org.id,
            system_id=system.id,
            customer_name=f"Kinds {tag}",
            platform="m365",
        )
        s.add(project)
        await s.flush()

        def entry(control_id: str, domain: str) -> SSPControlEntry:
            return SSPControlEntry(
                project_id=project.id,
                control_id=control_id,
                nist_id=control_id,
                domain=domain,
                requirement="protect the system",
                implementation_status=["Implemented"],
            )

        s.add_all(
            [
                entry("AC-2", "AC"),  # passing automated evidence
                entry("IA-2", "IA"),  # failed, with a POA&M
                entry("AU-2", "AU"),  # manual review gap
                entry(INHERITED_PRACTICE, "PE"),  # inherited
                entry("CM-7", "CM"),  # documented only -- no test at all
            ]
        )

        def test_for(control_id: str, check_key: str, status: str) -> ControlTest:
            return ControlTest(
                organization_id=org.id,
                system_id=system.id,
                control_id=control_id,
                control_ids=[control_id],
                name=f"{check_key} check",
                method="connector",
                source="generated",
                check_key=check_key,
                last_status=status,
                last_tested_at=NOW,
            )

        passing = test_for("AC-2", "demo.account.review", "pass")
        failing = test_for("IA-2", "demo.identity.mfa", "fail")
        unjudged = test_for("AU-2", "demo.audit.records", "manual_review_required")
        s.add_all([passing, failing, unjudged])
        await s.flush()

        # The POA&M the finding clause cites. Created directly rather than via a
        # scan: that path is the third acceptance criterion and is covered by
        # `test_acceptance_known_misconfigurations`. What matters here is that
        # the finding sentence carries a plan number an assessor can follow.
        s.add(
            POAM(
                system_id=system.id,
                title="MFA is not registered for every user",
                status="open",
                severity="high",
                source="control_test",
                source_ref=f"control_test:{failing.id}",
                remediation_plan="Run an authentication-methods registration campaign.",
                remediation_plan_source="generated",
            )
        )
        await s.flush()
        return org.id, system.id, project.id


async def _cleanup(org_id: int) -> None:
    async with session_scope() as s:
        await s.execute(delete(SSPProject).where(SSPProject.organization_id == org_id))
        await s.execute(delete(Organization).where(Organization.id == org_id))


async def _generate(project_id: int, system_id: int, org_id: int) -> dict[str, object]:
    """Derive, then compose -- the order the product runs them in.

    ``generate_statements`` reads responsibility out of ``profile.derivation``,
    which only ``derive_system`` fills. Composing without deriving first is not
    a shortcut: every control falls back to "customer", which is exactly how
    the inherited category silently disappeared from the first draft of this
    test. ``create_poams=False`` keeps the derivation's own gap placeholders out
    of the way, so the only POA&M in the scene is the one the finding cites.
    """
    async with session_scope() as s:
        profile = (
            await s.execute(
                select(SystemProfile).where(SystemProfile.system_id == system_id)
            )
        ).scalar_one()
        await automation_engine.derive_system(
            s, system_id=system_id, org_id=org_id, profile=profile, create_poams=False
        )
    async with session_scope() as s:
        project = await s.get(SSPProject, project_id)
        profile = (
            await s.execute(
                select(SystemProfile).where(SystemProfile.system_id == system_id)
            )
        ).scalar_one()
        return await automation_engine.generate_statements(
            s, project=project, profile=profile, mark_draft=False
        )


async def _narratives(project_id: int) -> dict[str, str]:
    async with session_scope() as s:
        entries = (
            (
                await s.execute(
                    select(SSPControlEntry).where(SSPControlEntry.project_id == project_id)
                )
            )
            .scalars()
            .all()
        )
    return {
        e.control_id: " ".join(p.get("text", "") for p in (e.part_narratives or []))
        for e in entries
    }


# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_each_kind_carries_its_own_marker_and_no_other() -> None:
    """The criterion, as one assertion per cell.

    Presence and absence are both asserted, because presence alone is the
    weaker half. A composer that appended every clause to every control would
    satisfy "distinguishes ... passing automated evidence" on a read of the
    document and be worthless.
    """
    org_id, system_id, project_id = await _scene()
    try:
        await _generate(project_id, system_id, org_id)
        narratives = await _narratives(project_id)

        expected_kind = {
            "AC-2": "passing_automated_evidence",
            "IA-2": "failed_with_poam",
            "AU-2": "manual_review_gap",
            INHERITED_PRACTICE: "inherited",
        }
        for control_id, kind in expected_kind.items():
            text = narratives[control_id]
            assert MARKERS[kind] in text, f"{control_id} is missing its {kind} marker"
            for other_kind, marker in MARKERS.items():
                if other_kind == kind:
                    continue
                assert marker not in text, (
                    f"{control_id} is a {kind} control but also reads as "
                    f"{other_kind}: {marker!r} appears in its statement"
                )
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_documented_only_control_claims_none_of_the_four() -> None:
    """The fifth kind is the absence of the other four, and it has to stay that way.

    Nothing tested CM-7 and nothing inherits it. The statement describes an
    implementation the organization asserts, and that is all it may do: a
    verification sentence here would credit a test that never ran.
    """
    org_id, system_id, project_id = await _scene()
    try:
        await _generate(project_id, system_id, org_id)
        text = (await _narratives(project_id))["CM-7"]

        assert text.strip(), "a documented-only control produced no statement at all"
        for kind, marker in MARKERS.items():
            assert marker not in text, (
                f"an untested, customer-owned control reads as {kind}: {marker!r}"
            )
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_the_finding_cites_a_plan_number_an_assessor_can_follow() -> None:
    """"Open finding" without the POA&M is a dead end in the document."""
    org_id, system_id, project_id = await _scene()
    try:
        await _generate(project_id, system_id, org_id)
        text = (await _narratives(project_id))["IA-2"]

        assert "tracked by POA&M #" in text
        assert "no POA&M on file" not in text
        # And the claim above it does not survive the finding below it.
        async with session_scope() as s:
            entry = (
                await s.execute(
                    select(SSPControlEntry).where(
                        SSPControlEntry.project_id == project_id,
                        SSPControlEntry.control_id == "IA-2",
                    )
                )
            ).scalar_one()
        assert entry.implementation_status == ["Partially Implemented"]
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_an_unassessable_control_is_not_reported_as_a_failure() -> None:
    """`manual_review_required` is not a finding, and inventing one is a defect.

    The distinction costs an assessor real time: a finding is something the
    organization must fix, while an unassessable control is something Concord
    could not reach. Collapsing the two would put remediation work on a control
    that may be operating correctly.
    """
    org_id, system_id, project_id = await _scene()
    try:
        result = await _generate(project_id, system_id, org_id)
        text = (await _narratives(project_id))["AU-2"]

        assert "rests on manual evidence" in text
        assert FINDING not in text
        assert "POA&M #" not in text
        # Counted apart from findings, not folded in with them. Note that the
        # summary's `manual_evidence_required` is a *different* measure -- it
        # counts controls no capture connector has technically verified for this
        # organization (FR-06), which is most of them here -- so the check that
        # belongs to this category is the marker, not that key.
        assert result["controls_with_open_findings"] == 1
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_the_summary_counts_agree_with_the_document() -> None:
    """The numbers a reviewer sees must be the ones the statements support.

    A count that disagrees with the text is the claim-versus-rendering defect
    in its purest form: both validate, and only one of them is read.
    """
    org_id, system_id, project_id = await _scene()
    try:
        result = await _generate(project_id, system_id, org_id)
        narratives = await _narratives(project_id)

        assert result["controls_with_open_findings"] == sum(
            1 for t in narratives.values() if FINDING in t
        )
        assert result["status_downgraded_by_findings"] == sum(
            1 for t in narratives.values() if FINDING in t
        )
        # Exactly one control of each machine-evidence kind, and the document
        # says so once each -- not zero, and not on every entry.
        assert sum(1 for t in narratives.values() if VERIFIED in t) == 1
        assert sum(1 for t in narratives.values() if MANUAL in t) == 1
        assert sum(1 for t in narratives.values() if INHERITED in t) == 1
    finally:
        await _cleanup(org_id)
