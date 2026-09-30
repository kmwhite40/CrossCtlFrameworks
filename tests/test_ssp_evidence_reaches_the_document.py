"""Posture verdicts must reach the SSP, or the SSP must say they did not.

Found by generating a real SSP for a real tenant. Organization 2's Microsoft 365
system has fourteen live posture verdicts -- ten passing, four failing, including
seven of seventy-nine users without MFA and unrestricted guest invitations. The
generated SSP reported:

    entries                      : 110
    controls_with_open_findings  : 0

A clean authorization package over a system with four open findings.

**Why the existing tests did not catch it.** The composer looks evidence up per
entry, keyed on `SSPControlEntry.control_id`. Posture checks declare NIST 800-53
control ids (`AC-2`, `IA-2`); a CMMC project's entries are practice ids
(`AC.L2-3.1.1`), seeded from `ccf.scoring_controls` by `seed_project_entries`.
The two vocabularies do not intersect -- measured against the live database, 2
of 110 entry ids matched any control test at all, and both of those came from
hand-authored tests rather than from any scan.

`test_acceptance_ssp_distinguishes_control_kinds.py` passes because it builds
its entries **by hand with 800-53 ids** (`entry("IA-2", "IA")`). That is a
spelling `seed_project_entries` never produces, so the fixture could not express
the defect: it proved the finding clause renders, not that a real project ever
reaches it. This file therefore seeds through the real path, which is the whole
point of it existing separately.

**What is fixed here and what is not.** Making a posture check's verdict land on
a CMMC practice needs the check to declare which practices it evidences -- a
compliance mapping, and one the catalog crosswalk cannot supply (it reaches 14
of 32 checks and none of the four that are failing). That mapping is not
invented here.

What is fixed is the silence. `controls_with_open_findings: 0` meant "nothing is
failing" and "seven controls are failing under names this document does not use"
identically, and the second rendered as the first. `findings_unmatched_controls`
now makes them different numbers.
"""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import delete, select

from ccf.db import session_scope
from ccf.governance.automation import generate_statements
from ccf.models import (
    Organization,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
)
from ccf.models_grc import ControlTest
from ccf.scoring.seed import seed_scoring_controls
from ccf.ssp.seed import seed_project_entries

_SEQ = itertools.count()


async def _cmmc_project_with_a_failing_check(
    *, extra_entry_control_id: str | None = None
) -> dict[str, object]:
    """One CMMC project seeded the real way, plus one failing posture verdict.

    The verdict is keyed the way a scan keys it -- `control_id="IA-2"` with the
    full declared set in `control_ids` -- because that is the shape the defect
    lives in. A fixture that wrote a practice id here could not fail.
    """
    tag = f"{next(_SEQ)}"
    async with session_scope() as session:
        await seed_scoring_controls(session)

    async with session_scope() as session:
        org = Organization(name=f"EvidenceReach-{tag}")
        session.add(org)
        await session.flush()
        system = System(organization_id=org.id, name=f"EvidenceReachSys-{tag}")
        session.add(system)
        await session.flush()
        profile = SystemProfile(
            system_id=system.id,
            answers={},
            environment_type="cloud",
            cloud_platform="m365_gcc_high",
            frameworks=["NIST_800_171"],
            derivation={},
        )
        session.add(profile)
        project = SSPProject(
            organization_id=org.id,
            system_id=system.id,
            customer_name=f"EvidenceReach {tag}",
            platform="m365",
            framework="cmmc-800-171",
        )
        session.add(project)
        await session.flush()
        await seed_project_entries(session, project)

        session.add(
            ControlTest(
                organization_id=org.id,
                system_id=system.id,
                name="m365.identity.mfa_registered",
                check_key="m365.identity.mfa_registered",
                source="generated",
                control_id="IA-2",
                control_ids=["IA-2", "IA-2(1)"],
                last_status="fail",
                method="api",
            )
        )
        if extra_entry_control_id:
            # An entry keyed the way the evidence is keyed, to show the
            # unmatched count is about the vocabularies and not about the
            # evidence being absent.
            session.add(
                SSPControlEntry(
                    project_id=project.id,
                    control_id=extra_entry_control_id,
                    nist_id=extra_entry_control_id,
                    domain="IA",
                    requirement="identify and authenticate users",
                    implementation_status=["Implemented"],
                )
            )
        await session.flush()
        result = await generate_statements(
            session, project=project, profile=profile, include_captured=True
        )
        project_id, org_id = project.id, org.id
        await session.commit()

    return {"result": result, "project_id": project_id, "org_id": org_id}


async def _cleanup(project_id: int, org_id: int) -> None:
    async with session_scope() as session:
        await session.execute(
            delete(SSPControlEntry).where(SSPControlEntry.project_id == project_id)
        )
        await session.execute(delete(SSPProject).where(SSPProject.id == project_id))
        await session.execute(delete(ControlTest).where(ControlTest.organization_id == org_id))
        systems = (
            await session.execute(select(System.id).where(System.organization_id == org_id))
        ).scalars().all()
        if systems:
            await session.execute(
                delete(SystemProfile).where(SystemProfile.system_id.in_(systems))
            )
            await session.execute(delete(System).where(System.id.in_(systems)))
        await session.execute(delete(Organization).where(Organization.id == org_id))


@pytest.mark.asyncio
async def test_a_failing_check_that_reaches_no_entry_is_reported_not_swallowed() -> None:
    """The defect, through the real CMMC seeding path."""
    made = await _cmmc_project_with_a_failing_check()
    try:
        result = made["result"]
        assert isinstance(result, dict)

        # The entries really are practice ids -- if this ever stops being true
        # the test has stopped reproducing the situation it was written for.
        async with session_scope() as session:
            ids = (
                await session.execute(
                    select(SSPControlEntry.control_id).where(
                        SSPControlEntry.project_id == made["project_id"]
                    )
                )
            ).scalars().all()
        assert any(i.startswith("AC.L2-") for i in ids), (
            "seed_project_entries no longer produces CMMC practice ids; this "
            "test's premise is gone"
        )
        assert "IA-2" not in ids

        # The finding exists and lands on no entry, so the per-entry count is
        # zero -- and the new field is what makes that zero readable.
        assert result["controls_with_open_findings"] == 0
        assert set(result["findings_unmatched_controls"]) == {"IA-2", "IA-2(1)"}, (
            "a failing check naming controls this SSP does not use must be "
            "reported; otherwise the document reads clean"
        )
        assert "IA-2" in result["evidence_unmatched_controls"]
    finally:
        await _cleanup(int(made["project_id"]), int(made["org_id"]))  # type: ignore[call-overload]


@pytest.mark.asyncio
async def test_evidence_that_does_reach_an_entry_is_not_reported_as_unmatched() -> None:
    """The other direction, so the field cannot be a constant.

    Add one entry keyed the way the evidence is keyed. The finding then attaches
    to it, `controls_with_open_findings` rises, and only the control ids that
    still match nothing remain unmatched.
    """
    made = await _cmmc_project_with_a_failing_check(extra_entry_control_id="IA-2")
    try:
        result = made["result"]
        assert isinstance(result, dict)
        assert result["controls_with_open_findings"] == 1, (
            "the finding should have attached to the entry sharing its id"
        )
        assert "IA-2" not in result["findings_unmatched_controls"]
        # IA-2(1) is still declared by the check and still has no entry, so it
        # stays reported -- the field tracks control ids, not whole checks.
        assert "IA-2(1)" in result["findings_unmatched_controls"]
    finally:
        await _cleanup(int(made["project_id"]), int(made["org_id"]))  # type: ignore[call-overload]


@pytest.mark.asyncio
async def test_the_unmatched_list_names_controls_rather_than_counting_them() -> None:
    """A count tells an operator something is wrong; a list tells them what.

    The lesson recorded in `ccf.cr26.sdr` and applied in `generate_statements`'
    `preserved_authored`: report the ids, because the next question is always
    "which ones".
    """
    made = await _cmmc_project_with_a_failing_check()
    try:
        result = made["result"]
        assert isinstance(result, dict)
        for key in ("evidence_unmatched_controls", "findings_unmatched_controls"):
            value = result[key]
            assert isinstance(value, list), f"{key} must be a list of control ids"
            assert value == sorted(value), f"{key} must be stably ordered"
            assert all(isinstance(v, str) and v for v in value)
    finally:
        await _cleanup(int(made["project_id"]), int(made["org_id"]))  # type: ignore[call-overload]
