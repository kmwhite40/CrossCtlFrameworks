"""`generate_statements` reaches the real control tests and POA&Ms, end to end.

The clause logic is unit-tested in ``test_ssp_cites_gaps_and_poams``; what is
pinned here is the wiring, which is where this kind of feature actually fails --
a clause that renders perfectly from a hand-built list and is never given one.
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
from ccf.governance.automation import generate_statements
from ccf.models import (
    POAM,
    Organization,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
)
from ccf.models_grc import ControlTest
from ccf.ssp.completeness_query import project_completeness

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _scene(
    *,
    tests: list[tuple[str, str]],
    with_poam_for: str | None = None,
    entry_status: list[str] | None = None,
) -> tuple[int, int, int, dict[str, int]]:
    """An org/system/project with one entry per tested control.

    ``tests`` is ``[(control_id, last_status), ...]``. Returns
    ``(org_id, system_id, project_id, {control_id: test_id})``.
    """
    tag = f"{next(_SEQ)}"
    test_ids: dict[str, int] = {}
    async with session_scope() as s:
        org = Organization(name=f"GapWire Org {tag}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"GapWire Sys {tag}")
        s.add(sys_)
        await s.flush()
        s.add(SystemProfile(system_id=sys_.id, cloud_platform="m365_gcc_high", derivation={}))
        proj = SSPProject(
            organization_id=org.id,
            system_id=sys_.id,
            customer_name="GapWire",
            platform="m365",
        )
        s.add(proj)
        await s.flush()
        for control_id, status in tests:
            s.add(
                SSPControlEntry(
                    project_id=proj.id,
                    control_id=control_id,
                    nist_id=control_id,
                    domain=control_id.split("-")[0],
                    requirement="manage system accounts",
                    implementation_status=list(entry_status or []),
                )
            )
            test = ControlTest(
                organization_id=org.id,
                system_id=sys_.id,
                control_id=control_id,
                name=f"{control_id} automated check",
                method="connector",
                source="generated",
                check_key=f"k.{control_id}",
                last_status=status,
                last_tested_at=datetime(2026, 9, 26, tzinfo=UTC),
            )
            s.add(test)
            await s.flush()
            test_ids[control_id] = test.id
        if with_poam_for is not None:
            s.add(
                POAM(
                    system_id=sys_.id,
                    title=f"{with_poam_for} weakness",
                    severity="high",
                    status="open",
                    source="control_test",
                    source_ref=f"control_test:{test_ids[with_poam_for]}",
                    identified_on=datetime(2026, 9, 26, tzinfo=UTC).date(),
                )
            )
        await s.flush()
        return org.id, sys_.id, proj.id, test_ids


async def _generate(project_id: int, system_id: int, **kw: object) -> dict[str, object]:
    async with session_scope() as s:
        proj = await s.get(SSPProject, project_id)
        profile = (
            await s.execute(select(SystemProfile).where(SystemProfile.system_id == system_id))
        ).scalar_one()
        return await generate_statements(s, project=proj, profile=profile, **kw)  # type: ignore[arg-type]


async def _entry(project_id: int, control_id: str) -> SSPControlEntry:
    async with session_scope() as s:
        return (
            await s.execute(
                select(SSPControlEntry).where(
                    SSPControlEntry.project_id == project_id,
                    SSPControlEntry.control_id == control_id,
                )
            )
        ).scalar_one()


async def _cleanup(org_id: int) -> None:
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id == org_id))


@pytest.mark.asyncio
async def test_a_failing_control_tests_poam_number_reaches_the_statement() -> None:
    org_id, sys_id, proj_id, _ = await _scene(
        tests=[("AC-2", "fail")], with_poam_for="AC-2"
    )
    try:
        result = await _generate(proj_id, sys_id, mark_draft=False)
        entry = await _entry(proj_id, "AC-2")
        async with session_scope() as s:
            poam = (
                await s.execute(select(POAM).where(POAM.system_id == sys_id))
            ).scalars().one()
        text = entry.part_narratives[0]["text"]
        assert "Open finding" in text
        assert "AC-2 automated check failed on 2026-09-26" in text
        assert f"POA&M #{poam.id}" in text, "the POA&M was never looked up"
        assert result["controls_with_open_findings"] == 1
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_failing_control_with_no_poam_says_none_is_on_file() -> None:
    org_id, sys_id, proj_id, _ = await _scene(tests=[("AC-3", "fail")])
    try:
        await _generate(proj_id, sys_id, mark_draft=False)
        text = (await _entry(proj_id, "AC-3")).part_narratives[0]["text"]
        assert "no POA&M on file" in text
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_closed_poam_is_not_cited_as_tracking_the_finding() -> None:
    """A closed plan tracks nothing. Citing it would tell an assessor the
    weakness is being worked when nobody is working it."""
    org_id, sys_id, proj_id, _test_ids = await _scene(
        tests=[("AC-6", "fail")], with_poam_for="AC-6"
    )
    try:
        async with session_scope() as s:
            poam = (
                await s.execute(select(POAM).where(POAM.system_id == sys_id))
            ).scalars().one()
            poam.status = "closed"
        await _generate(proj_id, sys_id, mark_draft=False)
        text = (await _entry(proj_id, "AC-6")).part_narratives[0]["text"]
        assert "no POA&M on file" in text
        assert "POA&M #" not in text
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_warning_is_disclosed_as_a_finding_not_as_unassessable() -> None:
    """A `warn` is the platform saying the control is not operating as expected.

    Routing it to the unassessable bucket would have the SSP claim Concord could
    not assess a control it assessed and did not like.
    """
    org_id, sys_id, proj_id, _ = await _scene(tests=[("AU-6", "warn")])
    try:
        result = await _generate(proj_id, sys_id, mark_draft=False)
        text = (await _entry(proj_id, "AU-6")).part_narratives[0]["text"]
        assert "Open finding" in text
        assert "Not machine-verified" not in text
        assert result["controls_with_open_findings"] == 1
        assert result["controls_not_machine_verified"] == 0
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_an_unassessable_control_is_disclosed_as_resting_on_manual_evidence() -> None:
    org_id, sys_id, proj_id, _ = await _scene(
        tests=[("SC-8", "manual_review_required")]
    )
    try:
        result = await _generate(proj_id, sys_id, mark_draft=False)
        text = (await _entry(proj_id, "SC-8")).part_narratives[0]["text"]
        assert "Not machine-verified" in text
        assert "Open finding" not in text
        assert result["controls_not_machine_verified"] == 1
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_failing_control_cannot_keep_claiming_implemented() -> None:
    """The status column is what an assessor samples on.

    Leaving "Implemented" beside a narrative describing an open finding would put
    the contradiction into the docx and the OSCAL export, not just a paragraph.
    """
    org_id, sys_id, proj_id, _ = await _scene(
        tests=[("IA-2", "fail")], entry_status=["Implemented"]
    )
    try:
        result = await _generate(proj_id, sys_id, mark_draft=False)
        entry = await _entry(proj_id, "IA-2")
        assert entry.implementation_status == ["Partially Implemented"]
        assert result["status_downgraded_by_findings"] == 1
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_passing_control_keeps_the_status_it_was_given() -> None:
    """The downgrade must be caused by the finding, not by running at all."""
    org_id, sys_id, proj_id, _ = await _scene(
        tests=[("AC-17", "pass")], entry_status=["Implemented"]
    )
    try:
        result = await _generate(proj_id, sys_id, mark_draft=False)
        entry = await _entry(proj_id, "AC-17")
        assert entry.implementation_status == ["Implemented"]
        assert result["status_downgraded_by_findings"] == 0
        assert "Verified by automated testing" in entry.part_narratives[0]["text"]
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_another_tenants_failing_test_is_not_cited_in_this_ssp() -> None:
    org_id, _sys_id, proj_id, _ = await _scene(tests=[("AC-2", "pass")])
    other_org, _other_sys, _other_proj, _ = await _scene(tests=[("AC-2", "fail")])
    try:
        async with session_scope() as s:
            proj = await s.get(SSPProject, proj_id)
            profile = (
                await s.execute(
                    select(SystemProfile).where(SystemProfile.system_id == proj.system_id)
                )
            ).scalar_one()
            result = await generate_statements(
                s, project=proj, profile=profile, mark_draft=False
            )
        text = (await _entry(proj_id, "AC-2")).part_narratives[0]["text"]
        assert "Open finding" not in text, "another tenant's failure reached this SSP"
        assert result["controls_with_open_findings"] == 0
    finally:
        await _cleanup(org_id)
        await _cleanup(other_org)


@pytest.mark.asyncio
async def test_the_readiness_gate_reads_the_same_findings_the_narrative_does() -> None:
    """The gate and the paragraph must not disagree about what counts as a gap."""
    org_id, _sys_id, proj_id, _ = await _scene(
        tests=[("AC-2", "fail"), ("SC-8", "manual_review_required")],
        with_poam_for="AC-2",
    )
    try:
        async with session_scope() as s:
            proj = await s.get(SSPProject, proj_id)
            report = await project_completeness(s, proj)
        blockers = " | ".join(report["readiness_blockers"])
        assert "1 control(s) have an open finding" in blockers
        assert "1 control(s) could not be assessed" in blockers
        assert "open high-severity POA&M(s)" in blockers
        assert report["ready"] is False
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_control_with_both_a_failure_and_a_warning_counts_once() -> None:
    """Three failing checks on one control is one control an assessor cannot
    accept; reporting three would overstate the breadth of the problem."""
    org_id, sys_id, proj_id, _ = await _scene(tests=[("AC-2", "fail")])
    try:
        async with session_scope() as s:
            s.add(
                ControlTest(
                    organization_id=org_id,
                    system_id=sys_id,
                    control_id="AC-2",
                    name="AC-2 second check",
                    method="connector",
                    source="generated",
                    check_key="k.AC-2.second",
                    last_status="warn",
                    last_tested_at=datetime(2026, 9, 26, tzinfo=UTC),
                )
            )
        async with session_scope() as s:
            proj = await s.get(SSPProject, proj_id)
            report = await project_completeness(s, proj)
        assert "1 control(s) have an open finding" in " | ".join(
            report["readiness_blockers"]
        )
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_missing_responsibility_template_coverage_blocks_ssp_readiness() -> None:
    """The DB-backed readiness gate must enforce the provider template gap."""
    org_id, _sys_id, proj_id, _ = await _scene(tests=[("AC-2", "pass")])
    try:
        async with session_scope() as s:
            proj = await s.get(SSPProject, proj_id)
            proj.platform = "aws_govcloud"

        async with session_scope() as s:
            report = await project_completeness(s, await s.get(SSPProject, proj_id))
        blockers = " | ".join(report["readiness_blockers"])
        assert "shared-responsibility template" in blockers
        assert report["ready"] is False
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_project_with_no_linked_system_reports_its_gate_unmeasured() -> None:
    """Nothing scanned, no POA&Ms to reach — so the conditions are unobservable.

    Returning all-zero counts here would make the report say "no blockers", which
    reads as conditions cleared. The DB half has to pass `None` for the pure
    layer's `readiness_measured` to mean anything.
    """
    tag = f"{next(_SEQ)}"
    async with session_scope() as s:
        org = Organization(name=f"GapWire NoSys {tag}")
        s.add(org)
        await s.flush()
        proj = SSPProject(
            organization_id=org.id, system_id=None, customer_name="NoSys", platform="m365"
        )
        s.add(proj)
        await s.flush()
        org_id, proj_id = org.id, proj.id
    try:
        async with session_scope() as s:
            report = await project_completeness(s, await s.get(SSPProject, proj_id))
        assert report["readiness_measured"] is False
        assert report["readiness_blockers"] == []
        assert any("no system linked" in n for n in report["not_yet_gated"])
    finally:
        await _cleanup(org_id)
