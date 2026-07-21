"""SSP control origination must reflect who actually performs the control on
the project's SELECTED platform — not always the Microsoft 365 placemat split
(FR-04/FR-05/FR-12).

Exercises the real production seeding path (``ccf.ssp.seed.seed_project_entries``,
the same function ``POST /api/ssp/projects`` and the reseed route call) against
the real scoring catalog and real ``SSPProject``/``SSPControlEntry`` rows — not a
synthetic entry shape — so a regression in the actual seeding pipeline fails
these tests, not just a hand-built unit-test double.
"""

from __future__ import annotations

import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, SSPControlEntry, SSPProject
from ccf.scoring.seed import seed_scoring_controls
from ccf.ssp import constants
from ccf.ssp.seed import seed_project_entries

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_project(platform: str) -> int:
    """Seed the real scoring catalog and a real SSP project on ``platform``
    through the production seeding function; return the project id."""
    async with session_scope() as s:
        await seed_scoring_controls(s)
        org = Organization(name=f"{platform} Org {uuid.uuid4().hex[:8]}")
        s.add(org)
        await s.flush()
        proj = SSPProject(
            organization_id=org.id,
            customer_name="Acme Co",
            system_name="Acme Sys",
            platform=platform,
        )
        s.add(proj)
        await s.flush()
        await seed_project_entries(s, proj)
        return proj.id


async def _entries_by_control(project_id: int) -> dict[str, SSPControlEntry]:
    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(SSPControlEntry).where(SSPControlEntry.project_id == project_id)
                )
            )
            .scalars()
            .all()
        )
        return {r.control_id: r for r in rows}


@pytest.mark.asyncio
async def test_aws_origination_is_independent_of_m365_coverage() -> None:
    """CM.L2-3.4.1 is 'Customer Responsibility' under the M365 placemat, so the
    M365 project's origination is 'Configured by Customer / Business Owner'.
    AWS GovCloud's CM (Configuration Management) domain is a known
    provider/customer *shared* domain (AWS Config / Systems Manager co-manage
    it) — the AWS project's origination must be 'Shared', not a copy of M365's
    value and not silently defaulted to customer/system-specific."""
    m365_id = await _make_project("m365")
    aws_id = await _make_project("aws_govcloud")

    m365_entries = await _entries_by_control(m365_id)
    aws_entries = await _entries_by_control(aws_id)

    m365_cm = m365_entries["CM.L2-3.4.1"]
    aws_cm = aws_entries["CM.L2-3.4.1"]

    assert m365_cm.control_origination == ["Configured by Customer / Business Owner"]
    assert aws_cm.control_origination == ["Shared"]
    assert aws_cm.control_origination != m365_cm.control_origination


@pytest.mark.asyncio
async def test_provider_performed_control_is_inherited_and_names_provider() -> None:
    """PE (Physical Protection) is provider-performed on AWS GovCloud — the
    origination column must render Inherited, never
    'Organization System Specific' / a customer-implemented value, and the
    narrative must name AWS specifically rather than a generic statement."""
    aws_id = await _make_project("aws_govcloud")
    entries = await _entries_by_control(aws_id)

    pe = entries["PE.L2-3.10.1"]
    assert pe.control_origination == ["Inherited"]
    assert "Organization System Specific" not in pe.control_origination
    assert "Configured by Customer / Business Owner" not in pe.control_origination

    narrative_text = " ".join(p["text"] for p in pe.part_narratives)
    assert "AWS GovCloud" in narrative_text


@pytest.mark.asyncio
async def test_azure_provider_performed_control_names_azure_not_aws() -> None:
    """The same PE control on Azure must name Azure, not AWS or a generic
    'the cloud provider' — proves origination/narrative are keyed off the
    project's actual platform, not a shared fallback."""
    azure_id = await _make_project("azure")
    entries = await _entries_by_control(azure_id)

    pe = entries["PE.L2-3.10.1"]
    assert pe.control_origination == ["Inherited"]
    narrative_text = " ".join(p["text"] for p in pe.part_narratives)
    assert "Azure Government" in narrative_text
    assert "AWS" not in narrative_text


@pytest.mark.asyncio
async def test_non_m365_control_without_per_control_coverage_is_flagged_for_manual_assignment() -> (
    None
):
    """AC (Access Control) has no per-control (M365-only) or per-domain (AWS/
    Azure domain table) coverage data for AWS GovCloud — seeding must not
    silently default it to a customer/system-specific origination; it must be
    flagged so a human assigns responsibility explicitly."""
    aws_id = await _make_project("aws_govcloud")
    entries = await _entries_by_control(aws_id)

    ac = entries["AC.L2-3.1.1"]
    assert ac.control_origination == []
    assert constants.MANUAL_RESPONSIBILITY_FLAG in (ac.responsible_role or "")


@pytest.mark.asyncio
async def test_m365_project_is_unaffected_by_the_platform_derivation_change() -> None:
    """Regression guard: Microsoft 365 projects must keep using the M365
    placemat's per-practice coverage status exactly as before — the new
    per-platform logic must not touch the m365 code path's values."""
    m365_id = await _make_project("m365")
    entries = await _entries_by_control(m365_id)

    # PE is "Microsoft Coverage" in the placemat -> Inherited, and AC.L2-3.1.1 is
    # "Shared Coverage" -> Shared, both computed from constants.default_origination,
    # not the new per-platform domain table.
    assert entries["PE.L2-3.10.1"].control_origination == ["Inherited"]
    assert entries["AC.L2-3.1.1"].control_origination == ["Shared"]
    assert constants.MANUAL_RESPONSIBILITY_FLAG not in (
        entries["AC.L2-3.1.1"].responsible_role or ""
    )
