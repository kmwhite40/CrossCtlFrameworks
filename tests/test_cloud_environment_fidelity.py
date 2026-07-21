"""FR-06 / FR-07: cloud-environment fidelity in SSP generation.

FR-06 — a platform with no live capture connector (Azure, or anything else not
wired up — connectors today are M365/Graph + AWS GovCloud only, see
``ccf.ssp.platforms.CONNECTOR_PLATFORMS``) must not have its auto-composed
statements read as auto-evidenced. They must carry an explicit
manual-evidence-required flag and must not silently count toward the coverage
rollup's "covered" figure.

FR-07 — the environment label injected into auto-composed statements must
reflect the *actual* confirmed tenant tier (from the intake questionnaire's
``cloud_platform`` code carried on the SystemProfile), never a hardcoded
"GCC High" regardless of what the customer's real M365 tenant is.

These tests drive the real production path — ``derive_system`` +
``generate_ssp`` (which calls ``seed_project_entries`` and
``generate_statements``) against the real database — and assert on the actual
composed narratives and the real ``coverage()`` rollup, not on the pure
``ccf.ssp.statements.compose`` helper in isolation (see test_statements.py for
that).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance.automation import coverage, derive_system, generate_ssp
from ccf.models import (
    Organization,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
)
from ccf.ssp.platforms import (
    GOV_ENVIRONMENTS,
    MANUAL_EVIDENCE_NOTE,
    environment_for,
    has_capture_connector,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_system(session, name: str) -> System:
    org = Organization(name=name)
    session.add(org)
    await session.flush()
    sys = System(organization_id=org.id, name=f"{name} system")
    session.add(sys)
    await session.flush()
    return sys


async def _seed_controls(session, prefix: str) -> list[str]:
    """One customer-responsibility-ish domain (AC) and one physically-inherited
    domain (PE) — enough to exercise both the "unknown" and "inherited"
    responsibility branches of the platform derivation.

    Returns the ``control_id``s created so the caller can remove them again —
    ``ScoringControl`` (``ccf.scoring_controls``) is a GLOBAL, shared table and
    the suite's DB reset only runs once per session, so anything inserted here
    must be cleaned up by the test or it leaks into every later test (e.g.
    test_enterprise.py's fixed-110-row CMMC catalog assertions)."""
    control_ids = [f"AC.{prefix}-3.1.1", f"PE.{prefix}-3.10.1"]
    session.add_all(
        [
            ScoringControl(
                control_id=control_ids[0],
                nist_id=f"AC-{prefix}-1",
                domain="AC",
                title="Access Control",
                point_value="5",
                requirement="limit system access to authorized users",
                m365_coverage_status="Customer Responsibility",
                sort_order=1,
            ),
            ScoringControl(
                control_id=control_ids[1],
                nist_id=f"PE-{prefix}-1",
                domain="PE",
                title="Physical Access",
                point_value="1",
                requirement="limit physical access to organizational systems",
                m365_coverage_status="Microsoft Coverage",
                sort_order=2,
            ),
        ]
    )
    await session.flush()
    return control_ids


@asynccontextmanager
async def _seeded_system(
    name: str, prefix: str, cloud_platform: str | None
) -> AsyncIterator[tuple[SSPProject, dict, list[SSPControlEntry]]]:
    """Seed a system with a throwaway pair of prefixed ``ScoringControl`` rows,
    generate its SSP, and yield ``(proj, cov, entries)`` — then ALWAYS delete
    the ``ScoringControl`` rows this created (even if the test body raises),
    so the global catalog is left exactly as found for every other test in
    the suite."""
    control_ids: list[str] = []
    try:
        async with session_scope() as session:
            sys = await _make_system(session, name)
            control_ids = await _seed_controls(session, prefix)
            proj, cov = await _generate(session, sys, cloud_platform)
            entries = await _entries(session, proj)
        yield proj, cov, entries
    finally:
        if control_ids:
            async with session_scope() as session:
                await session.execute(
                    delete(ScoringControl).where(ScoringControl.control_id.in_(control_ids))
                )


async def _generate(
    session, sys: System, cloud_platform: str | None
) -> tuple[SSPProject, dict]:
    profile = SystemProfile(
        system_id=sys.id, environment_type="cloud", cloud_platform=cloud_platform
    )
    session.add(profile)
    await session.flush()
    await derive_system(
        session,
        system_id=sys.id,
        org_id=sys.organization_id,
        profile=profile,
        create_poams=False,
    )
    proj_id = await generate_ssp(session, system=sys, profile=profile)
    proj = await session.get(SSPProject, proj_id)
    assert proj is not None
    cov = coverage(profile)
    return proj, cov


async def _entries(session, proj: SSPProject) -> list[SSPControlEntry]:
    rows = (
        (
            await session.execute(
                select(SSPControlEntry).where(SSPControlEntry.project_id == proj.id)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


def _all_narrative_text(entries: list[SSPControlEntry]) -> str:
    chunks: list[str] = []
    for e in entries:
        for part in e.part_narratives or []:
            chunks.append(part.get("text") or "")
    return "\n".join(chunks)


# --- FR-06: no-connector platforms are flagged and excluded from "covered" --


@pytest.mark.asyncio
async def test_azure_gov_statements_are_flagged_manual_evidence_required() -> None:
    async with _seeded_system("Azure Fidelity Org 1", "AZFLAG", "azure_gov") as (
        _proj,
        _cov,
        entries,
    ):
        assert entries, "expected seeded SSP entries"
        text = _all_narrative_text(entries)
        # Every entry — including the PE (physically-inherited) one that would
        # otherwise read as already evidenced — carries the explicit flag.
        for e in entries:
            entry_text = "\n".join((p.get("text") or "") for p in e.part_narratives or [])
            assert MANUAL_EVIDENCE_NOTE in entry_text, (
                f"{e.control_id} narrative missing manual-evidence flag: {entry_text!r}"
            )
        assert "no automated capture connector exists for this platform" in text


@pytest.mark.asyncio
async def test_azure_gov_platform_inherited_state_excluded_from_covered() -> None:
    async with _seeded_system("Azure Fidelity Org 2", "AZCOV", "azure_gov") as (
        _proj,
        cov,
        _entries,
    ):
        # PE derives "inherited" for azure (PLATFORM_DOMAIN_RESPONSIBILITY), but
        # with no Azure capture connector that must not silently count as
        # "covered".
        assert cov["by_state"].get("inherited", 0) >= 1
        assert cov["covered"] == 0
        assert cov["manual_evidence_required"] >= 1


@pytest.mark.asyncio
async def test_aws_govcloud_platform_inherited_state_still_counts_covered() -> None:
    """Control: AWS GovCloud *does* have a capture connector, so the identical
    domain-responsibility shape (PE inherited) must still count as covered —
    proves the exclusion is connector-driven, not a blanket "no platform ever
    counts" regression."""
    async with _seeded_system("AWS Fidelity Org 1", "AWSCOV", "aws_govcloud") as (
        _proj,
        cov,
        entries,
    ):
        assert cov["covered"] >= 1
        assert cov["manual_evidence_required"] == 0
        text = _all_narrative_text(entries)
        assert MANUAL_EVIDENCE_NOTE not in text


# --- FR-07: environment label reflects the actual confirmed tenant tier -----


@pytest.mark.asyncio
async def test_m365_unconfirmed_tier_does_not_render_gcc_high() -> None:
    """A profile with no cloud_platform selected still authors on the "m365"
    SSP platform (generate_ssp's default), but the tenant tier was never
    confirmed via intake — must not assert GCC High."""
    async with _seeded_system("M365 Fidelity Org 1", "M365U", None) as (
        proj,
        _cov,
        entries,
    ):
        assert proj.platform == "m365"
        text = _all_narrative_text(entries)
        assert "GCC High" not in text
        assert "Microsoft 365 (tenant tier not confirmed)" in text


@pytest.mark.asyncio
async def test_m365_gcc_high_confirmed_tier_renders_gcc_high() -> None:
    async with _seeded_system("M365 Fidelity Org 2", "M365G", "m365_gcc_high") as (
        proj,
        _cov,
        entries,
    ):
        assert proj.platform == "m365"
        text = _all_narrative_text(entries)
        assert "Microsoft 365 Government (GCC High)" in text


# --- Pure unit coverage of the new ssp/platforms.py helpers -----------------


def test_has_capture_connector_matches_known_connectors() -> None:
    assert has_capture_connector("m365") is True
    assert has_capture_connector("aws_govcloud") is True
    assert has_capture_connector("azure") is False
    assert has_capture_connector("something_unrecognized") is True  # falls back to DEFAULT_PLATFORM


def test_environment_for_only_confirms_gcc_high_with_exact_intake_code() -> None:
    assert environment_for("m365", "m365_gcc_high") == "Microsoft 365 Government (GCC High)"
    assert environment_for("m365", None) == GOV_ENVIRONMENTS["m365"]
    assert environment_for("m365", "none") == GOV_ENVIRONMENTS["m365"]
    assert environment_for("m365", "azure_gov") == GOV_ENVIRONMENTS["m365"]
    assert "GCC High" not in GOV_ENVIRONMENTS["m365"]


def test_environment_for_azure_and_aws_unaffected_by_tier_param() -> None:
    assert environment_for("azure", "azure_gov") == "Microsoft Azure Government"
    assert environment_for("aws_govcloud", "aws_govcloud") == "AWS GovCloud (US)"
