""""No cloud platform" is an answer, not a missing value.

See ``docs/superpowers/specs/2026-09-21-platform-default-design.md``.

The intake questionnaire offers ``none`` as one of four answers to "Primary
cloud platform?". Before this change every answer Concord did not recognize --
including ``none``, which the product itself offers -- was coerced to ``m365``
at three separate layers, so a customer who runs no cloud at all received an
SSP naming Entra ID, Purview and Intune as the mechanisms implementing their
controls.

Every fixture in this module is deliberately free of vendor and product names,
so an assertion that "no Microsoft or AWS service name appears" cannot be
satisfied -- or defeated -- by the fixture's own text.
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
from ccf.governance.automation import derive_system, generate_ssp
from ccf.models import (
    Organization,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
)
from ccf.ssp.platforms import platform_label

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# Product / vendor tokens that must never appear in a narrative drafted for a
# system that declared no cloud platform. Deliberately short and generic --
# the exhaustive, catalog-driven version of this assertion lives in
# ``test_no_other_platform_services_are_drafted_for_none`` below.
_PRODUCT_TOKENS = ("Microsoft", "Entra", "Purview", "Intune", "Defender", "Azure", "AWS")


async def _make_system(session, name: str) -> System:
    org = Organization(name=name)
    session.add(org)
    await session.flush()
    sys_row = System(organization_id=org.id, name=f"{name} system")
    session.add(sys_row)
    await session.flush()
    return sys_row


async def _seed_controls(session, prefix: str) -> list[str]:
    """Two throwaway scoring controls whose own text names no product.

    ``ccf.scoring_controls`` is a GLOBAL table and the suite resets the schema
    only once per session, so these rows are always deleted again by
    :func:`_seeded_none_system`'s ``finally``.
    """
    control_ids = [f"AC.{prefix}-3.1.1", f"SC.{prefix}-3.13.1"]
    session.add_all(
        [
            ScoringControl(
                control_id=control_ids[0],
                nist_id=f"AC-{prefix}-1",
                domain="AC",
                title="Account Management",
                point_value="5",
                requirement="limit system access to authorized users",
                objective_parts=[{"label": "[a]", "text": "authorized users are identified"}],
                sort_order=1,
            ),
            ScoringControl(
                control_id=control_ids[1],
                nist_id=f"SC-{prefix}-1",
                domain="SC",
                title="Boundary Protection",
                point_value="5",
                requirement="monitor and control communications at the system boundary",
                objective_parts=[{"label": "[a]", "text": "the system boundary is defined"}],
                sort_order=2,
            ),
        ]
    )
    await session.flush()
    return control_ids


@asynccontextmanager
async def _seeded_system(
    name: str, prefix: str, cloud_platform: str | None
) -> AsyncIterator[tuple[SSPProject, list[SSPControlEntry]]]:
    control_ids: list[str] = []
    try:
        async with session_scope() as session:
            sys_row = await _make_system(session, name)
            control_ids = await _seed_controls(session, prefix)
            profile = SystemProfile(
                system_id=sys_row.id,
                environment_type="on_prem",
                cloud_platform=cloud_platform,
            )
            session.add(profile)
            await session.flush()
            await derive_system(
                session,
                system_id=sys_row.id,
                org_id=sys_row.organization_id,
                profile=profile,
                create_poams=False,
            )
            proj_id = await generate_ssp(session, system=sys_row, profile=profile)
            proj = await session.get(SSPProject, proj_id)
            assert proj is not None
            entries = list(
                (
                    await session.execute(
                        select(SSPControlEntry).where(SSPControlEntry.project_id == proj.id)
                    )
                )
                .scalars()
                .all()
            )
        yield proj, entries
    finally:
        if control_ids:
            async with session_scope() as session:
                await session.execute(
                    delete(ScoringControl).where(ScoringControl.control_id.in_(control_ids))
                )


def _narrative_text(entries: list[SSPControlEntry]) -> str:
    return "\n".join(
        (part.get("text") or "")
        for e in entries
        for part in (e.part_narratives or [])
    )


# --- spec §4.1: the headline case, pinned -----------------------------------


@pytest.mark.asyncio
async def test_declared_none_yields_a_project_that_names_no_product() -> None:
    """A customer who answers "none" must not receive a Microsoft 365 SSP.

    ``none`` is one of the four answers the questionnaire itself offers
    (``QUESTIONNAIRE``'s ``cloud_platform`` options), so this is not an edge
    case -- it is a supported answer whose translation was wrong.
    """
    async with _seeded_system("No Platform Org 1", "NPHEAD", "none") as (proj, entries):
        assert proj.platform == "none", (
            f"declared 'none' but the project stored platform {proj.platform!r}"
        )
        label = platform_label(proj.platform)
        for token in _PRODUCT_TOKENS:
            assert token.lower() not in label.lower(), (
                f"platform label {label!r} names the product {token!r}"
            )
        assert entries, "expected seeded SSP entries"
        text = _narrative_text(entries)
        for token in _PRODUCT_TOKENS:
            assert token.lower() not in text.lower(), (
                f"a statement drafted for a system with no cloud platform names "
                f"{token!r}:\n{text}"
            )
