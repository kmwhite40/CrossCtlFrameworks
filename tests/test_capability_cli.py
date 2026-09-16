"""The capability CLI group and the scheduler's per-tenant derive step."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

from typer.testing import CliRunner

from ccf.capability.derive import derive_for_org
from ccf.cli import app
from ccf.db import session_scope
from ccf.models import Organization, System

runner = CliRunner()
_SEQ = itertools.count()


def test_capability_derive_is_registered() -> None:
    result = runner.invoke(app, ["capability", "derive", "--help"])
    assert result.exit_code == 0
    assert "system" in result.stdout


def test_existing_catalog_group_still_registered() -> None:
    """A new Typer group must not displace the ones already there."""
    assert runner.invoke(app, ["catalog", "revisions", "--help"]).exit_code == 0


async def test_derive_for_org_summarises_its_systems() -> None:
    async with session_scope() as session:
        org = Organization(name=f"OrgDerive-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        for _ in range(2):
            session.add(System(organization_id=org.id, name=f"S-{next(_SEQ)}"))
        await session.flush()

        out = await derive_for_org(session, organization_id=org.id)
        assert out == {"organization_id": org.id, "systems": 2, "rows_annotated": 0}


async def test_derive_for_org_skips_soft_deleted_systems() -> None:
    async with session_scope() as session:
        org = Organization(name=f"OrgDerive-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        session.add(System(organization_id=org.id, name=f"live-{next(_SEQ)}"))
        session.add(
            System(
                organization_id=org.id,
                name=f"gone-{next(_SEQ)}",
                deleted_at=datetime.now(UTC),
            )
        )
        await session.flush()

        out = await derive_for_org(session, organization_id=org.id)
        assert out["systems"] == 1  # a deleted system derives nothing


async def test_derive_for_org_with_no_systems_is_a_noop() -> None:
    async with session_scope() as session:
        org = Organization(name=f"OrgDerive-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        out = await derive_for_org(session, organization_id=org.id)
        assert out == {"organization_id": org.id, "systems": 0, "rows_annotated": 0}
