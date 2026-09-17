"""The pack-source row and the defaults that keep GitOps gated."""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_packs import PackSource

# Rows in catalog_sources / pack_sources are polled by scheduler.run_cycle(),
# so they must not outlive the test that made them -- see the fixture.
pytestmark = pytest.mark.usefixtures("isolate_source_rows")

_SEQ = itertools.count()


async def _org(session) -> Organization:
    org = Organization(name=f"PackSourceOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    return org


async def test_a_source_round_trips() -> None:
    async with session_scope() as session:
        org = await _org(session)
        src = PackSource(
            organization_id=org.id,
            pack_key="acme-baseline",
            url="https://raw.githubusercontent.com/acme/compliance/main/pack.json",
            ref="main",
        )
        session.add(src)
        await session.flush()
        got = (
            await session.execute(select(PackSource).where(PackSource.id == src.id))
        ).scalar_one()
        assert got.pack_key == "acme-baseline"
        assert got.ref == "main"


async def test_polling_is_enabled_but_installing_is_not() -> None:
    """The gate, asserted as a default rather than left to documentation."""
    async with session_scope() as session:
        org = await _org(session)
        src = PackSource(organization_id=org.id, pack_key="p", url="file:///tmp/p.json")
        session.add(src)
        await session.flush()
        assert src.enabled is True
        assert src.auto_install is False


async def test_nothing_is_pending_on_a_new_source() -> None:
    async with session_scope() as session:
        org = await _org(session)
        src = PackSource(organization_id=org.id, pack_key="p", url="file:///tmp/p.json")
        session.add(src)
        await session.flush()
        assert src.pending_manifest == {}
        assert src.pending_sha256 is None
        assert src.last_status is None


async def test_the_same_url_cannot_be_registered_twice_for_one_tenant() -> None:
    """Two sources for one pack at one URL would poll and install in a race."""
    async with session_scope() as session:
        org = await _org(session)
        for _ in range(2):
            session.add(
                PackSource(
                    organization_id=org.id, pack_key="p", url="file:///tmp/same.json"
                )
            )
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_two_tenants_may_register_the_same_url() -> None:
    """A shared upstream baseline is a legitimate arrangement."""
    async with session_scope() as session:
        a, b = await _org(session), await _org(session)
        for org in (a, b):
            session.add(
                PackSource(
                    organization_id=org.id, pack_key="p", url="file:///tmp/shared.json"
                )
            )
        await session.flush()
        rows = (
            await session.execute(
                select(PackSource).where(PackSource.url == "file:///tmp/shared.json")
            )
        ).scalars().all()
        assert {r.organization_id for r in rows} >= {a.id, b.id}
