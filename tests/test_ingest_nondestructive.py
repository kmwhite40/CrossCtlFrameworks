"""Re-ingesting must not delete the controls other tables point at.

``ingest_workbook`` used to open with ``DELETE FROM controls``. That was correct
while the database held nothing but catalog data. It stopped being correct the
moment SSP authoring created its first ``control_implementations`` row, and the
two failure modes are not equally kind:

    control_implementations   ON DELETE RESTRICT   the run fails and rolls back
    poams.control_id          ON DELETE SET NULL   the link is severed, silently
    risks.control_id          ON DELETE SET NULL   the link is severed, silently

The RESTRICT is what surfaced the problem on the deployed database — ``ccf
ingest`` aborted with a ForeignKeyViolationError. The SET NULLs are the ones
worth writing tests about, because nothing would have told anyone.

The load now matches on ``controls.identifier`` (UNIQUE) and updates in place,
so ids survive. A control the workbook has dropped is retired only when nothing
refers to it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ccf.config import get_settings
from ccf.etl import ingest_workbook
from ccf.etl.pipeline import _CONTROL_DEPENDANTS
from ccf.models import (
    POAM,
    Control,
    ControlImplementation,
    FrameworkMapping,
    Organization,
    Risk,
    System,
)


@pytest.fixture(scope="module", autouse=True)
def apply_migrations() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


@pytest.fixture
def session_factory() -> async_sessionmaker:
    engine = create_async_engine(str(get_settings().database_url))
    return async_sessionmaker(engine, expire_on_commit=False)


async def _a_control(session) -> Control:
    return (
        await session.execute(select(Control).order_by(Control.id).limit(1))
    ).scalars().one()


async def _a_system(session) -> System:
    """Get-or-create: these tests commit, so the org outlives each one."""
    org = (
        await session.execute(select(Organization).where(Organization.name == "Reingest Org"))
    ).scalar_one_or_none()
    if org is None:
        org = Organization(name="Reingest Org")
        session.add(org)
        await session.flush()
    system = (
        await session.execute(
            select(System).where(
                System.organization_id == org.id, System.name == "Reingest System"
            )
        )
    ).scalar_one_or_none()
    if system is None:
        system = System(organization_id=org.id, name="Reingest System")
        session.add(system)
        await session.flush()
    return system


# --- the delete is gone ------------------------------------------------------


def test_the_pipeline_no_longer_deletes_controls() -> None:
    """Pinned at the source, because the damage is invisible in a green run.

    A re-ingest with the delete restored would still pass every count assertion
    in ``test_ingest.py`` — the catalog reloads correctly. What it destroys is
    everything *pointing at* the catalog, and only these tests notice.
    """
    src = (Path(__file__).resolve().parents[1] / "src" / "ccf" / "etl" / "pipeline.py").read_text(
        encoding="utf-8"
    )
    assert "delete(Control)" not in src, "controls are being wiped again"
    assert "delete(FrameworkMapping)" in src, "mappings are still replaced wholesale"


def test_every_non_cascading_dependant_is_covered() -> None:
    """The retirement pass must know about each table a delete would not clean up.

    ``framework_mappings`` is deliberately absent — it cascades, and the load has
    already replaced it.
    """
    covered = {model.__tablename__ for model, _ in _CONTROL_DEPENDANTS}
    assert covered == {"control_implementations", "poams", "risks"}


# --- ids survive a re-ingest -------------------------------------------------


@pytest.mark.asyncio
async def test_reingest_preserves_control_ids(session_factory, mini_workbook: Path) -> None:
    """The property everything else depends on."""
    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        await session.commit()
        before = {
            c.identifier: c.id for c in (await session.execute(select(Control))).scalars()
        }
        assert before

    async with session_factory() as session:
        run = await ingest_workbook(session, mini_workbook)
        await session.commit()
        assert run.status == "succeeded"
        after = {
            c.identifier: c.id for c in (await session.execute(select(Control))).scalars()
        }

    assert after == before, "a re-ingest reissued control ids"


@pytest.mark.asyncio
async def test_reingest_reports_updates_rather_than_creations(
    session_factory, mini_workbook: Path
) -> None:
    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        await session.commit()

    async with session_factory() as session:
        run = await ingest_workbook(session, mini_workbook)
        await session.commit()
        sheet_stats = run.stats["sheets"]

    assessment = next(v for k, v in sheet_stats.items() if "assessment" in k)
    assert assessment["controls_updated"] > 0
    assert assessment["controls_created"] == 0


# --- the three dependants survive --------------------------------------------


@pytest.mark.asyncio
async def test_reingest_does_not_break_a_control_implementation(
    session_factory, mini_workbook: Path
) -> None:
    """This one used to abort the whole run with a ForeignKeyViolationError."""
    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        control = await _a_control(session)
        system = await _a_system(session)
        impl = ControlImplementation(
            system_id=system.id, control_id=control.id, status="planned"
        )
        session.add(impl)
        await session.commit()
        impl_id, control_id = impl.id, control.id

    async with session_factory() as session:
        run = await ingest_workbook(session, mini_workbook)
        await session.commit()
        assert run.status == "succeeded"
        survivor = (
            await session.execute(
                select(ControlImplementation).where(ControlImplementation.id == impl_id)
            )
        ).scalars().one()
        assert survivor.control_id == control_id


@pytest.mark.asyncio
async def test_reingest_does_not_sever_a_poam_from_its_control(
    session_factory, mini_workbook: Path
) -> None:
    """ON DELETE SET NULL: this would have failed silently, with no error."""
    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        control = await _a_control(session)
        system = await _a_system(session)
        poam = POAM(
            system_id=system.id,
            control_id=control.id,
            title="Keep my control",
            status="open",
        )
        session.add(poam)
        await session.commit()
        poam_id, control_id = poam.id, control.id

    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        await session.commit()
        survivor = (
            await session.execute(select(POAM).where(POAM.id == poam_id))
        ).scalars().one()
        assert survivor.control_id == control_id, "the POA&M lost its control"


@pytest.mark.asyncio
async def test_reingest_does_not_sever_a_risk_from_its_control(
    session_factory, mini_workbook: Path
) -> None:
    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        control = await _a_control(session)
        system = await _a_system(session)
        risk = Risk(system_id=system.id, control_id=control.id, title="Keep my control")
        session.add(risk)
        await session.commit()
        risk_id, control_id = risk.id, control.id

    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        await session.commit()
        survivor = (
            await session.execute(select(Risk).where(Risk.id == risk_id))
        ).scalars().one()
        assert survivor.control_id == control_id


# --- retiring a control the workbook dropped ---------------------------------


@pytest.mark.asyncio
async def test_a_dropped_control_is_removed_when_nothing_refers_to_it(
    session_factory, mini_workbook: Path
) -> None:
    """Leaving it would let a renamed control appear in the catalog twice."""
    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        orphan = Control(
            identifier="GONE-01",
            sequence_control="9",
            sort_as="gone-01",
            family_id=(await _a_control(session)).family_id,
            control_number="GONE-1",
            control_name="Dropped from the workbook",
            description="",
        )
        session.add(orphan)
        await session.commit()

    async with session_factory() as session:
        run = await ingest_workbook(session, mini_workbook)
        await session.commit()
        gone = (
            await session.execute(select(Control).where(Control.identifier == "GONE-01"))
        ).scalar_one_or_none()
        assert gone is None
        assessment = next(v for k, v in run.stats["sheets"].items() if "assessment" in k)
        assert assessment["controls_removed"] >= 1


@pytest.mark.asyncio
async def test_a_dropped_control_is_kept_when_a_poam_refers_to_it(
    session_factory, mini_workbook: Path
) -> None:
    """Deleting it would SET NULL the POA&M's control_id without complaint."""
    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        system = await _a_system(session)
        orphan = Control(
            identifier="GONE-02",
            sequence_control="9",
            sort_as="gone-02",
            family_id=(await _a_control(session)).family_id,
            control_number="GONE-2",
            control_name="Dropped, but cited",
            description="",
        )
        session.add(orphan)
        await session.flush()
        session.add(
            POAM(
                system_id=system.id,
                control_id=orphan.id,
                title="Cites a dropped control",
                status="open",
            )
        )
        await session.commit()
        orphan_id = orphan.id

    async with session_factory() as session:
        run = await ingest_workbook(session, mini_workbook)
        await session.commit()
        kept = (
            await session.execute(select(Control).where(Control.id == orphan_id))
        ).scalar_one_or_none()
        assert kept is not None, "a cited control was deleted"
        assessment = next(v for k, v in run.stats["sheets"].items() if "assessment" in k)
        assert assessment["controls_retained"] >= 1


# --- the load itself is still correct ----------------------------------------


@pytest.mark.asyncio
async def test_reingest_does_not_duplicate_mappings(
    session_factory, mini_workbook: Path
) -> None:
    """Mappings are replaced, not appended — the unique key would catch it late."""
    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        await session.commit()
        first = (
            await session.execute(select(func.count(FrameworkMapping.id)))
        ).scalar_one()

    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        await session.commit()
        second = (
            await session.execute(select(func.count(FrameworkMapping.id)))
        ).scalar_one()

    assert second == first


@pytest.mark.asyncio
async def test_reingest_refreshes_the_search_vector(
    session_factory, mini_workbook: Path
) -> None:
    """The tsvector refresh runs over the whole table, so updated rows are covered."""
    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        await session.commit()

    async with session_factory() as session:
        await ingest_workbook(session, mini_workbook)
        await session.commit()
        missing = (
            await session.execute(
                select(func.count(Control.id)).where(Control.search_vector.is_(None))
            )
        ).scalar_one()
        assert missing == 0
