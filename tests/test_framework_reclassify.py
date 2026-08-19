"""Reclassifying mappings in place, without the destructive re-ingest.

Adding a classification rule changes nothing for rows already in Postgres. The
only way to apply one used to be a full re-ingest, and that deletes and reloads
``controls`` — which mints new ids and severs every row referencing them. On a
database with SSP work in it the delete does not even complete: the RESTRICT
foreign key from ``control_implementations`` stops it.

``etl.reclassify`` re-runs the classifier over the ``column_key`` values already
stored and moves only ``framework_id``. These tests pin the two properties that
matter: it moves exactly the rows the plan promised, and it touches nothing else.

The suite shares one database, so no test here may assume it starts empty.
Each one first *quiesces* — applies the reclassification until it is a no-op —
so that whatever the ingest tests left behind is already at its fixed point.
After that, any move the plan reports belongs to this module's own fixture.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ccf.config import get_settings
from ccf.etl.frameworks import CORE_HEADERS, FRAMEWORKS, classify_header
from ccf.etl.reclassify import (
    FALLBACK_CODE,
    _target_code,
    apply_reclassification,
    plan_reclassification,
)
from ccf.models import Control, ControlFamily, Framework, FrameworkMapping

# A header the classifier places in a real framework, and one it cannot place.
_CLASSIFIED_HEADER = "IL-5 High"
_CLASSIFIED_CODE = "DOD_SRG_IL"
_UNCLASSIFIABLE_HEADER = "Acme Internal Boundary Notes"


@pytest.fixture
def session_factory() -> async_sessionmaker:
    engine = create_async_engine(str(get_settings().database_url))
    return async_sessionmaker(engine, expire_on_commit=False)


# --- fixture plumbing --------------------------------------------------------


async def _get_or_create_framework(session, code: str) -> Framework:
    found = (
        await session.execute(select(Framework).where(Framework.code == code))
    ).scalar_one_or_none()
    if found is not None:
        return found
    spec = next((f for f in FRAMEWORKS if f.code == code), None)
    row = Framework(
        code=code,
        name=spec.name if spec else "Other / Misc",
        family=spec.family if spec else "Other",
        description="",
    )
    session.add(row)
    await session.flush()
    return row


async def _quiesce(session) -> None:
    """Bring pre-existing rows to their fixed point, so later plans are ours."""
    await apply_reclassification(session)
    residue = await plan_reclassification(session)
    assert residue.changed == 0, "reclassification is not idempotent"


async def _seed(session, headers: list[str]) -> int:
    """Create one control with a mapping per header, all labelled OTHER."""
    family = (
        await session.execute(select(ControlFamily).where(ControlFamily.code == "AC"))
    ).scalar_one_or_none()
    if family is None:
        family = ControlFamily(code="AC", name="Access Control")
        session.add(family)
        await session.flush()
    control = Control(
        identifier="RECLASSIFY-FIXTURE-01",
        sequence_control="1",
        sort_as="reclassify-fixture-01",
        family_id=family.id,
        control_number="RC-1",
        control_name="Reclassify fixture",
        description="",
    )
    session.add(control)
    other = await _get_or_create_framework(session, FALLBACK_CODE)
    await session.flush()
    for header in headers:
        session.add(
            FrameworkMapping(
                control_id=control.id,
                framework_id=other.id,
                column_key=header,
                value="x",
            )
        )
    await session.flush()
    return control.id


async def _codes(session, control_id: int) -> dict[str, int]:
    """Framework labels on this control's mappings only."""
    rows = (
        await session.execute(
            select(Framework.code, func.count(FrameworkMapping.id))
            .join(Framework, Framework.id == FrameworkMapping.framework_id)
            .where(FrameworkMapping.control_id == control_id)
            .group_by(Framework.code)
        )
    ).all()
    return {code: n for code, n in rows}


# --- the classifier itself agrees with the fixtures --------------------------


def test_the_fixture_headers_behave_as_the_tests_assume() -> None:
    """Guard the premise: one header must classify, the other must fall back.

    Without this, a future rule change could make ``_UNCLASSIFIABLE_HEADER``
    match something and every 'left alone' assertion below would pass vacuously.
    """
    assert classify_header(_CLASSIFIED_HEADER) == _CLASSIFIED_CODE
    assert classify_header(_UNCLASSIFIABLE_HEADER) == FALLBACK_CODE


def test_a_core_header_is_left_alone_rather_than_relabelled() -> None:
    """``classify_header`` returns None for a control attribute, not OTHER.

    The two None-ish answers mean opposite things: ``OTHER`` is a crosswalk
    column nothing recognised; ``None`` is not a crosswalk column at all.
    Collapsing them with ``or FALLBACK_CODE`` would relabel an anomalous row
    instead of reporting it.
    """
    core = next(iter(CORE_HEADERS))
    assert classify_header(core) is None
    assert _target_code(core) is None
    assert _target_code("Some Crosswalk Nobody Matched") == FALLBACK_CODE


# --- planning ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_plan_reports_the_move_without_writing(session_factory) -> None:
    async with session_factory() as session:
        await _quiesce(session)
        before = await plan_reclassification(session)
        control_id = await _seed(session, [_CLASSIFIED_HEADER, _UNCLASSIFIABLE_HEADER])

        plan = await plan_reclassification(session)

        assert plan.moves == {(FALLBACK_CODE, _CLASSIFIED_CODE): 1}
        assert plan.changed == 1
        assert plan.unchanged - before.unchanged == 1  # the unclassifiable one
        assert plan.total - before.total == 2

        # nothing written: both of this control's mappings are still OTHER
        assert await _codes(session, control_id) == {FALLBACK_CODE: 2}
        await session.rollback()


@pytest.mark.asyncio
async def test_plan_is_empty_when_nothing_would_move(session_factory) -> None:
    async with session_factory() as session:
        await _quiesce(session)
        before = await plan_reclassification(session)
        await _seed(session, [_UNCLASSIFIABLE_HEADER])

        plan = await plan_reclassification(session)

        assert plan.moves == {}
        assert plan.changed == 0
        assert plan.unchanged - before.unchanged == 1
        await session.rollback()


# --- applying ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_moves_exactly_the_planned_rows(session_factory) -> None:
    async with session_factory() as session:
        await _quiesce(session)
        control_id = await _seed(session, [_CLASSIFIED_HEADER, _UNCLASSIFIABLE_HEADER])

        plan = await apply_reclassification(session)

        assert plan.changed == 1
        assert await _codes(session, control_id) == {
            _CLASSIFIED_CODE: 1,
            FALLBACK_CODE: 1,
        }
        await session.rollback()


@pytest.mark.asyncio
async def test_apply_seeds_the_framework_row_it_needs(session_factory) -> None:
    """A new rule usually names a framework that was never seeded."""
    async with session_factory() as session:
        await _quiesce(session)
        await session.execute(
            FrameworkMapping.__table__.delete().where(
                FrameworkMapping.framework_id.in_(
                    select(Framework.id).where(Framework.code == _CLASSIFIED_CODE)
                )
            )
        )
        await session.execute(
            Framework.__table__.delete().where(Framework.code == _CLASSIFIED_CODE)
        )
        await _seed(session, [_CLASSIFIED_HEADER])
        assert (
            await session.execute(select(Framework).where(Framework.code == _CLASSIFIED_CODE))
        ).scalar_one_or_none() is None

        plan = await apply_reclassification(session)

        assert _CLASSIFIED_CODE in plan.new_frameworks
        after = (
            await session.execute(select(Framework).where(Framework.code == _CLASSIFIED_CODE))
        ).scalar_one()
        spec = next(f for f in FRAMEWORKS if f.code == _CLASSIFIED_CODE)
        assert after.name == spec.name
        assert after.family == spec.family
        await session.rollback()


@pytest.mark.asyncio
async def test_apply_is_idempotent(session_factory) -> None:
    """Running it twice must be indistinguishable from running it once."""
    async with session_factory() as session:
        await _quiesce(session)
        control_id = await _seed(session, [_CLASSIFIED_HEADER, _UNCLASSIFIABLE_HEADER])
        await apply_reclassification(session)
        first = await _codes(session, control_id)

        second = await apply_reclassification(session)

        assert second.changed == 0
        assert second.moves == {}
        assert await _codes(session, control_id) == first
        await session.rollback()


@pytest.mark.asyncio
async def test_apply_never_deletes_a_control_or_a_mapping(session_factory) -> None:
    """The whole point: this is the non-destructive path.

    A re-ingest would delete both tables. Here the row counts must be identical
    before and after, and the control must keep the same id — that id is what
    ``control_implementations``, ``poams`` and ``risks`` point at.
    """
    async with session_factory() as session:
        await _quiesce(session)
        control_id = await _seed(session, [_CLASSIFIED_HEADER, _UNCLASSIFIABLE_HEADER])
        controls_before = (await session.execute(select(func.count(Control.id)))).scalar_one()
        maps_before = (
            await session.execute(select(func.count(FrameworkMapping.id)))
        ).scalar_one()

        await apply_reclassification(session)

        assert (
            await session.execute(select(func.count(Control.id)))
        ).scalar_one() == controls_before
        assert (
            await session.execute(select(func.count(FrameworkMapping.id)))
        ).scalar_one() == maps_before
        surviving = (
            await session.execute(select(Control).where(Control.id == control_id))
        ).scalar_one()
        assert surviving.identifier == "RECLASSIFY-FIXTURE-01"
        await session.rollback()


@pytest.mark.asyncio
async def test_apply_preserves_the_mapping_value(session_factory) -> None:
    """Only the label moves. The crosswalk value must be byte-identical."""
    async with session_factory() as session:
        await _quiesce(session)
        control_id = await _seed(session, [_CLASSIFIED_HEADER])

        await apply_reclassification(session)

        row = (
            await session.execute(
                select(FrameworkMapping).where(FrameworkMapping.control_id == control_id)
            )
        ).scalars().one()
        assert row.value == "x"
        assert row.column_key == _CLASSIFIED_HEADER
        await session.rollback()


@pytest.mark.asyncio
async def test_a_stored_core_header_is_skipped_not_moved(session_factory) -> None:
    """An anomalous mapping row must survive untouched, and be reported."""
    async with session_factory() as session:
        await _quiesce(session)
        core = next(iter(CORE_HEADERS))
        control_id = await _seed(session, [])
        other = await _get_or_create_framework(session, FALLBACK_CODE)
        session.add(
            FrameworkMapping(
                control_id=control_id,
                framework_id=other.id,
                column_key=core,
                value="x",
            )
        )
        await session.flush()

        plan = await apply_reclassification(session)

        assert plan.skipped.get(core) == 1
        assert plan.changed == 0
        row = (
            await session.execute(
                select(FrameworkMapping).where(FrameworkMapping.control_id == control_id)
            )
        ).scalars().one()
        assert row.framework_id == other.id
        assert row.column_key == core
        await session.rollback()


# --- the regression signal ---------------------------------------------------


@pytest.mark.asyncio
async def test_demotions_are_reported_separately(session_factory) -> None:
    """A row moving INTO the fallback means a rule stopped matching.

    Promotion out of OTHER is the expected direction. The reverse is a
    classification regression and must be visible, not buried in the totals.
    """
    async with session_factory() as session:
        await _quiesce(session)
        control_id = await _seed(session, [])
        fw = await _get_or_create_framework(session, _CLASSIFIED_CODE)
        # An unclassifiable header wrongly labelled as a real framework.
        session.add(
            FrameworkMapping(
                control_id=control_id,
                framework_id=fw.id,
                column_key=_UNCLASSIFIABLE_HEADER,
                value="x",
            )
        )
        await session.flush()

        plan = await plan_reclassification(session)

        assert plan.demotions == {(_CLASSIFIED_CODE, FALLBACK_CODE): 1}
        await session.rollback()


@pytest.mark.asyncio
async def test_promotions_are_not_reported_as_demotions(session_factory) -> None:
    async with session_factory() as session:
        await _quiesce(session)
        await _seed(session, [_CLASSIFIED_HEADER])

        plan = await plan_reclassification(session)

        assert plan.moves
        assert plan.demotions == {}
        await session.rollback()
