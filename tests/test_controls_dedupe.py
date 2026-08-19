"""Folding a stub control back onto the catalog control it duplicates.

The catalog pads single-digit control numbers -- ``IA-02``, ``SC-08``, ``AU-06``.
A caller spelling the same control ``IA-2`` finds nothing, because ``identifier``
is matched as an exact string, and anything that creates the control when the
lookup misses leaves a second row behind. The deployed database carried three,
and three of its four control implementations pointed at the stubs rather than
at the catalog.

Nothing complains about this: the duplicates satisfy the UNIQUE constraint on
``identifier``. It shows up only as a coverage figure that is quietly wrong.

The risk in fixing it is over-merging, so these tests spend most of their effort
on what must NOT be folded.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ccf.config import get_settings
from ccf.etl.dedupe import (
    _REFERENCES,
    Control,
    apply_dedupe,
    identity_key,
    plan_dedupe,
)
from ccf.models import (
    POAM,
    ControlFamily,
    ControlImplementation,
    Organization,
    Risk,
    System,
)
from ccf.self_assurance.service import _resolve_control


@pytest.fixture
def session_factory() -> async_sessionmaker:
    engine = create_async_engine(str(get_settings().database_url))
    return async_sessionmaker(engine, expire_on_commit=False)


# --- the identity key is where over-merging would start ----------------------


@pytest.mark.parametrize(
    "left,right",
    [
        ("IA-02", "IA-2"),  # the case that motivated this
        ("SC-08", "SC-8"),
        ("AU-06", "AU-6"),
        ("ac-02", "AC-2"),  # case is folded too
        ("AC-02(1)", "AC-2(1)"),  # padding folds even with an enhancement
    ],
)
def test_padding_folds(left: str, right: str) -> None:
    assert identity_key(left) == identity_key(right)


@pytest.mark.parametrize(
    "left,right",
    [
        ("AC-2", "AC-2(1)"),  # a control and its enhancement are NOT the same
        ("AC-2(1)", "AC-2(2)"),
        ("AC-2", "AC-3"),
        ("AC-2", "AU-2"),
        ("SC-8", "SC-28"),  # padding must not eat a real digit
        ("AC.L2-3.1.1", "AC.L2-3.1.2"),  # CMMC-style keeps every segment
    ],
)
def test_distinct_controls_never_fold(left: str, right: str) -> None:
    """``prep.screen.normalize_control_identifier`` folds ``AC-2(1)`` to ``AC-2``.

    That is right for search and catastrophic here -- it would merge an
    enhancement into its base control and delete one of them. This module keeps
    its own stricter key for exactly that reason.
    """
    assert identity_key(left) != identity_key(right)


def test_a_cmmc_identifier_passes_through() -> None:
    assert identity_key("AC.L2-3.1.1") == "AC.L2-3.1.1"


def test_every_foreign_key_to_controls_is_covered() -> None:
    """A reference this module does not know about would be orphaned or lost."""
    covered = {model.__tablename__ for model, _, _ in _REFERENCES}
    assert covered == {"control_implementations", "framework_mappings", "poams", "risks"}


# --- fixtures ----------------------------------------------------------------


async def _family(session) -> int:
    row = (
        await session.execute(select(ControlFamily).where(ControlFamily.code == "IA"))
    ).scalar_one_or_none()
    if row is None:
        row = ControlFamily(code="IA", name="Identification and Authentication")
        session.add(row)
        await session.flush()
    return row.id


async def _catalog_control(session, identifier: str, row: int = 1) -> Control:
    """A control that came from the workbook — ``source_row`` is what marks it."""
    control = Control(
        identifier=identifier,
        sequence_control="1",
        sort_as=identifier.lower(),
        family_id=await _family(session),
        control_number=identifier,
        control_name=f"Catalog {identifier}",
        description="",
        source_row=row,
    )
    session.add(control)
    await session.flush()
    return control


async def _stub_control(session, identifier: str) -> Control:
    """A control created outside the ingest — no ``source_row``."""
    control = Control(
        identifier=identifier,
        sequence_control="",
        sort_as=identifier.lower(),
        control_number="",
        control_name=identifier,
        description="",
    )
    session.add(control)
    await session.flush()
    return control


async def _system(session, name: str) -> System:
    org = (
        await session.execute(select(Organization).where(Organization.name == "Dedupe Org"))
    ).scalar_one_or_none()
    if org is None:
        org = Organization(name="Dedupe Org")
        session.add(org)
        await session.flush()
    system = System(organization_id=org.id, name=name)
    session.add(system)
    await session.flush()
    return system


# --- planning ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_stub_is_paired_with_its_catalog_control(session_factory) -> None:
    async with session_factory() as session:
        catalog = await _catalog_control(session, "IA-02")
        stub = await _stub_control(session, "IA-2")

        plan = await plan_dedupe(session)

        merge = next(m for m in plan.merges if m.stub_id == stub.id)
        assert merge.canonical_id == catalog.id
        assert merge.blocked is None
        await session.rollback()


@pytest.mark.asyncio
async def test_two_catalog_controls_are_never_paired(session_factory) -> None:
    """Both came from the workbook, so both are real, whatever they look like."""
    async with session_factory() as session:
        a = await _catalog_control(session, "IA-02", row=1)
        b = await _catalog_control(session, "IA-2", row=2)

        plan = await plan_dedupe(session)

        ids = {m.stub_id for m in plan.merges}
        assert a.id not in ids
        assert b.id not in ids
        await session.rollback()


@pytest.mark.asyncio
async def test_a_stub_with_no_catalog_counterpart_is_left_alone(session_factory) -> None:
    """Concord's own controls (``CSA-RLS``) are stubs by design."""
    async with session_factory() as session:
        stub = await _stub_control(session, "CSA-RLS")

        plan = await plan_dedupe(session)

        assert stub.id not in {m.stub_id for m in plan.merges}
        await session.rollback()


# --- applying ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_implementation_is_moved_to_the_catalog_control(session_factory) -> None:
    """The whole point — three of four live implementations pointed at a stub."""
    async with session_factory() as session:
        catalog = await _catalog_control(session, "IA-02")
        stub = await _stub_control(session, "IA-2")
        system = await _system(session, "Dedupe System A")
        impl = ControlImplementation(
            system_id=system.id, control_id=stub.id, status="implemented"
        )
        session.add(impl)
        await session.flush()

        await apply_dedupe(session)

        moved = (
            await session.execute(
                select(ControlImplementation).where(ControlImplementation.id == impl.id)
            )
        ).scalars().one()
        assert moved.control_id == catalog.id
        assert moved.status == "implemented", "the implementation's own data must survive"
        await session.rollback()


@pytest.mark.asyncio
async def test_the_stub_is_deleted_and_the_catalog_control_kept(session_factory) -> None:
    async with session_factory() as session:
        catalog = await _catalog_control(session, "SC-08")
        stub = await _stub_control(session, "SC-8")

        await apply_dedupe(session)

        assert (await session.get(Control, stub.id)) is None
        survivor = await session.get(Control, catalog.id)
        assert survivor is not None
        assert survivor.identifier == "SC-08"
        await session.rollback()


@pytest.mark.asyncio
async def test_a_poam_and_a_risk_follow_the_merge(session_factory) -> None:
    """Both are ON DELETE SET NULL, so a plain delete would sever them silently."""
    async with session_factory() as session:
        catalog = await _catalog_control(session, "AU-06")
        stub = await _stub_control(session, "AU-6")
        system = await _system(session, "Dedupe System B")
        poam = POAM(system_id=system.id, control_id=stub.id, title="p", status="open")
        risk = Risk(system_id=system.id, control_id=stub.id, title="r")
        session.add_all([poam, risk])
        await session.flush()

        await apply_dedupe(session)

        assert (await session.get(POAM, poam.id)).control_id == catalog.id
        assert (await session.get(Risk, risk.id)).control_id == catalog.id
        await session.rollback()


@pytest.mark.asyncio
async def test_plan_does_not_write(session_factory) -> None:
    async with session_factory() as session:
        await _catalog_control(session, "IA-02")
        stub = await _stub_control(session, "IA-2")

        await plan_dedupe(session)

        assert (await session.get(Control, stub.id)) is not None
        await session.rollback()


# --- the case that must refuse to act ----------------------------------------


@pytest.mark.asyncio
async def test_a_colliding_implementation_blocks_the_merge(session_factory) -> None:
    """Both controls already have an implementation for the same system.

    ``uq_impl_system_control`` means one of them would have to be discarded.
    Which one carries the real narrative is a judgement about live data, not
    something a mechanical fix may decide, so nothing is touched.
    """
    async with session_factory() as session:
        catalog = await _catalog_control(session, "IA-02")
        stub = await _stub_control(session, "IA-2")
        system = await _system(session, "Dedupe System C")
        session.add_all([
            ControlImplementation(
                system_id=system.id, control_id=catalog.id, status="implemented"
            ),
            ControlImplementation(
                system_id=system.id, control_id=stub.id, status="not_implemented"
            ),
        ])
        await session.flush()

        plan = await apply_dedupe(session)

        merge = next(m for m in plan.merges if m.stub_id == stub.id)
        assert merge.blocked is not None
        assert "control_implementations" in merge.blocked
        assert merge not in plan.applicable
        # nothing moved, nothing deleted
        assert (await session.get(Control, stub.id)) is not None
        assert (
            await session.execute(
                select(ControlImplementation).where(
                    ControlImplementation.control_id == stub.id
                )
            )
        ).scalars().all()
        await session.rollback()


@pytest.mark.asyncio
async def test_a_different_system_does_not_block(session_factory) -> None:
    """The constraint is per system, so two systems are not a collision."""
    async with session_factory() as session:
        catalog = await _catalog_control(session, "IA-02")
        stub = await _stub_control(session, "IA-2")
        a = await _system(session, "Dedupe System D")
        b = await _system(session, "Dedupe System E")
        session.add_all([
            ControlImplementation(system_id=a.id, control_id=catalog.id, status="implemented"),
            ControlImplementation(system_id=b.id, control_id=stub.id, status="implemented"),
        ])
        await session.flush()

        plan = await apply_dedupe(session)

        merge = next(m for m in plan.merges if m.stub_id == stub.id)
        assert merge.blocked is None
        assert (await session.get(Control, stub.id)) is None
        await session.rollback()


@pytest.mark.asyncio
async def test_apply_is_idempotent(session_factory) -> None:
    async with session_factory() as session:
        await _catalog_control(session, "IA-02")
        await _stub_control(session, "IA-2")
        first = await apply_dedupe(session)
        assert first.applicable

        second = await apply_dedupe(session)

        assert second.merges == []
        await session.rollback()


# --- the root cause: the lookup that created the stubs -----------------------


@pytest.mark.asyncio
async def test_a_pack_control_resolves_to_the_padded_catalog_row(session_factory) -> None:
    """This is the miss that created the three stubs in the first place.

    A pack naming ``IA-2`` used to find nothing, because the catalog stores
    ``IA-02``, and the caller then created a second control row.
    """
    async with session_factory() as session:
        catalog = await _catalog_control(session, "IA-02")

        found = await _resolve_control(session, "IA-2")

        assert found is not None
        assert found.id == catalog.id
        await session.rollback()


@pytest.mark.asyncio
async def test_an_exact_spelling_still_wins(session_factory) -> None:
    """Folding must never override a control the catalog spells exactly."""
    async with session_factory() as session:
        exact = await _catalog_control(session, "SC-28")

        found = await _resolve_control(session, "SC-28")

        assert found is not None and found.id == exact.id
        await session.rollback()


@pytest.mark.asyncio
async def test_concords_own_control_still_resolves_to_nothing(session_factory) -> None:
    """``CSA-*`` has no catalog counterpart, so a stub remains correct there."""
    async with session_factory() as session:
        assert await _resolve_control(session, "CSA-RLS") is None
        await session.rollback()


@pytest.mark.asyncio
async def test_the_resolver_ignores_stub_rows(session_factory) -> None:
    """Otherwise one stub would resolve to another and the duplicate persists."""
    async with session_factory() as session:
        await _stub_control(session, "IA-2")

        assert await _resolve_control(session, "IA-02") is None
        await session.rollback()
