"""Posture measured against the baseline, not against what we happened to check.

The gap report answered "of the controls Concord assessed, which failed" --
so a tenant with six machine-tested controls read as "8 failing of 14" while
the baseline it is held to has 288, and 283 controls nobody had looked at
were invisible. The denominator is the finding.
"""

from __future__ import annotations

import pytest

from ccf.analytics.framework_posture import (
    baseline_controls,
    fold_to_control,
    framework_posture,
)
from ccf.db import session_scope

pytestmark = pytest.mark.usefixtures("fresh_engine")



async def _seed_catalog() -> None:
    """A miniature catalog with the baseline flags the module reads.

    Seeded rather than relying on an ingested catalog: the test database has
    no control data, so every assertion below would pass vacuously against
    empty baselines. The rows deliberately include an assessment objective
    and an ODP placeholder, because folding those away is the thing being
    tested.
    """
    import uuid

    from sqlalchemy import select

    from ccf.models import Control

    tag = uuid.uuid4().hex[:6].upper()
    rows = [
        # (identifier, low, mod, high)
        (f"ZA-01a.[01]", True, True, True),
        (f"ZA-01_ODP_01", True, True, True),
        (f"ZA-02", False, True, True),
        (f"ZA-02(03)(c)", False, True, True),
        (f"ZA-03", False, False, True),
    ]
    async with session_scope() as s:
        existing = set(
            (await s.execute(select(Control.identifier))).scalars().all()
        )
        for identifier, low, mod, high in rows:
            if identifier in existing:
                continue
            s.add(
                Control(
                    identifier=identifier,
                    fisma_low=low,
                    fisma_mod=mod,
                    fisma_high=high,
                )
            )
        await s.flush()


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        # Assessment objectives and ODP placeholders are rows, not controls.
        # Counting them overstates a baseline roughly fourfold.
        ("AC-02f.[01]", "AC-2"),
        ("AC-06(01)_ODP_02", "AC-6(1)"),
        ("SC-07(04)(a)", "SC-7(4)"),
        # Enhancements stay distinct: a baseline names them separately.
        ("AC-02(03)(c)", "AC-2(3)"),
        ("AC-17", "AC-17"),
        # Zero padding is folded away, so AC-02 and AC-2 are one control.
        ("AC-02", "AC-2"),
        ("", None),
        ("not-a-control", None),
    ],
)
def test_a_catalog_row_folds_to_the_control_it_belongs_to(row: str, expected) -> None:
    assert fold_to_control(row) == expected


def test_an_enhancement_is_not_folded_into_its_base_control() -> None:
    """`normalize_control` in the KSI path deliberately collapses these; this
    one must not, or a baseline of 288 would collapse to its ~100 families."""
    assert fold_to_control("AC-2(3)") != fold_to_control("AC-2")


@pytest.mark.asyncio
async def test_each_baseline_is_a_distinct_and_growing_set() -> None:
    """Low ⊂ Moderate ⊂ High is the shape FIPS-199 baselines have.

    Asserted as a real containment rather than counts, so a fold that silently
    dropped controls could not satisfy it by shrinking all three.
    """
    await _seed_catalog()
    async with session_scope() as s:
        low = await baseline_controls(s, "low")
        moderate = await baseline_controls(s, "moderate")
        high = await baseline_controls(s, "high")

    assert low and moderate and high, "a baseline came back empty"
    assert low < moderate < high, "baselines are not nested as FIPS-199 defines them"
    assert all(c == fold_to_control(c) for c in moderate), "a baseline holds unfolded rows"
    # The objective row and the ODP placeholder folded into one control, not three.
    assert "ZA-1" in low and "ZA-1a.[01]" not in low


@pytest.mark.asyncio
async def test_an_unknown_baseline_returns_nothing_rather_than_guessing() -> None:
    async with session_scope() as s:
        assert await baseline_controls(s, "fedramp-li-saas") == set()
        assert await baseline_controls(s, "") == set()


@pytest.mark.asyncio
async def test_a_system_with_no_baseline_reports_no_coverage() -> None:
    """Coverage of an undeclared baseline is not zero -- it is unanswerable,
    and reporting 0% would read as a finding about the system."""
    import uuid

    from ccf.models import Organization, System

    async with session_scope() as s:
        org = Organization(name=f"NoBaseline {uuid.uuid4().hex[:6]}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name="Unscoped")
        s.add(system)
        await s.flush()
        org_id, system_id = org.id, system.id

    async with session_scope() as s:
        p = await framework_posture(s, org_id=org_id, system_id=system_id)
    assert p["total"] == 0
    assert p["unaddressed"] == []


@pytest.mark.asyncio
async def test_another_organizations_system_is_not_reported() -> None:
    import uuid

    from ccf.models import Organization, System

    await _seed_catalog()
    async with session_scope() as s:
        owner = Organization(name=f"Owner {uuid.uuid4().hex[:6]}")
        outsider = Organization(name=f"Outsider {uuid.uuid4().hex[:6]}")
        s.add_all([owner, outsider])
        await s.flush()
        system = System(organization_id=owner.id, name="Theirs", baseline="moderate")
        s.add(system)
        await s.flush()
        owner_id, outsider_id, system_id = owner.id, outsider.id, system.id

    async with session_scope() as s:
        mine = await framework_posture(s, org_id=owner_id, system_id=system_id)
        theirs = await framework_posture(s, org_id=outsider_id, system_id=system_id)

    assert mine["total"] > 0, "the owner sees nothing, so this proves nothing"
    assert theirs["total"] == 0
