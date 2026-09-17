"""Certification Class and Path are independent axes, never derived.

FedRAMP states plainly that a Certification Class is not a replacement for an
impact level: "Agencies should not treat Certification Classes as one-for-one
replacements for Low, Moderate, or High impact levels." The published
definitions are deliberately overlapping adequacy ranges -- Class B is adequate
for most Low and SOME Moderate or High -- so a mapping between the two is wrong
in both directions.
"""

from __future__ import annotations

from sqlalchemy import select

from ccf.constants import CERTIFICATION_CLASSES, CERTIFICATION_PATHS
from ccf.db import session_scope
from ccf.models import Organization, System


def test_the_vocabularies_are_what_fedramp_publishes() -> None:
    assert CERTIFICATION_CLASSES == ("A", "B", "C", "D")
    assert CERTIFICATION_PATHS == ("program", "agency")


async def test_a_system_may_hold_a_class_and_a_path() -> None:
    async with session_scope() as s:
        org = Organization(name="cr26-cols-org")
        s.add(org)
        await s.flush()
        sys_ = System(
            organization_id=org.id,
            name="cr26-cols-system",
            baseline="moderate",
            certification_class="B",
            certification_path="program",
        )
        s.add(sys_)
        await s.flush()
        sid = sys_.id

    async with session_scope() as s:
        got = (await s.execute(select(System).where(System.id == sid))).scalar_one()
        assert got.certification_class == "B"
        assert got.certification_path == "program"
        # The independence that matters: Class B on a moderate baseline is
        # legal, and so is Class B on high. Neither column constrains the other.
        assert got.baseline == "moderate"


async def test_both_columns_default_to_null() -> None:
    """Null means "not CR26-certified" -- correct for every existing row and for
    the whole Rev5 lane. No row may be forced to claim a Class it lacks."""
    async with session_scope() as s:
        org = Organization(name="cr26-null-org")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name="cr26-null-system", baseline="low")
        s.add(sys_)
        await s.flush()
        sid = sys_.id

    async with session_scope() as s:
        got = (await s.execute(select(System).where(System.id == sid))).scalar_one()
        assert got.certification_class is None
        assert got.certification_path is None


async def test_every_class_in_the_vocabulary_is_storable() -> None:
    """A tuple the database rejects is a vocabulary in name only."""
    async with session_scope() as s:
        org = Organization(name="cr26-all-classes-org")
        s.add(org)
        await s.flush()
        for cls in CERTIFICATION_CLASSES:
            s.add(
                System(
                    organization_id=org.id,
                    name=f"cr26-class-{cls}",
                    certification_class=cls,
                )
            )
        await s.flush()
