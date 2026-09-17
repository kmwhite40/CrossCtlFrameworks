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


async def test_one_class_rides_on_two_different_baselines() -> None:
    """The independence that matters, asserted on something that varies.

    Class B is adequate for most Low and SOME Moderate or High, so B against a
    ``high`` baseline and B against a ``low`` one must both round-trip: neither
    column constrains the other, in either direction. Asserting the baseline of
    a single row would only re-read a value passed in on the line above -- an
    assertion on a field set before the branch under test, the recurring defect
    the spec names for this programme.
    """
    async with session_scope() as s:
        org = Organization(name="cr26-one-class-two-baselines-org")
        s.add(org)
        await s.flush()
        for baseline in ("high", "low"):
            s.add(
                System(
                    organization_id=org.id,
                    name=f"cr26-class-b-on-{baseline}",
                    baseline=baseline,
                    certification_class="B",
                )
            )
        await s.flush()
        oid = org.id

    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(System.baseline, System.certification_class)
                    .where(System.organization_id == oid)
                    .order_by(System.name)
                )
            )
            .tuples()
            .all()
        )
        assert rows == [("high", "B"), ("low", "B")]


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
    """A tuple the database rejects is a vocabulary in name only.

    This loop is the only thing checking the migration's hardcoded enum members
    against ``constants.py``: ``migrations/versions/0078_cr26_certification.py``
    spells ``"A", "B", "C", "D"`` out independently of the constant, so a typo
    in either would ship unnoticed without an INSERT of every member.
    """
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


async def test_every_path_in_the_vocabulary_is_storable() -> None:
    """The same check for the other enum, which had none.

    ``0078_cr26_certification`` hardcodes ``"program", "agency"`` beside
    ``CERTIFICATION_PATHS`` without reading it; until this loop existed, a
    misspelled member on either side would have been caught by nothing.
    """
    async with session_scope() as s:
        org = Organization(name="cr26-all-paths-org")
        s.add(org)
        await s.flush()
        for path in CERTIFICATION_PATHS:
            s.add(
                System(
                    organization_id=org.id,
                    name=f"cr26-path-{path}",
                    certification_path=path,
                )
            )
        await s.flush()
