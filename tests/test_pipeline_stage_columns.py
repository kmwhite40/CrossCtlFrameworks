"""``systems.pipeline_stage`` -- Concord's own note, stored where it cannot lie.

The stage is NOT a status FedRAMP conferred. FedRAMP has published no status
enumeration at all: the brand pages give two marketplace designations and
nothing else, and the five-per-regime lists these values borrow their words
from appear only in RFC-0020, which is still a proposal. So this column answers
"where does Concord understand this system to be?" and never "what does the
FedRAMP Marketplace say?" -- see
``docs/superpowers/specs/2026-09-21-pipeline-stage-design.md`` §1.1.

The regime rides INSIDE each value rather than in a second column, so the
impossible pair "Rev5 + Persistent Validation" is unrepresentable rather than
merely undocumented. These tests hold that property down at both layers that
claim it.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, StatementError

from ccf.constants import PIPELINE_STAGES
from ccf.db import session_scope
from ccf.models import Organization, System

#: A value that is one member's regime and another's stage. It must be
#: storable by no path at all -- see the two tests at the bottom.
_CROSS_REGIME = "rev5:persistent-validation"


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return org.id


def test_the_members_are_rfc_0020s_two_lists_regime_prefixed() -> None:
    """Asserted against a literal, so a silent edit to the tuple fails here.

    RFC-0020 gives two five-member lists that overlap on three words
    (Preparation, Assessment by FedRAMP, Remediation) and differ on two each.
    Continuous Monitoring is Rev5-only; Prioritized and Persistent Validation
    are 20x-only. Ten members, not a seven-member union: the union is what
    would make a cross-regime value representable.
    """
    assert PIPELINE_STAGES == (
        "rev5:preparation",
        "rev5:agency-authorization-in-process",
        "rev5:assessment-by-fedramp",
        "rev5:continuous-monitoring",
        "rev5:remediation",
        "20x:preparation",
        "20x:prioritized",
        "20x:assessment-by-fedramp",
        "20x:persistent-validation",
        "20x:remediation",
    )


def test_every_member_carries_its_own_regime() -> None:
    """The property the whole design rests on, asserted as a property rather
    than re-read off the literal above: a member with no regime prefix could
    not say which list it came from, which is the flat-union failure."""
    assert all(m.startswith(("rev5:", "20x:")) for m in PIPELINE_STAGES)
    assert len(set(PIPELINE_STAGES)) == len(PIPELINE_STAGES)
    # Exactly five per regime, and the three shared words appear once each side
    # -- "preparing for Rev5" and "preparing for 20x" are different states that
    # happen to share a label, and both must exist.
    assert len([m for m in PIPELINE_STAGES if m.startswith("rev5:")]) == 5
    assert len([m for m in PIPELINE_STAGES if m.startswith("20x:")]) == 5


async def test_every_stage_in_the_vocabulary_is_storable() -> None:
    """A tuple the database rejects is a vocabulary in name only.

    This loop is the only thing checking the migration's hardcoded enum
    members against ``constants.py``: ``0082_pipeline_stage`` spells all ten
    out independently of :data:`ccf.constants.PIPELINE_STAGES` -- deliberately,
    so the migration cannot shift under a later edit -- so a typo on either
    side would ship unnoticed without an INSERT of every member. Same reason
    ``tests/test_cr26_certification_columns.py`` does this for Class and Path.
    """
    oid = await _org("pipeline-all-stages-org")
    async with session_scope() as s:
        for stage in PIPELINE_STAGES:
            s.add(
                System(
                    organization_id=oid,
                    name=f"pipeline-{stage}",
                    pipeline_stage=stage,
                )
            )
        await s.flush()

    async with session_scope() as s:
        stored = (
            (
                await s.execute(
                    select(System.pipeline_stage).where(System.organization_id == oid)
                )
            )
            .scalars()
            .all()
        )
        assert sorted(stored) == sorted(PIPELINE_STAGES)


async def test_a_stage_round_trips_beside_a_class_and_a_path() -> None:
    """Read back in a second session, so the assertion is on what Postgres
    returned rather than on the value handed to the constructor."""
    oid = await _org("pipeline-round-trip-org")
    async with session_scope() as s:
        sysm = System(
            organization_id=oid,
            name="pipeline-round-trip-system",
            baseline="moderate",
            certification_class="B",
            certification_path="program",
            pipeline_stage="20x:persistent-validation",
        )
        s.add(sysm)
        await s.flush()
        sid = sysm.id

    async with session_scope() as s:
        got = (await s.execute(select(System).where(System.id == sid))).scalar_one()
        assert got.pipeline_stage == "20x:persistent-validation"
        assert got.certification_class == "B"
        assert got.certification_path == "program"
        assert got.baseline == "moderate"


async def test_the_column_defaults_to_null() -> None:
    """NULL means "nobody has said", and no platform signal can say. A system
    with no stage is an ordinary, valid system -- not a gap to be filled."""
    oid = await _org("pipeline-null-org")
    async with session_scope() as s:
        sysm = System(organization_id=oid, name="pipeline-null-system", baseline="low")
        s.add(sysm)
        await s.flush()
        sid = sysm.id

    async with session_scope() as s:
        got = (await s.execute(select(System).where(System.id == sid))).scalar_one()
        assert got.pipeline_stage is None
        # And nothing quietly filled it from the neighbours it is independent of.
        assert got.certification_class is None
        assert got.certification_path is None


async def test_one_stage_rides_on_two_different_baselines() -> None:
    """Independence asserted on something that varies.

    Re-reading a single row's baseline would only confirm the value passed in
    on the line above. Two rows sharing a stage across different baselines is
    the assertion that neither column constrains the other.
    """
    oid = await _org("pipeline-one-stage-two-baselines-org")
    async with session_scope() as s:
        for baseline in ("high", "low"):
            s.add(
                System(
                    organization_id=oid,
                    name=f"pipeline-prep-on-{baseline}",
                    baseline=baseline,
                    certification_class="B",
                    pipeline_stage="rev5:preparation",
                )
            )
        await s.flush()

    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(System.baseline, System.pipeline_stage)
                    .where(System.organization_id == oid)
                    .order_by(System.name)
                )
            )
            .tuples()
            .all()
        )
        assert rows == [
            ("high", "rev5:preparation"),
            ("low", "rev5:preparation"),
        ]


async def test_the_python_enum_rejects_a_cross_regime_value() -> None:
    """Belt one of two, asserted on its own so the claim is tested rather than
    assumed (spec §5.6).

    ``Persistent Validation`` is 20x-only, so ``rev5:persistent-validation`` is
    a state that cannot exist. The column is declared
    ``validate_strings=True`` precisely so this fails here, in Python, before
    any SQL is emitted: SQLAlchemy's ``Enum`` otherwise passes an unrecognised
    *string* straight through to the database (``_db_value_for_elem`` returns
    it as-is for any ``str`` when ``validate_strings`` is False), which would
    leave the spec's belt-and-suspenders claim with only one belt.
    """
    oid = await _org("pipeline-python-reject-org")
    assert _CROSS_REGIME not in PIPELINE_STAGES
    with pytest.raises(StatementError) as excinfo:
        async with session_scope() as s:
            s.add(
                System(
                    organization_id=oid,
                    name="pipeline-python-reject-system",
                    pipeline_stage=_CROSS_REGIME,
                )
            )
            await s.flush()

    # The two belts must be told apart, or this test passes on the OTHER
    # belt's refusal and asserts nothing of its own -- measured: with
    # ``validate_strings`` removed, this same write raises ``DBAPIError``,
    # which IS a ``StatementError``, so the type alone cannot separate them.
    # A Python refusal never reaches the driver: it is a bare
    # ``StatementError`` wrapping ``LookupError``, not a DBAPI error.
    assert not isinstance(excinfo.value, DBAPIError), (
        "this is Postgres refusing the value, not the Python enum -- the "
        "column has lost validate_strings=True and belt one is gone"
    )
    assert isinstance(excinfo.value.orig, LookupError)
    assert "not among the defined enum values" in str(excinfo.value)
    assert _CROSS_REGIME in str(excinfo.value)

    # Nothing was written by the attempt.
    async with session_scope() as s:
        count = (
            await s.execute(select(System).where(System.organization_id == oid))
        ).scalars().all()
        assert count == []


async def test_the_postgres_enum_rejects_a_cross_regime_value() -> None:
    """Belt two of two, reached by going round belt one.

    The literal is spelled into the SQL text rather than bound as a parameter
    so the value is parsed by the server against ``ccf.pipeline_stage`` itself.
    A test that only exercised the ORM would prove nothing about the database
    a backfill, a psql session or a future raw ``op.execute`` would meet.
    """
    oid = await _org("pipeline-postgres-reject-org")
    with pytest.raises(DBAPIError) as excinfo:
        async with session_scope() as s:
            await s.execute(
                text(
                    "INSERT INTO ccf.systems (organization_id, name, pipeline_stage) "
                    f"VALUES (:oid, :name, '{_CROSS_REGIME}')"
                ),
                {"oid": oid, "name": "pipeline-postgres-reject-system"},
            )
    message = str(excinfo.value)
    assert "pipeline_stage" in message
    assert _CROSS_REGIME in message


async def test_the_postgres_enum_accepts_the_same_stage_in_its_own_regime() -> None:
    """The mirror of the test above, so its failure is proved to come from the
    cross-regime pairing and not merely from writing this column in raw SQL."""
    oid = await _org("pipeline-postgres-accept-org")
    async with session_scope() as s:
        await s.execute(
            text(
                "INSERT INTO ccf.systems (organization_id, name, pipeline_stage) "
                "VALUES (:oid, :name, '20x:persistent-validation')"
            ),
            {"oid": oid, "name": "pipeline-postgres-accept-system"},
        )

    async with session_scope() as s:
        stored = (
            await s.execute(
                select(System.pipeline_stage).where(System.organization_id == oid)
            )
        ).scalar_one()
        assert stored == "20x:persistent-validation"
