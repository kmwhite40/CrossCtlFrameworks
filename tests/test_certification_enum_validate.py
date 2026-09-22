"""``certification_class`` and ``certification_path`` refuse junk in Python.

Both columns are SQLAlchemy ``Enum`` types, and ``Enum`` passes an unknown
*string* straight through to the database by default -- measured on 2.0.51,
``_db_value_for_elem("ZZZ")`` returns ``"ZZZ"`` unchanged. So until the columns
were declared ``validate_strings=True`` a bad value was refused by Postgres
alone. Their neighbour ``pipeline_stage`` had carried the guard since
feat/pipeline-stage (spec 2026-09-21-pipeline-stage-design.md §5.6); these
tests hold the two columns beside it to the same standard, one test per
column, so removing the guard from either one fails exactly one test.

The valid-member round trips live in ``tests/test_cr26_certification_columns.py``
and are deliberately not repeated here.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import DBAPIError, StatementError

from ccf.constants import CERTIFICATION_CLASSES, CERTIFICATION_PATHS
from ccf.db import session_scope
from ccf.models import Organization, System

#: Values that are not members. Each is a different shape of wrong so the
#: refusal cannot be mistaken for a length or case check: a single letter that
#: is simply not in the tuple, and a lower-cased spelling of a real member.
_JUNK_CLASS = "Z"
_JUNK_PATH = "sponsor"


@pytest.fixture
async def org_id() -> AsyncIterator[int]:
    """A throwaway organization, hard-deleted afterwards so its CASCADE takes
    any system a test managed to write with it."""
    async with session_scope() as s:
        org = Organization(name="cert-enum-validate-org")
        s.add(org)
        await s.flush()
        oid = org.id
    try:
        yield oid
    finally:
        async with session_scope() as s:
            await s.execute(delete(Organization).where(Organization.id == oid))


def test_the_junk_values_are_not_members() -> None:
    """If a later edit admits either value, the tests below would be asserting
    a refusal of something that is now legitimate."""
    assert _JUNK_CLASS not in CERTIFICATION_CLASSES
    assert _JUNK_PATH not in CERTIFICATION_PATHS


async def _assert_python_enum_refuses(oid: int, **column: str) -> None:
    """Write one System with a single junk column and prove the refusal came
    from the Python enum, not from Postgres.

    ``DBAPIError`` IS a ``StatementError``, so ``pytest.raises(StatementError)``
    on its own is satisfied by the database refusing the value -- a test that
    passes on the wrong belt. Measured on ``pipeline_stage`` when that column
    gained the guard: with ``validate_strings`` removed the same write raises
    ``DBAPIError``. A Python refusal never reaches the driver; it is a bare
    ``StatementError`` wrapping ``LookupError``.
    """
    (name, junk), = column.items()
    with pytest.raises(StatementError) as excinfo:
        async with session_scope() as s:
            s.add(System(organization_id=oid, name=f"cert-enum-{name}", **column))
            await s.flush()

    assert not isinstance(excinfo.value, DBAPIError), (
        f"this is Postgres refusing {name}={junk!r}, not the Python enum -- "
        "the column has lost validate_strings=True"
    )
    assert isinstance(excinfo.value.orig, LookupError)
    assert "not among the defined enum values" in str(excinfo.value)
    assert junk in str(excinfo.value)
    assert f"Enum name: {name}" in str(excinfo.value)

    # Nothing was written by the attempt.
    async with session_scope() as s:
        rows = (
            (await s.execute(select(System).where(System.organization_id == oid)))
            .scalars()
            .all()
        )
        assert rows == []


async def test_the_python_enum_rejects_an_unknown_certification_class(org_id: int) -> None:
    await _assert_python_enum_refuses(org_id, certification_class=_JUNK_CLASS)


async def test_the_python_enum_rejects_an_unknown_certification_path(org_id: int) -> None:
    await _assert_python_enum_refuses(org_id, certification_path=_JUNK_PATH)
