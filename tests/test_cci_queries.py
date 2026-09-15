"""The reverse index -- the reason this sub-project exists."""
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import select

from ccf.cci.service import ccis_for_control, controls_for_cci, load_cci_list
from ccf.db import session_scope
from ccf.models_cci import CciItemRow

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def loaded(clean_migrated_db: None) -> AsyncIterator[None]:
    """Load the CCI list before each test in this module, and clean it up after.

    The brief's fixture shape is module-scoped ("load once"), but that shape
    is incompatible with this suite's ``fresh_engine`` fixture (conftest.py):
    ``fresh_engine`` is function-scoped/autouse and disposes the global async
    engine after every test on that test's own event loop. A module-scoped
    async fixture builds the engine on a *different* (module-setup) loop, so
    the very first test's teardown raised ``RuntimeError: ... attached to a
    different loop`` while tearing down an asyncpg connection -- confirmed by
    actually running it. Every other CCI test module (test_cci_load.py,
    test_cci_overlay.py) loads per-test for the same reason, so this follows
    suit: function-scoped, ~5.8s per load, ~30s total for five tests.

    Teardown always runs, even if a test fails an assertion: a yield
    fixture's post-yield code executes on every exit path once setup has
    completed, which is exactly what "guaranteed cleanup" requires here.
    These rows are loaded into a database shared with the rest of the suite
    (``clean_migrated_db`` resets the schema once per *session*, not per
    test) -- leaving them behind would corrupt every test that runs after.
    """
    async with session_scope() as s:
        await load_cci_list(s)
    try:
        yield
    finally:
        async with session_scope() as s:
            rows = (await s.execute(select(CciItemRow))).scalars().all()
            for row in rows:
                await s.delete(row)


async def test_a_cci_resolves_to_its_control() -> None:
    async with session_scope() as s:
        assert await controls_for_cci(s, "CCI-000002") == ["AC-1"]


async def test_the_unresolvable_reference_still_names_its_control() -> None:
    async with session_scope() as s:
        assert await controls_for_cci(s, "CCI-005020") == ["SI-18"]


async def test_a_control_lists_the_ccis_covering_it() -> None:
    async with session_scope() as s:
        cov = await ccis_for_control(s, "AC-1")
    ids = {c.cci for c in cov}
    assert {"CCI-000002", "CCI-002107"} <= ids
    entry = next(c for c in cov if c.cci == "CCI-000002")
    assert entry.oscal_part_id == "ac-1_smt.a.1.a"
    assert entry.type == "policy"


async def test_revision_scopes_the_answer() -> None:
    # CCI-000002's Rev. 4 and Rev. 5 references both resolve to "AC-1", so
    # that CCI cannot tell a real revision filter apart from a dropped one
    # (or one hardcoded to "5") -- both would still return ["AC-1"] here.
    # CCI-002364 resolves to genuinely different controls per revision
    # (Rev. 4: AC-12(1), Rev. 5: AC-12(2)), so it is the pair that actually
    # exercises the ``revision`` filter.
    async with session_scope() as s:
        rev4 = await controls_for_cci(s, "CCI-000002", revision="4")
    assert rev4 == ["AC-1"]  # smoke check, not the guard

    async with session_scope() as s:
        rev4_disjoint = await controls_for_cci(s, "CCI-002364", revision="4")
        rev5_disjoint = await controls_for_cci(s, "CCI-002364", revision="5")
    assert rev4_disjoint == ["AC-12(1)"]
    assert rev5_disjoint == ["AC-12(2)"]


async def test_an_unknown_cci_returns_empty_rather_than_raising() -> None:
    async with session_scope() as s:
        assert await controls_for_cci(s, "CCI-999999") == []
