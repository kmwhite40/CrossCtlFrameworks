"""Baseline delta — "we are Moderate; what would High require?".

Two layers, deliberately:

* **Against the real shipped workbook** (``data/NIST Cross Mappings Rev.
  1.1.xlsx``) for the measured numbers the design rests on. The *test*
  database is a separate instance that carries a handful of synthetic control
  rows, not the catalog — ``controls`` there has 25 rows against the dev
  catalog's 5430 — so a DB-backed assertion could not see 157/323/409 at all.
  Reading the workbook is not a workaround for that: it is the stronger pin.
  §9.1 asks that the numbers fail and be re-measured *if the workbook changes*,
  and the workbook is the thing that would change. Ingest is replayed through
  ``etl/pipeline.py``'s own ``_iter_sheet_rows``/``_clean`` and its own
  duplicate-identifier rule, so what is measured here is exactly the
  ``controls`` rows a real ingest produces — confirmed identical, control for
  control, to the dev catalog on 5433.

* **Against a seeded database** for the service end to end: the join onto a
  system's implementations, the refusal, the degenerate case and tenant
  scoping. The seeded catalog reproduces the shape that makes the design
  necessary — an enhancement spelled padded, an ODP placeholder, a row marker
  and an objective whose control is not itself in the baseline — at a scale
  where the expected answer can be read off by eye.

The ``ZK-`` namespace is unused anywhere else in ``src`` or ``tests``.
``controls.identifier`` is UNIQUE across the whole database, not per test
module, so a familiar-looking ``AC-1`` here would collide with eleven other
files and fail only in the full suite.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import openpyxl
import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from ccf.api.main import create_app
from ccf.catalog.baseline_delta import (
    BASELINE_COLUMN_KEYS,
    MEMBERSHIP_VALUE,
    BaselineNotSetError,
    UnknownBaselineError,
    _assemble,
    _membership,
    baseline_delta,
)
from ccf.catalog.canonical import canonicalize
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.etl.pipeline import ASSESSMENT_SHEET, _clean, _iter_sheet_rows
from ccf.models import Control, ControlImplementation, FrameworkMapping, Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine")

WORKBOOK = Path(__file__).resolve().parents[1] / "data" / "NIST Cross Mappings Rev. 1.1.xlsx"

#: Measured 2026-09-22 against the shipped workbook and reproduced exactly on
#: the dev catalog. Rows first, canonical controls second — the whole point of
#: the design is that these two columns are not the same number.
PINNED: dict[str, tuple[int, int]] = {
    "low": (1525, 157),
    "moderate": (2312, 323),
    "high": (2673, 409),
}

#: Moderate -> High. 87 canonical controls; 387 if you count catalog rows.
PINNED_ADDED_CANONICAL = 87
PINNED_ADDED_RAW_ROWS = 387

#: In Moderate and not in High. The target does not superset the current
#: baseline, so the result carries ``removed``.
PINNED_REMOVED = ["CM-2(2)"]


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


# --- the real shipped catalog -------------------------------------------------


@pytest.fixture(scope="module")
def workbook_rows() -> dict[str, list[tuple[str, str | None]]]:
    """``{level: [(identifier, sequence_control), ...]}`` from the real workbook.

    Replays ``etl/pipeline.py``'s ingest rules rather than approximating them:
    its ``_iter_sheet_rows`` (header row consumed, all-blank rows skipped), its
    ``_clean`` (strip, empty string is absent) and its duplicate-identifier
    rule (``pipeline.py:268`` — a repeated identifier becomes
    ``<identifier>#row<n>``, which is where ``AU-06(07)#row906`` comes from and
    why it is a catalog row rather than a control).
    """
    wb = openpyxl.load_workbook(WORKBOOK, read_only=True, data_only=True)
    try:
        ws = wb[ASSESSMENT_SHEET]
        out: dict[str, list[tuple[str, str | None]]] = {level: [] for level in BASELINE_COLUMN_KEYS}
        seen: set[str] = set()
        for row_idx, headers, row in _iter_sheet_rows(ws):
            record: dict[str, Any] = dict(zip(headers, row, strict=False))
            identifier = _clean(record.get("identifier"))
            if not identifier:
                continue
            identifier = str(identifier)
            if identifier in seen:
                identifier = f"{identifier}#row{row_idx}"
            seen.add(identifier)
            sequence = _clean(record.get("Sequence Control"))
            sequence = str(sequence) if sequence is not None else None
            for level, column_key in BASELINE_COLUMN_KEYS.items():
                value = _clean(record.get(column_key))
                if value is not None and str(value) == MEMBERSHIP_VALUE:
                    out[level].append((identifier, sequence))
        return out
    finally:
        wb.close()


def test_pinned_baseline_sizes_against_the_shipped_workbook(
    workbook_rows: dict[str, list[tuple[str, str | None]]],
) -> None:
    """§9.1 — the measured numbers, against the catalog that actually ships.

    If the workbook is re-issued this fails and is re-measured. That is the
    point: a silently drifting baseline size would change every uplift number
    the product quotes without anyone being told.
    """
    for level, (expected_rows, expected_controls) in PINNED.items():
        rows = workbook_rows[level]
        members, _ = _membership(rows)
        assert len(rows) == expected_rows, f"{level}: catalog rows"
        assert len(members) == expected_controls, f"{level}: distinct canonical controls"


def test_uplift_is_counted_in_controls_not_catalog_rows(
    workbook_rows: dict[str, list[tuple[str, str | None]]],
) -> None:
    """§9.3 — the test the design exists for.

    Counting catalog rows gives 387; counting canonical controls gives 87. Both
    are asserted, so the failure message names the wrong answer as well as the
    right one. Remove the canonicalization from ``_membership`` and ``added``
    becomes the 387 the second assertion pins as *not* the answer.
    """
    moderate, _ = _membership(workbook_rows["moderate"])
    high, high_unmapped = _membership(workbook_rows["high"])

    raw_moderate = {identifier for identifier, _ in workbook_rows["moderate"]}
    raw_high = {identifier for identifier, _ in workbook_rows["high"]}
    assert len(raw_high - raw_moderate) == PINNED_ADDED_RAW_ROWS

    delta = _assemble(
        system_id=0,
        current="moderate",
        target="high",
        current_members=moderate,
        target_members=high,
        target_unmapped=high_unmapped,
        satisfied=set(),
    )
    assert len(delta.added) == PINNED_ADDED_CANONICAL
    assert len(delta.added) != PINNED_ADDED_RAW_ROWS


def test_cm_2_2_is_in_removed_not_added(
    workbook_rows: dict[str, list[tuple[str, str | None]]],
) -> None:
    """§9.2 — pinned in both directions, so the anomaly cannot vanish unnoticed.

    ``CM-2(2)`` is in Moderate and not in High. Reporting only additions would
    silently imply that a control the system currently owes is being dropped;
    reporting it as an addition would be flatly wrong.
    """
    moderate, _ = _membership(workbook_rows["moderate"])
    high, high_unmapped = _membership(workbook_rows["high"])
    assert "CM-2(2)" in moderate
    assert "CM-2(2)" not in high

    delta = _assemble(
        system_id=0,
        current="moderate",
        target="high",
        current_members=moderate,
        target_members=high,
        target_unmapped=high_unmapped,
        satisfied=set(),
    )
    assert delta.removed == PINNED_REMOVED
    assert "CM-2(2)" not in delta.added


def test_unmapped_names_the_rows_the_catalog_could_not_place(
    workbook_rows: dict[str, list[tuple[str, str | None]]],
) -> None:
    """§6 — what cannot be resolved is named, never dropped.

    2264 of High's 2673 marked rows do not canonicalize; all but nine of them
    decompose a control that *is* in the baseline. The nine that remain are the
    signal, and two of them are the direct evidence behind §4: ``CM-02(02)``'s
    objectives are marked in the High column while ``CM-02(02)`` itself is not.
    """
    _, unmapped = _membership(workbook_rows["high"])
    non_canonical = [i for i, _ in workbook_rows["high"] if canonicalize(i) is None]
    assert len(non_canonical) == 2264
    assert unmapped == [
        "AC-06(01)_ODP_01",
        "AC-06(01)_ODP_02",
        "CM-02(02)[01]",
        "CM-02(02)[02]",
        "CM-02(02)[03]",
        "CM-02(02)[04]",
        "CM-02(02)_ODP",
        "SR-11(03)#row5420",
        "SR-11(03)_ODP",
    ]


# --- seeded database ----------------------------------------------------------

#: ``(identifier, sequence_control, levels)``. Spelled the way the real catalog
#: spells things: a padded enhancement, an ODP placeholder, a ``#row`` marker
#: minted by the ETL's duplicate rule, and an objective (``ZK-3b.[01]``) whose
#: own control is *not* marked — the ``CM-02(02)``/``SR-11(03)`` shape.
_SEED_CONTROLS: list[tuple[str, str | None, tuple[str, ...]]] = [
    ("ZK-1", "ZK-1", ("moderate", "high")),
    ("ZK-1_ODP[01]", "ZK-1", ("moderate", "high")),
    ("ZK-2", "ZK-2", ("high",)),
    ("ZK-02(01)", "ZK-2(1)", ("high",)),
    ("ZK-02(01)_ODP[01]", "ZK-2(1)", ("high",)),
    ("ZK-02(01)#row77", "ZK-2(1)", ("high",)),
    ("ZK-3b.[01]", "ZK-3", ("high",)),
    ("ZK-4", "ZK-4", ("moderate",)),
    ("ZK-5", "ZK-5", ("high",)),
    ("ZK-6", "ZK-6", ("high",)),
]

#: What the seeded catalog means, read off by eye.
SEEDED_ADDED = ["ZK-2", "ZK-2(1)", "ZK-5", "ZK-6"]
SEEDED_REMOVED = ["ZK-4"]
SEEDED_UNMAPPED = ["ZK-3b.[01]"]
#: The wrong answer: High carries 8 identifiers Moderate does not.
SEEDED_ADDED_RAW_ROWS = 8

#: System A implements two of the four additions; system B (another tenant)
#: implements the other two, which must not reach A's answer.
_SYSTEM_A_IMPLEMENTATIONS = [
    ("ZK-2", "implemented"),
    ("ZK-02(01)", "planned"),
    ("ZK-5", "inherited"),
    ("ZK-1", "implemented"),
]
_SYSTEM_B_IMPLEMENTATIONS = [
    ("ZK-02(01)", "implemented"),
    ("ZK-6", "inherited"),
]


@pytest.fixture(scope="module")
def seeded() -> Iterator[dict[str, int]]:
    """Two tenants, one shared ZK catalog, and a system with no baseline.

    Seeded over a short-lived **synchronous** engine, the same device
    ``conftest._delete_keyed_cr26_documents_before_wipe`` uses: this fixture is
    module-scoped while ``fresh_engine`` disposes the async engine after every
    test, so an async fixture here would bind ``ccf.db``'s global engine to a
    loop that is closed before the second test runs.

    ``try``/``finally`` so the rows go away even when an assertion fails —
    ``controls.identifier`` is UNIQUE across the whole database, not per
    module, and a leaked ``ZK-1`` would fail every later run of this module for
    everyone.
    """
    engine = create_engine(str(get_settings().database_url_sync))
    ids: dict[str, int] = {}
    try:
        with Session(engine) as s:
            control_ids: dict[str, int] = {}
            for identifier, sequence, levels in _SEED_CONTROLS:
                control = Control(
                    identifier=identifier,
                    sequence_control=sequence,
                    control_name=identifier,
                )
                s.add(control)
                s.flush()
                control_ids[identifier] = control.id
                for level in levels:
                    s.add(
                        FrameworkMapping(
                            control_id=control.id,
                            column_key=BASELINE_COLUMN_KEYS[level],
                            value=MEMBERSHIP_VALUE,
                        )
                    )
            org_a = Organization(name="BaselineDeltaOrgA")
            org_b = Organization(name="BaselineDeltaOrgB")
            s.add_all([org_a, org_b])
            s.flush()
            sys_a = System(organization_id=org_a.id, name="BDSysA", baseline="moderate")
            sys_b = System(organization_id=org_b.id, name="BDSysB", baseline="moderate")
            sys_none = System(organization_id=org_a.id, name="BDSysNoBaseline", baseline=None)
            s.add_all([sys_a, sys_b, sys_none])
            s.flush()
            for identifier, status in _SYSTEM_A_IMPLEMENTATIONS:
                s.add(
                    ControlImplementation(
                        system_id=sys_a.id, control_id=control_ids[identifier], status=status
                    )
                )
            for identifier, status in _SYSTEM_B_IMPLEMENTATIONS:
                s.add(
                    ControlImplementation(
                        system_id=sys_b.id, control_id=control_ids[identifier], status=status
                    )
                )
            s.commit()
            ids = {
                "org_a": org_a.id,
                "org_b": org_b.id,
                "system_a": sys_a.id,
                "system_b": sys_b.id,
                "system_none": sys_none.id,
            }
        yield ids
    finally:
        with Session(engine) as s:
            system_ids = [ids[k] for k in ("system_a", "system_b", "system_none") if k in ids]
            control_ids_found = list(
                s.execute(
                    select(Control.id).where(
                        Control.identifier.in_([i for i, _, _ in _SEED_CONTROLS])
                    )
                ).scalars()
            )
            if system_ids:
                s.execute(
                    delete(ControlImplementation).where(
                        ControlImplementation.system_id.in_(system_ids)
                    )
                )
            if control_ids_found:
                s.execute(
                    delete(FrameworkMapping).where(
                        FrameworkMapping.control_id.in_(control_ids_found)
                    )
                )
                s.execute(delete(Control).where(Control.id.in_(control_ids_found)))
            if system_ids:
                s.execute(delete(System).where(System.id.in_(system_ids)))
            org_ids = [ids[k] for k in ("org_a", "org_b") if k in ids]
            if org_ids:
                s.execute(delete(Organization).where(Organization.id.in_(org_ids)))
            s.commit()
        engine.dispose()


@pytest.mark.asyncio
async def test_seeded_delta_counts_controls_not_rows(seeded: dict[str, int]) -> None:
    """§9.3 at the database layer: the same defect, end to end.

    Eight catalog identifiers are in High and not in Moderate; four canonical
    controls are. Remove the canonicalization and ``added`` becomes the eight.
    """
    async with session_scope() as s:
        delta = await baseline_delta(s, system_id=seeded["system_a"], target="high")
    assert delta.added == SEEDED_ADDED
    assert len(delta.added) != SEEDED_ADDED_RAW_ROWS
    assert delta.current == "moderate"
    assert delta.target == "high"


@pytest.mark.asyncio
async def test_seeded_delta_reports_removed_and_unmapped(seeded: dict[str, int]) -> None:
    """§9.2 and §6 at the database layer.

    ``ZK-4`` is in Moderate and not in High — reported, never hidden.
    ``ZK-3b.[01]`` is marked in High but its control ``ZK-3`` is not, so it is
    a row the platform could not place; the three other non-canonicalizing High
    rows decompose controls it placed and are therefore not listed.
    """
    async with session_scope() as s:
        delta = await baseline_delta(s, system_id=seeded["system_a"], target="high")
    assert delta.removed == SEEDED_REMOVED
    assert delta.unmapped == SEEDED_UNMAPPED
    assert "ZK-4" not in delta.added


@pytest.mark.asyncio
async def test_already_satisfied_plus_outstanding_equals_added(seeded: dict[str, int]) -> None:
    """§9.4 — over implemented, inherited, planned and absent.

    ``ZK-2`` implemented and ``ZK-5`` inherited are satisfied; ``ZK-2(1)``
    planned is not (``{implemented, inherited}`` is the whole of it) and
    ``ZK-6`` has no implementation row at all.
    """
    async with session_scope() as s:
        delta = await baseline_delta(s, system_id=seeded["system_a"], target="high")
    assert delta.already_satisfied == ["ZK-2", "ZK-5"]
    assert delta.outstanding == ["ZK-2(1)", "ZK-6"]
    assert sorted(delta.already_satisfied + delta.outstanding) == delta.added


@pytest.mark.asyncio
async def test_system_with_no_baseline_is_refused_with_the_reason(
    seeded: dict[str, int],
) -> None:
    """§9.5 — refused, not defaulted to Low.

    Matched on the specific refusal text and the specific exception type: a
    bare ``pytest.raises(ValueError)`` here would be satisfied by any other
    layer raising for any other reason, which is exactly how a "refusal" test
    ends up passing while the code quietly defaults.
    """
    async with session_scope() as s:
        with pytest.raises(BaselineNotSetError, match="has no baseline"):
            await baseline_delta(s, system_id=seeded["system_none"], target="high")

    # And the refusal is not a disguised default: a Low-baselined delta would
    # have produced an answer, so assert none was produced by any path.
    async with session_scope() as s:
        try:
            await baseline_delta(s, system_id=seeded["system_none"], target="high")
        except BaselineNotSetError as exc:
            assert "not computable" in str(exc)
        else:  # pragma: no cover - the assertion above already failed
            pytest.fail("a system with no baseline produced a delta")


@pytest.mark.asyncio
async def test_same_baseline_in_and_out_is_empty_not_an_error(seeded: dict[str, int]) -> None:
    """§9.6 — the degenerate case."""
    async with session_scope() as s:
        delta = await baseline_delta(s, system_id=seeded["system_a"], target="moderate")
    assert delta.added == []
    assert delta.removed == []
    assert delta.already_satisfied == []
    assert delta.outstanding == []


@pytest.mark.asyncio
async def test_unknown_target_is_refused(seeded: dict[str, int]) -> None:
    async with session_scope() as s:
        with pytest.raises(UnknownBaselineError, match="unknown baseline 'il5'"):
            await baseline_delta(s, system_id=seeded["system_a"], target="il5")


@pytest.mark.asyncio
async def test_implementation_join_sees_only_this_systems_rows(seeded: dict[str, int]) -> None:
    """§9.7 — tenant isolation, pinned where RLS cannot be doing the work.

    ``get_session`` binds the RLS tenant, so an HTTP-only test cannot tell an
    explicit predicate from RLS. This runs on an unscoped ``session_scope()``
    and first asserts the *other* tenant's implementation rows are plainly
    visible on it — without that assertion this test would pass just as well
    against a session that could not see them, and would be proving nothing.

    The predicate doing the work is ``ControlImplementation.system_id``: an
    implementation belongs to exactly one system and a system to exactly one
    organization, so org B's ``ZK-2(1) implemented`` and ``ZK-6 inherited``
    cannot reach org A's answer.
    """
    async with session_scope() as s:
        visible = (
            (
                await s.execute(
                    select(ControlImplementation.id).where(
                        ControlImplementation.system_id == seeded["system_b"]
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(visible) == len(_SYSTEM_B_IMPLEMENTATIONS), (
            "org B's rows must be visible on this session, or the isolation "
            "assertion below proves nothing"
        )
        delta = await baseline_delta(s, system_id=seeded["system_a"], target="high")

    # B satisfies exactly the two A does not. If the join leaked, these would
    # move from `outstanding` to `already_satisfied`.
    assert delta.outstanding == ["ZK-2(1)", "ZK-6"]
    assert "ZK-6" not in delta.already_satisfied


# --- route --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_baseline_delta_route(seeded: dict[str, int]) -> None:
    """The JSON API. No UI — §8.

    Auth is disabled under test, so the caller is ``SYSTEM_PRINCIPAL``, which
    is global and has no ``org_id``; this therefore pins the payload and the
    refusals, not the tenancy (which ``test_implementation_join_...`` pins on
    an unscoped session instead).
    """
    async with _client() as c:
        ok = await c.get(f"/api/systems/{seeded['system_a']}/baseline-delta?target=high")
        assert ok.status_code == 200, ok.text
        body = ok.json()
        assert body["added"] == SEEDED_ADDED
        assert body["removed"] == SEEDED_REMOVED
        assert body["already_satisfied"] == ["ZK-2", "ZK-5"]
        assert body["outstanding"] == ["ZK-2(1)", "ZK-6"]
        assert body["unmapped"] == SEEDED_UNMAPPED
        assert body["current"] == "moderate"

        no_baseline = await c.get(
            f"/api/systems/{seeded['system_none']}/baseline-delta?target=high"
        )
        assert no_baseline.status_code == 422, no_baseline.text
        assert "has no baseline" in no_baseline.json()["detail"]

        bad_target = await c.get(f"/api/systems/{seeded['system_a']}/baseline-delta?target=il5")
        assert bad_target.status_code == 400, bad_target.text

        missing = await c.get("/api/systems/99999999/baseline-delta?target=high")
        assert missing.status_code == 404
