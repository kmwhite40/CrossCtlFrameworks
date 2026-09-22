"""Organization-defined parameters reach an 800-53 SSP's editing surfaces.

Before this module, an 800-53r5 project rendered every ODP as a bare key with
no label, no guidance and no choice list. Three linked causes, each measured:

1. ``ssp/nist80053.build_80053_entries`` built the definitions and its only
   caller, ``ssp/seed.seed_80053_project``, bound them to ``_odp_defs`` and
   never referenced the name again — the sole occurrence in ``src`` or
   ``tests``.
2. ODP definitions were read from ``ScoringControl.odp_definitions``, and
   ``ccf.scoring_controls`` is the CMMC L2 matrix: 110 rows, every id of the
   shape ``AC.L2-3.1.1``, none of 800-53 shape. There is no 800-53 row in it
   and there must not be — widening it would put two control vocabularies in
   one column, the defect this codebase already carries in
   ``AssessmentControlResult.control_id``.
3. So the join on ``ScoringControl.control_id`` matched 0 of a LOW-baseline
   project's 149 entries, silently.

A key-name mismatch was masked by all three: ``nist80053.py`` emitted
``{"id": ...}`` while ``ssp/completeness.py`` and ``_ssp_entry.html`` both read
``key``. ``key`` is authoritative — it is the spelling of
``ccf.ssp.odp.ODP``, the one dataclass that defines this shape — and both
frameworks now produce definitions through it.

The fix resolves 800-53 definitions from the parsed OSCAL catalog at read time
(``ssp/odp_defs.py``) instead of storing a second copy of the catalog in the
database. The CMMC path keeps reading ``ScoringControl`` exactly as before,
which ``test_cmmc_odp_definitions_unchanged`` pins by equality.

Trap avoided: ``ScoringControl.control_id`` is globally UNIQUE across the
shared test database, so the CMMC fixture uses a private ``ZQ`` namespace
(``ZP-``/``ZK-`` are taken elsewhere) and tears its rows down in a ``finally``.
"""

from __future__ import annotations

import itertools
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import fields
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.catalog.oscal import load_oscal_catalog
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    Organization,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    System,
)
from ccf.ssp.completeness import _entry_gaps
from ccf.ssp.completeness_query import project_completeness
from ccf.ssp.nist80053 import build_80053_entries, odp_definitions_for
from ccf.ssp.odp import ODP
from ccf.ssp.seed import seed_80053_project

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()

# A private ScoringControl namespace: control_id is globally UNIQUE across the
# shared test database, so a realistic id would collide with another module's
# rows and fail only under the full suite.
_CMMC_NS = "ZQ"
_CMMC_C1 = f"{_CMMC_NS}.L2-9.8.1"
_CMMC_C2 = f"{_CMMC_NS}.L2-9.8.2"

# Exactly what a CMMC project's ODP definitions look like today (the shape
# ``scoring/seed.py`` stores via ``ssp/odp.odps_for``), asserted by equality so
# the 800-53 change cannot quietly alter the CMMC path.
_CMMC_DEFS_C1: list[dict[str, Any]] = [
    {
        "key": "audit_retention_period",
        "label": "audit record retention period",
        "kind": "assignment",
        "choices": [],
        "guidance": "DoD/DFARS practice commonly retains at least 90 days online.",
        "suggested": "at least 90 days",
        "source": "NIST SP 800-171",
    }
]

# Catalog facts this module leans on (800-53B LOW baseline, packaged OSCAL):
#   AC-1 / ac-01_odp.03 — a select with exactly these three choices
#   AC-1 / ac-1_prm_1   — no guidance, no choices
#   AC-2                — ten parameters, all carrying guidance prose
_CHOICE_CONTROL = "AC-1"
_CHOICE_PARAM = "ac-01_odp.03"
_CHOICE_VALUES = ["organization-level", "mission/business process-level", "system-level"]
_BARE_PARAM = "ac-1_prm_1"
_LABELLED_CONTROL = "AC-2"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


@asynccontextmanager
async def _project(framework: str, *, baseline: str | None = None) -> AsyncIterator[int]:
    """An org + system + SSP project, seeded from the 800-53B baseline when
    asked, torn down in a ``finally`` so a failure never leaves rows behind in
    the shared database."""
    n = next(_SEQ)
    org_id = project_id = None
    try:
        async with session_scope() as s:
            org = Organization(name=f"ODP Defs Org {framework} {n}")
            s.add(org)
            await s.flush()
            org_id = org.id
            sysrow = System(
                organization_id=org.id, name=f"ODP Defs System {n}", baseline=baseline
            )
            s.add(sysrow)
            await s.flush()
            proj = SSPProject(
                organization_id=org.id,
                system_id=sysrow.id,
                customer_name=f"ODP Defs Customer {n}",
                framework=framework,
            )
            s.add(proj)
            await s.flush()
            project_id = proj.id
        if framework == "nist-800-53r5":
            async with session_scope() as s:
                proj = await s.get(SSPProject, project_id)
                assert proj is not None
                await seed_80053_project(s, proj)
        yield project_id
    finally:
        async with session_scope() as s:
            if project_id is not None:
                await s.execute(delete(SSPProject).where(SSPProject.id == project_id))
            if org_id is not None:
                await s.execute(delete(Organization).where(Organization.id == org_id))


@asynccontextmanager
async def _cmmc_project() -> AsyncIterator[int]:
    """A CMMC project with two entries and the ScoringControl reference rows
    the CMMC path has always read. Rows are namespaced and removed in a
    ``finally`` — ``scoring_controls.control_id`` is globally unique."""
    async with _project("cmmc-800-171") as project_id:
        try:
            async with session_scope() as s:
                s.add_all(
                    [
                        ScoringControl(
                            control_id=_CMMC_C1,
                            domain=_CMMC_NS,
                            point_value="5",
                            title="Retains audit records",
                            odp_definitions=_CMMC_DEFS_C1,
                        ),
                        ScoringControl(
                            control_id=_CMMC_C2,
                            domain=_CMMC_NS,
                            point_value="3",
                            title="Has no parameters",
                            odp_definitions=[],
                        ),
                    ]
                )
                for order, cid in enumerate((_CMMC_C1, _CMMC_C2)):
                    s.add(
                        SSPControlEntry(
                            project_id=project_id,
                            control_id=cid,
                            nist_id="3.3.1",
                            domain=_CMMC_NS,
                            title=f"Practice {cid}",
                            requirement="The organization does the thing.",
                            sort_order=order,
                        )
                    )
            yield project_id
        finally:
            async with session_scope() as s:
                await s.execute(
                    delete(ScoringControl).where(
                        ScoringControl.control_id.in_([_CMMC_C1, _CMMC_C2])
                    )
                )


def _defs_by_control(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return {e["control_id"]: e.get("odp_definitions") or [] for e in payload["entries"]}


async def _get_project(project_id: int) -> dict[str, Any]:
    async with _client() as c:
        r = await c.get(f"/api/ssp/projects/{project_id}")
    assert r.status_code == 200, r.text
    return dict(r.json())


# --------------------------------------------------------------------------
# 1. The defect: an 800-53 project's entries expose ODP definitions carrying a
#    label and the catalog's guidance. On unmodified code this printed
#    "no 800-53 entry carried any ODP definition; 149 entries, all with
#    odp_definitions == []".
# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_80053_entries_expose_odp_definitions_with_label_and_guidance() -> None:
    async with _project("nist-800-53r5", baseline="low") as project_id:
        payload = await _get_project(project_id)
        by_control = _defs_by_control(payload)

        with_defs = {cid: d for cid, d in by_control.items() if d}
        assert with_defs, (
            "no 800-53 entry carried any ODP definition; "
            f"{len(by_control)} entries, all with odp_definitions == []"
        )

        ac2 = by_control[_LABELLED_CONTROL]
        assert ac2, f"{_LABELLED_CONTROL} has catalog parameters but no definitions"
        assert all(d["label"] for d in ac2), "an ODP reached the editor with no label"
        assert any(d["guidance"] for d in ac2), "no ODP carried its catalog guidance"

        # Every prompt addresses a slot the seed actually scaffolded, so the
        # editor's field and the stored value share one key. Without this the
        # prompt could render and still never read its own value back.
        entry = next(
            e for e in payload["entries"] if e["control_id"] == _LABELLED_CONTROL
        )
        assert {d["key"] for d in ac2} <= set(entry["odp_values"])

        # The definitions come from the catalog, not from a new row in the CMMC
        # matrix. ``ScoringControl`` is the 110-row CMMC L2 table and must not
        # grow an 800-53 vocabulary alongside it.
        async with session_scope() as s:
            ids = (await s.execute(select(ScoringControl.control_id))).scalars().all()
        assert not [c for c in ids if c.startswith(("AC-", "AU-", "SC-", "SI-"))], (
            "800-53 control ids appeared in ccf.scoring_controls"
        )


# --------------------------------------------------------------------------
# 2. The completeness gate now measures them: ``missing_odp`` can fire for an
#    800-53 project, which it previously could not at all (``defined`` was
#    always the empty set), and it stops firing once the values are filled.
# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_completeness_gate_counts_unfilled_80053_parameters() -> None:
    async with _project("nist-800-53r5", baseline="low") as project_id:
        async with session_scope() as s:
            proj = await s.get(SSPProject, project_id)
            assert proj is not None
            report = await project_completeness(s, proj)

        gaps = {g["control_id"]: g["gaps"] for g in report["control_gaps"]}
        ac2_gaps = [g for g in gaps.get(_LABELLED_CONTROL, []) if "unfilled parameter" in g]
        catalog = load_oscal_catalog()
        n_params = len(catalog.get(_LABELLED_CONTROL).params)  # type: ignore[union-attr]
        assert ac2_gaps == [f"{n_params} unfilled parameter(s)"], (
            "the unfilled-parameter gate did not fire for an 800-53 control; "
            f"{_LABELLED_CONTROL} gaps were {gaps.get(_LABELLED_CONTROL)}"
        )

        # Fill them and the gap must go away — proving the gate measures these
        # values rather than merely emitting a constant string.
        async with session_scope() as s:
            entry = (
                await s.execute(
                    select(SSPControlEntry).where(
                        SSPControlEntry.project_id == project_id,
                        SSPControlEntry.control_id == _LABELLED_CONTROL,
                    )
                )
            ).scalar_one()
            entry.odp_values = {k: "a defined value" for k in entry.odp_values}

        async with session_scope() as s:
            proj = await s.get(SSPProject, project_id)
            assert proj is not None
            report2 = await project_completeness(s, proj)
        gaps2 = {g["control_id"]: g["gaps"] for g in report2["control_gaps"]}
        assert not [g for g in gaps2.get(_LABELLED_CONTROL, []) if "unfilled parameter" in g]


# --------------------------------------------------------------------------
# 3. A control with ``select.choice[]`` carries its choices through to the
#    editor. tests/test_catalog_params.py proves the parse side; this is the
#    delivery side, through the API and the rendered HTML.
# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_select_choices_reach_the_editor() -> None:
    async with _project("nist-800-53r5", baseline="low") as project_id:
        payload = await _get_project(project_id)
        defs = {d["key"]: d for d in _defs_by_control(payload)[_CHOICE_CONTROL]}

        param = defs[_CHOICE_PARAM]
        assert param["choices"] == _CHOICE_VALUES
        # ``_ssp_entry.html`` renders a <select> only when kind == 'selection',
        # so a choice list with the wrong kind would silently render a free-text
        # box and lose the constraint.
        assert param["kind"] == "selection"

        async with _client() as c:
            html = (await c.get(f"/ssp/{project_id}")).text
        assert f'name="odp::{_CHOICE_PARAM}"' in html
        for choice in _CHOICE_VALUES:
            assert f'<option value="{choice}"' in html


# --------------------------------------------------------------------------
# 4. The CMMC path is unchanged, asserted by equality against what it returns
#    today from ``ScoringControl.odp_definitions``.
# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cmmc_odp_definitions_unchanged() -> None:
    async with _cmmc_project() as project_id:
        payload = await _get_project(project_id)
        by_control = _defs_by_control(payload)

        assert by_control[_CMMC_C1] == _CMMC_DEFS_C1
        assert by_control[_CMMC_C2] == []

        async with session_scope() as s:
            proj = await s.get(SSPProject, project_id)
            assert proj is not None
            report = await project_completeness(s, proj)
        gaps = {g["control_id"]: g["gaps"] for g in report["control_gaps"]}
        assert "1 unfilled parameter(s)" in gaps[_CMMC_C1]
        assert not [g for g in gaps[_CMMC_C2] if "unfilled parameter" in g]

        async with _client() as c:
            html = (await c.get(f"/ssp/{project_id}")).text
        assert 'name="odp::audit_retention_period"' in html
        assert "audit record retention period" in html


# --------------------------------------------------------------------------
# 5. The key-name mismatch is closed: one spelling, ``key``, asserted in the
#    producer and in the consumer.
# --------------------------------------------------------------------------
def test_one_key_spelling_in_producer_and_consumer() -> None:
    catalog = load_oscal_catalog()
    _entries, defs = build_80053_entries(catalog, "low")
    sample = defs[_LABELLED_CONTROL]

    # Producer: exactly the ccf.ssp.odp.ODP shape — the CMMC producer's shape —
    # and no lingering "id" spelling.
    odp_shape = {f.name for f in fields(ODP)}
    assert {frozenset(d) for d in sample} == {frozenset(odp_shape)}
    assert not any("id" in d for d in sample)

    # Consumer: ssp/completeness.py reads "key". Feeding it these definitions
    # with nothing filled must count every one of them.
    entry = {
        "control_id": _LABELLED_CONTROL,
        "odp_definitions": sample,
        "odp_values": {d["key"]: None for d in sample},
    }
    assert f"{len(sample)} unfilled parameter(s)" in _entry_gaps(entry)

    # And a definition spelled the old way must NOT satisfy the gate — this is
    # the assertion that fails if the producer reverts to {"id": ...}.
    legacy = [{"id": d["key"], "label": d["label"]} for d in sample]
    assert f"{len(sample)} unfilled parameter(s)" not in _entry_gaps(
        {**entry, "odp_definitions": legacy}
    )


# --------------------------------------------------------------------------
# 6. A parameter with no guidance and no choices renders without inventing
#    either.
# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_parameter_without_guidance_or_choices_invents_nothing() -> None:
    async with _project("nist-800-53r5", baseline="low") as project_id:
        payload = await _get_project(project_id)
        defs = {d["key"]: d for d in _defs_by_control(payload)[_CHOICE_CONTROL]}

        bare = defs[_BARE_PARAM]
        assert bare["guidance"] is None
        assert bare["choices"] == []
        assert bare["kind"] == "assignment"
        # The 800-53 catalog proposes no example value. Filling ``suggested``
        # would put an unreviewed number in front of a human as though NIST had
        # offered it.
        assert bare["suggested"] is None
        assert bare["label"]

        async with _client() as c:
            html = (await c.get(f"/ssp/{project_id}")).text
        # Rendered as a free-text input with the template's generic placeholder,
        # not a <select> and not an italic guidance clause.
        at = html.index(f'name="odp::{_BARE_PARAM}"')
        # Exactly this parameter's own <label class="field-group"> block — a
        # wider window picks up the *previous* parameter's guidance clause.
        start = html.rindex('<label class="field-group">', 0, at)
        field = html[start : html.index("</label>", at)]
        assert "<select" not in field
        assert "font-style:italic" not in field, "guidance markup rendered for a param with none"
        assert "organization-defined value" in field


def test_parameter_with_no_catalog_label_falls_back_to_its_identifier() -> None:
    """Two catalog params carry no label at all (``SC-36``, ``SI-7(1)``).

    Added after a mutation survived: dropping the ``label or p.id`` fallback
    changed nothing any other test could see, because every parameter in the
    LOW baseline happens to be labelled. A blank prompt would ask a human to
    type a value into a box with no question above it.
    """
    catalog = load_oscal_catalog()
    for cid, param_id in (("SC-36", "sc-36_prm_1"), ("SI-7(1)", "si-7.1_prm_2")):
        oc = catalog.get(cid)
        assert oc is not None
        assert not any((p.label or "").strip() for p in oc.params if p.id == param_id)
        defs = {d["key"]: d for d in odp_definitions_for(oc)}
        assert defs[param_id]["label"] == param_id
