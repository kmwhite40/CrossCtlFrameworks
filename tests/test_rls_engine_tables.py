"""Structural + behavioral RLS coverage for the eleven engine tables slices
1-6 built without it -- migration 0060 (2026-08-12 RLS-coverage design).

`current_tenant() IS NULL` means *unrestricted*. The failure mode this module
exists to catch is not an outage -- it is a policy that exists, reports as
enabled, and filters nothing, because FORCE was omitted (the table's owner,
role `ccf`, bypasses its own policy without it) or because the session under
test never had the tenant GUC set. So every table gets two independent
assertions, not one:

1. STRUCTURAL: `relrowsecurity` AND `relforcerowsecurity` are both true, and
   a `tenant_isolation` row exists in `pg_policy` for that table. Asserting
   `relrowsecurity` alone would pass on a table an operator could still read
   in full as the owning role -- the two columns are separate and only the
   pair is meaningful (see the design doc's "Ownership and FORCE" section).
2. BEHAVIORAL: with the tenant GUC actually set to org A (via
   `ccf.db.set_session_tenant`, the same call `ccf.api.deps.get_session`
   makes on every real request), org B's row is invisible -- both from a
   list query and from a direct fetch by id. Asserted against a *scoped*
   session, never the bootstrap session `session_scope()` opens by default,
   which every policy here treats as bypass and would make this assertion
   vacuous.

Parametrized over the eleven so a twelfth table added later without a policy
is caught by the same test, not a new one -- see also
tests/test_rls_registry_no_gap.py, which catches the same gap from the
schema side (no organization_id-carrying table lacking a policy) rather than
this module's enumerated side.

`_seed_chain` builds one full chain per organization -- prep_runs through
prep_embeddings/prep_jobs, and the assessment_control_proposals through
assessment_jobs chain, plus a standalone calibration_snapshots row -- so
every one of the eleven tables gets a real row per org in one call. Content
strings differ between org A and org B (asymmetric fixtures): a bug that
swapped which org's id was checked would otherwise be invisible.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from pgvector.sqlalchemy import Vector
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select, text, update
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.exc import DBAPIError

from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import Assessment, Organization, System
from ccf.models_assessment_engine import (
    AssessmentControlProposal,
    AssessmentJob,
    AssessmentObjectiveProposal,
    CalibrationSnapshot,
)
from ccf.models_prep import (
    PrepClassification,
    PrepEmbedding,
    PrepJob,
    PrepLine,
    PrepRun,
    PrepScreen,
    PrepUnit,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


ENGINE_TABLES: tuple[str, ...] = (
    "prep_runs",
    "prep_lines",
    "prep_screens",
    "prep_units",
    "prep_classifications",
    "prep_embeddings",
    "prep_jobs",
    "assessment_control_proposals",
    "assessment_objective_proposals",
    "assessment_jobs",
    "calibration_snapshots",
)

_MODEL_BY_TABLE: dict[str, type] = {
    "prep_runs": PrepRun,
    "prep_lines": PrepLine,
    "prep_screens": PrepScreen,
    "prep_units": PrepUnit,
    "prep_classifications": PrepClassification,
    "prep_embeddings": PrepEmbedding,
    "prep_jobs": PrepJob,
    "assessment_control_proposals": AssessmentControlProposal,
    "assessment_objective_proposals": AssessmentObjectiveProposal,
    "assessment_jobs": AssessmentJob,
    "calibration_snapshots": CalibrationSnapshot,
}


async def _seed_chain(tag: str) -> tuple[int, dict[str, int]]:
    """One full chain across all eleven tables for a fresh throwaway org
    tagged ``tag`` ("A" or "B") -- content and identifiers differ between
    tags so a swap bug is never silently undetectable.

    ``organizations.name`` is unique, and this helper is invoked once per
    parametrized table case (11 times per tag, since ``fresh_engine`` does
    not truncate data between tests) -- so every name gets a fresh uuid4
    suffix rather than a bare ``tag``, which would collide on the second
    parametrized case.
    """
    unique = uuid.uuid4().hex[:8]
    async with session_scope() as s:  # bootstrap role -- unscoped, full access
        org = Organization(name=f"RlsEngineOrg{tag}{unique}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"RlsEngineSys{tag}{unique}")
        s.add(system)
        await s.flush()
        assessment = Assessment(
            system_id=system.id, name=f"RlsEngineAssess{tag}{unique}", kind="self"
        )
        s.add(assessment)
        await s.flush()

        run = PrepRun(organization_id=org.id, source_kind="evidence_version", source_id=1)
        s.add(run)
        await s.flush()

        line = PrepLine(
            run_id=run.id,
            organization_id=org.id,
            line_number=1,
            content=f"Engine RLS line content, organization {tag}.",
        )
        s.add(line)
        await s.flush()

        screen = PrepScreen(line_id=line.id, run_id=run.id, organization_id=org.id)
        unit = PrepUnit(
            run_id=run.id,
            organization_id=org.id,
            trigger_line_id=line.id,
            content=f"Engine RLS unit content, organization {tag}.",
        )
        s.add_all([screen, unit])
        await s.flush()

        classification = PrepClassification(unit_id=unit.id, run_id=run.id, organization_id=org.id)
        embedding = PrepEmbedding(
            unit_id=unit.id, run_id=run.id, organization_id=org.id, model_name="rls-test-model"
        )
        job = PrepJob(run_id=run.id, organization_id=org.id)
        s.add_all([classification, embedding, job])
        await s.flush()

        control_proposal = AssessmentControlProposal(
            organization_id=org.id, assessment_id=assessment.id, control_identifier=f"AC-{tag}"
        )
        s.add(control_proposal)
        await s.flush()

        objective_proposal = AssessmentObjectiveProposal(
            organization_id=org.id,
            control_proposal_id=control_proposal.id,
            label=f"AC-2{tag.lower()}",
            objective_text=f"Objective text, organization {tag}.",
            objective_text_sha256=("a" if tag == "A" else "b") * 64,
        )
        assessment_job = AssessmentJob(
            organization_id=org.id, control_proposal_id=control_proposal.id
        )
        calibration = CalibrationSnapshot(
            organization_id=org.id, config_fingerprint=("11" if tag == "A" else "22") * 4
        )
        s.add_all([objective_proposal, assessment_job, calibration])
        await s.flush()

        return int(org.id), {
            "prep_runs": int(run.id),
            "prep_lines": int(line.id),
            "prep_screens": int(screen.id),
            "prep_units": int(unit.id),
            "prep_classifications": int(classification.id),
            "prep_embeddings": int(embedding.id),
            "prep_jobs": int(job.id),
            "assessment_control_proposals": int(control_proposal.id),
            "assessment_objective_proposals": int(objective_proposal.id),
            "assessment_jobs": int(assessment_job.id),
            "calibration_snapshots": int(calibration.id),
        }


@pytest.mark.parametrize("table", ENGINE_TABLES)
async def test_engine_table_rls_enabled_and_forced(table: str) -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        row = (
            await s.execute(
                text(
                    "SELECT c.relrowsecurity, c.relforcerowsecurity, "
                    "EXISTS(SELECT 1 FROM pg_policy p JOIN pg_class pc ON pc.oid = p.polrelid "
                    "  WHERE pc.relname = :t AND p.polname = 'tenant_isolation') AS has_policy "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'ccf' AND c.relname = :t"
                ),
                {"t": table},
            )
        ).one()
    assert row.relrowsecurity is True, f"ccf.{table}: ROW LEVEL SECURITY is not ENABLED"
    assert row.relforcerowsecurity is True, f"ccf.{table}: ROW LEVEL SECURITY is not FORCED"
    assert row.has_policy is True, f"ccf.{table}: tenant_isolation policy is missing"


@pytest.mark.parametrize("table", ENGINE_TABLES)
async def test_engine_table_scopes_to_owning_org(table: str) -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a, ids_a = await _seed_chain("A")
    org_b, ids_b = await _seed_chain("B")
    model = _MODEL_BY_TABLE[table]
    id_a, id_b = ids_a[table], ids_b[table]

    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        visible = (await s.execute(select(model.id))).scalars().all()  # type: ignore[attr-defined]
        assert id_a in visible, f"{table}: org A cannot see its own row"
        assert id_b not in visible, f"{table}: org A can see org B's row"
        direct = (
            await s.execute(select(model).where(model.id == id_b))  # type: ignore[attr-defined]
        ).scalar_one_or_none()
        assert direct is None, f"{table}: direct fetch of org B's row by id succeeded under org A"

    async with session_scope() as s:
        await set_session_tenant(s, org_b)
        visible = (await s.execute(select(model.id))).scalars().all()  # type: ignore[attr-defined]
        assert id_b in visible, f"{table}: org B cannot see its own row"
        assert id_a not in visible, f"{table}: org B can see org A's row"


@pytest.mark.parametrize("table", ENGINE_TABLES)
async def test_engine_table_refuses_to_write_a_row_into_another_org(table: str) -> None:
    """Writes, which nothing else in this file exercises -- every other test reads.

    Re-parenting org A's own row to org B must be refused. Verified to be a
    real guard: with the policy weakened, the update succeeds.

    On what actually enforces it, stated precisely because the obvious reading
    is wrong. This is a FOR ALL policy, and Postgres applies its USING
    expression to the *new* row on UPDATE as well as the old one. Weakening
    only WITH CHECK to (true) still leaves this refused -- confirmed by
    mutation, with Postgres reporting "new row violates row-level security
    policy" even then. So this test guards the re-parent, and USING is what
    stands behind it.

    WITH CHECK was therefore still uncovered on the path where it is the
    *only* guard: an INSERT of a brand-new row carrying another org's id,
    where there is no old row for USING to inspect. The final review
    demonstrated that a cross-tenant INSERT persists silently under a
    weakened WITH CHECK. That path is now closed by
    ``test_engine_table_refuses_a_cross_tenant_insert`` below.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a, ids_a = await _seed_chain("A")
    org_b, _ids_b = await _seed_chain("B")
    model = _MODEL_BY_TABLE[table]
    id_a = ids_a[table]

    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        with pytest.raises(DBAPIError) as excinfo:
            await s.execute(
                update(model)  # type: ignore[arg-type]
                .where(model.id == id_a)  # type: ignore[attr-defined]
                .values(organization_id=org_b)
            )
            await s.flush()
        assert "row-level security" in str(excinfo.value).lower(), (
            f"{table}: the write was refused, but not by the RLS policy"
        )

    # And the row really did stay put -- a refused write must not be a silent
    # partial one. Checked unscoped, so this cannot pass by being filtered out.
    async with session_scope() as s:
        row = await s.get(model, id_a)  # type: ignore[arg-type]
        assert row is not None, f"{table}: org A's row vanished"
        assert row.organization_id == org_a, f"{table}: org A's row was re-parented to org B"


@pytest.mark.parametrize("table", ENGINE_TABLES)
async def test_engine_table_refuses_a_cross_tenant_insert(table: str) -> None:
    """WITH CHECK, exercised on the one path where it is the *only* guard.

    The UPDATE test above refuses a re-parent, but (per its own docstring,
    confirmed by mutation) that refusal is USING's doing -- this is a FOR ALL
    policy, and Postgres applies USING to the new row on UPDATE too, so
    WITH CHECK is never actually exercised alone there.

    INSERT is different: there is no old row for USING to inspect, so
    WITH CHECK alone stands between the caller and a row belonging to another
    tenant. A prior review weakened WITH CHECK to ``(true)`` and every
    existing RLS test still passed, then showed by raw SQL that a
    cross-tenant INSERT silently persists under it -- this test is what would
    have caught that.

    The forged row is built generically, from org A's own persisted row, so
    this covers all eleven tables without eleven hand-written fixtures: read
    the row back unscoped, drop the primary key, and override
    organization_id to org B's id. Every foreign key on the row is still
    valid (it pointed into a real chain when org A's own insert succeeded);
    the only thing wrong with the row is the tenant it claims.

    Three tables carry a table-wide (not per-organization) uniqueness
    constraint on a column this straight copy would otherwise duplicate
    verbatim from org A's row: prep_embeddings.unit_id, and the
    (assessment_id, control_identifier) / (control_proposal_id, label) partial
    unique indexes on the two assessment-engine proposal tables. Verified
    live: left alone, that constraint fires before WITH CHECK ever runs, and
    the resulting DBAPIError would not mention row-level security --
    silently defeating this test's whole purpose without the assertion below
    ever going red. So those three columns are perturbed to a fresh,
    still-valid value first, leaving organization_id as the forged row's one
    and only problem, same as every other table here.

    The INSERT itself is issued as raw parameterised SQL, not SQLAlchemy's
    ``insert()`` construct, for a reason verified the hard way rather than
    assumed: SQLAlchemy compiles a plain ORM/Core ``INSERT`` against a
    Postgres table with an implicit ``RETURNING id``, to fetch the generated
    primary key, and Postgres applies the table's *SELECT* (USING) policy to
    whatever a RETURNING clause would hand back -- separately from WITH
    CHECK. A first draft built on ``insert()`` kept raising "row-level
    security" even with WITH CHECK alone weakened to ``(true)``, not because
    WITH CHECK caught the forged row but because the implicit RETURNING did,
    through USING -- reintroducing exactly the masking this test exists to
    avoid, and doing it silently: every assertion still read as green. Trying
    to suppress that by flipping the mapped ``Table.implicit_returning`` flag
    at runtime did not help either -- ``_seed_chain`` above already flushed an
    ORM insert against these same tables earlier in the test, and whatever
    SQLAlchemy caches from that first compile ignores a later flag flip, so
    the RETURNING clause came back anyway. Raw SQL sidesteps both problems at
    once: it is never compiled with implicit RETURNING in the first place.
    Two column types need their own handling to build that SQL generically --
    JSONB columns are passed through ``json.dumps`` with an explicit
    ``::jsonb`` cast, since asyncpg cannot infer a JSON parameter's type on
    its own, and pgvector's ``Vector`` / Postgres's ``TSVECTOR`` columns are
    left out of the statement entirely (both are nullable and irrelevant to
    whether WITH CHECK refuses the row on organization_id alone, and neither
    has a plain literal syntax worth reproducing here).
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a, ids_a = await _seed_chain("A")
    org_b, ids_b = await _seed_chain("B")
    model = _MODEL_BY_TABLE[table]
    id_a, id_b = ids_a[table], ids_b[table]

    mapper = sa_inspect(model)
    pk_keys = {c.key for c in mapper.primary_key}

    async with session_scope() as s:  # bootstrap role -- unscoped, full access
        row = await s.get(model, id_a)  # type: ignore[arg-type]
        assert row is not None, f"{table}: org A's seeded row is missing"
        forged = {
            col.key: getattr(row, col.key) for col in mapper.columns if col.key not in pk_keys
        }

    forged["organization_id"] = org_b

    if table == "prep_embeddings":
        # unit_id is unique across the whole table -- org A's own unit
        # already has the embedding row this copy started from, so reusing
        # it collides regardless of tenant. A second, not-yet-embedded unit
        # on org A's own chain sidesteps that without touching organization_id.
        async with session_scope() as s:
            spare_unit = PrepUnit(
                run_id=ids_a["prep_runs"],
                organization_id=org_a,
                trigger_line_id=ids_a["prep_lines"],
                content="Spare unit for the cross-tenant INSERT probe.",
            )
            s.add(spare_unit)
            await s.flush()
            forged["unit_id"] = int(spare_unit.id)
    elif table == "assessment_control_proposals":
        # uq_control_proposal_first_pass: (assessment_id, control_identifier)
        # where source_poam_id IS NULL -- org A's row already holds that pair.
        forged["control_identifier"] = f"{forged['control_identifier']}-XTENANT"
    elif table == "assessment_objective_proposals":
        # uq_objective_proposal_label: (control_proposal_id, label).
        forged["label"] = f"{forged['label']}-XTENANT"

    columns: list[str] = []
    placeholders: list[str] = []
    params: dict[str, Any] = {}
    for col in mapper.columns:
        if col.key not in forged:
            continue
        if isinstance(col.type, (TSVECTOR, Vector)):
            continue
        columns.append(col.key)
        if isinstance(col.type, JSONB):
            # CAST(...), not a bare ``::jsonb`` suffix -- SQLAlchemy's
            # text() bind-param parser trips on ``:name::jsonb``, reading
            # the second colon as the start of another (invalid) parameter.
            placeholders.append(f"CAST(:{col.key} AS jsonb)")
            params[col.key] = json.dumps(forged[col.key])
        else:
            placeholders.append(f":{col.key}")
            params[col.key] = forged[col.key]
    insert_sql = text(
        f"INSERT INTO ccf.{table} ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
    )

    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        with pytest.raises(DBAPIError) as excinfo:
            await s.execute(insert_sql, params)
        assert "row-level security" in str(excinfo.value).lower(), (
            f"{table}: the insert was refused, but not by the RLS policy"
        )

    # And no such row landed -- checked unscoped, so this cannot pass by being
    # filtered out. Org B's *own* legitimately seeded row (id_b) is expected;
    # anything else with organization_id == org_b would be the forged row
    # having partially persisted despite the raised error.
    async with session_scope() as s:
        org_b_ids = (
            await s.execute(
                select(model.id).where(model.organization_id == org_b)  # type: ignore[attr-defined]
            )
        ).scalars().all()
        assert org_b_ids == [id_b], (
            f"{table}: a cross-tenant row landed for org B "
            f"(found {org_b_ids}, expected only {id_b})"
        )
