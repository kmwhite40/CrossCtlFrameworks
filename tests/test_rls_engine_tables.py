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

import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text, update
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

    WITH CHECK is therefore still uncovered on the path where it is the *only*
    guard: an INSERT of a brand-new row carrying another org's id, where there
    is no old row for USING to inspect. The final review demonstrated that a
    cross-tenant INSERT persists silently under a weakened WITH CHECK. Closing
    that needs a valid FK chain per table and is filed as debt rather than
    claimed here.
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
