"""GUC audit (2026-08-12 RLS-coverage design, Task 2): direct assertions on
the mechanism that makes the worker/CLI paths' unscoped access to the eleven
newly-RLS'd engine tables (migration 0064) deliberate rather than an
oversight.

``ccf.db.session_scope()`` -- every CLI command, both worker drain loops
(``ccf prep-worker``, ``ccf assessment-worker``) -- always calls
``set_session_tenant(session, None)``: RESET ROLE plus a cleared
``ccf.tenant_id`` GUC, leaving the bootstrap role ``ccf`` (a superuser) in
effect. ``current_tenant() IS NULL`` is what every tenant_isolation policy in
this schema treats as bypass, by design: one worker process must drain every
organization's queued jobs in a single claim query
(``ccf.queue.claim_jobs``/``ccf.prep.jobs.claim`` have no organization_id
filter, intentionally). This is not new to this slice -- ``models_prep.py``
and ``models_assessment_engine.py`` already documented it before migration
0064 existed, when it read as "no RLS at all"; both docstrings are updated
in this same task to say "has RLS via 0064, worker deliberately bypasses
it," since after Task 1 the old wording is simply false.

What was missing before this module: a *direct* assertion on the mechanism
itself, on the exact session type the worker opens, rather than only on its
downstream effect. ``tests/test_prep_tenant_isolation.py`` and
``tests/test_assessment_engine_api.py::test_create_proposal_app_check_rejects_cross_tenant_assessment_indep_of_rls``
already prove the *application*-level guards hold even though RLS cannot
help on this session type -- this module is not a duplicate of either; it
instead pins the GUC/role state itself, so a future change that accidentally
scopes ``session_scope()`` (e.g. it starts calling SET ROLE ccf_app) is caught
here, as a worker silently seeing only one organization's jobs from then on,
rather than discovered later as orphaned queues in every other organization.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select, text

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentJob
from ccf.models_prep import PrepJob, PrepRun
from ccf.prep import jobs as prep_jobs
from ccf.queue import claim_jobs

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def test_session_scope_leaves_the_tenant_guc_unset_and_the_bootstrap_role_in_effect() -> (
    None
):
    """Direct assertion on the mechanism, not just its effect: session_scope()
    never sets ccf.tenant_id and never SET ROLEs to ccf_app. It stays on the
    bootstrap `ccf` role, which the eleven tables' new FORCE RLS (migration
    0064) cannot restrict -- a table's owner bypasses its own policy unless
    it queries as a *different*, non-owning role (see the design doc's
    "Ownership and FORCE" section, and Global Constraints' "RLS mechanics").
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        tenant_guc = (
            await s.execute(text("SELECT current_setting('ccf.tenant_id', true)"))
        ).scalar_one()
        role = (await s.execute(text("SELECT current_user"))).scalar_one()
    assert tenant_guc in ("", None), f"session_scope() left ccf.tenant_id={tenant_guc!r}"
    assert role == "ccf", f"session_scope() switched role to {role!r}, expected bootstrap 'ccf'"


async def test_prep_worker_claim_drains_two_organizations_in_one_cycle() -> None:
    """The deliberate cross-tenant behavior, through the real worker entrypoint
    (`prep_jobs.claim`, exactly what `ccf.prep.jobs.run_once` -- and therefore
    `ccf prep-worker` -- calls) on a `session_scope()` session, exactly as the
    CLI opens it. Two organizations' pending jobs are claimed in the same
    call: proof migration 0064's FORCE RLS does not narrow this on the one
    path that would fail loudly (a job silently never claimed, sitting
    `pending` forever) rather than leak.

    ``limit`` is sized to the *actual* pending backlog rather than a fixed
    constant: other test modules in this suite legitimately leave `pending`
    `PrepJob` rows behind (the shared test database is migrated once per
    session, not reset per test -- see `tests/conftest.py::clean_migrated_db`),
    and `claim()` is FIFO by `created_at`. A fixed `limit=10` claims only the
    ten *oldest* pending jobs in the whole table when run inside the full
    suite, which are not necessarily these two -- starving this test's own
    jobs out of the claim and failing for a reason that has nothing to do
    with RLS or the GUC. Counting the real backlog first and using it as the
    limit keeps the assertion meaningful (both seeded jobs are claimed) while
    working alone or inside the full suite.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        org_a = Organization(name="RlsGucWorkerOrgA")
        org_b = Organization(name="RlsGucWorkerOrgB")
        s.add_all([org_a, org_b])
        await s.flush()
        run_a = PrepRun(organization_id=org_a.id, source_kind="evidence_version", source_id=201)
        run_b = PrepRun(organization_id=org_b.id, source_kind="evidence_version", source_id=202)
        s.add_all([run_a, run_b])
        await s.flush()
        job_a = PrepJob(run_id=run_a.id, organization_id=org_a.id, status="pending")
        job_b = PrepJob(run_id=run_b.id, organization_id=org_b.id, status="pending")
        s.add_all([job_a, job_b])
        await s.flush()
        job_a_id, job_b_id = int(job_a.id), int(job_b.id)

    async with session_scope() as s:
        pending_count_query = (
            select(func.count()).select_from(PrepJob).where(PrepJob.status == "pending")
        )
        pending_backlog = (await s.execute(pending_count_query)).scalar_one()
        claimed = await prep_jobs.claim(s, worker="rls-guc-audit", limit=int(pending_backlog))
        await s.commit()
    claimed_ids = {int(j.id) for j in claimed}
    assert job_a_id in claimed_ids and job_b_id in claimed_ids, (
        "one worker session must claim pending jobs across both organizations in the "
        "same cycle -- claiming only one org's job means FORCE RLS is narrowing the "
        "worker's own claim query, the silent-no-op failure this slice exists to prevent"
    )


async def test_assessment_worker_claim_drains_two_organizations_in_one_cycle() -> None:
    """Mirrors the prep-worker test above for `assessment_jobs`, via
    `ccf.queue.claim_jobs` directly -- `ccf.assessment.engine.jobs` has no
    local `claim` wrapper of its own; `run_once` calls the shared primitive
    inline, so this test does too, matching the real call site exactly.

    ``limit`` is sized to the actual pending backlog for the same reason as
    the prep-worker test above: other test modules legitimately leave
    `pending` `AssessmentJob` rows behind in the shared, session-scoped test
    database.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        org_a = Organization(name="RlsGucAssessOrgA")
        org_b = Organization(name="RlsGucAssessOrgB")
        s.add_all([org_a, org_b])
        await s.flush()
        system_a = System(organization_id=org_a.id, name="RlsGucAssessSysA")
        system_b = System(organization_id=org_b.id, name="RlsGucAssessSysB")
        s.add_all([system_a, system_b])
        await s.flush()
        assessment_a = Assessment(system_id=system_a.id, name="RlsGucAssessA", kind="self")
        assessment_b = Assessment(system_id=system_b.id, name="RlsGucAssessB", kind="self")
        s.add_all([assessment_a, assessment_b])
        await s.flush()
        proposal_a = AssessmentControlProposal(
            organization_id=org_a.id, assessment_id=assessment_a.id, control_identifier="AC-GUC-A"
        )
        proposal_b = AssessmentControlProposal(
            organization_id=org_b.id, assessment_id=assessment_b.id, control_identifier="AC-GUC-B"
        )
        s.add_all([proposal_a, proposal_b])
        await s.flush()
        job_a = AssessmentJob(organization_id=org_a.id, control_proposal_id=proposal_a.id)
        job_b = AssessmentJob(organization_id=org_b.id, control_proposal_id=proposal_b.id)
        s.add_all([job_a, job_b])
        await s.flush()
        job_a_id, job_b_id = int(job_a.id), int(job_b.id)

    async with session_scope() as s:
        pending_count_query = (
            select(func.count()).select_from(AssessmentJob).where(AssessmentJob.status == "pending")
        )
        pending_backlog = (await s.execute(pending_count_query)).scalar_one()
        claimed = await claim_jobs(
            s, AssessmentJob, worker="rls-guc-audit", limit=int(pending_backlog)
        )
        await s.commit()
    claimed_ids = {int(j.id) for j in claimed}
    assert job_a_id in claimed_ids and job_b_id in claimed_ids, (
        "one assessment-worker session must claim pending jobs across both organizations "
        "in the same cycle -- see the prep-worker version of this test for why"
    )
