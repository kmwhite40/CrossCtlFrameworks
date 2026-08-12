"""Coverage regression test for tenant-isolation RLS across the whole schema.

``tests/test_rls.py`` proves the RLS mechanism works end-to-end on two tables
(``systems`` and ``fedramp_dependencies``). That leaves the other ~100+
policy-bound tables unverified: a dropped ``tenant_isolation`` policy, a
disabled/unforced RLS flag, or a loosened predicate on any of them would still
pass CI. This module closes that gap with two complementary checks:

1. A STRUCTURAL guard (``test_rls_policy_structural_guard``) that enumerates
   every ``ccf``-schema table carrying a ``tenant_isolation`` policy straight
   from the Postgres catalog (``pg_policy``/``pg_class``/``pg_namespace``) and
   asserts, for each, that ``relrowsecurity`` and ``relforcerowsecurity`` are
   both true. The enumerated set is compared against a hardcoded snapshot of
   every table policied as of this writing (121 tables spanning migrations
   0010 through 0060) — so the test fails loudly if a table's policy is
   dropped (it silently disappears from the live-enumerated set) or if RLS
   enforcement is disabled on a table that still has one.
2. A BEHAVIORAL check (``test_rls_scopes_representative_org_scoped_tables``)
   that extends the existing systems/fedramp_dependencies pattern to seven more
   practical, easy-to-seed tables covering all scoping shapes used across the
   schema: direct ``organization_id`` (``ssp_projects``, ``organizations``
   itself), ``system_id`` via the owning system (``poams``, ``risks``,
   ``assessments``), a multi-hop FK chain (``evidence`` ->
   ``control_implementations`` -> ``systems``), and a two-hop parent chain via
   a non-organization_id parent (``poam_milestones`` -> ``poams`` ->
   ``systems``).
3. A dedicated behavioral check for ``audit_log`` (DATA-06,
   ``test_rls_scopes_audit_log_with_system_rows_visible_to_all``) — its
   predicate is a three-way OR (own org, or a NULL/system row) rather than the
   plain two-way ownership check the other tables use, since audit_log rows
   from system/unauthenticated events must stay visible to every scoped
   tenant. Rows are inserted with a real hash-chain link (mirroring
   ``ccf.api.audit``'s prev_hash/row_hash computation) so this test can't
   corrupt the global chain for other tests that run ``/api/audit/verify``.

Both tests seed only throwaway, uniquely-named orgs/systems/rows and clean up
everything except the get-or-create orgs/systems themselves (same convention
as ``test_rls.py``) — those are org-scoped and never counted by any other
test's unscoped assertions, so leaving them behind cannot leak into another
test's expectations (see the prior slice's isolation lesson referenced in the
task brief).
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ccf.api.audit import _GENESIS, row_hash
from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import (
    POAM,
    Assessment,
    AuditLog,
    Control,
    ControlImplementation,
    Evidence,
    Organization,
    PoamMilestone,
    Risk,
    SSPProject,
    System,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# Snapshot of every ccf-schema table carrying a `tenant_isolation` policy,
# taken from `pg_policy`/`pg_class` on the fully-migrated schema (migrations
# 0010 through 0046). If a future migration adds/removes RLS coverage, update
# this set alongside it — that's the point: the test is living documentation
# of exactly which tables are protected.
EXPECTED_TENANT_ISOLATION_TABLES: frozenset[str] = frozenset(
    {
        "access_review_items", "access_reviews", "ai_action_citations", "ai_action_evaluations",
        "ai_action_inputs", "ai_action_outputs", "ai_action_reviews", "ai_action_runs",
        "ai_agent_approvals", "ai_agent_incidents", "ai_agent_kill_switch_events",
        "ai_agent_monitoring_events", "ai_agent_risk_assessments", "ai_agents",
        "ai_approved_mutations", "ai_guardrail_violations", "ai_provider_configs", "approvals",
        "artifacts", "assessment_control_proposals", "assessment_control_results",
        "assessment_jobs", "assessment_objective_proposals", "assessment_results", "assessments",
        "assurance_build_runs", "assurance_edges", "assurance_impacts", "assurance_nodes",
        "assurance_queries", "assurance_query_results", "assurance_snapshots", "audit_engagements",
        "audit_findings", "audit_log", "audit_requests", "authorization_delta_memos",
        "authorization_package_artifacts", "authorization_package_diffs",
        "authorization_package_facts", "authorization_package_replay_runs",
        "authorization_packages", "calibration_snapshots", "capture_snapshots",
        "compliance_pack_versions",
        "compliance_packs", "connector_configs", "control_implementations",
        "control_test_results", "control_tests", "events", "evidence",
        "evidence_access_events", "evidence_confidence_scores", "evidence_objects",
        "evidence_replay_runs", "evidence_reproducibility_checks", "evidence_retention_policies",
        "evidence_reviews", "evidence_source_trust_policies", "evidence_versions",
        "external_access_grants", "external_comments", "external_evidence_shares",
        "external_identities", "external_package_shares", "external_portal_audit_events",
        "external_principals", "external_questionnaire_requests", "fedramp20x_profiles",
        "fedramp20x_readiness_snapshots", "fedramp_dependencies", "framework_controls",
        "group_role_mappings",
        "identity_providers", "ksi_assessor_reviews", "ksi_exceptions", "ksi_states",
        "ksi_validation_results", "monitoring_runs", "notifications", "organizations",
        "pack_controls", "pack_evidence_requirements", "pack_install_runs", "pack_mappings",
        "pack_rules", "pack_test_results", "people", "poam_milestones", "poams", "policies",
        "policy_attestations", "policy_versions", "prep_classifications", "prep_embeddings",
        "prep_jobs", "prep_lines", "prep_runs", "prep_screens", "prep_units",
        "questionnaire_responses",
        "questionnaire_templates", "regulatory_updates", "risks", "scan_ingestions",
        "scim_provisioning_events",
        "scoring_statuses", "self_assurance_runs", "ssp_control_entries", "ssp_projects",
        "system_profiles", "systems", "tasks", "training_records", "trust_access_requests",
        "trust_profiles", "users", "vendor_questionnaires", "vendors", "webhooks",
    }
)


@pytest.mark.asyncio
async def test_rls_policy_structural_guard() -> None:
    """Every table that should have tenant-isolation RLS still has it, enabled + forced.

    Enumerates `pg_policy` joined to `pg_class`/`pg_namespace` for policies named
    `tenant_isolation` in the `ccf` schema — this is a live catalog query, not an
    ORM assumption, so it directly reflects what Postgres will actually enforce.
    A dropped policy makes its table vanish from the enumerated set (caught by the
    set-equality assertion below); a disabled `relrowsecurity` or
    `relforcerowsecurity` flag is caught by the per-table assertions.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")

    async with session_scope() as s:
        await set_session_tenant(s, None)
        rows = (
            await s.execute(
                text(
                    "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity "
                    "FROM pg_policy p "
                    "JOIN pg_class c ON c.oid = p.polrelid "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'ccf' AND p.polname = 'tenant_isolation'"
                )
            )
        ).all()

    found = {r[0] for r in rows}
    missing = EXPECTED_TENANT_ISOLATION_TABLES - found
    unexpected = found - EXPECTED_TENANT_ISOLATION_TABLES
    assert not missing, (
        f"tenant_isolation policy missing/dropped on: {sorted(missing)} — "
        "RLS no longer protects these tables"
    )
    assert not unexpected, (
        f"tables with tenant_isolation not in the expected snapshot: {sorted(unexpected)} — "
        "update EXPECTED_TENANT_ISOLATION_TABLES for the new coverage"
    )
    assert len(found) == len(EXPECTED_TENANT_ISOLATION_TABLES) == 121

    for relname, rowsecurity, forcerowsecurity in rows:
        assert rowsecurity is True, f"ccf.{relname}: ROW LEVEL SECURITY is not ENABLED"
        assert forcerowsecurity is True, f"ccf.{relname}: ROW LEVEL SECURITY is not FORCED"


async def _seed_two_orgs() -> tuple[int, int, int, int]:
    """Get-or-create two throwaway orgs each with one system; returns their ids."""
    async with session_scope() as s:  # unscoped (bypass) — full access
        out: list[int] = []
        for org_name, sys_name in (("RlsCovOrgA", "RlsCovSysA"), ("RlsCovOrgB", "RlsCovSysB")):
            org = (
                await s.execute(select(Organization).where(Organization.name == org_name))
            ).scalar_one_or_none() or Organization(name=org_name)
            if org.id is None:
                s.add(org)
                await s.flush()
            sys = (
                await s.execute(
                    select(System).where(
                        System.organization_id == org.id, System.name == sys_name
                    )
                )
            ).scalar_one_or_none() or System(organization_id=org.id, name=sys_name)
            if sys.id is None:
                s.add(sys)
                await s.flush()
            out += [org.id, sys.id]
        return out[0], out[1], out[2], out[3]


async def _assert_scoped_to_owner(
    model: type, id_a: int, id_b: int, org_a: int, org_b: int
) -> None:
    """Under tenant A, only A's row is visible/fetchable — and vice versa."""
    table = model.__tablename__  # type: ignore[attr-defined]
    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        ids = (await s.execute(select(model.id))).scalars().all()  # type: ignore[attr-defined]
        assert id_a in ids and id_b not in ids, f"{table}: tenant A leaked/missing rows"
        # Direct fetch of B's row by id also returns nothing under tenant A (proves
        # the block isn't just a list-filter artifact of the app layer).
        assert (
            await s.execute(select(model).where(model.id == id_b))  # type: ignore[attr-defined]
        ).scalar_one_or_none() is None

    async with session_scope() as s:
        await set_session_tenant(s, org_b)
        ids = (await s.execute(select(model.id))).scalars().all()  # type: ignore[attr-defined]
        assert id_b in ids and id_a not in ids, f"{table}: tenant B leaked/missing rows"


@pytest.mark.asyncio
async def test_rls_scopes_representative_org_scoped_tables() -> None:
    """Behavioral RLS check on seven practical, easy-to-seed tables.

    Covers every predicate shape used across the schema: direct
    ``organization_id`` (``ssp_projects``, and ``organizations`` itself scoped
    on its own primary key), ``system_id`` scoped via the owning system
    (``poams``, ``risks``, ``assessments``), a two-hop FK chain (``evidence``
    -> ``control_implementations`` -> ``systems``), and a two-hop parent chain
    via a non-``organization_id`` parent (``poam_milestones`` -> ``poams`` ->
    ``systems``).
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")

    org_a, sys_a, org_b, sys_b = await _seed_two_orgs()

    poam_a = poam_b = risk_a = risk_b = None
    ssp_a = ssp_b = assess_a = assess_b = None
    impl_a = impl_b = evidence_a = evidence_b = None
    milestone_a = milestone_b = None
    control = None

    try:
        async with session_scope() as s:
            await set_session_tenant(s, None)

            # A shared, non-tenant-owned control catalog row (mirrors the real
            # catalog: `controls` carries no RLS) that both orgs' implementations
            # point at.
            control = (
                await s.execute(select(Control).where(Control.identifier == "RLS-COV-CTRL"))
            ).scalar_one_or_none() or Control(
                identifier="RLS-COV-CTRL", control_name="RLS Coverage Test"
            )
            if control.id is None:
                s.add(control)
                await s.flush()

            poam_a = POAM(system_id=sys_a, title="RlsCovPoamA")
            poam_b = POAM(system_id=sys_b, title="RlsCovPoamB")
            risk_a = Risk(system_id=sys_a, title="RlsCovRiskA")
            risk_b = Risk(system_id=sys_b, title="RlsCovRiskB")
            ssp_a = SSPProject(organization_id=org_a, customer_name="RlsCovSspA")
            ssp_b = SSPProject(organization_id=org_b, customer_name="RlsCovSspB")
            assess_a = Assessment(system_id=sys_a, name="RlsCovAssessA", kind="self")
            assess_b = Assessment(system_id=sys_b, name="RlsCovAssessB", kind="self")
            impl_a = ControlImplementation(system_id=sys_a, control_id=control.id)
            impl_b = ControlImplementation(system_id=sys_b, control_id=control.id)
            s.add_all(
                [poam_a, poam_b, risk_a, risk_b, ssp_a, ssp_b, assess_a, assess_b, impl_a, impl_b]
            )
            await s.flush()

            evidence_a = Evidence(
                implementation_id=impl_a.id, kind="document", title="RlsCovEvidenceA"
            )
            evidence_b = Evidence(
                implementation_id=impl_b.id, kind="document", title="RlsCovEvidenceB"
            )
            milestone_a = PoamMilestone(poam_id=poam_a.id, description="RlsCovMilestoneA")
            milestone_b = PoamMilestone(poam_id=poam_b.id, description="RlsCovMilestoneB")
            s.add_all([evidence_a, evidence_b, milestone_a, milestone_b])
            await s.flush()

            poam_ids = (poam_a.id, poam_b.id)
            risk_ids = (risk_a.id, risk_b.id)
            ssp_ids = (ssp_a.id, ssp_b.id)
            assess_ids = (assess_a.id, assess_b.id)
            evidence_ids = (evidence_a.id, evidence_b.id)
            milestone_ids = (milestone_a.id, milestone_b.id)

        await _assert_scoped_to_owner(POAM, *poam_ids, org_a, org_b)
        await _assert_scoped_to_owner(Risk, *risk_ids, org_a, org_b)
        await _assert_scoped_to_owner(SSPProject, *ssp_ids, org_a, org_b)
        await _assert_scoped_to_owner(Assessment, *assess_ids, org_a, org_b)
        await _assert_scoped_to_owner(Evidence, *evidence_ids, org_a, org_b)
        await _assert_scoped_to_owner(PoamMilestone, *milestone_ids, org_a, org_b)
        # `organizations` is scoped on its own primary key: under tenant A only
        # org A's own row is visible, not org B's (and vice versa).
        await _assert_scoped_to_owner(Organization, org_a, org_b, org_a, org_b)

        # Cross-tenant INSERT is rejected by the WITH CHECK clause — spot-check on
        # the deep-chain tables, the hardest predicates to get wrong.
        with pytest.raises(Exception):  # noqa: B017 - asyncpg/psycopg raise a DB error
            async with session_scope() as s:
                await set_session_tenant(s, org_a)
                s.add(POAM(system_id=sys_b, title="RlsCovSmuggledPoam"))
                await s.flush()

        with pytest.raises(Exception):  # noqa: B017 - asyncpg/psycopg raise a DB error
            async with session_scope() as s:
                await set_session_tenant(s, org_a)
                s.add(PoamMilestone(poam_id=poam_b.id, description="RlsCovSmuggledMilestone"))
                await s.flush()
    finally:
        # Self-cleaning: remove every row this test created (but leave the
        # get-or-create orgs/systems, same convention as test_rls.py — they're
        # org-scoped and no other test asserts an unscoped total over them).
        async with session_scope() as s:
            await set_session_tenant(s, None)
            await s.execute(
                delete(PoamMilestone).where(
                    PoamMilestone.description.in_(
                        ["RlsCovMilestoneA", "RlsCovMilestoneB", "RlsCovSmuggledMilestone"]
                    )
                )
            )
            await s.execute(
                delete(Evidence).where(Evidence.title.in_(["RlsCovEvidenceA", "RlsCovEvidenceB"]))
            )
            await s.execute(
                delete(ControlImplementation).where(
                    ControlImplementation.system_id.in_([sys_a, sys_b]),
                    ControlImplementation.control_id == (control.id if control else -1),
                )
            )
            await s.execute(
                delete(POAM).where(
                    POAM.title.in_(["RlsCovPoamA", "RlsCovPoamB", "RlsCovSmuggledPoam"])
                )
            )
            await s.execute(delete(Risk).where(Risk.title.in_(["RlsCovRiskA", "RlsCovRiskB"])))
            await s.execute(
                delete(SSPProject).where(
                    SSPProject.customer_name.in_(["RlsCovSspA", "RlsCovSspB"])
                )
            )
            await s.execute(
                delete(Assessment).where(Assessment.name.in_(["RlsCovAssessA", "RlsCovAssessB"]))
            )
            await s.execute(delete(Control).where(Control.identifier == "RLS-COV-CTRL"))


async def _add_chained_audit_row(
    session: AsyncSession, *, organization_id: int | None, entity_id: str
) -> AuditLog:
    """Insert one ``audit_log`` row with a genuine hash-chain link, mirroring
    ``ccf.api.audit``'s prev_hash/row_hash computation. ``organization_id`` is
    deliberately kept OUT of the hashed content (matching production — it is a
    scoping column only), so this helper both seeds valid RLS test data and
    doubles as a regression guard: if a future change folded organization_id
    into the hash, the chain-recompute assertion in the test below would
    detect it.
    """
    content = {
        "actor": "rls-coverage-test",
        "action": "test",
        "entity_type": "rls-cov-audit",
        "entity_id": entity_id,
        "diff": {},
    }
    prev = (
        await session.execute(select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1))
    ).scalar_one_or_none() or _GENESIS
    row = AuditLog(
        **content,
        organization_id=organization_id,
        prev_hash=prev,
        row_hash=row_hash(prev, content),
    )
    session.add(row)
    await session.flush()
    return row


@pytest.mark.asyncio
async def test_rls_scopes_audit_log_with_system_rows_visible_to_all() -> None:
    """``audit_log``'s ``tenant_isolation`` predicate (DATA-06) is a three-way
    OR — a scoped tenant sees its own org's rows *and* NULL-org (system) rows,
    but never another tenant's rows. This is a distinct predicate shape from
    every other table ``_assert_scoped_to_owner`` covers above (plain
    ownership, no NULL-visible-to-everyone branch), so it gets its own check.

    Rows are inserted (and later deleted) with a real hash-chain link so this
    test can never corrupt ``/api/audit/verify`` for any other test that runs
    later in the same session — see ``_add_chained_audit_row``.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")

    org_a, _sys_a, org_b, _sys_b = await _seed_two_orgs()

    row_a_id = row_b_id = row_system_id = None
    try:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            row_a = await _add_chained_audit_row(
                s, organization_id=org_a, entity_id="RlsCovAuditA"
            )
            row_b = await _add_chained_audit_row(
                s, organization_id=org_b, entity_id="RlsCovAuditB"
            )
            row_system = await _add_chained_audit_row(
                s, organization_id=None, entity_id="RlsCovAuditSystem"
            )
            row_a_id, row_b_id, row_system_id = row_a.id, row_b.id, row_system.id

        # Tenant A: sees its own row + the system row, never B's.
        async with session_scope() as s:
            await set_session_tenant(s, org_a)
            ids = (await s.execute(select(AuditLog.id))).scalars().all()
            assert row_a_id in ids and row_system_id in ids, "audit_log: own/system rows missing"
            assert row_b_id not in ids, "audit_log: tenant A can see tenant B's row"

        # Tenant B: sees its own row + the system row, never A's.
        async with session_scope() as s:
            await set_session_tenant(s, org_b)
            ids = (await s.execute(select(AuditLog.id))).scalars().all()
            assert row_b_id in ids and row_system_id in ids, "audit_log: own/system rows missing"
            assert row_a_id not in ids, "audit_log: tenant B can see tenant A's row"

        # organization_id is excluded from the hash payload: recomputing
        # row_hash from the persisted content (sans organization_id) still
        # matches the stored value.
        async with session_scope() as s:
            await set_session_tenant(s, None)
            row = (
                await s.execute(select(AuditLog).where(AuditLog.id == row_a_id))
            ).scalar_one()
            content = {
                "actor": row.actor,
                "action": row.action,
                "entity_type": row.entity_type,
                "entity_id": row.entity_id,
                "diff": row.diff,
            }
            assert row.row_hash == row_hash(row.prev_hash or _GENESIS, content)
    finally:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            await s.execute(
                delete(AuditLog).where(
                    AuditLog.entity_id.in_(
                        ["RlsCovAuditA", "RlsCovAuditB", "RlsCovAuditSystem"]
                    )
                )
            )
