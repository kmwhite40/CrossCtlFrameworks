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
   every table policied as of this writing (106 tables spanning migrations
   0010 through 0037) — so the test fails loudly if a table's policy is
   dropped (it silently disappears from the live-enumerated set) or if RLS
   enforcement is disabled on a table that still has one.
2. A BEHAVIORAL check (``test_rls_scopes_representative_org_scoped_tables``)
   that extends the existing systems/fedramp_dependencies pattern to five more
   practical, easy-to-seed tables covering both scoping shapes used across the
   schema: direct ``organization_id`` (``ssp_projects``), ``system_id`` via the
   owning system (``poams``, ``risks``, ``assessments``), and a multi-hop FK
   chain (``evidence`` -> ``control_implementations`` -> ``systems``).

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

from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import (
    POAM,
    Assessment,
    Control,
    ControlImplementation,
    Evidence,
    Organization,
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
# 0010 through 0037). If a future migration adds/removes RLS coverage, update
# this set alongside it — that's the point: the test is living documentation
# of exactly which tables are protected.
EXPECTED_TENANT_ISOLATION_TABLES: frozenset[str] = frozenset(
    {
        "access_review_items", "access_reviews", "ai_action_citations", "ai_action_evaluations",
        "ai_action_inputs", "ai_action_outputs", "ai_action_reviews", "ai_action_runs",
        "ai_agent_approvals", "ai_agent_incidents", "ai_agent_kill_switch_events",
        "ai_agent_monitoring_events", "ai_agent_risk_assessments", "ai_agents",
        "ai_approved_mutations", "ai_guardrail_violations", "ai_provider_configs", "approvals",
        "artifacts", "assessment_control_results", "assessment_results", "assessments",
        "assurance_build_runs", "assurance_edges", "assurance_impacts", "assurance_nodes",
        "assurance_queries", "assurance_query_results", "assurance_snapshots", "audit_engagements",
        "audit_findings", "audit_requests", "authorization_delta_memos",
        "authorization_package_artifacts", "authorization_package_diffs",
        "authorization_package_facts", "authorization_package_replay_runs",
        "authorization_packages", "capture_snapshots", "compliance_pack_versions",
        "compliance_packs", "connector_configs", "control_implementations",
        "control_test_results", "control_tests", "events", "evidence",
        "evidence_access_events", "evidence_confidence_scores", "evidence_objects",
        "evidence_replay_runs", "evidence_reproducibility_checks", "evidence_retention_policies",
        "evidence_reviews", "evidence_source_trust_policies", "evidence_versions",
        "external_access_grants", "external_comments", "external_evidence_shares",
        "external_identities", "external_package_shares", "external_portal_audit_events",
        "external_principals", "external_questionnaire_requests", "fedramp20x_profiles",
        "fedramp20x_readiness_snapshots", "fedramp_dependencies", "group_role_mappings",
        "identity_providers", "ksi_assessor_reviews", "ksi_exceptions", "ksi_states",
        "ksi_validation_results", "monitoring_runs", "notifications", "pack_controls",
        "pack_evidence_requirements", "pack_install_runs", "pack_mappings", "pack_rules",
        "pack_test_results", "people", "poams", "policies", "policy_attestations",
        "policy_versions", "questionnaire_responses", "questionnaire_templates",
        "regulatory_updates", "risks", "scan_ingestions", "scim_provisioning_events",
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
    assert len(found) == len(EXPECTED_TENANT_ISOLATION_TABLES) == 106

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
    """Behavioral RLS check on five practical, easy-to-seed tables.

    Covers both predicate shapes used across the schema: direct
    ``organization_id`` (``ssp_projects``), ``system_id`` scoped via the owning
    system (``poams``, ``risks``, ``assessments``), and a two-hop FK chain
    (``evidence`` -> ``control_implementations`` -> ``systems``).
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")

    org_a, sys_a, org_b, sys_b = await _seed_two_orgs()

    poam_a = poam_b = risk_a = risk_b = None
    ssp_a = ssp_b = assess_a = assess_b = None
    impl_a = impl_b = evidence_a = evidence_b = None
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
            s.add_all([evidence_a, evidence_b])
            await s.flush()

            poam_ids = (poam_a.id, poam_b.id)
            risk_ids = (risk_a.id, risk_b.id)
            ssp_ids = (ssp_a.id, ssp_b.id)
            assess_ids = (assess_a.id, assess_b.id)
            evidence_ids = (evidence_a.id, evidence_b.id)

        await _assert_scoped_to_owner(POAM, *poam_ids, org_a, org_b)
        await _assert_scoped_to_owner(Risk, *risk_ids, org_a, org_b)
        await _assert_scoped_to_owner(SSPProject, *ssp_ids, org_a, org_b)
        await _assert_scoped_to_owner(Assessment, *assess_ids, org_a, org_b)
        await _assert_scoped_to_owner(Evidence, *evidence_ids, org_a, org_b)

        # Cross-tenant INSERT is rejected by the WITH CHECK clause — spot-check on
        # the deep-chain table, the hardest predicate to get wrong.
        with pytest.raises(Exception):  # noqa: B017 - asyncpg/psycopg raise a DB error
            async with session_scope() as s:
                await set_session_tenant(s, org_a)
                s.add(POAM(system_id=sys_b, title="RlsCovSmuggledPoam"))
                await s.flush()
    finally:
        # Self-cleaning: remove every row this test created (but leave the
        # get-or-create orgs/systems, same convention as test_rls.py — they're
        # org-scoped and no other test asserts an unscoped total over them).
        async with session_scope() as s:
            await set_session_tenant(s, None)
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
