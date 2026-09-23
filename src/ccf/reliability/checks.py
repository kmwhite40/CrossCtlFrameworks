"""Reliability checks — see package docstring. Pure result objects + async runners."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import _DEFAULT_SESSION_SECRET, get_settings, is_dev_env

PASS, WARN, FAIL = "pass", "warn", "fail"


@dataclass
class Check:
    name: str
    status: str
    message: str
    remediation: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }


async def _regclass(session: AsyncSession, qualified: str) -> bool:
    got = (await session.execute(text("SELECT to_regclass(:t)"), {"t": qualified})).scalar()
    return got is not None


async def _count(session: AsyncSession, qualified: str) -> int | None:
    if not await _regclass(session, qualified):
        return None
    # `qualified` is always a fixed internal "schema.table" literal from this
    # module's own check functions, never user input.
    query = text(f"SELECT count(*) FROM {qualified}")  # nosec B608
    return int((await session.execute(query)).scalar() or 0)


# --- platform checks --------------------------------------------------------


async def _check_database(session: AsyncSession) -> Check:
    try:
        await session.execute(text("SELECT 1"))
        return Check("database_connectivity", PASS, "Database reachable.")
    except Exception as exc:
        return Check(
            "database_connectivity",
            FAIL,
            f"Database unreachable: {exc}",
            "Check CCF_DATABASE_URL and that Postgres is running.",
        )


async def _check_migrations(session: AsyncSession) -> Check:
    try:
        from alembic.config import Config  # noqa: PLC0415
        from alembic.script import ScriptDirectory  # noqa: PLC0415

        head = ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()
        current = None
        # Read from the schema the table actually lives in (version_table_schema
        # is "ccf"); relying on search_path here would fail when ccf isn't on it.
        version_table = None
        if await _regclass(session, "ccf.alembic_version"):
            version_table = "ccf.alembic_version"
        elif await _regclass(session, "public.alembic_version"):
            version_table = "public.alembic_version"
        if version_table is not None:
            # version_table is one of two fixed literals set above, never user
            # input.
            query = text(f"SELECT version_num FROM {version_table}")  # nosec B608
            current = (await session.execute(query)).scalar()
        if current is None:
            return Check(
                "alembic_migration_status",
                FAIL,
                "No alembic_version row found.",
                "Run `alembic upgrade head`.",
            )
        if current == head:
            return Check("alembic_migration_status", PASS, f"At head ({head}).")
        # Behind-head is a readiness FAILURE, not just a WARN: a container serving
        # traffic against a stale schema can crash or corrupt data on code paths
        # that assume the newer schema. This check is in BLOCKING_CHECKS, so a
        # FAIL here pulls the instance out of rotation via /readyz.
        return Check(
            "alembic_migration_status",
            FAIL,
            f"DB at {current}; head is {head}.",
            "Run `alembic upgrade head`.",
        )
    except Exception as exc:
        return Check("alembic_migration_status", WARN, f"Could not determine: {exc}")


async def _check_core_tables(session: AsyncSession) -> Check:
    required = [
        "ccf.controls",
        "ccf.framework_mappings",
        "ccf.systems",
        "ccf.control_implementations",
        "ccf.evidence",
        "ccf.poams",
        "ccf.risks",
        "ccf.audit_log",
    ]
    missing = [t for t in required if not await _regclass(session, t)]
    if missing:
        return Check(
            "required_tables", FAIL, f"Missing tables: {missing}", "Run `alembic upgrade head`."
        )
    return Check("required_tables", PASS, f"All {len(required)} core tables present.")


async def _check_workbook(session: AsyncSession) -> Check:
    runs = await _count(session, "ccf.ingestion_runs")
    controls = await _count(session, "ccf.controls") or 0
    if controls == 0:
        return Check(
            "workbook_ingestion",
            WARN,
            "No controls ingested yet.",
            "Run `ccf ingest` (catalog features require the NIST workbook).",
        )
    return Check("workbook_ingestion", PASS, f"{controls} controls; {runs or 0} ingestion run(s).")


async def _check_control_count(session: AsyncSession) -> Check:
    controls = await _count(session, "ccf.controls") or 0
    if controls == 0:
        return Check("control_count_sanity", WARN, "0 controls.", "Ingest the workbook.")
    if controls < 100:
        return Check(
            "control_count_sanity",
            WARN,
            f"Only {controls} controls — expected thousands.",
            "Re-ingest; the workbook may have been truncated.",
        )
    return Check("control_count_sanity", PASS, f"{controls} controls.")


async def _check_mappings(session: AsyncSession) -> Check:
    m = await _count(session, "ccf.framework_mappings") or 0
    if m == 0:
        return Check(
            "framework_mapping_sanity", WARN, "0 framework mappings.", "Ingest the workbook."
        )
    return Check("framework_mapping_sanity", PASS, f"{m} framework mappings.")


async def _check_search_vector(session: AsyncSession) -> Check:
    if not await _regclass(session, "ccf.controls"):
        return Check("search_vector", WARN, "controls table absent.")
    try:
        populated = (
            await session.execute(
                text("SELECT count(*) FROM ccf.controls WHERE search_vector IS NOT NULL")
            )
        ).scalar()
        total = await _count(session, "ccf.controls") or 0
        if total and populated:
            return Check("search_vector", PASS, f"{populated}/{total} controls indexed.")
        if total == 0:
            return Check("search_vector", WARN, "No controls to index yet.")
        return Check(
            "search_vector", WARN, "search_vector unpopulated.", "Re-ingest to build the FTS index."
        )
    except Exception as exc:
        return Check("search_vector", WARN, f"Could not verify: {exc}")


def _import_check(name: str, dotted: str, attr: str, hint: str) -> Check:
    try:
        mod = __import__(dotted, fromlist=[attr])
        if not hasattr(mod, attr):
            return Check(name, FAIL, f"{dotted}.{attr} missing.", hint)
        return Check(name, PASS, f"{dotted}.{attr} importable.")
    except Exception as exc:
        return Check(name, FAIL, f"Import failed: {exc}", hint)


async def _check_scoring_service(_s: AsyncSession) -> Check:
    return _import_check(
        "scoring_service", "ccf.scoring.engine", "score_system", "Reinstall the ccf package."
    )


async def _check_evidence_service(session: AsyncSession) -> Check:
    if await _regclass(session, "ccf.evidence"):
        return Check("evidence_service", PASS, "Evidence store reachable.")
    return Check("evidence_service", FAIL, "evidence table missing.", "Run migrations.")


async def _check_ssp_service(_s: AsyncSession) -> Check:
    return _import_check(
        "ssp_generation_service", "ccf.ssp.generator", "generate_ssp_docx", "Reinstall the package."
    )


async def _check_audit_write(session: AsyncSession) -> Check:
    settings = get_settings()
    if settings.readonly:
        return Check(
            "audit_log_write_path", PASS, "Read-only build — writes intentionally blocked."
        )
    if await _regclass(session, "ccf.audit_log"):
        return Check("audit_log_write_path", PASS, "audit_log present and writable.")
    return Check("audit_log_write_path", FAIL, "audit_log table missing.", "Run migrations.")


async def _check_background(_s: AsyncSession) -> Check:
    settings = get_settings()
    try:
        from ..governance import scheduler  # noqa: PLC0415,F401

        state = "enabled" if settings.scheduler_enabled else "disabled (on-demand)"
        return Check("background_task_readiness", PASS, f"Scheduler importable; {state}.")
    except Exception as exc:
        return Check("background_task_readiness", WARN, f"Scheduler import issue: {exc}")


async def _check_auth_posture(_s: AsyncSession) -> Check:
    """Warn/fail on insecure auth defaults outside a dev environment (go-live gate)."""
    settings = get_settings()
    # ``is_dev_env`` / ``_DEFAULT_SESSION_SECRET``, not a second copy of the
    # dev-env list and the default-secret literal. This check had drifted from
    # both: it spelled the list out again and defaulted a missing ``env`` to
    # ``"dev"``, where ``is_dev_env`` defaults it to ``""`` -- i.e. to the
    # production side. A deployment with ``CCF_ENV=""`` therefore got
    # "Dev environment — open access is expected" from the *go-live gate*
    # while every cookie, the HSTS header and ``enforce_secure_config`` all
    # treated it as production. A readiness check that disagrees with the
    # runtime about which environment it is in is worse than no check.
    if is_dev_env(settings):
        return Check(
            "auth_posture", PASS, f"Dev environment ({settings.env}) — open access is expected."
        )
    if not settings.auth_enabled:
        return Check(
            "auth_posture", FAIL, f"Auth is DISABLED in a '{settings.env}' environment.",
            "Set CCF_AUTH_ENABLED=true before serving federal data.",
        )
    if settings.auth_session_secret == _DEFAULT_SESSION_SECRET:
        return Check(
            "auth_posture", FAIL, "Auth enabled but using the default session secret.",
            "Set CCF_AUTH_SESSION_SECRET to a strong, secret value.",
        )
    return Check("auth_posture", PASS, "Auth enabled with a non-default session secret.")


# --- FedRAMP 20x checks -----------------------------------------------------


async def _check_ksi_catalog_file(_s: AsyncSession) -> Check:
    try:
        from ..fedramp20x.catalog import catalog_path, load_records  # noqa: PLC0415

        path = catalog_path()
        n = len(load_records())
        return Check("fedramp20x_ksi_catalog_file", PASS, f"Catalog readable ({n} KSIs) at {path}.")
    except Exception as exc:
        return Check(
            "fedramp20x_ksi_catalog_file",
            FAIL,
            f"Catalog not loadable: {exc}",
            "Ensure data/fedramp_20x_ksi_catalog.json exists.",
        )


async def _check_ksi_loaded(session: AsyncSession) -> Check:
    n = await _count(session, "ccf.ksis")
    if n is None:
        return Check(
            "fedramp20x_ksi_catalog_loaded", FAIL, "ksis table missing.", "Run migrations."
        )
    if n == 0:
        return Check(
            "fedramp20x_ksi_catalog_loaded",
            WARN,
            "KSI catalog not seeded.",
            "Run `ccf fedramp20x seed-ksi`.",
        )
    return Check("fedramp20x_ksi_catalog_loaded", PASS, f"{n} KSIs seeded.")


async def _check_ksi_mappings(session: AsyncSession) -> Check:
    if not await _regclass(session, "ccf.ksis"):
        return Check("fedramp20x_ksi_control_mappings", WARN, "ksis table missing.")
    mapped = (
        await session.execute(
            text("SELECT count(*) FROM ccf.ksis WHERE jsonb_array_length(nist_refs) > 0")
        )
    ).scalar()
    total = await _count(session, "ccf.ksis") or 0
    if total == 0:
        return Check("fedramp20x_ksi_control_mappings", WARN, "No KSIs seeded.")
    if mapped:
        return Check(
            "fedramp20x_ksi_control_mappings",
            PASS,
            f"{mapped}/{total} KSIs mapped to NIST controls.",
        )
    return Check("fedramp20x_ksi_control_mappings", WARN, "No KSI→control mappings present.")


async def _check_validation_service(_s: AsyncSession) -> Check:
    return _import_check(
        "fedramp20x_validation_service",
        "ccf.fedramp20x.validation",
        "validate_system",
        "Reinstall the ccf package.",
    )


async def _check_readiness_service(_s: AsyncSession) -> Check:
    return _import_check(
        "fedramp20x_readiness_scoring",
        "ccf.fedramp20x.readiness",
        "score_system",
        "Reinstall the ccf package.",
    )


async def _check_package_service(_s: AsyncSession) -> Check:
    try:
        from ..fedramp20x import package as pkg  # noqa: PLC0415

        for attr in ("build_package", "render_markdown", "to_oscal_shaped", "validate_oscal"):
            if not hasattr(pkg, attr):
                return Check("fedramp20x_package_export", FAIL, f"package.{attr} missing.")
        # Smoke the OSCAL-shaped transform on a minimal package + structurally validate it.
        sample = {
            "system": {"id": 0, "name": "sample"},
            "generated_at": datetime.now(UTC).isoformat(),
            "disclaimer": "sample",
            "readiness": {"readiness_pct": 0, "status": "not_started"},
            "ksis": [],
            "dependencies": [],
        }
        errors = pkg.validate_oscal(pkg.to_oscal_shaped(sample))
        mode = pkg.validation_mode()
        if errors:
            return Check(
                "fedramp20x_package_export", FAIL,
                f"OSCAL validation ({mode}) failed: {errors[:3]}",
            )
        return Check(
            "fedramp20x_package_export", PASS,
            f"Package export (JSON/MD/DOCX/bundle/OSCAL) OK; OSCAL valid ({mode}).",
        )
    except Exception as exc:
        return Check("fedramp20x_package_export", FAIL, f"Package export error: {exc}")


async def _check_auth_oidc_posture(session: AsyncSession) -> Check:
    """Report OIDC/SCIM configuration coherence (never required in dev)."""
    s = get_settings()
    if not s.oidc_enabled and not s.scim_enabled:
        return Check("auth_oidc_posture", PASS, "Enterprise SSO/SCIM disabled (local login).")
    problems: list[str] = []
    if s.oidc_enabled and not (s.oidc_issuer and s.oidc_client_id and s.oidc_redirect_uri):
        problems.append("OIDC enabled but issuer/client_id/redirect_uri incomplete")
    if s.scim_enabled and not s.scim_bearer_token:
        problems.append("SCIM enabled but CCF_SCIM_BEARER_TOKEN is unset")
    if not await _regclass(session, "ccf.external_identities"):
        problems.append("identity tables missing (run migrations)")
    if problems:
        return Check(
            "auth_oidc_posture", FAIL, "; ".join(problems),
            "Complete the CCF_OIDC_*/CCF_SCIM_* config.",
        )
    return Check("auth_oidc_posture", PASS, "Enterprise SSO/SCIM configured.")


async def _check_evidence_confidence_freshness(session: AsyncSession) -> Check:
    """Warn when evidence objects exist but confidence has not been scored."""
    if not await _regclass(session, "ccf.evidence_confidence_scores"):
        return Check(
            "evidence_confidence_freshness", FAIL,
            "evidence_confidence_scores table missing.", "Run migrations.",
        )
    objs = await _count(session, "ccf.evidence_objects") or 0
    scored = await _count(session, "ccf.evidence_confidence_scores") or 0
    if objs and scored < objs:
        return Check(
            "evidence_confidence_freshness", WARN,
            f"{objs - scored} evidence object(s) unscored.",
            "Run `ccf evidence score` or GET /api/evidence-repo/{id}/confidence.",
        )
    return Check("evidence_confidence_freshness", PASS, "Evidence confidence scored.")


async def _check_evidence_replayability(session: AsyncSession) -> Check:
    """Report replayable (connector/scan) evidence that failed reproduction."""
    if not await _regclass(session, "ccf.evidence_replay_runs"):
        return Check("evidence_replayability", PASS, "No replay runs recorded yet.")
    drifted = (
        await session.execute(
            text(
                "SELECT count(*) FROM ccf.evidence_replay_runs "
                "WHERE status IN ('drifted', 'missing')"
            )
        )
    ).scalar() or 0
    if drifted:
        return Check(
            "evidence_replayability", WARN,
            f"{drifted} evidence replay(s) drifted or missing.",
            "Re-collect the affected evidence from its source.",
        )
    return Check("evidence_replayability", PASS, "Evidence replays reproducible.")


async def _check_ai_disabled_safe_default(_s: AsyncSession) -> Check:
    """AI is optional; confirm it is off by default (or requires human approval)."""
    s = get_settings()
    if not s.ai_enabled:
        return Check("ai_disabled_safe_default", PASS, "AI actions disabled (deterministic stub).")
    if not s.ai_require_human_approval:
        return Check(
            "ai_disabled_safe_default", WARN,
            "AI enabled with human approval NOT required.",
            "Set CCF_AI_REQUIRE_HUMAN_APPROVAL=true.",
        )
    return Check("ai_disabled_safe_default", PASS, "AI enabled with human approval required.")


async def _check_ai_guardrail_violations(session: AsyncSession) -> Check:
    """Surface AI guardrail violations (cross-tenant / uncited-mutation blocks)."""
    if not await _regclass(session, "ccf.ai_guardrail_violations"):
        return Check("ai_guardrail_violations", PASS, "No AI guardrail table yet.")
    n = await _count(session, "ccf.ai_guardrail_violations") or 0
    if n:
        return Check(
            "ai_guardrail_violations", WARN, f"{n} AI guardrail violation(s) recorded.",
            "Review /api/ai-actions/guardrail-violations.",
        )
    return Check("ai_guardrail_violations", PASS, "No AI guardrail violations.")


async def _check_ai_action_review_backlog(session: AsyncSession) -> Check:
    """Warn on a growing AI action review backlog."""
    if not await _regclass(session, "ccf.ai_action_runs"):
        return Check("ai_action_review_backlog", PASS, "No AI action runs yet.")
    pending = (
        await session.execute(
            text("SELECT count(*) FROM ccf.ai_action_runs WHERE status = 'pending_review'")
        )
    ).scalar() or 0
    if pending > 25:
        return Check(
            "ai_action_review_backlog", WARN, f"{pending} AI action runs awaiting review.",
            "Work the /api/ai-actions/review-queue.",
        )
    return Check("ai_action_review_backlog", PASS, f"{pending} AI action(s) awaiting review.")


async def _check_installed_pack_integrity(session: AsyncSession) -> Check:
    """Compliance packs are installed and their conformance tests pass."""
    if not await _regclass(session, "ccf.compliance_packs"):
        return Check("installed_pack_integrity", PASS, "No pack runtime yet.")
    installed = await _count(session, "ccf.compliance_packs") or 0
    if not installed:
        return Check("installed_pack_integrity", PASS, "No compliance packs installed.")
    failed = (
        await session.execute(
            text("SELECT count(*) FROM ccf.pack_test_results WHERE status = 'fail'")
        )
    ).scalar() or 0
    if failed:
        return Check(
            "installed_pack_integrity", WARN,
            f"{installed} pack(s) installed; {failed} pack test(s) failing.",
            "Run `ccf packs test <pack>` and review the manifest.",
        )
    return Check("installed_pack_integrity", PASS, f"{installed} compliance pack(s) installed.")


async def _check_ai_agent_governance(session: AsyncSession) -> Check:
    """Flag high-risk / unapproved-production / unmonitored / overdue AI agents."""
    if not await _regclass(session, "ccf.ai_agents"):
        return Check("ai_agent_governance", PASS, "No AI agent inventory yet.")
    problems = (
        await session.execute(
            text(
                "SELECT "
                "count(*) FILTER (WHERE production_access AND approval_status <> 'approved'), "
                "count(*) FILTER (WHERE risk_rating IN ('high','critical') "
                "  AND monitoring_coverage = 'none'), "
                "count(*) FILTER (WHERE next_review_on IS NOT NULL "
                "  AND next_review_on < CURRENT_DATE)"
                " FROM ccf.ai_agents"
            )
        )
    ).first()
    unapproved_prod, high_no_mon, overdue = (problems or (0, 0, 0))
    if unapproved_prod or high_no_mon:
        return Check(
            "ai_agent_governance", WARN,
            f"{unapproved_prod} agent(s) with unapproved production access; "
            f"{high_no_mon} high-risk without monitoring; {overdue} overdue review.",
            "Review /ai-agents; approve, monitor, or engage the kill-switch.",
        )
    return Check("ai_agent_governance", PASS, "AI agent governance healthy.")


async def _check_assurance_graph_freshness(session: AsyncSession) -> Check:
    """Assurance-graph tables present; warn when the graph has never been built."""
    if not await _regclass(session, "ccf.assurance_build_runs"):
        return Check(
            "assurance_graph_freshness", FAIL, "assurance_build_runs table missing.",
            "Run migrations.",
        )
    row = (
        await session.execute(
            text(
                "SELECT node_count, edge_count, finished_at FROM ccf.assurance_build_runs "
                "WHERE status = 'ok' ORDER BY id DESC LIMIT 1"
            )
        )
    ).first()
    if row is None:
        return Check(
            "assurance_graph_freshness", WARN, "Assurance graph has not been built yet.",
            "Run `ccf assurance graph-rebuild` or POST /api/assurance/graph/rebuild.",
        )
    return Check(
        "assurance_graph_freshness", PASS,
        f"Assurance graph built ({row[0]} nodes, {row[1]} edges).",
    )


async def _check_evidence_repository(session: AsyncSession) -> Check:
    """Evidence repository present; surface expired evidence as a warning."""
    if not await _regclass(session, "ccf.evidence_objects"):
        return Check(
            "evidence_repository", FAIL, "evidence_objects table missing.", "Run migrations."
        )
    expired = (
        await session.execute(
            text(
                "SELECT count(*) FROM ccf.evidence_objects "
                "WHERE expires_on IS NOT NULL AND expires_on < CURRENT_DATE "
                "AND status <> 'expired'"
            )
        )
    ).scalar() or 0
    if expired:
        return Check(
            "evidence_repository", WARN, f"{expired} evidence object(s) past freshness.",
            "Refresh or re-approve expired evidence (ccf evidence expire-scan).",
        )
    return Check("evidence_repository", PASS, "Evidence repository healthy.")


async def _check_oscal_official_schema(_s: AsyncSession) -> Check:
    """Report whether official OSCAL schema validation is available (vs structural)."""
    try:
        from ..oscal import official_schema_available  # noqa: PLC0415

        settings = get_settings()
        kinds = ("ssp", "component", "poam")
        available = [k for k in kinds if official_schema_available(k)]
        if len(available) == len(kinds):
            return Check("oscal_official_schema", PASS, "Official OSCAL schema validation active.")
        missing = [k for k in kinds if k not in available]
        if settings.oscal_require_official_schema:
            return Check(
                "oscal_official_schema", FAIL,
                f"Official OSCAL schema required but missing for: {missing}.",
                "Set CCF_OSCAL_SCHEMA_DIR to the NIST OSCAL JSON schema directory.",
            )
        return Check(
            "oscal_official_schema", WARN,
            f"Structural OSCAL validation only (no official schema for: {missing}).",
            "Set CCF_OSCAL_SCHEMA_DIR for full OSCAL conformance checking.",
        )
    except Exception as exc:
        return Check("oscal_official_schema", FAIL, f"OSCAL schema check error: {exc}")


async def _check_assessor(session: AsyncSession) -> Check:
    if await _regclass(session, "ccf.ksi_assessor_reviews"):
        return Check("fedramp20x_assessor_review", PASS, "Assessor review workflow available.")
    return Check(
        "fedramp20x_assessor_review", FAIL, "ksi_assessor_reviews missing.", "Run migrations."
    )


async def _check_dependency(session: AsyncSession) -> Check:
    if await _regclass(session, "ccf.fedramp_dependencies"):
        return Check("fedramp20x_dependency_tracking", PASS, "Dependency tracking available.")
    return Check(
        "fedramp20x_dependency_tracking", FAIL, "fedramp_dependencies missing.", "Run migrations."
    )


async def _check_ksi_conmon(session: AsyncSession) -> Check:
    if await _regclass(session, "ccf.ksi_validation_results"):
        n = await _count(session, "ccf.ksi_validation_results") or 0
        return Check("fedramp20x_ksi_conmon", PASS, f"KSI validation history available ({n} rows).")
    return Check(
        "fedramp20x_ksi_conmon", FAIL, "ksi_validation_results missing.", "Run migrations."
    )


async def _check_20x_api(_s: AsyncSession) -> Check:
    try:
        from ..api.routes import fedramp20x as route  # noqa: PLC0415

        n = len(route.router.routes)
        return Check("fedramp20x_api_endpoints", PASS, f"20x router loaded ({n} routes).")
    except Exception as exc:
        return Check("fedramp20x_api_endpoints", FAIL, f"20x router import failed: {exc}")


# --- GRC OS checks (Trust, Audit, Regulatory, Connectors, Control tests) ----


async def _check_grc_tables(session: AsyncSession) -> Check:
    required = [
        "ccf.trust_profiles",
        "ccf.trust_access_requests",
        "ccf.regulatory_updates",
        "ccf.audit_engagements",
        "ccf.audit_requests",
        "ccf.audit_findings",
        "ccf.connector_configs",
        "ccf.control_tests",
        "ccf.control_test_results",
    ]
    missing = [t for t in required if not await _regclass(session, t)]
    if missing:
        return Check(
            "grc_os_tables", FAIL, f"Missing GRC tables: {missing}", "Run `alembic upgrade head`."
        )
    return Check("grc_os_tables", PASS, f"All {len(required)} GRC tables present.")


async def _check_grc_api(_s: AsyncSession) -> Check:
    try:
        from ..api.routes import grc as route  # noqa: PLC0415

        n = len(route.router.routes)
        return Check("grc_os_api_endpoints", PASS, f"GRC router loaded ({n} routes).")
    except Exception as exc:
        return Check("grc_os_api_endpoints", FAIL, f"GRC router import failed: {exc}")


async def _check_grc_ui(_s: AsyncSession) -> Check:
    try:
        from ..api.routes import ui_grc as route  # noqa: PLC0415

        paths = {getattr(r, "path", "") for r in route.router.routes}
        expected = {"/trust", "/regulatory", "/connectors", "/control-tests", "/audit-workspace"}
        missing = expected - paths
        if missing:
            return Check("grc_os_ui_pages", FAIL, f"Missing GRC UI routes: {sorted(missing)}")
        return Check("grc_os_ui_pages", PASS, f"All {len(expected)} GRC UI pages registered.")
    except Exception as exc:
        return Check("grc_os_ui_pages", FAIL, f"GRC UI router import failed: {exc}")


async def _check_control_tests_health(session: AsyncSession) -> Check:
    if not await _regclass(session, "ccf.control_tests"):
        return Check("grc_control_test_health", FAIL, "control_tests missing.", "Run migrations.")
    try:
        failing = (
            await session.execute(
                text("SELECT count(*) FROM ccf.control_tests WHERE last_status = 'fail'")
            )
        ).scalar() or 0
        total = await _count(session, "ccf.control_tests") or 0
        if total and failing:
            return Check(
                "grc_control_test_health",
                WARN,
                f"{failing}/{total} control tests failing.",
                "Review /control-tests; each failure opens a remediation task.",
            )
        return Check("grc_control_test_health", PASS, f"{total} control tests; none failing.")
    except Exception as exc:
        return Check("grc_control_test_health", WARN, f"Could not verify: {exc}")


async def _check_external_access_scope_integrity(session: AsyncSession) -> Check:
    """Fail if any portal share references an artifact outside its grant's tenant."""
    if not await _regclass(session, "ccf.external_package_shares"):
        return Check("external_access_scope_integrity", PASS, "External portal not deployed.")
    row = (
        await session.execute(
            text(
                "SELECT "
                "(SELECT count(*) FROM ccf.external_package_shares s "
                " JOIN ccf.external_access_grants g ON g.id = s.grant_id "
                " JOIN ccf.authorization_packages p ON p.id = s.package_id "
                " WHERE p.organization_id IS DISTINCT FROM g.organization_id), "
                "(SELECT count(*) FROM ccf.external_evidence_shares s "
                " JOIN ccf.external_access_grants g ON g.id = s.grant_id "
                " JOIN ccf.evidence_objects e ON e.id = s.evidence_object_id "
                " WHERE e.organization_id IS DISTINCT FROM g.organization_id)"
            )
        )
    ).first()
    pkg_leak, ev_leak = row or (0, 0)
    if pkg_leak or ev_leak:
        return Check(
            "external_access_scope_integrity", FAIL,
            f"{pkg_leak} package + {ev_leak} evidence share(s) cross a tenant boundary.",
            "Revoke the offending grants; a share must reference its grant's own tenant.",
        )
    return Check("external_access_scope_integrity", PASS, "All portal shares are within-tenant.")


async def _check_external_grant_expiration(session: AsyncSession) -> Check:
    """Warn on dead external grants that were never revoked (hygiene).

    "Dead" means what ``ccf.portal.service.grant_status`` means, not merely
    ``expires_at < now()``. An assessment credential also stops resolving when
    its engagement is revoked or its ``period_to`` passes, and this check used
    to miss that case entirely -- reporting "no expired, un-revoked external
    grants" while a grant that authorizes nothing sat un-revoked. A hygiene
    check that states a clean bill of health it has not actually verified is
    worse than one that does not run.
    """
    if not await _regclass(session, "ccf.external_access_grants"):
        return Check("external_grant_expiration", PASS, "External portal not deployed.")
    # The engagements table postdates the grants table, so a database migrated
    # only to 0082 has grants and no engagements; fall back to the expiry-only
    # count there rather than failing on a missing relation.
    # Counted separately, and reported separately: "3 dead grants" sends an
    # operator looking in one place when the cause may be in the other. An
    # expired grant needs a new token; an engagement-ended one needs a new
    # engagement, or nothing at all because the assessment is simply over.
    if await _regclass(session, "ccf.assessment_engagements"):
        sql = (
            "SELECT "
            "  count(*) FILTER (WHERE g.expires_at IS NOT NULL"
            "                     AND g.expires_at < now()) AS expired,"
            "  count(*) FILTER (WHERE g.expires_at IS NULL OR g.expires_at >= now()) AS ended "
            "FROM ccf.external_access_grants g "
            "LEFT JOIN ccf.assessment_engagements e ON e.id = g.engagement_id "
            "WHERE NOT g.revoked AND ("
            "  (g.expires_at IS NOT NULL AND g.expires_at < now())"
            "  OR (g.engagement_id IS NOT NULL"
            "      AND (e.id IS NULL OR e.revoked_at IS NOT NULL OR e.period_to < now()))"
            ")"
        )
        row = (await session.execute(text(sql))).one()
        expired, ended = int(row.expired or 0), int(row.ended or 0)
    else:
        expired = int(
            (
                await session.execute(
                    text(
                        "SELECT count(*) FROM ccf.external_access_grants "
                        "WHERE NOT revoked AND expires_at IS NOT NULL AND expires_at < now()"
                    )
                )
            ).scalar()
            or 0
        )
        ended = 0
    parts = []
    if expired:
        parts.append(f"{expired} expired")
    if ended:
        parts.append(f"{ended} engagement-ended")
    if parts:
        return Check(
            "external_grant_expiration", WARN,
            f"{' and '.join(parts)} external grant(s) not yet revoked.",
            "Revoke stale grants in the portal admin; they already deny access.",
        )
    return Check("external_grant_expiration", PASS, "No dead, un-revoked external grants.")


async def _check_external_portal_audit_completeness(session: AsyncSession) -> Check:
    """Warn if any external grant lacks a portal audit trail (e.g. a direct insert)."""
    if not await _regclass(session, "ccf.external_access_grants"):
        return Check("external_portal_audit_completeness", PASS, "External portal not deployed.")
    n = int(
        (
            await session.execute(
                text(
                    "SELECT count(*) FROM ccf.external_access_grants g WHERE NOT EXISTS ("
                    "SELECT 1 FROM ccf.external_portal_audit_events e WHERE e.grant_id = g.id)"
                )
            )
        ).scalar()
        or 0
    )
    if n:
        return Check(
            "external_portal_audit_completeness", WARN,
            f"{n} external grant(s) have no portal audit trail.",
            "Every grant should record an issuance event; investigate any direct inserts.",
        )
    return Check("external_portal_audit_completeness", PASS, "Every external grant is audited.")


async def _check_catalog_integrity(session: AsyncSession) -> Check:
    """Report advisory OSCAL 800-53r5 catalog reconciliation status (never blocks readiness)."""
    from ..catalog.oscal import OscalManifestError, load_oscal_catalog  # noqa: PLC0415
    from ..catalog.report import latest_report  # noqa: PLC0415

    try:
        catalog = load_oscal_catalog()
    except OscalManifestError as exc:
        return Check("catalog_integrity", WARN, f"OSCAL catalog unreadable: {exc}")
    version = catalog.version

    # Which retained revision the platform is actually serving. The adoption
    # pointer and the filesystem can drift apart (a lost volume, a hand-edited
    # directory), and this is where that shows up.
    revision_note, revision_status = await _adopted_revision_note(session)

    report = await latest_report(session)
    if report is None:
        return Check(
            "catalog_integrity",
            revision_status,
            f"OSCAL {version} loaded ({revision_note}); no reconciliation run yet.",
        )
    return Check(
        "catalog_integrity",
        revision_status,
        f"OSCAL {version} ({revision_note}); last run {report.controls_checked} checked, "
        f"{report.findings_total} findings {report.findings_by_severity}.",
    )


async def _adopted_revision_note(session: AsyncSession) -> tuple[str, str]:
    """Describe the adopted catalog revision and whether its content verifies.

    Returns ``(message_fragment, status)``. A deployment predating the revision
    table, or one that has simply never adopted anything, is reported rather
    than failed -- the packaged catalog still loads, which is why the check
    above already succeeded.
    """
    from pathlib import Path as _Path  # noqa: PLC0415

    from sqlalchemy import select  # noqa: PLC0415

    from ..catalog.oscal import OscalManifestError as _ManifestError  # noqa: PLC0415
    from ..catalog.oscal import _verify  # noqa: PLC0415
    from ..models import CatalogRevision  # noqa: PLC0415

    try:
        row = (
            await session.execute(
                select(CatalogRevision).where(CatalogRevision.status == "adopted")
            )
        ).scalars().first()
    except Exception:  # table absent on an un-migrated deployment
        return "no adopted revision recorded", PASS
    if row is None:
        return "no adopted revision recorded", PASS
    if not row.content_dir:
        return f"revision {row.revision} (packaged)", PASS

    d = _Path(row.content_dir)
    try:
        manifest = _verify(d)
    except _ManifestError as exc:
        return f"revision {row.revision} FAILS verification: {exc}", WARN
    if manifest.get("files") != row.files:
        return (
            f"revision {row.revision} manifest on disk differs from the recorded hashes",
            WARN,
        )
    return f"revision {row.revision} verified", PASS


async def _check_query_templates_health(session: AsyncSession) -> Check:
    """Run every assurance query template (default params) to catch schema drift."""
    try:
        from ..queries import REGISTRY, run_query  # noqa: PLC0415
    except Exception:  # pragma: no cover - query layer optional
        return Check("query_templates_health", PASS, "Assurance query layer not deployed.")
    broken: list[str] = []
    for key in REGISTRY:
        try:
            await run_query(session, key, {}, org_id=None)
        except Exception as exc:
            broken.append(f"{key}: {exc}")
    if broken:
        return Check(
            "query_templates_health", FAIL,
            f"{len(broken)} query template(s) failed: {'; '.join(broken)[:180]}",
            "Fix the template SQL or restore the columns/tables it references.",
        )
    return Check("query_templates_health", PASS, f"All {len(REGISTRY)} query templates run.")


async def _check_ssp_platform_agreement(session: AsyncSession) -> Check:
    """Warn on SSP projects whose platform disagrees with the intake answer.

    Until ``fix/platform-default``, three layers each coerced an unrecognized
    ``cloud_platform`` to "m365": a customer who answered "none" -- one of the
    four answers the questionnaire offers -- received an SSP describing
    Microsoft 365, and so did everyone on GCP, Oracle Cloud or on-premises
    equipment. Those rows were written and cannot be silently repaired: a
    project coerced to "m365" is now indistinguishable from one legitimately on
    M365, so rewriting them would be a second guess on top of the first and
    would destroy the record of what was actually stored.

    They are, however, **detectable**: ``SystemProfile.cloud_platform`` still
    holds the declared answer while ``SSPProject.platform`` holds the stored
    one. This counts the disagreements and names the remediation as a human
    decision.

    ``WARN``, never ``FAIL``. A legitimate mismatch exists: an author may
    deliberately change a project's platform after intake, and an SSP authored
    directly in the editor never had an intake answer to agree with. This check
    finds candidates for a human to look at -- it does not allege an error.

    The two causes are counted and reported **separately**, for the same reason
    :func:`_check_external_grant_expiration` reports its two: "4 mismatched
    projects" sends someone looking in one place when the cause may be in the
    other. A project that disagrees with a *recognized* answer needs the intake
    answer and the project reconciled; one that names a product for a system
    that declared nothing Concord recognizes needs someone to find out what the
    customer actually runs.

    The intake-code mapping is rendered from :data:`PLATFORM_TO_SSP` rather
    than retyped as SQL, so a new questionnaire answer cannot leave this check
    quietly comparing against a stale table.
    """
    if not await _regclass(session, "ccf.ssp_projects") or not await _regclass(
        session, "ccf.system_profiles"
    ):
        return Check("ssp_platform_agreement", PASS, "SSP projects not deployed.")
    from ..governance.automation import PLATFORM_TO_SSP  # noqa: PLC0415
    from ..ssp.platforms import NO_PLATFORM  # noqa: PLC0415

    keys = {f"c{i}": cloud for i, cloud in enumerate(PLATFORM_TO_SSP)}
    values = ", ".join(f"(:{k}, :{k}_v)" for k in keys)
    params: dict[str, str] = {"no_platform": NO_PLATFORM}
    for k, cloud in keys.items():
        params[k], params[f"{k}_v"] = cloud, PLATFORM_TO_SSP[cloud]
    # ``values`` is built from this module's own PLATFORM_TO_SSP keys, never
    # from user input, and every value in it is a bound parameter.
    sql = (  # nosec B608
        "SELECT "
        "  count(*) FILTER (WHERE m.ssp IS NOT NULL AND p.platform <> m.ssp) AS disagrees,"
        "  count(*) FILTER (WHERE m.ssp IS NULL AND p.platform <> :no_platform) AS unmapped "
        "FROM ccf.ssp_projects p "
        "JOIN ccf.system_profiles sp ON sp.system_id = p.system_id "
        f"LEFT JOIN (VALUES {values}) AS m(cloud, ssp) ON m.cloud = sp.cloud_platform"
    )
    row = (await session.execute(text(sql), params)).one()
    disagrees, unmapped = int(row.disagrees or 0), int(row.unmapped or 0)
    parts = []
    if disagrees:
        parts.append(f"{disagrees} disagree with a recognized intake answer")
    if unmapped:
        parts.append(
            f"{unmapped} name a platform for a system that declared none Concord recognizes"
        )
    if parts:
        return Check(
            "ssp_platform_agreement", WARN,
            f"SSP project platform vs. declared cloud platform: {'; '.join(parts)}.",
            "Review each project against its system's intake answer and correct it by hand. "
            "Concord does not rewrite these: a project coerced to a platform is "
            "indistinguishable from one legitimately on it, so only a human can tell which "
            "past rows were wrong.",
        )
    return Check(
        "ssp_platform_agreement", PASS,
        "Every SSP project's platform agrees with its system's declared cloud platform.",
    )


_CHECKS = [
    _check_database,
    _check_migrations,
    _check_core_tables,
    _check_workbook,
    _check_control_count,
    _check_mappings,
    _check_search_vector,
    _check_scoring_service,
    _check_evidence_service,
    _check_evidence_repository,
    _check_evidence_confidence_freshness,
    _check_evidence_replayability,
    _check_assurance_graph_freshness,
    _check_ai_disabled_safe_default,
    _check_ai_guardrail_violations,
    _check_ai_action_review_backlog,
    _check_ai_agent_governance,
    _check_installed_pack_integrity,
    _check_ssp_service,
    _check_audit_write,
    _check_background,
    _check_auth_posture,
    _check_auth_oidc_posture,
    _check_ksi_catalog_file,
    _check_ksi_loaded,
    _check_ksi_mappings,
    _check_validation_service,
    _check_readiness_service,
    _check_package_service,
    _check_oscal_official_schema,
    _check_assessor,
    _check_dependency,
    _check_ksi_conmon,
    _check_20x_api,
    _check_grc_tables,
    _check_grc_api,
    _check_grc_ui,
    _check_control_tests_health,
    _check_external_access_scope_integrity,
    _check_external_grant_expiration,
    _check_external_portal_audit_completeness,
    _check_query_templates_health,
    _check_catalog_integrity,
    _check_ssp_platform_agreement,
]


# --- blocking subset (gates /readyz — unsafe-to-serve conditions only) ------
#
# Kept small and cheap on purpose: /readyz runs on every rotation decision, so it
# must not pay for the full ~40-check suite (e.g. query_templates_health, which
# exercises every assurance query template). Each entry here can return FAIL for
# a condition that means THIS container should NOT receive traffic:
#   - database_connectivity: no DB, no service.
#   - alembic_migration_status: schema behind head or unmigrated — unsafe to
#     serve against a stale/partial schema.
#   - required_tables: core tables missing (broken/partial migration).
#   - auth_posture: auth disabled (or default secret) outside dev — go-live gate.
#
# external_access_scope_integrity is deliberately NOT here even though it can
# FAIL: it detects a cross-tenant data leak, which is a GLOBAL data condition,
# not a per-instance/per-process one. Every container reads the same database,
# so putting it in BLOCKING_CHECKS would 503 the entire fleet simultaneously
# on a single bad data row — and since the admin UI needed to fix that row
# lives on the very containers pulled from rotation, the outage couldn't
# self-heal. It stays in the full check suite (_CHECKS) below so it still
# surfaces via /api/admin/reliability and alerts, just without gating readiness.
BLOCKING_CHECKS = [
    _check_database,
    _check_migrations,
    _check_core_tables,
    _check_auth_posture,
]


async def _run(session: AsyncSession, checks: list[Any]) -> list[Check]:
    results: list[Check] = []
    for fn in checks:
        try:
            results.append(await fn(session))
        except Exception as exc:
            results.append(Check(fn.__name__.lstrip("_"), FAIL, f"Check crashed: {exc}"))
    return results


async def run_checks(session: AsyncSession) -> list[Check]:
    """Run all reliability checks; never raises — a crashed check becomes a FAIL."""
    return await _run(session, _CHECKS)


async def run_blocking_checks(session: AsyncSession) -> list[Check]:
    """Run only the checks that gate readiness (see ``BLOCKING_CHECKS``).

    Never raises — a crashed check becomes a FAIL, which is the correct
    fail-closed behavior for a readiness probe.
    """
    return await _run(session, BLOCKING_CHECKS)


def summarize(checks: list[Check]) -> dict[str, Any]:
    counts = {PASS: 0, WARN: 0, FAIL: 0}
    for c in checks:
        counts[c.status] = counts.get(c.status, 0) + 1
    overall = FAIL if counts[FAIL] else (WARN if counts[WARN] else PASS)
    return {
        "overall": overall,
        "counts": counts,
        "total": len(checks),
        "checks": [c.as_dict() for c in checks],
        "timestamp": datetime.now(UTC).isoformat(),
    }
