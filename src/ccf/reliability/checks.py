"""Reliability checks — see package docstring. Pure result objects + async runners."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings

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
    return int((await session.execute(text(f"SELECT count(*) FROM {qualified}"))).scalar() or 0)


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
            current = (
                await session.execute(text(f"SELECT version_num FROM {version_table}"))
            ).scalar()
        if current is None:
            return Check(
                "alembic_migration_status",
                FAIL,
                "No alembic_version row found.",
                "Run `alembic upgrade head`.",
            )
        if current == head:
            return Check("alembic_migration_status", PASS, f"At head ({head}).")
        return Check(
            "alembic_migration_status",
            WARN,
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
    if (settings.env or "dev").lower() in ("dev", "local", "test"):
        return Check(
            "auth_posture", PASS, f"Dev environment ({settings.env}) — open access is expected."
        )
    if not settings.auth_enabled:
        return Check(
            "auth_posture", FAIL, f"Auth is DISABLED in a '{settings.env}' environment.",
            "Set CCF_AUTH_ENABLED=true before serving federal data.",
        )
    if settings.auth_session_secret == "dev-insecure-change-me":
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
    _check_assurance_graph_freshness,
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
]


async def run_checks(session: AsyncSession) -> list[Check]:
    """Run all reliability checks; never raises — a crashed check becomes a FAIL."""
    results: list[Check] = []
    for fn in _CHECKS:
        try:
            results.append(await fn(session))
        except Exception as exc:
            results.append(Check(fn.__name__.lstrip("_"), FAIL, f"Check crashed: {exc}"))
    return results


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
