"""In-app automation scheduler.

When ``CCF_SCHEDULER_ENABLED`` is set, a background asyncio loop runs the
continuous jobs on a cadence — catalog drift poll, ConMon scan, alert digest,
and connector collection — so the platform operates as a live program without an
external cron. One cycle is also exposed via ``ccf scheduler --once`` / the API.

Two kinds of job live in one cycle, and they are scoped differently (IA-06):

* GLOBAL — the catalog-currency poll (:mod:`ccf.etl.sources`) and the
  cross-module alert digest (:mod:`ccf.governance.digest`) read/write
  platform-wide records (``CatalogSource``, ATO/POA&M/policy/vendor rollups)
  that are not owned by any one organization. These run once per cycle with
  the session's RLS tenant unscoped (bypass), same as CLI/ETL.
* PER-TENANT — connector collection, the ConMon scan, connector-backed
  control-test auto-runs, and the assurance-graph rebuild all read/write an
  organization's own rows
  (``CaptureSnapshot``, ``MonitoringRun``, ``ControlTestResult``, tasks,
  notifications, POA&Ms). These run once per organization inside
  :func:`_run_per_tenant_cycle`, each iteration clamped to that org via
  :func:`ccf.db.set_session_tenant` — RLS then backstops the ``org_id``
  filters the called functions already apply, so a bug in the app-layer
  scoping still can't leak org A's job into org B's rows.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..assurance import builder as assurance_builder
from ..capability import derive as capability_derive
from ..config import get_settings
from ..db import get_engine, session_scope, set_session_tenant
from ..etl.sources import poll as poll_sources
from ..logging import get_logger
from ..models import Organization, System
from ..packs import sync as pack_sync
from . import collection, conmon, control_tests, digest

log = get_logger(__name__)

# Postgres advisory-lock key so only ONE replica runs a cycle at a time
# (multi-replica leader election without external coordination). Arbitrary constant.
_SCHEDULER_LOCK_KEY = 809_057_120

_task: asyncio.Task[None] | None = None


async def _active_org_ids(session: AsyncSession) -> list[int]:
    """Every non-deleted organization — the per-tenant loop's fan-out set.

    Run while the session's RLS tenant is unscoped (bypass), so this always
    sees every organization regardless of which org last held the tenant GUC.
    """
    stmt = select(Organization.id).where(Organization.deleted_at.is_(None))
    return sorted((await session.execute(stmt)).scalars().all())


async def _scan_org_systems(session: AsyncSession, *, org_id: int) -> dict[str, Any]:
    """Run every posture provider against every live system in one organization.

    Systems are enumerated here rather than passed in because the caller is
    already clamped to this tenant and RLS backstops the filter -- and because
    "which systems does this organization have" is the question the scheduler is
    answering, not one it should be told the answer to.

    Soft-deleted systems are skipped. Scanning one would make live provider API
    calls on behalf of a boundary somebody has retired, and record evidence
    against it.

    Each system's scan is independent: a provider failure inside
    ``scan_all_providers`` is already contained per provider, and this loop adds
    nothing on top, so one system's total failure propagates to the caller's
    savepoint. That is deliberate -- the per-system savepoint is the caller's,
    and duplicating containment here would hide which system broke.
    """
    from ..posture.scan_all import scan_all_providers  # noqa: PLC0415 - avoids an import cycle

    system_ids = (
        (
            await session.execute(
                select(System.id).where(
                    System.organization_id == org_id,
                    System.deleted_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    scanned = 0
    checks_run = 0
    checks_expected = 0
    manual_review = 0
    for system_id in system_ids:
        out = await scan_all_providers(
            session,
            system_id=int(system_id),
            organization_id=org_id,
            # Recorded on every result, so a scheduled scan is distinguishable
            # in the evidence record from one a person asked for. Matches what
            # `control_tests.run_due` already writes.
            actor="scheduler",
            # The cycle owns the transaction; see the call site.
            commit=False,
        )
        scanned += 1
        checks_run += int(out.get("checks_run") or 0)
        checks_expected += int(out.get("checks_expected") or 0)
        manual_review += int(out.get("manual_review_total") or 0)
    return {
        "organization_id": org_id,
        "systems_scanned": scanned,
        "checks_run": checks_run,
        "checks_expected": checks_expected,
        "manual_review": manual_review,
    }


async def _run_per_tenant_cycle(
    session: AsyncSession, org_ids: list[int], *, today: date
) -> dict[str, Any]:
    """Run collection + ConMon + control-test auto-run for every organization.

    Each organization's slice runs under its own ``set_session_tenant`` and
    each step is wrapped in its own SAVEPOINT (``session.begin_nested()``).
    On a DB-level failure the whole *shared* Postgres transaction goes
    ABORTED — a bare ``try/except`` around the step's own call would swallow
    the Python exception but leave that abort in place, so the very next
    statement on this session (even a later org's ``set_session_tenant``)
    would itself raise and blow up the entire cycle. The savepoint contains
    the abort to just that one step: on exception, ``begin_nested()`` issues
    ``ROLLBACK TO SAVEPOINT``, which undoes that step's writes *and* clears
    the abort, leaving the session fully usable for the next step/org.
    """
    collection_results: list[dict[str, Any]] = []
    pack_sync_results: list[dict[str, Any]] = []
    conmon_results: list[dict[str, Any]] = []
    control_test_results: list[dict[str, Any]] = []
    derive_results: list[dict[str, Any]] = []
    assurance_results: list[dict[str, Any]] = []
    posture_results: list[dict[str, Any]] = []
    derive_enabled = get_settings().capability_derive_enabled
    #: (organization id, step) for every savepointed step that raised. Counted
    #: rather than only logged, so the cycle summary can distinguish "did
    #: nothing" from "tried and failed".
    step_failures: list[dict[str, str]] = []
    for org_id in org_ids:
        await set_session_tenant(session, org_id)
        try:
            async with session.begin_nested():
                collection_results.append(await collection.collect_for_org(session, org_id))
        except Exception as e:
            log.warning(
                "scheduler.per_tenant_step_failed",
                org_id=org_id,
                step="collection",
                error=str(e)[:200],
            )
            step_failures.append({"organization_id": str(org_id), "step": "collection"})
        try:
            # Read-only: fetch, hash, validate and record. Installing is never
            # automatic unless a source opts in (auto_install), because a pack
            # rule executes against this tenant.
            async with session.begin_nested():
                pack_sync_results.append(await pack_sync.sync_for_org(session, org_id))
        except Exception as e:
            log.warning(
                "scheduler.per_tenant_step_failed",
                org_id=org_id,
                step="pack_sync",
                error=str(e)[:200],
            )
            step_failures.append({"organization_id": str(org_id), "step": "pack_sync"})
        try:
            async with session.begin_nested():
                result = await conmon.scan(session, today=today, org_id=org_id)
                conmon_results.append({"organization_id": org_id, **result})
        except Exception as e:
            log.warning(
                "scheduler.per_tenant_step_failed",
                org_id=org_id,
                step="conmon",
                error=str(e)[:200],
            )
            step_failures.append({"organization_id": str(org_id), "step": "conmon"})
        try:
            async with session.begin_nested():
                result = await control_tests.run_due(session, today=today, org_id=org_id)
                control_test_results.append({"organization_id": org_id, **result})
        except Exception as e:
            log.warning(
                "scheduler.per_tenant_step_failed",
                org_id=org_id,
                step="control_tests",
                error=str(e)[:200],
            )
            step_failures.append({"organization_id": str(org_id), "step": "control_tests"})
        try:
            # The posture scan. `run_due` above deliberately excludes
            # scan-generated tests (`source != "generated"`), because its
            # connector-freshness evaluator has nothing useful to say about a
            # posture check and would bury the real verdict under a spurious
            # warn. Correct -- and it left nothing at all re-running posture
            # checks, so a tenant scanned once in September still showed
            # September's verdicts in November while the SSP cited them as
            # automated evidence with their original observed-on dates.
            #
            # Before this step existed the only way to refresh a verdict was for
            # a person to click Scan. Nothing reported the gap: the cycle's
            # `tests_evaluated` counts `run_due`'s work, which rightly excludes
            # these, so zero was an honest answer to a question nobody asked.
            #
            # Per system, and each system in its own savepoint: one system's
            # provider failure must not cost the others their scan. (Per
            # *provider* containment already lives inside
            # `scan_all_providers`.) `commit=False` because this runs inside the
            # cycle's shared transaction -- committing here would end it under
            # the steps that follow.
            async with session.begin_nested():
                posture_results.append(
                    await _scan_org_systems(session, org_id=org_id)
                )
        except Exception as e:
            log.warning(
                "scheduler.per_tenant_step_failed",
                org_id=org_id,
                step="posture_scan",
                error=str(e)[:200],
            )
            step_failures.append({"organization_id": str(org_id), "step": "posture_scan"})
        if derive_enabled:
            try:
                async with session.begin_nested():
                    derive_results.append(
                        await capability_derive.derive_for_org(
                            session, organization_id=org_id
                        )
                    )
            except Exception as e:
                log.warning(
                    "scheduler.per_tenant_step_failed",
                    org_id=org_id,
                    step="capability_derive",
                    error=str(e)[:200],
                )
                step_failures.append({"organization_id": str(org_id), "step": "capability_derive"})
        try:
            # The assurance graph is derived from this organization's own
            # records, so it goes stale the moment any of the steps above
            # writes one. Nothing rebuilt it: it was built only when somebody
            # ran the CLI or posted the endpoint, and the reliability check
            # meant to notice reported PASS regardless of age. Rebuilding it
            # here is what makes "authorization digital twin" true of the
            # thing on the page rather than of the thing the builder can
            # produce on request.
            #
            # Last of the per-tenant steps on purpose: it summarises what the
            # earlier ones just wrote, so running it first would snapshot the
            # previous cycle.
            async with session.begin_nested():
                run = await assurance_builder.rebuild_org(session, org_id)
                assurance_results.append(
                    {
                        "organization_id": org_id,
                        "nodes": run.node_count,
                        "edges": run.edge_count,
                        "status": run.status,
                    }
                )
        except Exception as e:
            log.warning(
                "scheduler.per_tenant_step_failed",
                org_id=org_id,
                step="assurance_graph",
                error=str(e)[:200],
            )
            step_failures.append({"organization_id": str(org_id), "step": "assurance_graph"})
    # Back to bypass before any global step (or the advisory unlock) runs.
    # Suppressed: a prior step's failure must not prevent the tenant clamp
    # from being reset — mirrors the advisory-unlock suppress in run_cycle.
    with contextlib.suppress(Exception):
        await set_session_tenant(session, None)
    return {
        # Every per-tenant step above is savepointed, so a failure is contained
        # and logged as its own warning -- and then contributes nothing to the
        # lists below. That made a cycle whose collection failed for all seven
        # organizations indistinguishable, in the cycle summary, from one where
        # collection had nothing to do. The count travels with the results so
        # the summary can say so.
        "step_failures": step_failures,
        "collection": {
            "organizations_processed": [r["organization_id"] for r in collection_results],
            "connectors_run": [
                f"{r['organization_id']}:{k}"
                for r in collection_results
                for k in r["connectors_run"]
            ],
            "captured": sum(r["captured"] for r in collection_results),
            "drift": sum(r["drift"] for r in collection_results),
        },
        "assurance_graph": {
            "organizations_processed": [r["organization_id"] for r in assurance_results],
            "nodes": sum(r["nodes"] for r in assurance_results),
            "edges": sum(r["edges"] for r in assurance_results),
        },
        "pack_sync": {
            "organizations_processed": [r["organization_id"] for r in pack_sync_results],
            "sources": sum(r["sources"] for r in pack_sync_results),
            "pending": sum(r["pending"] for r in pack_sync_results),
            "installed": sum(r["installed"] for r in pack_sync_results),
        },
        "conmon": conmon_results,
        "posture_scan": posture_results,
        "control_tests": control_test_results,
        "capability_derive": {
            "organizations_processed": [r["organization_id"] for r in derive_results],
            "systems": sum(r["systems"] for r in derive_results),
            "rows_annotated": sum(r["rows_annotated"] for r in derive_results),
        },
    }


def _total(rows: list[dict[str, Any]], field: str) -> int:
    """Sum one integer field across per-organization result rows.

    A value that will not convert counts as zero **and logs a warning naming the
    field**. Both halves matter. The summary is the last thing ``run_cycle``
    does, so an exception raised here escapes into ``_loop``'s handler and the
    whole cycle -- all of it already committed -- reports as failed; a summary
    that can destroy the report it is summarizing is not worth the strictness.
    But swallowing it silently would leave a step under-reporting forever with
    nothing to notice, which is the other half of the same mistake.
    """
    total = 0
    for row in rows:
        raw = row.get(field)
        if raw is None or raw == "":
            continue
        try:
            total += int(raw)
        except (TypeError, ValueError):
            log.warning(
                "scheduler.summary_field_unusable",
                field=field,
                value=str(raw)[:80],
                organization_id=str(row.get("organization_id")),
            )
    return total


def cycle_summary(out: dict[str, Any]) -> dict[str, Any]:
    """The one line an operator reads, with numbers in it.

    This used to be ``{k: v if isinstance(v, int) else "ok"}``, which flattened
    every result in the cycle to the literal string ``ok`` -- and every result
    except ``catalog_checks`` is a dict or a list, so the summary read
    ``collection=ok conmon=ok control_tests=ok ...`` whatever happened. Three
    things it could not distinguish, all of which an operator needs to:

    * a cycle that evaluated 400 control tests from one that evaluated none,
      because no connector is bound and nothing is due;
    * a cycle that opened twelve POA&Ms from one that opened none;
    * a cycle where a step **failed for every organization** from a clean one.
      Each per-tenant step is savepointed, so a failure logs its own warning and
      then contributes nothing to the results -- leaving the summary to say
      ``ok`` about work that did not happen. The warnings are above it in the
      log, which helps only somebody who already suspects something.

    ``failures`` first, and always present rather than omitted when zero: a
    field that appears only on the bad path is one a reader has no habit of
    looking for, and ``failures=0`` is the sentence that makes ``failures=7``
    legible when it comes.

    Counts, not verdicts. This deliberately does not decide whether a cycle was
    "healthy" -- zero control tests is correct for a tenant with no connector
    bound and alarming for one with six, and nothing here knows which. It
    reports what happened and leaves the judgment to the reliability checks,
    which have the context to make it.
    """
    conmon = out.get("conmon") or []
    posture = out.get("posture_scan") or []
    tests = out.get("control_tests") or []
    collection = out.get("collection") or {}
    assurance = out.get("assurance_graph") or {}
    packs = out.get("pack_sync") or {}
    derive = out.get("capability_derive") or {}
    fedramp = out.get("fedramp20x") or {}
    step_failures = out.get("step_failures") or []
    global_failures = out.get("global_failures") or []

    if out.get("skipped"):
        return {"skipped": out["skipped"]}

    summary: dict[str, Any] = {
        "failures": len(step_failures) + len(global_failures),
        "orgs": len(collection.get("organizations_processed") or []),
        "catalog_checks": int(out.get("catalog_checks") or 0),
        "connectors_run": len(collection.get("connectors_run") or []),
        "captured": int(collection.get("captured") or 0),
        "drift": int(collection.get("drift") or 0),
        "pack_sources": int(packs.get("sources") or 0),
        "packs_pending": int(packs.get("pending") or 0),
        # The posture scan's own numbers. Kept separate from `tests_evaluated`,
        # which counts `run_due` and correctly excludes scan-generated tests --
        # conflating them would make the zero that exposed this gap unreadable
        # again in the other direction.
        "posture_systems": _total(posture, "systems_scanned"),
        "posture_checks_run": _total(posture, "checks_run"),
        "posture_checks_expected": _total(posture, "checks_expected"),
        # Why expected and run can differ without anything failing: the
        # responsibility template ruled these out of API scope.
        "posture_manual_review": _total(posture, "manual_review"),
        "conmon_controls": _total(conmon, "controls_checked"),
        "conmon_findings": _total(conmon, "findings"),
        "poams_created": _total(conmon, "poams_created"),
        "poams_recovered": _total(conmon, "poams_recovered"),
        "tasks_created": _total(conmon, "tasks_created"),
        "tests_evaluated": _total(tests, "evaluated"),
        "tests_failed": _total(tests, "fail"),
        "tests_warned": _total(tests, "warn"),
        "derive_systems": int(derive.get("systems") or 0),
        "assurance_nodes": int(assurance.get("nodes") or 0),
        "assurance_edges": int(assurance.get("edges") or 0),
        "fedramp_scanned": int(fedramp.get("systems_scanned") or 0),
        # An int, not a list. `len()` here passed every hand-written test and
        # crashed the first real cycle that had drift, because `0 or []` is
        # falsy and a zero-drift cycle took the list branch harmlessly.
        "fedramp_drift": int(fedramp.get("drift_events") or 0),
    }
    # Named only when non-empty: which step broke is the first question after
    # seeing a non-zero count, and repeating "none" on every clean cycle would
    # bury the counts that are always worth reading.
    if step_failures:
        summary["failed_steps"] = sorted(
            {f"{f['step']}@{f['organization_id']}" for f in step_failures}
        )
    if global_failures:
        summary["failed_global_steps"] = sorted(set(global_failures))
    return summary


async def run_cycle() -> dict[str, Any]:
    """Run one full automation cycle. Returns per-job results."""
    today = datetime.now(UTC).date()
    out: dict[str, Any] = {}
    #: Global (non-per-tenant) steps that raised. Same reason as
    #: ``step_failures``: each is savepointed and logged, and then leaves no
    #: trace in ``out``, so the summary could not tell a skipped step from a
    #: successful one.
    global_failures: list[str] = []
    is_pg = get_engine().dialect.name == "postgresql"
    async with session_scope() as session:
        # Multi-replica safety: only the instance that wins the advisory lock runs
        # the cycle; others skip this tick. Session-level lock survives the
        # intermediate commits inside the jobs and is released in ``finally``.
        if is_pg:
            got = (
                await session.execute(
                    text("SELECT pg_try_advisory_lock(:k)"), {"k": _SCHEDULER_LOCK_KEY}
                )
            ).scalar()
            if not got:
                log.info("scheduler.cycle_skipped", reason="another instance holds the lock")
                return {"skipped": "another instance holds the scheduler lock"}
        try:
            # GLOBAL: platform-wide upstream source registry, not org-owned.
            # Wrapped in its own SAVEPOINT for the same reason each per-tenant
            # step is (see ``_run_per_tenant_cycle``'s docstring): a bare
            # ``contextlib.suppress`` swallows the Python exception but, on a
            # DB-level failure, leaves the shared transaction ABORTED — the
            # very next statement on this session (``_active_org_ids`` below)
            # would then raise and kill the whole cycle. ``begin_nested()``
            # issues ``ROLLBACK TO SAVEPOINT`` on exception, which clears the
            # abort and leaves the session usable for the next step.
            try:
                async with session.begin_nested():
                    checks = await poll_sources(session)
                    out["catalog_checks"] = len(checks)
            except Exception as e:
                log.warning("scheduler.global_step_failed", step="poll_sources", error=str(e)[:200])
                global_failures.append("poll_sources")

            # PER-TENANT: collection, ConMon, and control-test auto-run — one
            # pass per organization, each clamped to its own RLS tenant.
            org_ids = await _active_org_ids(session)
            out.update(await _run_per_tenant_cycle(session, org_ids, today=today))

            # GLOBAL: cross-module alert digest (ATO/POA&M/policy/vendor/etc.
            # rollups spanning the whole platform) — intentionally unscoped.
            # Same savepoint containment as above, so a digest failure can't
            # abort the transaction out from under the fedramp20x scan below.
            try:
                async with session.begin_nested():
                    out["digest"] = await digest.run(session, today=today)
            except Exception as e:
                log.warning("scheduler.global_step_failed", step="digest", error=str(e)[:200])
                global_failures.append("digest")
            try:
                async with session.begin_nested():
                    from ..fedramp20x import monitoring  # noqa: PLC0415 — lazy, keeps startup light

                    out["fedramp20x"] = await monitoring.scan(session, today=today)
            except Exception as e:
                log.warning(
                    "scheduler.global_step_failed", step="fedramp20x_monitoring", error=str(e)[:200]
                )
                global_failures.append("fedramp20x_monitoring")
        finally:
            # Release the advisory lock, and do not let anything above it stop
            # that from happening.
            #
            # pg_try_advisory_lock is SESSION-scoped: a rollback does not
            # release it, and the connection returns to the pool still holding
            # it. So if the unlock is skipped, every later cycle on every
            # replica logs "another instance holds the lock" — a silent,
            # permanent scheduler outage caused by one transient step failure.
            #
            # The hazard is an ABORTED transaction: a DB-level error in any step
            # leaves the shared transaction unusable, and every subsequent
            # statement on it raises — including the unlock itself, and
            # including set_session_tenant, which issues SQL on Postgres.
            #
            # Do NOT roll back unconditionally to avoid that. run_cycle executes
            # inside session_scope, which commits on normal exit, so a blanket
            # rollback here would discard the whole cycle's work on the happy
            # path. Instead: attempt the unlock, and only if it fails (i.e. the
            # transaction really is aborted, in which case the cycle's work is
            # already lost to Postgres) roll back and try once more.
            if is_pg:
                try:
                    await session.execute(
                        text("SELECT pg_advisory_unlock(:k)"), {"k": _SCHEDULER_LOCK_KEY}
                    )
                except Exception:
                    with contextlib.suppress(Exception):
                        await session.rollback()
                    with contextlib.suppress(Exception):
                        await session.execute(
                            text("SELECT pg_advisory_unlock(:k)"), {"k": _SCHEDULER_LOCK_KEY}
                        )
            # Never leave the session's next use pinned to a stale org.
            with contextlib.suppress(Exception):
                await set_session_tenant(session, None)
    out["global_failures"] = global_failures
    log.info("scheduler.cycle", **cycle_summary(out))
    return out


async def _loop(interval_seconds: float) -> None:
    # Small startup delay so the app is fully up before the first cycle.
    await asyncio.sleep(15)
    while True:
        try:
            await run_cycle()
        except Exception as e:
            log.warning("scheduler.cycle_failed", error=str(e)[:200])
        await asyncio.sleep(interval_seconds)


def start() -> None:
    """Start the background scheduler if enabled (idempotent)."""
    global _task  # noqa: PLW0603 — module-level singleton task
    settings = get_settings()
    if not settings.scheduler_enabled or _task is not None:
        return
    interval = max(60.0, settings.scheduler_interval_hours * 3600.0)
    _task = asyncio.create_task(_loop(interval))
    log.info("scheduler.started", interval_hours=settings.scheduler_interval_hours)


async def stop() -> None:
    global _task  # noqa: PLW0603 — module-level singleton task
    if _task is not None:
        _task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _task
        _task = None
