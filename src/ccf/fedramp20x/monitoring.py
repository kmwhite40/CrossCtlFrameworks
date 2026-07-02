"""Continuous monitoring for FedRAMP 20x.

Re-runs deterministic KSI validation on a cadence for every system that has 20x
activity (a CSO profile or prior KSI state), records a fresh readiness snapshot,
and detects *drift* — a KSI that regressed from ``pass`` to ``warn``/``fail``
since the last run. Drift is surfaced as an event on the activity/notification bus
so it flows to webhooks and the feed, reusing the platform's existing plumbing
rather than a parallel alerting path. Invoked by the scheduler cycle and on demand
via ``ccf fedramp20x monitor``.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..governance import bus
from ..models import KSI, FedRAMP20xProfile, KSIState, System
from .readiness import score_system
from .validation import validate_system

_REGRESSED_TO = ("fail", "warn")


async def _systems_with_20x(session: AsyncSession) -> list[System]:
    """Systems that have any 20x footprint (profile or prior KSI state)."""
    ids = set(
        (await session.execute(select(KSIState.system_id).distinct())).scalars().all()
    )
    ids |= set(
        (await session.execute(select(FedRAMP20xProfile.system_id).distinct())).scalars().all()
    )
    if not ids:
        return []
    return list(
        (await session.execute(select(System).where(System.id.in_(ids)))).scalars().all()
    )


async def scan_system(
    session: AsyncSession, system: System, *, ksi_ident: dict[int, str]
) -> dict[str, Any]:
    """Re-validate one system, snapshot readiness, and report drift."""
    prior = {
        ksi_ident.get(s.ksi_id, str(s.ksi_id)): s.status
        for s in (
            await session.execute(select(KSIState).where(KSIState.system_id == system.id))
        )
        .scalars()
        .all()
    }
    results = await validate_system(session, system_id=system.id)
    regressions = [
        {
            "ksi": r["ksi_identifier"],
            "from": prior.get(r["ksi_identifier"], "not_tested"),
            "to": r["validation_status"],
        }
        for r in results
        if prior.get(r["ksi_identifier"]) == "pass"
        and r["validation_status"] in _REGRESSED_TO
    ]
    readiness = await score_system(session, system_id=system.id, persist=True)

    if regressions:
        await bus.emit(
            session,
            verb="drift",
            entity_type="system",
            entity_id=system.id,
            summary=(
                f"FedRAMP 20x KSI drift on {system.name}: "
                f"{len(regressions)} regression(s); readiness now {readiness['readiness_pct']}%"
            ),
            org_id=system.organization_id,
            actor="scheduler",
            payload={"regressions": regressions, "readiness": readiness},
        )
    return {
        "system_id": system.id,
        "readiness_pct": readiness["readiness_pct"],
        "status": readiness["status"],
        "regressions": len(regressions),
    }


async def scan(session: AsyncSession, *, today: date | None = None) -> dict[str, Any]:
    """Continuous-monitoring sweep across all 20x systems. Safe to run repeatedly."""
    _ = today or datetime.now(UTC).date()
    systems = await _systems_with_20x(session)
    if not systems:
        return {"systems_scanned": 0, "drift_events": 0}
    ksi_ident = {
        k.id: k.identifier for k in (await session.execute(select(KSI))).scalars().all()
    }
    per_system = [await scan_system(session, s, ksi_ident=ksi_ident) for s in systems]
    drift = sum(1 for r in per_system if r["regressions"] > 0)
    return {
        "systems_scanned": len(systems),
        "drift_events": drift,
        "systems": per_system,
    }
