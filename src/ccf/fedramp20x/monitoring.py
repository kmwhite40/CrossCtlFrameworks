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
from ..logging import get_logger
from ..models import KSI, FedRAMP20xProfile, KSIState, System
from .applicability import counted_ksi_ids
from .readiness import score_system
from .validation import validate_system

log = get_logger(__name__)

_REGRESSED_TO = ("fail", "warn")


def _twentyx_ids() -> Any:
    """Ids of systems with any 20x footprint: a CSO profile or prior KSI state.

    The one definition of "a 20x system" for the sweep and for a single
    system, so :func:`scan` and :func:`is_20x_system` cannot disagree.
    """
    return select(KSIState.system_id).union(select(FedRAMP20xProfile.system_id))


async def _systems_with_20x(session: AsyncSession) -> list[System]:
    """Systems that have any 20x footprint (profile or prior KSI state)."""
    ids = set((await session.execute(_twentyx_ids())).scalars().all())
    if not ids:
        return []
    return list(
        (await session.execute(select(System).where(System.id.in_(ids)))).scalars().all()
    )


async def is_20x_system(session: AsyncSession, system_id: int) -> bool:
    """Whether :func:`scan` would include this system."""
    sub = _twentyx_ids().subquery()
    found = (
        await session.execute(select(sub.c[0]).where(sub.c[0] == system_id).limit(1))
    ).first()
    return found is not None


async def _ksi_ident(session: AsyncSession) -> dict[int, str]:
    return {k.id: k.identifier for k in (await session.execute(select(KSI))).scalars().all()}


async def scan_system(
    session: AsyncSession, *, system_id: int, ksi_ident: dict[int, str] | None = None
) -> dict[str, Any]:
    """Re-validate one system, snapshot readiness, and report drift.

    The per-system body of :func:`scan`. It does not check the system's 20x
    footprint (the sweep only calls it for 20x systems): a caller that may
    hold any system checks :func:`is_20x_system` first.
    """
    system = await session.get(System, system_id)
    if system is None:
        raise ValueError(f"unknown system: {system_id!r}")
    if ksi_ident is None:
        ksi_ident = await _ksi_ident(session)
    prior = {
        ksi_ident.get(s.ksi_id, str(s.ksi_id)): s.status
        for s in (
            await session.execute(select(KSIState).where(KSIState.system_id == system.id))
        )
        .scalars()
        .all()
    }
    results = await validate_system(session, system_id=system.id)
    # Drift on a KSI this system's Class/Path does not owe moves no score;
    # alerting on it would announce a regression beside an unchanged readiness.
    counted = {
        ksi_ident.get(i, str(i)) for i in await counted_ksi_ids(session, system.id)
    }
    regressions = [
        {
            "ksi": r["ksi_identifier"],
            "from": prior.get(r["ksi_identifier"], "not_tested"),
            "to": r["validation_status"],
        }
        for r in results
        if r["ksi_identifier"] in counted
        and prior.get(r["ksi_identifier"]) == "pass"
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
        log.warning(
            "fedramp20x.drift",
            system_id=system.id,
            regressions=len(regressions),
            readiness_pct=readiness["readiness_pct"],
        )
        # Fan to the notification sink (Slack/Teams webhook honours notify_min_severity).
        await bus.notify(
            session,
            category="conmon",
            title=f"FedRAMP 20x KSI drift: {system.name}",
            body=(
                f"{len(regressions)} KSI(s) regressed; readiness now "
                f"{readiness['readiness_pct']}% ({readiness['status']})."
            ),
            org_id=system.organization_id,
            severity="warning",
            entity_type="system",
            entity_id=system.id,
            dedupe_key=f"20x-drift:{system.id}:{sorted(r['ksi'] for r in regressions)}",
        )
        try:
            from ..api.metrics import KSI_DRIFT_EVENTS  # noqa: PLC0415

            KSI_DRIFT_EVENTS.inc(len(regressions))
        except Exception:
            pass
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
    ksi_ident = await _ksi_ident(session)
    per_system = [
        await scan_system(session, system_id=s.id, ksi_ident=ksi_ident) for s in systems
    ]
    drift = sum(1 for r in per_system if r["regressions"] > 0)
    return {
        "systems_scanned": len(systems),
        "drift_events": drift,
        "systems": per_system,
    }
