"""Connector-driven evidence collection + config-drift detection.

Runs every configured config-capture connector, records what it captured as a
baseline snapshot, and raises a drift alert when a value changes from the last
capture (e.g. an MFA policy or log-retention setting drifted). This is the
continuous side of the connectors — the Vanta/Drata evidence loop.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..connectors import list_connectors
from ..logging import get_logger
from ..models import CaptureSnapshot
from . import bus

log = get_logger(__name__)


async def collect_all(session: AsyncSession, *, org_id: int | None = None) -> dict[str, Any]:
    """Capture from all configured connectors; snapshot values + detect drift."""
    captured = drift = 0
    ran: list[str] = []
    for conn in list_connectors():
        if not conn.is_configured():
            continue
        ran.append(conn.key)
        try:
            caps = await conn.capture()
        except Exception as e:
            log.warning("collection.capture_failed", connector=conn.key, error=str(e)[:200])
            continue
        for cap in caps:
            captured += 1
            snap = (
                await session.execute(
                    select(CaptureSnapshot).where(
                        CaptureSnapshot.organization_id == org_id,
                        CaptureSnapshot.connector == conn.key,
                        CaptureSnapshot.odp_key == cap.odp_key,
                    )
                )
            ).scalar_one_or_none()
            if snap is None:
                session.add(
                    CaptureSnapshot(
                        organization_id=org_id,
                        connector=conn.key,
                        odp_key=cap.odp_key,
                        value=cap.value,
                        nist_id=cap.nist_id,
                    )
                )
            elif snap.value != cap.value:
                drift += 1
                await bus.notify(
                    session,
                    category="conmon",
                    title=f"Config drift: {cap.odp_key}",
                    body=f"{conn.label}: '{snap.value}' → '{cap.value}'",
                    org_id=org_id,
                    severity="warning",
                    entity_type="capture_snapshot",
                    entity_id=snap.id,
                    dedupe_key=f"drift:{conn.key}:{cap.odp_key}:{cap.value}",
                )
                await bus.emit(
                    session,
                    verb="drifted",
                    entity_type="config",
                    entity_id=cap.odp_key,
                    summary=f"Config drift in {cap.odp_key}: {snap.value} → {cap.value}",
                    org_id=org_id,
                    payload={"connector": conn.key, "old": snap.value, "new": cap.value},
                )
                snap.value = cap.value
    await session.flush()
    return {"connectors_run": ran, "captured": captured, "drift": drift}
