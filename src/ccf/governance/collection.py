"""Connector-driven evidence collection + config-drift detection.

Runs every config-capture connector this organization has its OWN bound
credential for, records what it captured as a baseline snapshot, and raises a
drift alert when a value changes from the last capture (e.g. an MFA policy or
log-retention setting drifted). This is the continuous side of the connectors
— the Vanta/Drata evidence loop.

Credentials are resolved strictly per-organization (IA-05, see
:mod:`ccf.connectors.credentials`): a connector with no credential bound to
the org is skipped — never run under a global/no-identity credential and
never attributed to an org that didn't produce it.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..connectors import connector_keys, get_connector
from ..connectors.credentials import orgs_with_bound_credentials, resolve_credential
from ..logging import get_logger
from ..models import CaptureSnapshot
from . import bus

log = get_logger(__name__)


async def collect_for_org(session: AsyncSession, org_id: int) -> dict[str, Any]:
    """Capture from every connector ``org_id`` has its own bound credential for.

    A connector with no bound credential is reported in ``not_configured`` and
    is never run — there is no global-credential fallback, so nothing is
    written for it.
    """
    captured = drift = 0
    ran: list[str] = []
    not_configured: list[str] = []
    for key in connector_keys():
        credential = await resolve_credential(session, org_id, key)
        conn = get_connector(key, credential=credential)
        if conn is None or not conn.is_configured():
            not_configured.append(key)
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
    return {
        "organization_id": org_id,
        "connectors_run": ran,
        "not_configured": not_configured,
        "captured": captured,
        "drift": drift,
    }


async def collect_all(session: AsyncSession, *, org_id: int | None = None) -> dict[str, Any]:
    """Capture config-drift evidence, attributed to the org whose credential ran.

    With ``org_id`` set (the authenticated API path), scoped to that one
    organization. With no ``org_id`` (the scheduler's global cycle), fans out
    to every organization that has at least one bound connector credential —
    each capture still runs under, and is attributed to, only that org's own
    credential; organizations with no bound credential are never touched.
    """
    if org_id is not None:
        return await collect_for_org(session, org_id)

    org_ids = await orgs_with_bound_credentials(session)
    per_org = [await collect_for_org(session, oid) for oid in org_ids]
    ran = [f"{r['organization_id']}:{k}" for r in per_org for k in r["connectors_run"]]
    return {
        "organizations_processed": org_ids,
        "connectors_run": ran,
        "captured": sum(r["captured"] for r in per_org),
        "drift": sum(r["drift"] for r in per_org),
    }
