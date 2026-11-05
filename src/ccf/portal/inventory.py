"""Inventory and history of access to FedRAMP Certification Data (CDS-TRC-AAI).

*"Trust centers MUST maintain an inventory and history of federal agency users
or systems with access to FedRAMP Certification Data and MUST make this
information available to FedRAMP upon request."*

The inventory is every portal grant that has ever covered certification data
(``scope.certification_system_ids``, trust-center step 1) -- current and
ended alike, because "history" is the half a list of live grants cannot
answer. Grants of every principal kind are included and each row names its
kind: an assessor holding certification data has access to it too, and
leaving them out would make the inventory smaller than the truth. Filter by
``kind="agency"`` for the agency-only view.

How FedRAMP obtains it (the rule's artifact): an organization admin exports
``GET /api/admin/portal/certification-access-inventory?format=csv|json`` and
sends it; the JSON carries the rule id, its statement as pinned, the dataset
version and the generation time.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants import EXTERNAL_PRINCIPAL_KINDS
from ..fedramp20x.rules import load_rules
from ..models import System
from ..models_portal import ExternalAccessGrant, ExternalPortalAuditEvent, ExternalPrincipal
from .certification import shared_system_ids
from .service import current_engagement_ids, grant_status

RULE_ID = "CDS-TRC-AAI"

#: The export's columns, in order. One vocabulary for the CSV header, the JSON
#: rows and the page, so the three cannot drift.
FIELDS: tuple[str, ...] = (
    "grant_id",
    "principal_kind",
    "principal_name",
    "principal_organization",
    "principal_email",
    "label",
    "systems",
    "status",
    "issued_at",
    "issued_by",
    "expires_at",
    "revoked_at",
    "revoked_by",
    "downloads",
    "first_accessed_at",
    "last_accessed_at",
)

#: A cell a spreadsheet would evaluate as a formula (CWE-1236). Principal names
#: are typed by people outside the provider once agencies request access
#: themselves (step 4), and this file is opened by FedRAMP.
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def rule_statement() -> str:
    """CDS-TRC-AAI's text, read from the pinned dataset rather than typed."""
    rule: dict[str, Any] = load_rules().data["FRR"]["CDS"]["data"]["all"]["TRC"][RULE_ID]
    return str(rule["statement"])


async def access_inventory(
    session: AsyncSession, *, org_id: int, kind: str | None = None
) -> list[dict[str, Any]]:
    """One row per grant that covers, or covered, certification data."""
    if kind is not None and kind not in EXTERNAL_PRINCIPAL_KINDS:
        raise ValueError(f"unknown principal kind {kind!r}")

    query = select(ExternalAccessGrant).where(
        ExternalAccessGrant.organization_id == org_id,
        ExternalAccessGrant.scope["certification_system_ids"].isnot(None),
    )
    grants = [
        g
        for g in (await session.execute(query.order_by(ExternalAccessGrant.id))).scalars()
        if shared_system_ids(g)
    ]
    if not grants:
        return []

    principal_ids = {g.principal_id for g in grants if g.principal_id is not None}
    principals = (
        {
            p.id: p
            for p in (
                await session.execute(
                    select(ExternalPrincipal).where(ExternalPrincipal.id.in_(principal_ids))
                )
            ).scalars()
        }
        if principal_ids
        else {}
    )

    # Deleted systems keep their names here: the history is of what was shared.
    system_ids = {s for g in grants for s in shared_system_ids(g)}
    systems = {
        s.id: s
        for s in (
            await session.execute(
                select(System).where(System.id.in_(system_ids), System.organization_id == org_id)
            )
        ).scalars()
    }

    grant_ids = [g.id for g in grants]
    access = {
        row.grant_id: row
        for row in (
            await session.execute(
                select(
                    ExternalPortalAuditEvent.grant_id,
                    func.count()
                    .filter(ExternalPortalAuditEvent.action == "download")
                    .label("downloads"),
                    func.min(ExternalPortalAuditEvent.created_at).label("first"),
                    func.max(ExternalPortalAuditEvent.created_at).label("last"),
                )
                .where(
                    ExternalPortalAuditEvent.grant_id.in_(grant_ids),
                    ExternalPortalAuditEvent.target_type == "certification_data",
                    # Listing shows each document's title and digest: a view
                    # is access too. ``downloads`` counts downloads only.
                    ExternalPortalAuditEvent.action.in_(("view", "download")),
                )
                .group_by(ExternalPortalAuditEvent.grant_id)
            )
        )
    }
    current = await current_engagement_ids(
        session, [g.engagement_id for g in grants if g.engagement_id is not None]
    )

    rows = []
    for g in grants:
        p = principals.get(g.principal_id) if g.principal_id is not None else None
        used = access.get(g.id)
        rows.append(
            {
                "grant_id": g.id,
                "principal_kind": _kind(g, p),
                "principal_name": p.name if p else None,
                "principal_organization": p.organization_name if p else None,
                "principal_email": p.email if p else None,
                "label": g.label,
                "systems": [_system_entry(sid, systems.get(sid)) for sid in shared_system_ids(g)],
                "status": _status(g, current, systems),
                "issued_at": g.created_at,
                "issued_by": g.issued_by,
                "expires_at": g.expires_at,
                "revoked_at": g.revoked_at,
                "revoked_by": g.revoked_by,
                "downloads": int(used.downloads) if used else 0,
                "first_accessed_at": used.first if used else None,
                "last_accessed_at": used.last if used else None,
            }
        )
    if kind is not None:
        rows = [r for r in rows if r["principal_kind"] == kind]
    return rows


def _kind(grant: ExternalAccessGrant, principal: ExternalPrincipal | None) -> str:
    """Who the grantee is. The principal's kind wins: issuance now refuses a
    mismatch, but a row from before that check may still carry one."""
    return principal.kind if principal is not None else grant.kind


def _status(grant: ExternalAccessGrant, current: set[int], systems: dict[int, System]) -> str:
    """``grant_status``, plus the case it cannot see: every shared system is
    deleted, so the grant resolves but serves nothing."""
    status = grant_status(grant, current)
    shared = [systems.get(s) for s in shared_system_ids(grant)]
    if status == "active" and all(s is None or s.deleted_at is not None for s in shared):
        return "systems deleted"
    return status


def _system_entry(system_id: int, system: System | None) -> dict[str, Any]:
    if system is None:
        return {"id": system_id, "name": None, "deleted": None}
    return {"id": system_id, "name": system.name, "deleted": system.deleted_at is not None}


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


def to_json(rows: list[dict[str, Any]], *, org_id: int, kind: str | None) -> dict[str, Any]:
    """The export FedRAMP receives: the rows plus what they answer to."""
    rules = load_rules()
    return {
        "rule": RULE_ID,
        "statement": rule_statement(),
        "rules_version": rules.version,
        "organization_id": org_id,
        "kind": kind,
        "generated_at": datetime.now(UTC).isoformat(),
        "count": len(rows),
        "grants": [{k: _iso(v) for k, v in row.items()} for row in rows],
    }


def _cell(value: Any) -> str:
    """One CSV cell: ISO dates, ``;``-joined systems, formulas neutralized."""
    if value is None:
        return ""
    if isinstance(value, list):
        text = "; ".join(
            f"{s['id']} {s['name'] or '(unknown)'}{' (deleted)' if s.get('deleted') else ''}"
            for s in value
        )
    else:
        text = str(_iso(value))
    return "'" + text if text.startswith(_FORMULA_LEAD) else text


def to_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(FIELDS)
    for row in rows:
        writer.writerow([_cell(row[f]) for f in FIELDS])
    return buf.getvalue()
