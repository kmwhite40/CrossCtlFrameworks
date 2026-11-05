"""Access logging for FedRAMP Certification Data (CDS-TRC-ACL).

*"Trust centers MUST log access to FedRAMP Certification Data and store
summaries of access for at least six months; such information, as it pertains
to specific parties, SHOULD be made available upon request by those parties."*

- **Logged:** every portal read (``view``/``download``), refused document
  (``denied``), comment, and -- since step 3 -- every attempt by a revoked,
  expired or ended-engagement credential (``refused``). A token matching no
  grant names no party and is not logged here.
- **Kept:** raw events, not only summaries, for at least six months. Migration
  0109 makes the table append-only with a trigger that refuses UPDATE and
  refuses DELETE of a row younger than six months, for every database role.
- **Summarized:** :func:`summary`, per grantee per month per target, for the
  provider (``GET /api/admin/portal/access-log-summary``).
- **Available to each party:** :func:`party_log`, the events of the caller's
  own grant (``GET /api/portal/access-log``, by its token).
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..fedramp20x.rules import load_rules
from ..models_portal import ExternalAccessGrant, ExternalPortalAuditEvent
from .inventory import csv_cell

RULE_ID = "CDS-TRC-ACL"
RETENTION = "6 months"

#: Access, counted per summary row. Anything else a grantee does still lands in
#: ``other`` rather than vanishing from the count.
ACCESS_ACTIONS: tuple[str, ...] = ("view", "download", "denied", "refused", "comment", "respond")
#: What the provider did to a grant: history, not access. In the party's own
#: log, left out of the access summary.
ADMIN_ACTIONS: tuple[str, ...] = ("issued", "revoked")

SUMMARY_FIELDS: tuple[str, ...] = (
    "month",
    "grant_id",
    "grantee_kind",
    "grantee_name",
    "grantee_organization",
    "target_type",
    *ACCESS_ACTIONS,
    "other",
)

PARTY_LOG_LIMIT = 5000


def rule_statement() -> str:
    rule: dict[str, Any] = load_rules().data["FRR"]["CDS"]["data"]["all"]["TRC"][RULE_ID]
    return str(rule["statement"])


async def summary(
    session: AsyncSession, *, org_id: int, since: datetime | None = None
) -> dict[str, Any]:
    """Access per grantee, per month, per target -- one organization's."""
    E = ExternalPortalAuditEvent  # noqa: N806
    month = func.date_trunc("month", E.created_at).label("month")
    counts = [func.count().filter(E.action == a).label(a) for a in ACCESS_ACTIONS]
    other = func.count().filter(E.action.notin_(ACCESS_ACTIONS)).label("other")
    keys = (
        month,
        E.grant_id,
        E.grantee_kind,
        E.grantee_name,
        E.grantee_organization,
        E.target_type,
    )
    query = (
        select(*keys, *counts, other)
        .where(E.organization_id == org_id, E.action.notin_(ADMIN_ACTIONS))
        .group_by(*keys)
        .order_by(month, E.grant_id, E.target_type)
    )
    if since is not None:
        query = query.where(E.created_at >= since)
    rows = [dict(r._mapping) for r in (await session.execute(query))]
    oldest = (
        await session.execute(select(func.min(E.created_at)).where(E.organization_id == org_id))
    ).scalar()
    for r in rows:
        r["month"] = r["month"].date().isoformat()[:7]
    return {
        "rule": RULE_ID,
        "statement": rule_statement(),
        "rules_version": load_rules().version,
        "retention": f"raw events are kept at least {RETENTION}; the database refuses "
        "to delete a younger one or alter any",
        "organization_id": org_id,
        "since": since.isoformat() if since else None,
        # How far back this organization's record actually reaches, so a short
        # summary reads as "little history", not as "little access".
        "oldest_event_at": oldest.isoformat() if oldest else None,
        "generated_at": datetime.now(UTC).isoformat(),
        "rows": rows,
    }


def summary_csv(result: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(SUMMARY_FIELDS)
    for row in result["rows"]:
        writer.writerow([csv_cell(row[f]) for f in SUMMARY_FIELDS])
    return buf.getvalue()


async def party_log(session: AsyncSession, grant: ExternalAccessGrant) -> dict[str, Any]:
    """Everything logged against the caller's own grant, newest first."""
    E = ExternalPortalAuditEvent  # noqa: N806
    events = (
        (
            await session.execute(
                select(E)
                .where(E.grant_id == grant.id, E.organization_id == grant.organization_id)
                .order_by(E.created_at.desc(), E.id.desc())
                .limit(PARTY_LOG_LIMIT + 1)
            )
        )
        .scalars()
        .all()
    )
    return {
        "rule": RULE_ID,
        "grant_id": grant.id,
        "retention": RETENTION,
        "truncated": len(events) > PARTY_LOG_LIMIT,
        "events": [
            {
                "at": e.created_at.isoformat(),
                "action": e.action,
                "target_type": e.target_type,
                "target_id": e.target_id,
                "detail": e.detail,
            }
            for e in events[:PARTY_LOG_LIMIT]
        ],
    }
