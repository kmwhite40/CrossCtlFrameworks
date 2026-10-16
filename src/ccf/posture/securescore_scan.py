"""Record Microsoft Secure Score, through Concord's crosswalk, for one system.

The write side of :mod:`ccf.posture.securescore`; read that module first, because
everything that makes these rows honest is decided there. This module only reads
the snapshot, upserts one generated test per mapped profile, and records the
verdict.

The shape follows :mod:`ccf.posture.attested_scan` deliberately -- same upsert,
same refusal to write when the read was unusable, same ``write=False`` dry run on
the same code path -- because the two answer the same question with different
provenance, and a second shape would be a second place for one of them to drift.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..governance.control_tests import record_result
from ..logging import get_logger
from ..models import System
from . import securescore
from .scan import _connector_for_org, _upsert_generated_test

log = get_logger(__name__)

#: Secure Score is read through the Microsoft Graph connector.
CONNECTOR_KEY = "msgraph"


def report(
    system_id: int, *, available: bool, reason: str | None, **extra: Any
) -> dict[str, Any]:
    """The one shape every Secure Score report takes, read or not.

    Built in one place because the scan reports it from three paths -- the
    ingest, out of scope, and a failed read -- and hand-building it in each is
    how a payload's keys drift (the empty framework payload did, twice).
    """
    return {
        "system_id": system_id,
        "connector": CONNECTOR_KEY,
        "check_source": securescore.CHECK_SOURCE,
        "available": available,
        "reason": reason,
        "written": 0,
        "rows": 0,
        "scored_on": None,
        "statuses": {},
        "profiles": 0,
        "scored": 0,
        "mapped": len(securescore.crosswalk_index()),
        "mapped_but_not_scored": [],
        "scored_but_not_mapped": [],
        **extra,
    }


async def ingest_securescore(
    session: AsyncSession,
    *,
    system_id: int,
    actor: str = "securescore-scan",
    write: bool = True,
) -> dict[str, Any]:
    """Read Secure Score and record one verdict per mapped, scored profile.

    Always reports whether the read was usable and, if not, why: "nothing was
    written" and "nothing failed" must never look alike. Does not commit.
    """
    system = await session.get(System, system_id)
    if system is None:
        raise ValueError(f"unknown system: {system_id}")

    def _report(*, available: bool, reason: str | None, **extra: Any) -> dict[str, Any]:
        return report(system_id, available=available, reason=reason, **extra)

    conn = await _connector_for_org(
        session, organization_id=system.organization_id, connector_key=CONNECTOR_KEY
    )
    if conn is None:
        return _report(
            available=False,
            reason=(
                f"the {CONNECTOR_KEY} connector is not configured for this "
                "organization, so Secure Score was not read"
            ),
        )

    read = await conn.securescore_snapshot()
    if not read.get("available"):
        log.info(
            "posture.securescore.unavailable",
            system_id=system_id,
            reason=str(read.get("reason"))[:200],
        )
        return _report(available=False, reason=str(read.get("reason") or "unavailable"))

    rows, coverage = securescore.crosswalk_rows(
        read.get("profiles") or [], read.get("control_scores") or []
    )
    statuses: dict[str, int] = {}
    for row in rows:
        statuses[row.status] = statuses.get(row.status, 0) + 1

    written = 0
    if write:
        for row in rows:
            test = await _upsert_generated_test(
                session,
                organization_id=system.organization_id,
                system_id=system_id,
                check_key=row.check_key,
                check_source=securescore.CHECK_SOURCE,
                control_id=row.family.primary,
                control_ids=list(row.family.controls),
                title=f"Secure Score: {row.title}",
                expected=(
                    f"Full Secure Score points for '{row.profile_id}'. Concord "
                    f"relates it to {row.family.primary}: {row.family.rationale} "
                    "(Concord's crosswalk; Microsoft publishes no 800-53 mapping.)"
                ),
                capability_id=None,
                connector_key=CONNECTOR_KEY,
            )
            if not test.active:
                # A human deactivated this generated test; honoured as every
                # other generated test's deactivation is.
                continue
            await record_result(
                session,
                test,
                status=row.status,
                detail=row.detail,
                actor=actor,
                evaluated=1,
                failing=1 if row.status == "fail" else 0,
                expected=test.expected,
                # The attribution is Concord's, not observed, so a failure is
                # recorded and shown but not filed as a POA&M automatically.
                # See ccf.posture.securescore.
                open_remediation=False,
            )
            written += 1

    log.info(
        "posture.securescore.recorded" if write else "posture.securescore.dry_run",
        system_id=system_id,
        written=written,
        rows=len(rows),
    )
    return _report(
        available=True,
        reason=None,
        written=written,
        scored_on=read.get("scored_on"),
        statuses=statuses,
        **coverage,
    )


__all__ = ["CONNECTOR_KEY", "ingest_securescore", "report"]
