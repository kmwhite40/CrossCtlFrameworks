"""Land provider attestations on the spine a posture scan already uses.

Reads AWS's own NIST 800-53 Rev 5 control results (see
:mod:`ccf.posture.attested` for what they are and why the rows are shaped the
way they are) and records them as ``ControlTest`` + ``ControlTestResult`` rows
through ``governance.control_tests.record_result`` -- the only writer of
results. That is deliberate: attested evidence then reaches the posture rollups,
the SSP, the drilldown and ``effective_verdict`` by exactly the path a posture
scan's evidence takes. There is no parallel store and no second rollup, so
there is no second set of numbers to disagree with the first.

Two refusals, both load-bearing
-------------------------------
**A read that is not available writes nothing.** The connector reports
``available=False`` for a standard that is off, a standard that is not
``READY``, any provider refusal, and a truncated page walk. The truncated case
is the dangerous one, because the data it carries is real: writing it would
overwrite a complete assessment with a prefix of the next one, and nothing
downstream could tell. The earlier rows are left alone and staleness --
``scan.STALE_AFTER_DAYS`` -- is what eventually stops them being believed.

**A failing attestation opens no POA&M and no remediation Task.** One Security
Hub control relating to three requirements is three rows by construction, and
that split is what stops one automated check crediting three controls. But
``record_result`` opens a notification, a Task and a POA&M per failing row, so
inheriting that behaviour files three weaknesses for one misconfigured bucket --
an assessor reading the POA&M list would see three times the work that exists.
These rows are coverage evidence; the remediation queue stays fed by Concord's
own checks and by ``ingest.scanners``, both of which group by finding. The
verdict is still recorded in full: the queue is suppressed, never the evidence.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..governance.control_tests import record_result
from ..logging import get_logger
from ..models import System
from . import attested
from .scan import _connector_for_org, _upsert_generated_test

log = get_logger(__name__)

#: The connector these attestations come from. Only AWS publishes a control
#: catalog with its own 800-53 mapping today -- Microsoft Secure Score carries
#: 224 control states and an empty ``complianceInformation`` on every profile,
#: so there is nothing to read there without hand-authoring the crosswalk this
#: module exists to avoid.
CONNECTOR_KEY = "aws_govcloud"


async def ingest_attestations(
    session: AsyncSession,
    *,
    system_id: int,
    actor: str = "attested-scan",
    max_pages: int | None = None,
) -> dict[str, Any]:
    """Record AWS's own 800-53 control results for one system.

    Returns a report that always says whether the read was usable and, when it
    was not, why -- the same contract the connector keeps, for the same reason:
    "nothing was written" and "everything passed" must never look alike.

    Does not commit. The caller owns the transaction, as every other writer in
    this package does.
    """
    system = await session.get(System, system_id)
    if system is None:
        raise ValueError(f"unknown system: {system_id}")

    def _report(
        *,
        available: bool,
        reason: str | None,
        written: int = 0,
        read: dict[str, Any] | None = None,
        controls_without_a_requirement: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "system_id": system_id,
            "connector": CONNECTOR_KEY,
            "available": available,
            "reason": reason,
            "written": written,
            "controls_read": len(read["controls"]) if read else 0,
            "controls_without_a_requirement": controls_without_a_requirement or [],
            "unreadable_requirements": list(read["unreadable_requirements"])
            if read
            else [],
            "region": read.get("region") if read else None,
            "account_id": read.get("account_id") if read else None,
            "pages_read": read.get("pages_read", 0) if read else 0,
            "truncated": bool(read.get("truncated")) if read else False,
        }

    conn = await _connector_for_org(
        session, organization_id=system.organization_id, connector_key=CONNECTOR_KEY
    )
    if conn is None:
        return _report(
            available=False,
            reason=(
                f"the {CONNECTOR_KEY} connector is not configured for this "
                "organization, so no provider attestation was read"
            ),
        )

    read = await conn.securityhub_attestations(max_pages=max_pages)
    if not read.get("available"):
        log.info(
            "posture.attested.unavailable",
            system_id=system_id,
            reason=str(read.get("reason"))[:200],
            truncated=bool(read.get("truncated")),
        )
        return _report(available=False, reason=read.get("reason"), read=read)

    controls = read["controls"]
    rows = attested.attested_rows(controls)
    # Named, not merely counted: an operator who sees coverage lower than the
    # Security Hub console needs to know which controls Concord could not place.
    without_requirement = [
        c.security_control_id for c in controls if not c.requirements
    ]

    written = 0
    for row in rows:
        test = await _upsert_generated_test(
            session,
            organization_id=system.organization_id,
            system_id=system_id,
            check_key=row.check_key,
            check_source=attested.CHECK_SOURCE,
            control_id=row.control_id,
            control_ids=row.control_ids,
            title=f"{row.security_control_id}: {row.title}",
            expected=(
                f"AWS Security Hub control {row.security_control_id} passing, which "
                f"AWS relates to {row.control_id}"
            ),
            capability_id=None,
            connector_key=CONNECTOR_KEY,
        )
        if not test.active:
            # A human deactivated this generated test. The same edit a posture
            # scan honours, honoured here for the same reason: deactivation has
            # to actually stop validation, not be a preserved-but-ignored field.
            continue
        detail = (
            f"AWS Security Hub reports {row.security_control_id} as {row.verdict} "
            f"across {row.evaluated} resource(s), {row.failing} failing; AWS relates "
            f"this control to {row.control_id}"
        )
        await record_result(
            session,
            test,
            status=row.verdict,
            detail=detail,
            actor=actor,
            evaluated=row.evaluated,
            failing=row.failing,
            expected=test.expected,
            # See the module docstring: three rows for one Security Hub finding
            # must not become three POA&Ms.
            open_remediation=False,
        )
        written += 1

    log.info(
        "posture.attested.recorded",
        system_id=system_id,
        controls_read=len(controls),
        written=written,
        region=read.get("region"),
    )
    return _report(
        available=True,
        reason=None,
        written=written,
        read=read,
        controls_without_a_requirement=without_requirement,
    )
