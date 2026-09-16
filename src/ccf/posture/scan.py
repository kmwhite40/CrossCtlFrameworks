"""Run posture checks against a system and record what they found.

Deliberately thin: it resolves the org's connector, calls ``scan()``, and
hands every outcome to :func:`ccf.governance.control_tests.record_result` --
the one writer that already owns alerting, POA&M upsert, recovery, and events.
Nothing here re-implements any of that.

Check retirement is not handled here. When a ``PostureCheck`` is removed from
the registry its generated ``ControlTest`` must be DEACTIVATED, never deleted
-- validation history is the product. That sweep belongs with P3, the first
pass that can actually remove a check; implementing it now would be untestable
code guarding a state the empty registry makes unreachable.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..connectors import get_connector
from ..connectors.base import ConfigConnector
from ..connectors.credentials import resolve_credential
from ..governance.control_tests import record_result
from ..logging import get_logger
from ..models import System
from ..models_capability import Capability
from ..models_grc import ControlTest, ControlTestResult
from .checks import CheckOutcome, checks_for

log = get_logger(__name__)

#: A deterministic result older than this is treated as absent by
#: :func:`effective_verdict`.
STALE_AFTER_DAYS = 30


async def _connector_for_org(
    session: AsyncSession, *, organization_id: int, connector_key: str
) -> ConfigConnector | None:
    """The org's configured connector, or ``None``.

    Credentials come only from ``resolve_credential`` -- per-organization,
    with no global or environment fallback.
    """
    credential = await resolve_credential(session, organization_id, connector_key)
    conn = get_connector(connector_key, credential=credential)
    if conn is None or not conn.is_configured():
        return None
    return conn


async def _capability_id_for(
    session: AsyncSession, *, organization_id: int, capability_key: str | None
) -> int | None:
    """Resolve a check's capability by key, if the tenant authored one.

    A missing capability is not an error: checks ship as content, while
    capabilities are authored per tenant.
    """
    if not capability_key:
        return None
    return (
        await session.execute(
            select(Capability.id).where(
                Capability.organization_id == organization_id,
                Capability.key == capability_key,
            )
        )
    ).scalar_one_or_none()


async def _upsert_generated_test(
    session: AsyncSession,
    *,
    organization_id: int,
    system_id: int,
    check_key: str,
    control_id: str,
    title: str,
    capability_id: int | None,
    connector_key: str,
) -> ControlTest:
    """Find or create the generated test for one check on one system.

    Writes **machine-owned fields only**. A human's ``name``, ``frequency``,
    and ``active`` survive a re-scan -- the same discipline
    ``_resolve_on_recovery`` applies to human-edited Task and POA&M fields.

    ``connector_type`` IS machine-owned (it names which connector this check
    runs against, not something a human chooses) and is written on both
    create and update -- backfilling it here rather than only at creation
    means an already-generated row from before this field existed also picks
    it up on its next scan.
    """
    test = (
        await session.execute(
            select(ControlTest).where(
                ControlTest.system_id == system_id,
                ControlTest.check_key == check_key,
            )
        )
    ).scalars().first()
    description = f"Generated from posture check {check_key}."
    if test is None:
        test = ControlTest(
            organization_id=organization_id,
            system_id=system_id,
            control_id=control_id,
            name=title,
            method="connector",
            source="generated",
            check_key=check_key,
            capability_id=capability_id,
            description=description,
            connector_type=connector_key,
        )
        session.add(test)
        await session.flush()
        return test

    test.control_id = control_id
    test.capability_id = capability_id
    test.description = description
    test.connector_type = connector_key
    return test


async def scan_for_system(
    session: AsyncSession,
    *,
    system_id: int,
    connector_key: str,
    actor: str = "scan",
) -> dict[str, Any]:
    """Scan one system with one connector and record every outcome."""
    system = await session.get(System, system_id)
    if system is None:
        raise ValueError(f"unknown system: {system_id}")

    conn = await _connector_for_org(
        session, organization_id=system.organization_id, connector_key=connector_key
    )
    if conn is None:
        return {
            "system_id": system_id,
            "connector": connector_key,
            "checks_run": 0,
            "results": [],
            "reason": "connector not configured for this organization",
        }

    by_key = {c.key: c for c in checks_for(connector_key)}
    outcomes: list[CheckOutcome] = await conn.scan()

    recorded: list[dict[str, Any]] = []
    for outcome in outcomes:
        check = by_key.get(outcome.check_key)
        if check is None:
            # A connector returned an outcome for a check this build does not
            # know. Skipped rather than guessed at: without the definition
            # there is no control to attribute it to.
            log.warning(
                "posture.unknown_check",
                check_key=outcome.check_key,
                provider=connector_key,
            )
            continue
        capability_id = await _capability_id_for(
            session,
            organization_id=system.organization_id,
            capability_key=check.capability_key,
        )
        # A check may evidence several controls; the test carries the first and
        # the rest are reachable through the capability graph.
        test = await _upsert_generated_test(
            session,
            organization_id=system.organization_id,
            system_id=system_id,
            check_key=outcome.check_key,
            control_id=check.control_ids[0],
            title=check.title,
            capability_id=capability_id,
            connector_key=connector_key,
        )
        if not test.active:
            # A human deactivated this generated test (a supported edit --
            # see test_human_edits_survive_a_rescan). Deactivation must
            # actually stop validation, not just be a preserved-but-ignored
            # field: recording a result here would still write a
            # ControlTestResult, alert, and open a POA&M through a test the
            # human turned off.
            log.info(
                "posture.skipped_inactive_test",
                check_key=outcome.check_key,
                control_test_id=test.id,
            )
            continue
        detail = (
            f"{outcome.failing} of {outcome.evaluated} {check.resource_type}(s) failing"
            if outcome.evaluated
            else "no resources in scope"
        )
        await record_result(
            session,
            test,
            status=outcome.verdict,
            detail=detail,
            actor=actor,
            evaluated=outcome.evaluated,
            failing=outcome.failing,
            expected=outcome.expected,
            resources=outcome.findings,
        )
        recorded.append(
            {
                "check_key": outcome.check_key,
                "verdict": outcome.verdict,
                "evaluated": outcome.evaluated,
                "failing": outcome.failing,
            }
        )

    return {
        "system_id": system_id,
        "connector": connector_key,
        "checks_run": len(recorded),
        "results": recorded,
    }


async def effective_verdict(
    session: AsyncSession, *, system_id: int, control_id: str
) -> dict[str, Any]:
    """Which verdict should be believed for this control on this system.

    A fresh deterministic result outranks a model verdict: a check that
    actually read the environment is stronger evidence than a model reasoning
    over documents. The model covers what no check reaches.

    Restricted to ``source == "generated"`` tests -- the ones an actual
    posture scan produced. A human-run manual test (``source == "authored"``,
    e.g. via ``POST /api/grc/control-tests/{id}/run``) is not a check that
    read the environment, so its result must never be reported here as
    ``"deterministic"``.

    This is a read-side helper. It deliberately does not rewire the assessment
    engine, which keeps recording its own verdicts.
    """
    cutoff = datetime.now(UTC) - timedelta(days=STALE_AFTER_DAYS)
    row = (
        await session.execute(
            select(ControlTestResult, ControlTest)
            .join(ControlTest, ControlTest.id == ControlTestResult.control_test_id)
            .where(
                ControlTest.system_id == system_id,
                ControlTest.control_id == control_id,
                ControlTest.source == "generated",
                ControlTestResult.run_at >= cutoff,
            )
            .order_by(ControlTestResult.run_at.desc())
            .limit(1)
        )
    ).first()
    if row is None:
        return {
            "system_id": system_id,
            "control_id": control_id,
            "source": None,
            "verdict": None,
            "reason": "no fresh deterministic result",
        }
    result, test = row[0], row[1]
    return {
        "system_id": system_id,
        "control_id": control_id,
        "source": "deterministic",
        "verdict": result.status,
        "run_at": result.run_at,
        "evaluated": result.evaluated,
        "failing": result.failing,
        "test_id": test.id,
        "reason": "a deterministic check outranks a model verdict",
    }
