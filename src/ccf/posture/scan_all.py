"""Scan one system with every posture provider — callable without a request.

This orchestration used to live inside the ``POST /systems/{id}/scan-all`` route
handler, which meant the only way to run a full posture scan was for a person to
ask for one. The scheduler could not: it runs collection, ConMon, capability
derivation and the assurance-graph rebuild, and its control-test pass
deliberately excludes scan-generated tests (``control_tests.run_due`` filters
``source != "generated"``, because ``_evaluate`` has nothing
connector-freshness-shaped to say about a posture check and would bury the real
verdict under a spurious warn).

So **posture verdicts never refreshed on their own**. A tenant scanned once in
September still showed September's verdicts in November, and the SSP cited them
as automated evidence with their original observed-on dates. Nothing reported
it: the cycle summary's ``tests_evaluated`` counts ``run_due``'s work, which
correctly excludes these, so zero was the honest answer to a question nobody was
asking.

Extracting this changes no behaviour for the route, which now calls it. What it
adds is a second caller.

The per-provider failure containment is the part to preserve exactly. One
provider's exception must not discard the providers that already succeeded, and
the ``session.rollback()`` in that path is load-bearing rather than tidy: a
failed scan can leave the session unusable, turning one provider's fault into
every provider's.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..connectors.readiness import provider_readiness
from ..logging import get_logger
from ..models import System
from .attested_scan import ingest_attestations
from .checks import known_providers
from .scan import record_manual_review_check, scan_for_system
from .scope import apply_provider_scope

log = get_logger(__name__)


async def scan_all_providers(
    session: AsyncSession,
    *,
    system_id: int,
    organization_id: int | None,
    actor: str = "scan",
    commit: bool = True,
) -> dict[str, Any]:
    """Every provider, against one system. The shape the API already returns.

    ``commit`` exists for the scheduler, which runs inside one long transaction
    shared with the rest of its cycle and manages its own savepoints -- a commit
    from here would end that transaction underneath it. The route keeps
    ``True``, which is the behaviour it had when this code lived there.

    ``actor`` lands on every recorded result, so a scheduled scan is
    distinguishable in the evidence record from one a person asked for. The
    route passes the principal's email; the scheduler passes ``"scheduler"``,
    matching what ``control_tests.run_due`` already records. An assessor reading
    "verified on" wants to know whether a human was watching.

    Callers are responsible for authorization. The route checks
    ``require_system_in_scope`` before calling; the scheduler passes systems it
    enumerated for the tenant it is already clamped to. This function takes
    ``organization_id`` explicitly rather than reading a principal, so there is
    no ambient scope for a caller to forget to set.
    """
    results: list[dict[str, Any]] = []

    # Which providers this *environment* is assessed against. One organization
    # runs both Microsoft and AWS systems, so the question is per system.
    #
    # Before this, the loop below ran every registered provider and recorded a
    # manual_review_required row for every check of each one that was not ready.
    # On a Microsoft-only organization that put 13 aws_govcloud, 3 gcp and 2
    # puppetdb verdicts on every system -- 23 of 42 control tests for clouds the
    # customer does not have, all in the bucket /dashboard calls "Need a human".
    # There is no human action for "enable Amazon Inspector" on a tenant with no
    # AWS. See ccf.posture.scope.
    system = await session.get(System, system_id)
    if system is None:
        raise ValueError(f"unknown system: {system_id}")
    # Out-of-scope providers are not scanned. Rows a previous scan wrote for them
    # are retired (never held a verdict) or withdrawn (did), or they would keep
    # claiming a verdict for ever -- see `scope.apply_provider_scope`.
    applied = await apply_provider_scope(session, system=system, actor=actor)
    scope = applied["scope"]
    out_of_scope: list[dict[str, Any]] = applied["out_of_scope"]
    retired: list[dict[str, Any]] = applied["retired"]

    for key in sorted(known_providers()):
        provider = scope.get(key)
        if provider is not None and not provider.in_scope:
            continue
        readiness = await provider_readiness(
            session,
            organization_id=organization_id,
            connector_key=key,
            persist=True,
        )
        if not readiness["ready"]:
            reason = readiness.get("reason") or readiness["status"]
            manual_results = [
                await record_manual_review_check(
                    session,
                    system_id=system_id,
                    connector_key=key,
                    check=check,
                    reason=reason,
                    actor=actor,
                )
                for check in readiness["checks"]
            ]
            results.append(
                {
                    "system_id": system_id,
                    "connector": key,
                    "readiness": readiness,
                    "checks_expected": readiness["checks_expected"],
                    "checks_run": 0,
                    "results": [],
                    "skipped_checks": [
                        {**check, "reason": reason} for check in readiness["checks"]
                    ],
                    "manual_review_results": manual_results,
                    "reason": reason,
                }
            )
            continue
        try:
            manual_results = [
                await record_manual_review_check(
                    session,
                    system_id=system_id,
                    connector_key=key,
                    check=check,
                    reason=check["scan_applicability"],
                    actor=actor,
                )
                for check in readiness["checks"]
                if check["scan_applicability"] != "scan"
            ]
            api_check_keys = {
                str(check["check_key"])
                for check in readiness["checks"]
                if check["scan_applicability"] == "scan"
            }
            out = await scan_for_system(
                session,
                system_id=system_id,
                connector_key=key,
                actor=actor,
                check_keys=api_check_keys,
            )
            out["readiness"] = readiness
            out["manual_review_results"] = manual_results
            results.append(out)
        except Exception as exc:  # reported per provider, never swallowed
            # One provider's failure must not discard the providers that worked.
            # The rollback is required, not tidiness: a failed scan can leave the
            # session in a state where every later provider's flush fails too,
            # which would turn one provider's fault into all of them.
            await session.rollback()
            log.warning(
                "posture.scan_all_provider_failed",
                system_id=system_id,
                connector=key,
                error=type(exc).__name__,
            )
            results.append(
                {
                    "system_id": system_id,
                    "connector": key,
                    "readiness": readiness,
                    "checks_expected": 0,
                    "checks_run": 0,
                    "results": [],
                    "skipped_checks": [],
                    "reason": (
                        f"provider scan failed ({type(exc).__name__}); "
                        "nothing was recorded for this provider"
                    ),
                }
            )
    # Provider-attested control results, on the same trigger. Not a provider in
    # the loop above: those run Concord's own checks against a connector, while
    # this reads AWS's assessment of its own control catalog -- a different kind
    # of evidence, labelled differently in the record (see posture.attested).
    #
    # In a SAVEPOINT, and that is the whole point of where it sits. The provider
    # loop's own handler calls `session.rollback()`, which is correct there
    # because nothing has been committed yet and a broken session would fail
    # every later provider. Here the loop has already recorded its results and
    # the commit is two lines below, so a bare rollback would discard every scan
    # that just succeeded. `AsyncSession.rollback()` is also not savepoint-scoped,
    # so an unguarded flush error would leave the outer transaction aborted and
    # take those results down on the caller's commit anyway -- the same reasoning
    # `control_tests.record_result` records for its waiver block.
    try:
        async with session.begin_nested():
            attestations = await ingest_attestations(
                session, system_id=system_id, actor=actor
            )
    except Exception as exc:
        log.warning(
            "posture.attested_ingest_failed",
            system_id=system_id,
            error=type(exc).__name__,
        )
        attestations = {
            "system_id": system_id,
            "connector": "aws_govcloud",
            "available": False,
            "reason": (
                f"the provider attestation read failed ({type(exc).__name__}); "
                "nothing was recorded for it, and the posture scan above is "
                "unaffected"
            ),
            "written": 0,
            "controls_read": 0,
            "controls_without_a_requirement": [],
            "unreadable_requirements": [],
            "region": None,
            "account_id": None,
            "pages_read": 0,
            "truncated": False,
        }
    if commit:
        await session.commit()
    # `skipped_checks` is a list on every per-provider entry, so the aggregate
    # gets its own name rather than the same key holding an int at one level and
    # a list at the next -- a consumer walking `response["skipped_checks"]` would
    # otherwise get a different type depending on where it looked.
    return {
        "system_id": system_id,
        "connectors": results,
        "checks_expected": sum(int(r.get("checks_expected") or 0) for r in results),
        "checks_run": sum(int(r.get("checks_run") or 0) for r in results),
        "skipped_checks_total": sum(len(r.get("skipped_checks") or []) for r in results),
        # Which providers actually contributed, so "0 checks run" is readable. A
        # provider registering no posture checks at all is a different fact from
        # one holding no credential, and both differ from one that broke.
        # Checks the responsibility template ruled out of API scope, recorded as
        # manual review rather than run. Aggregated because the gap between
        # `checks_expected` and `checks_run` is otherwise unexplained in a
        # summary: a tenant whose template answers "unknown" for a domain gets
        # every check in it filtered to `manual_scope_review`, so a ready
        # connector with fourteen working checks scans none of them and the only
        # visible trace is two numbers that do not match.
        "manual_review_total": sum(
            len(r.get("manual_review_results") or []) for r in results
        ),
        "providers_scanned": sum(1 for r in results if r.get("checks_run")),
        "providers_without_checks": sum(
            1 for r in results if not r.get("checks_expected") and not r.get("reason")
        ),
        "providers_unavailable": [
            {"connector": r["connector"], "reason": r["reason"]}
            for r in results
            if r.get("reason")
        ],
        # Always present, never omitted on failure: an absent key renders as
        # nothing and reads as "no problem", while a reason reads as a thing to
        # go and configure. Every organization in this deployment is currently in
        # the "no AWS credential bound" case.
        "attestations": attestations,
        # Named, not silent. A provider that did not run because this environment
        # does not have it is a different fact from one that broke or holds no
        # credential, and an operator seeing fewer checks than they expected needs
        # to be able to tell which.
        "providers_out_of_scope": out_of_scope,
        # Rows a previous scan wrote for a provider now out of scope, removed so
        # they stop claiming a verdict. Reported because deleting evidence
        # silently is worse than leaving it.
        "retired_checks": retired,
        "withdrawn_checks": applied["withdrawn"],
        "framework_posture_url": f"/api/systems/{system_id}/framework-posture",
    }
