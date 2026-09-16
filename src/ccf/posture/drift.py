"""Per-resource drift -- what changed between two observations of a check.

``0068`` made the resource table append-only history, which was right, but
history is only useful if something reads it *as* history. This module is that
read: given the findings of two results, it says which resources got worse, got
better, arrived, left, or changed their reason.

``recovered`` is reserved for a move to a genuinely clean verdict (``pass``).
A move between two verdicts that both still need cover -- ``fail`` to
``warn``, say -- is less bad, but the resource is still uncovered, so it is
``improved`` rather than ``recovered``: an assessor reading "recovered" must
be able to trust nothing is still wrong.

Two of the six kinds do not exist anywhere else in the platform, and they are
the reason this module does:

* **appeared** -- a resource entering scope already failing is a different fact
  from one that regressed. Conflating them misattributes when the weakness
  began, which is the first thing an assessor asks.
* **disappeared** -- a resource present before and absent now was deleted,
  moved out of scope, *or the collection silently truncated*. Nothing notices
  that today, and the truncation case currently looks like an improvement:
  the failing row simply stops being returned.

Pure -- no database, no clock -- and classification keys on ``REQUIRES_COVER``
from :mod:`ccf.governance.waivers` rather than a second verdict list, so
"which verdicts are a problem" has one definition across waivers and drift.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..governance.waivers import REQUIRES_COVER
from ..models_grc import ControlTestResourceResult, ControlTestResult
from .types import ResourceFinding

#: Every kind :func:`diff_resources` can produce. A kind absent from here is
#: one no consumer can interpret, so a test asserts the two sets match exactly.
TRANSITION_KINDS: tuple[str, ...] = (
    "regressed",
    "recovered",
    "improved",
    "appeared",
    "disappeared",
    "changed",
)


@dataclass(frozen=True)
class ResourceTransition:
    """One resource's change between two results."""

    resource_id: str
    kind: str
    #: The earlier verdict, or ``None`` when the resource is new.
    before: str | None
    #: The later verdict, or ``None`` when the resource is gone.
    after: str | None
    #: The later observation, for context. ``None`` for a disappearance --
    #: there is no newer observation of an absent resource.
    observed: str | None = None


def _by_id(findings: Sequence[ResourceFinding]) -> dict[str, ResourceFinding]:
    """Index by resource id, last occurrence winning.

    A provider that returns the same resource twice must not produce two
    transitions whose order decides the verdict.
    """
    return {f.resource_id: f for f in findings}


def _classify(before: ResourceFinding, after: ResourceFinding) -> str | None:
    """The kind for a resource present on both sides, or ``None`` if unchanged.

    ``REQUIRES_COVER`` is the pivot: a verdict in it is a problem, one outside
    it is not. So ``fail -> not_applicable`` is **not** a recovery -- nothing
    was re-observed as passing, the resource simply left scope -- and it is
    reported as ``changed`` rather than silently dropped.
    """
    was_problem = before.verdict in REQUIRES_COVER
    is_problem = after.verdict in REQUIRES_COVER
    if not was_problem and is_problem:
        return "regressed"
    if was_problem and not is_problem:
        # Only a move to a genuinely clean verdict is a recovery. A move to an
        # excluded verdict (not_applicable, not_tested) asserts nothing about
        # the weakness.
        return "recovered" if after.verdict == "pass" else "changed"
    if was_problem and is_problem:
        # Both are still problems -- ``after.verdict`` is still in
        # REQUIRES_COVER -- so this can never be "recovered": only a move to a
        # genuinely clean verdict earns that word. A different verdict means
        # the posture moved (worse, or less bad but still uncovered); the same
        # verdict with different wording means it broke for a new reason.
        if before.verdict != after.verdict:
            return "regressed" if _worse(before.verdict, after.verdict) else "improved"
        return "changed" if before.observed != after.observed else None
    # Neither is a problem: still worth reporting a verdict or wording change,
    # because leaving scope is a fact an assessor may need.
    if before.verdict != after.verdict or before.observed != after.observed:
        return "changed"
    return None


#: Severity among the verdicts that need cover, worst last. Used only to decide
#: the direction of a move between two problem verdicts.
#:
#: This is a hardcoded triple where ``REQUIRES_COVER`` is *derived* from
#: ``VALIDATION_STATUSES``. Left unchecked, adding a fourth problem status to
#: the vocabulary would grow ``REQUIRES_COVER`` automatically while this tuple
#: stayed frozen -- ``_worse`` would then raise on the new status, the
#: ``except ValueError`` would swallow it, and every transition into that
#: status would be silently misclassified as ``improved``. The assertion below
#: turns that into a loud import-time failure instead.
_PROBLEM_SEVERITY = ("manual_review_required", "warn", "fail")

assert set(_PROBLEM_SEVERITY) == REQUIRES_COVER, (
    "_PROBLEM_SEVERITY has drifted from REQUIRES_COVER -- add the new "
    "status to _PROBLEM_SEVERITY in its correct severity order"
)


def _worse(before: str, after: str) -> bool:
    return _PROBLEM_SEVERITY.index(after) > _PROBLEM_SEVERITY.index(before)


def diff_resources(
    before: Sequence[ResourceFinding], after: Sequence[ResourceFinding]
) -> list[ResourceTransition]:
    """Transitions between two results' findings, sorted by resource id.

    Sorted absolutely, not by input order: regenerating a drift report must not
    reorder it. Unchanged resources produce nothing -- a drift report listing
    every resource is not a drift report.
    """
    old, new = _by_id(before), _by_id(after)
    out: list[ResourceTransition] = []
    for resource_id in sorted(set(old) | set(new)):
        was, now = old.get(resource_id), new.get(resource_id)
        if was is None and now is not None:
            out.append(
                ResourceTransition(
                    resource_id=resource_id,
                    kind="appeared",
                    before=None,
                    after=now.verdict,
                    observed=now.observed,
                )
            )
            continue
        if now is None and was is not None:
            out.append(
                ResourceTransition(
                    resource_id=resource_id,
                    kind="disappeared",
                    before=was.verdict,
                    after=None,
                    observed=None,
                )
            )
            continue
        if was is None or now is None:  # pragma: no cover - the union guarantees one
            continue
        kind = _classify(was, now)
        if kind is None:
            continue
        out.append(
            ResourceTransition(
                resource_id=resource_id,
                kind=kind,
                before=was.verdict,
                after=now.verdict,
                observed=now.observed,
            )
        )
    return out


async def _findings_for_result(
    session: AsyncSession, result_id: int
) -> list[ResourceFinding]:
    """One result's resource rows as findings, so the pure differ can take them."""
    rows = (
        await session.execute(
            select(ControlTestResourceResult).where(
                ControlTestResourceResult.result_id == result_id
            )
        )
    ).scalars().all()
    return [
        ResourceFinding(
            resource_id=r.resource_id,
            resource_type=r.resource_type,
            verdict=r.verdict,
            observed=r.observed or "",
            detail=r.detail or {},
        )
        for r in rows
    ]


async def latest_drift(session: AsyncSession, *, test_id: int) -> list[ResourceTransition]:
    """What changed between this check's two most recent results.

    The two most recent, not the first and the last: drift means "what changed
    in this scan", and comparing against an ancient baseline would report
    months of accumulated change as though it had just happened.

    A check with fewer than two results reports **no drift** rather than
    treating everything as ``appeared``. There is no baseline, and inventing
    one would report a first scan as wholesale change -- drowning the real
    signal on the day the check is introduced.
    """
    recent = (
        await session.execute(
            select(ControlTestResult.id)
            .where(ControlTestResult.control_test_id == test_id)
            .order_by(ControlTestResult.id.desc())
            .limit(2)
        )
    ).scalars().all()
    if len(recent) < 2:
        return []
    newer_id, older_id = recent[0], recent[1]
    return diff_resources(
        await _findings_for_result(session, older_id),
        await _findings_for_result(session, newer_id),
    )


async def resource_timeline(
    session: AsyncSession, *, test_id: int, resource_id: str, limit: int = 50
) -> list[dict[str, Any]]:
    """One resource's verdicts for one check, newest first.

    The "when did this start failing, and what has it been doing since"
    question. ``waiver_id`` travels with each entry, so a stretch of accepted
    failures is visible as acceptance rather than as unexplained silence.
    """
    rows = (
        await session.execute(
            select(ControlTestResourceResult, ControlTestResult.run_at, ControlTestResult.id)
            .join(
                ControlTestResult,
                ControlTestResult.id == ControlTestResourceResult.result_id,
            )
            .where(
                ControlTestResult.control_test_id == test_id,
                ControlTestResourceResult.resource_id == resource_id,
            )
            .order_by(ControlTestResult.id.desc())
            .limit(max(1, min(limit, 500)))
        )
    ).all()
    return [
        {
            "result_id": result_id,
            "run_at": run_at,
            "verdict": row.verdict,
            "observed": row.observed,
            "detail": row.detail,
            "waiver_id": row.waiver_id,
        }
        for row, run_at, result_id in rows
    ]
