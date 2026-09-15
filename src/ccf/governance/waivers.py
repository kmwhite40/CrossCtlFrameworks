"""Waivers -- accepting a finding without erasing it.

A waiver stops the *consequence* of a finding that has been formally accepted:
no fresh notification, no repeated remediation task, no POA&M churn. It never
touches the finding. The recorded status stays ``fail``, every per-resource
verdict and observation stays, ``ControlTest.last_status`` stays, and
``posture.scan.effective_verdict`` still reports ``fail``.

That distinction is the entire design (see
``docs/superpowers/specs/2026-09-15-waivers-design.md`` section 2), and it is
what separates a waiver from ``KSIException`` -- which is a *disclosure*
counted against readiness rather than a suppressor, and is deliberately left
alone.

This module is pure and clock-injected: ``today`` is a parameter, never read
from the system clock here, so expiry is testable and there is exactly one
definition of "active". The database-facing half (:func:`waivers_for_test`)
resolves candidates; it does not decide activity.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Protocol, runtime_checkable

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..fedramp20x import VALIDATION_STATUSES
from ..models_grc import ControlTest
from ..models_waivers import Waiver
from ..posture.rollup import EXCLUDED_FROM_ROLLUP
from ..posture.types import ResourceFinding

#: The only status that lets a waiver suppress anything. ``requested``
#: suppresses nothing -- if asking were enough, anyone could silence a check by
#: asking -- and ``revoked`` stops suppressing immediately.
APPROVED = "approved"

#: Every waiver status, in lifecycle order.
WAIVER_STATUSES = ("requested", APPROVED, "revoked")

#: Verdicts a waiver has to cover for a result to be fully accepted. Derived
#: from the one vocabulary rather than restated, so adding a verdict cannot
#: leave coverage behind: ``pass`` needs no acceptance, and the rollup-excluded
#: verdicts (``not_applicable``, ``not_tested``) are not findings to accept.
REQUIRES_COVER: frozenset[str] = frozenset(VALIDATION_STATUSES) - {"pass"} - EXCLUDED_FROM_ROLLUP


@runtime_checkable
class WaiverLike(Protocol):
    """What coverage needs of a waiver -- so the pure layer needs no ORM."""

    id: int
    status: str
    expires_on: date | None
    resource_id: str | None


@dataclass(frozen=True)
class Coverage:
    """Whether a result is fully accepted, and by which waiver per resource."""

    suppress: bool
    waived: int = 0
    #: Resource id -> the id of the waiver recorded against it. Only failing
    #: resources appear: attributing an acceptance to a resource that passed
    #: would misstate the evidence.
    by_resource: dict[str, int] = field(default_factory=dict)
    #: Failing resources no active waiver covers, so an operator can see what
    #: still needs accepting or fixing.
    uncovered: tuple[str, ...] = ()


def is_active(waiver: WaiverLike, *, today: date) -> bool:
    """Is this waiver in force on ``today``?

    Expiry is **inclusive**: an acceptance runs to the end of its last day.
    """
    if waiver.status != APPROVED:
        return False
    return waiver.expires_on is None or waiver.expires_on >= today


def cover(
    findings: Sequence[ResourceFinding],
    waivers: Sequence[WaiverLike],
    *,
    today: date,
) -> Coverage:
    """Decide whether a failing result's consequence is fully accepted.

    Suppression requires that **every** finding needing cover is covered: one
    uncovered failing resource and the alert fires normally, because a
    partially accepted check is still an unaccepted finding.

    A result with no enumerated findings -- a manual test, or a caller from
    before the posture spine -- can be covered only by a waiver with no
    ``resource_id``. A resource-scoped waiver must never silence a result whose
    resources were never listed: nothing would prove the waived resource was
    the failing one.
    """
    active = [w for w in waivers if is_active(w, today=today)]
    whole = next((w for w in active if w.resource_id is None), None)
    by_resource_waiver = {w.resource_id: w for w in active if w.resource_id is not None}

    needing = [f for f in findings if f.verdict in REQUIRES_COVER]

    if not needing:
        # Either everything passed or nothing was in scope. There is no alert
        # to suppress, and claiming suppression would make the flag mean two
        # different things to its one caller.
        return Coverage(suppress=bool(whole) and not findings, waived=0)

    attributed: dict[str, int] = {}
    uncovered: list[str] = []
    for f in needing:
        # The narrowest acceptance wins: a resource-specific waiver is what an
        # auditor should see recorded against that resource, even when a
        # whole-check waiver would also have covered it.
        specific = by_resource_waiver.get(f.resource_id)
        if specific is not None:
            attributed[f.resource_id] = specific.id
        elif whole is not None:
            attributed[f.resource_id] = whole.id
        else:
            uncovered.append(f.resource_id)

    return Coverage(
        suppress=not uncovered,
        waived=len(attributed),
        by_resource=attributed,
        uncovered=tuple(uncovered),
    )


async def waivers_for_test(session: AsyncSession, test: ControlTest) -> list[Waiver]:
    """Candidate waivers for one control test, scoped to its tenant and system.

    Returns **candidates**, not active ones: status and expiry are decided by
    :func:`is_active` in the pure layer, so there is exactly one definition of
    "in force". Filtering status here as well would create a second definition
    that could silently diverge from it.

    A waiver matches either the test's ``check_key`` or its ``control_id``. The
    ``check_key`` arm is included only when the test actually has one -- a
    manual test's ``check_key`` is NULL, and matching NULL to NULL would pull in
    every control-targeting waiver as though it were a check waiver.

    An org-wide test (``system_id`` is NULL) resolves nothing: there is no
    system to scope an acceptance to, and matching every system's waivers would
    let one system's acceptance silence another's finding.
    """
    if test.system_id is None:
        return []
    targets = [Waiver.control_id == test.control_id]
    if test.check_key:
        targets.append(Waiver.check_key == test.check_key)
    rows = (
        await session.execute(
            select(Waiver)
            .where(
                Waiver.organization_id == test.organization_id,
                Waiver.system_id == test.system_id,
                or_(*targets),
            )
            .order_by(Waiver.id)
        )
    ).scalars().all()
    return list(rows)


def can_approve(requested_by: str | None, approver: str | None, *, is_global: bool) -> bool:
    """Separation of duties: the requester may not approve their own waiver.

    A waiver silences a finding in a system under authorization, so the person
    asking for it must not also be the person granting it.

    Two deliberate exemptions. A **global** principal -- auth disabled, or the
    system/scheduler -- is not a person, and enforcing the rule there would
    make the endpoint unusable in development. An **unattributed** request
    (``requested_by`` is NULL, as rows created before attribution existed will
    be) must not become permanently unapprovable.

    Pure, so every combination is testable without a scoped session.
    """
    if is_global:
        return True
    if not requested_by:
        return True
    return requested_by != approver
