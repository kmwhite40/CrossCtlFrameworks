"""An authorization package's review path to an AO decision.

A package is a frozen snapshot -- ``packages.service.create_package`` digests
every fact when it is captured -- so what moves here is the *decision* about
it, not its content. Each reviewer signs the package's manifest hash, so the
history says which content was approved, not just that something was::

    draft ─submit▶ isso_review ─isso_approve▶ issm_review ─issm_approve▶ ao_review
    (any review stage) ─return▶ returned ─submit▶ isso_review
    ao_review ─authorize▶ authorized | ─authorize_conditional▶ conditional | ─deny▶ denied
    authorized|conditional ─(a newer package authorized)▶ superseded
    authorized|conditional ─(scheduler: past its expiry)▶ expired

The package drives ``System.ato_status``, which until now nothing but a direct
admin write ever set: entering review makes a system ``in_progress``, an AO
decision ``authorized``, and :func:`expire_due` (a scheduler step) ``expired``.

With authentication enabled, each review stage belongs to the system's holder
of that role (or an ``admin``), and one cycle's sign-offs must come from
different people, none of them the submitter. Without it there is one
operator, and separation of duties cannot apply -- the rule the approval
engine already follows.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.audit import record_event
from ..auth import Principal
from ..config import get_settings
from ..constants import POAM_ACTIVE_STATUSES
from ..governance import bus
from ..models import POAM, System
from ..models_ato import AuthorizationPackageEvent
from ..models_packages import AuthorizationPackage, AuthorizationPackageFact
from . import acceptances
from . import roles as system_roles

#: An ATO with no stated period lasts this long -- the value
#: ``POST /systems/{id}/authorize`` has always used.
DEFAULT_ATO_PERIOD_DAYS = 365

#: Weaknesses that must not be authorized away: open critical/high POA&Ms.
#: One definition, shared with ``POST /systems/{id}/authorize``.
BLOCKING_POAM_SEVERITIES = ("critical", "high")
BLOCKING_POAM_STATUSES = POAM_ACTIVE_STATUSES

REVIEW_STATUSES = ("isso_review", "issm_review", "ao_review")
DECIDED_STATUSES = ("authorized", "conditional")

#: The system role each review stage belongs to.
STAGE_ROLE = {
    "isso_review": "isso",
    "issm_review": "issm",
    "ao_review": "authorizing_official",
}


@dataclass(frozen=True)
class Rule:
    sources: tuple[str, ...]
    target: str
    requires_reason: bool = False
    #: True when the action is the current stage's decision (needs the stage's role).
    stage_decision: bool = False
    #: True when the action is an authorization (blockers enforced).
    authorizes: bool = False


TRANSITIONS: dict[str, Rule] = {
    "submit": Rule(("draft", "returned"), "isso_review"),
    "isso_approve": Rule(("isso_review",), "issm_review", stage_decision=True),
    "issm_approve": Rule(("issm_review",), "ao_review", stage_decision=True),
    "return": Rule(REVIEW_STATUSES, "returned", requires_reason=True, stage_decision=True),
    "authorize": Rule(("ao_review",), "authorized", stage_decision=True, authorizes=True),
    "authorize_conditional": Rule(
        ("ao_review",), "conditional", requires_reason=True, stage_decision=True, authorizes=True
    ),
    "deny": Rule(("ao_review",), "denied", requires_reason=True, stage_decision=True),
}

ACTION_LABELS = {
    "submit": "Submit for ISSO review",
    "isso_approve": "ISSO approve",
    "issm_approve": "ISSM approve",
    "return": "Return with reason",
    "authorize": "Authorize",
    "authorize_conditional": "Authorize with conditions",
    "deny": "Deny authorization",
}


@dataclass(frozen=True)
class Blocker:
    code: str
    title: str
    detail: str


@dataclass
class LifecycleError(Exception):
    """A refused transition. ``status`` is the HTTP code it maps to."""

    status: int
    message: str
    blockers: list[Blocker] = field(default_factory=list)

    def __str__(self) -> str:
        return self.message


def available_actions(status: str) -> list[str]:
    return [a for a, r in TRANSITIONS.items() if status in r.sources]


async def manifest_sha256(session: AsyncSession, package: AuthorizationPackage) -> str:
    """SHA-256 over the package's facts, stored the first time it is needed.

    Facts are immutable after capture, so the hash identifies the content a
    reviewer signed. Sorted, so two packages with the same facts hash alike.
    """
    if package.manifest_sha256:
        return package.manifest_sha256
    rows = (
        await session.execute(
            select(
                AuthorizationPackageFact.fact_type,
                AuthorizationPackageFact.fact_key,
                AuthorizationPackageFact.digest,
            ).where(AuthorizationPackageFact.package_id == package.id)
        )
    ).all()
    lines = sorted(f"{t}\t{k}\t{d}" for t, k, d in rows)
    digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()
    package.manifest_sha256 = digest
    return digest


async def blocking_poam_count(session: AsyncSession, system_id: int) -> int:
    return (
        await session.execute(
            select(func.count(POAM.id)).where(
                POAM.system_id == system_id,
                POAM.severity.in_(BLOCKING_POAM_SEVERITIES),
                POAM.status.in_(BLOCKING_POAM_STATUSES),
            )
        )
    ).scalar_one()


async def blockers(
    session: AsyncSession, system_id: int, *, today: date | None = None
) -> list[Blocker]:
    """What stops this system being authorized right now. Recomputed, never cached."""
    today = today or date.today()
    out: list[Blocker] = []
    n = await blocking_poam_count(session, system_id)
    if n:
        out.append(
            Blocker(
                "open_high_poam",
                f"{n} open critical/high POA&M{'s' if n != 1 else ''}",
                "An unresolved high-risk weakness must not be authorized away. Remediate it, "
                "or have the AO accept the risk.",
            )
        )
    expired = [a for a in await acceptances.for_system(session, system_id) if a.expired(today)]
    if expired:
        out.append(
            Blocker(
                "expired_acceptance",
                f"{len(expired)} risk acceptance{'s' if len(expired) != 1 else ''} past expiry",
                "; ".join(f"{a.label}: {a.title} (expired {a.expires_on})" for a in expired[:5]),
            )
        )
    if get_settings().auth_enabled:
        held = await system_roles.holders(session, system_id)
        missing = [r for r in system_roles.REVIEW_ROLES if r not in held]
        if missing:
            out.append(
                Blocker(
                    "unassigned_role",
                    "Signing role" + ("s" if len(missing) != 1 else "") + " not assigned: "
                    + ", ".join(system_roles.ROLE_LABELS[r] for r in missing),
                    "Assign the system's ISSO, ISSM and Authorizing Official before review.",
                )
            )
    return out


async def events(session: AsyncSession, package_id: int) -> list[AuthorizationPackageEvent]:
    return list(
        (
            await session.execute(
                select(AuthorizationPackageEvent)
                .where(AuthorizationPackageEvent.package_id == package_id)
                .order_by(AuthorizationPackageEvent.id)
            )
        ).scalars()
    )


def _current_cycle(history: list[AuthorizationPackageEvent]) -> list[AuthorizationPackageEvent]:
    """Events since the most recent submit, inclusive."""
    for i in range(len(history) - 1, -1, -1):
        if history[i].action == "submit":
            return history[i:]
    return []


async def _authority(
    session: AsyncSession, package: AuthorizationPackage, rule: Rule, principal: Principal
) -> str | None:
    """The capacity ``principal`` acts in, or raise. None when auth is off."""
    if not get_settings().auth_enabled:
        return None
    if not rule.stage_decision:
        # Submitting is the preparer's act; the viewer gate already refuses
        # read-only users, and the roles must exist for review to mean anything.
        held = await system_roles.holders(session, package.system_id or 0)
        missing = [r for r in system_roles.REVIEW_ROLES if r not in held]
        if missing:
            raise LifecycleError(
                409,
                "assign the system's "
                + ", ".join(system_roles.ROLE_LABELS[r] for r in missing)
                + " before submitting a package for review",
            )
        return None
    stage_role = STAGE_ROLE[package.status]
    capacity = await system_roles.acting_as(
        session,
        system_id=package.system_id,
        user_id=principal.user_id,
        user_role=principal.role,
        allowed=(stage_role,),
    )
    if capacity is None:
        raise LifecycleError(
            403,
            f"only the system's {system_roles.ROLE_LABELS[stage_role]} (or an admin) can act "
            f"on a package in {package.status.replace('_', ' ')}",
        )
    cycle = _current_cycle(await events(session, package.id))
    signers = {e.actor for e in cycle if e.actor}
    if principal.email in signers:
        raise LifecycleError(
            403,
            "separation of duties: you already submitted or signed this package in this "
            "review cycle; a different person must act at this stage",
        )
    return capacity


async def _supersede_older(
    session: AsyncSession, package: AuthorizationPackage, principal: Principal, now: datetime
) -> None:
    older = (
        await session.execute(
            select(AuthorizationPackage).where(
                AuthorizationPackage.system_id == package.system_id,
                AuthorizationPackage.id != package.id,
                AuthorizationPackage.status.in_(DECIDED_STATUSES),
            )
        )
    ).scalars().all()
    for p in older:
        session.add(
            AuthorizationPackageEvent(
                organization_id=p.organization_id, package_id=p.id, action="supersede",
                from_status=p.status, to_status="superseded", actor=principal.email,
                reason=f"superseded by package {package.id}",
                manifest_sha256=p.manifest_sha256,
            )
        )
        p.status = "superseded"
        p.status_changed_at = now


async def _others_in_review(session: AsyncSession, package: AuthorizationPackage) -> bool:
    return bool(
        (
            await session.execute(
                select(func.count(AuthorizationPackage.id)).where(
                    AuthorizationPackage.system_id == package.system_id,
                    AuthorizationPackage.id != package.id,
                    AuthorizationPackage.status.in_(REVIEW_STATUSES),
                )
            )
        ).scalar_one()
    )


async def apply(
    session: AsyncSession,
    *,
    package: AuthorizationPackage,
    action: str,
    principal: Principal,
    reason: str | None = None,
    expires_on: date | None = None,
    today: date | None = None,
) -> AuthorizationPackageEvent:
    """Perform ``action`` on ``package`` or raise :class:`LifecycleError`.

    The caller has already resolved ``package`` in the principal's scope, and
    commits. Everything here happens in the caller's transaction.
    """
    today = today or date.today()
    rule = TRANSITIONS.get(action)
    if rule is None:
        raise LifecycleError(400, f"unknown action: {action}")
    if package.system_id is None:
        raise LifecycleError(409, "this package is not attached to a system")
    if package.status not in rule.sources:
        allowed = ", ".join(available_actions(package.status)) or "none"
        raise LifecycleError(
            409,
            f"cannot {action} a package in {package.status} (available: {allowed})",
        )
    reason = (reason or "").strip() or None
    if rule.requires_reason and reason is None:
        raise LifecycleError(409, f"{action} requires a reason")
    if action == "authorize_conditional" and expires_on is None:
        raise LifecycleError(
            409, "a conditional authorization needs an end date for its conditions"
        )
    if expires_on is not None and expires_on <= today:
        raise LifecycleError(409, "an authorization must end after today")

    capacity = await _authority(session, package, rule, principal)

    if rule.authorizes:
        found = await blockers(session, package.system_id, today=today)
        if found:
            raise LifecycleError(
                409,
                "cannot authorize: " + "; ".join(b.title for b in found),
                blockers=found,
            )

    system = (
        await session.execute(select(System).where(System.id == package.system_id))
    ).scalar_one()
    digest = await manifest_sha256(session, package)
    now = datetime.now(UTC)
    from_status = package.status
    package.status = rule.target
    package.status_changed_at = now

    if action == "submit" and system.ato_status in (None, "none"):
        system.ato_status = "in_progress"
    elif rule.authorizes:
        until = expires_on or today + timedelta(days=DEFAULT_ATO_PERIOD_DAYS)
        package.authorization_expires_on = until
        system.ato_status = "authorized"
        system.ato_expires_on = until
        await _supersede_older(session, package, principal, now)
    elif (
        rule.target in ("returned", "denied")
        and system.ato_status == "in_progress"
        and not await _others_in_review(session, package)
    ):
        system.ato_status = "none"

    event = AuthorizationPackageEvent(
        organization_id=package.organization_id,
        package_id=package.id,
        action=action,
        from_status=from_status,
        to_status=rule.target,
        actor=principal.email,
        acted_as=capacity,
        reason=reason,
        manifest_sha256=digest,
    )
    session.add(event)
    await session.flush()
    await record_event(
        session,
        actor=principal.email or "system",
        action=f"package_{action}",
        entity_type="authorization_package",
        entity_id=str(package.id),
        diff={
            "from": from_status, "to": rule.target, "acted_as": capacity,
            "reason": reason, "manifest_sha256": digest,
            "authorization_expires_on": (
                str(package.authorization_expires_on) if rule.authorizes else None
            ),
        },
        organization_id=package.organization_id,
    )
    await bus.emit(
        session,
        verb=f"package_{action}",
        entity_type="authorization_package",
        entity_id=package.id,
        summary=f"{system.name}: package {package.id} {from_status} → {rule.target}",
        org_id=package.organization_id,
        actor=principal.email,
    )
    return event


async def expire_due(
    session: AsyncSession, *, today: date | None = None, org_id: int | None = None
) -> dict[str, int]:
    """Mark authorizations past their end date ``expired`` (scheduler step).

    Covers systems authorized before packages had a workflow too: anything
    ``authorized`` whose ``ato_expires_on`` has passed. Nothing wrote
    ``expired`` before, so an expired ATO kept reading as authorized.
    """
    today = today or date.today()
    pkg_stmt = select(AuthorizationPackage).where(
        AuthorizationPackage.status.in_(DECIDED_STATUSES),
        AuthorizationPackage.authorization_expires_on.is_not(None),
        AuthorizationPackage.authorization_expires_on < today,
    )
    sys_stmt = select(System).where(
        System.ato_status == "authorized",
        System.ato_expires_on.is_not(None),
        System.ato_expires_on < today,
        System.deleted_at.is_(None),
    )
    if org_id is not None:
        pkg_stmt = pkg_stmt.where(AuthorizationPackage.organization_id == org_id)
        sys_stmt = sys_stmt.where(System.organization_id == org_id)
    packages = (await session.execute(pkg_stmt)).scalars().all()
    for p in packages:
        session.add(
            AuthorizationPackageEvent(
                organization_id=p.organization_id, package_id=p.id, action="expire",
                from_status=p.status, to_status="expired", actor=None,
                reason=f"authorization ended {p.authorization_expires_on}",
                manifest_sha256=p.manifest_sha256,
            )
        )
        p.status = "expired"
        p.status_changed_at = datetime.now(UTC)
    systems = (await session.execute(sys_stmt)).scalars().all()
    for s in systems:
        s.ato_status = "expired"
        await record_event(
            session,
            actor="scheduler",
            action="ato_expired",
            entity_type="system",
            entity_id=str(s.id),
            diff={"ato_expires_on": str(s.ato_expires_on)},
            organization_id=s.organization_id,
        )
    await session.flush()
    return {"packages_expired": len(packages), "systems_expired": len(systems)}
