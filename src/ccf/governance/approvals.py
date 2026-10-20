"""Approval workflow with separation of duties.

A governed entity (SSP project, POA&M, risk, assessment) moves
draft → submitted → approved / rejected. Separation of duties: the approver must
be a different person than the submitter, and must have authority over the
entity's system -- an ``admin``, or the holder of one of the system roles
:data:`APPROVAL_AUTHORITY` names for that entity type (``ccf.ato.roles``). Both
rules are enforced only when authentication is enabled (single-operator mode has
one principal, so SoD cannot apply). Approving an SSP project also stamps its own
status so downstream views reflect the authorization.

Authority used to be ``role in {"admin", "authorizing_official"}``, but
``authorizing_official`` is not a value ``User.role`` can hold, so only admins
could ever approve, and an AO had no way to be one. Every submit and decision
also resolves the entity first: it must exist and belong to the caller's
organization, so no tenant can create or decide another tenant's approval row.

An approval authorizes one decision. A gate that relies on it calls
``consume``, which returns the entity to draft so the next gated transition
needs a fresh review. Without that, one reviewer decision kept authorizing
every later close, re-accept or expiry extension on the same record.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..ato import roles as system_roles
from ..config import get_settings
from ..models import POAM, Approval, Assessment, Risk, SSPProject, System
from . import bus

#: Which system roles may decide an approval of each entity type (an ``admin``
#: always may). Accepting risk is the AO's decision under RMF, so the gates that
#: spend an approval on a risk acceptance additionally require it was granted
#: by the AO (:data:`RISK_ACCEPTANCE_AUTHORITY`, see :func:`granted_as`); a
#: POA&M approval the ISSO granted can still close a remediated weakness.
APPROVAL_AUTHORITY: dict[str, tuple[str, ...]] = {
    "ssp_project": ("issm", "authorizing_official"),
    "poam": ("isso", "issm", "authorizing_official"),
    "risk": ("authorizing_official",),
    "assessment": ("issm", "authorizing_official"),
}
ENTITY_TYPES = set(APPROVAL_AUTHORITY)
RISK_ACCEPTANCE_AUTHORITY: tuple[str, ...] = ("authorizing_official",)
#: Entity types whose approval a gate spends (``consume``). An unspent one may
#: be replaced by a new request; an SSP approval stamps the project's status,
#: so it stays final.
_RESUBMITTABLE = {"poam", "risk"}


class WorkflowError(Exception):
    """Raised on an invalid transition or a separation-of-duties violation."""


class EntityNotFoundError(WorkflowError):
    """The entity does not exist, or is not visible to the caller's org."""


async def _entity_scope(
    session: AsyncSession, entity_type: str, entity_id: str | int
) -> tuple[int | None, int | None] | None:
    """``(system_id, organization_id)`` of a governed entity, or None if absent."""
    try:
        eid = int(entity_id)
    except (TypeError, ValueError):
        return None
    if entity_type == "ssp_project":
        row = (
            await session.execute(
                select(SSPProject.system_id, SSPProject.organization_id).where(
                    SSPProject.id == eid
                )
            )
        ).one_or_none()
        return (row[0], row[1]) if row is not None else None
    stmt: Select[Any]
    if entity_type == "poam":
        stmt = select(POAM.system_id, System.organization_id).outerjoin(
            System, System.id == POAM.system_id
        ).where(POAM.id == eid)
    elif entity_type == "risk":
        stmt = select(Risk.system_id, System.organization_id).outerjoin(
            System, System.id == Risk.system_id
        ).where(Risk.id == eid)
    else:
        stmt = select(Assessment.system_id, System.organization_id).outerjoin(
            System, System.id == Assessment.system_id
        ).where(Assessment.id == eid)
    found = (await session.execute(stmt)).one_or_none()
    return (found[0], found[1]) if found is not None else None


async def _require_scope(
    session: AsyncSession, entity_type: str, entity_id: str | int, org_id: int | None
) -> int | None:
    """The entity's system id; raises :class:`EntityNotFoundError` across tenants."""
    scope = await _entity_scope(session, entity_type, entity_id)
    if scope is None:
        raise EntityNotFoundError(f"{entity_type} {entity_id} not found")
    system_id, entity_org = scope
    if org_id is not None and entity_org is not None and entity_org != org_id:
        raise EntityNotFoundError(f"{entity_type} {entity_id} not found")
    return system_id


async def granted_as(
    session: AsyncSession, entity_type: str, entity_id: str | int, roles: tuple[str, ...]
) -> str | None:
    """The capacity in which the current approval's reviewer held ``roles``.

    Used by gates that need more than "someone approved": a risk acceptance
    spent on an ISSO's POA&M approval would let the ISSO accept risk.
    """
    found = await _reviewer_acting_as(session, entity_type, entity_id, roles)
    return found[1] if found is not None else None


async def authorized_reviewer(
    session: AsyncSession, entity_type: str, entity_id: str | int, roles: tuple[str, ...]
) -> str | None:
    """The current approval's reviewer, if they held ``roles`` -- else None.

    A gate passes this to :func:`consume` as ``reviewed_by``. Checking the
    reviewer and then spending would be a read followed by a write: in between,
    the approval could be spent, resubmitted and re-approved by someone without
    the role. Pinning the reviewer makes the spend itself refuse that.
    """
    found = await _reviewer_acting_as(session, entity_type, entity_id, roles)
    return found[0] if found is not None else None


async def _reviewer_acting_as(
    session: AsyncSession, entity_type: str, entity_id: str | int, roles: tuple[str, ...]
) -> tuple[str, str] | None:
    """``(reviewer email, capacity)`` for an approved approval whose reviewer
    held one of ``roles`` on the entity's system, else None."""
    a = (
        await session.execute(
            select(Approval).where(
                Approval.entity_type == entity_type, Approval.entity_id == str(entity_id)
            )
        )
    ).scalar_one_or_none()
    if a is None or a.state != "approved" or not a.reviewed_by:
        return None
    scope = await _entity_scope(session, entity_type, entity_id)
    system_id = scope[0] if scope is not None else None
    capacity = await system_roles.acting_as_email(
        session, system_id=system_id, email=a.reviewed_by, allowed=roles
    )
    return (a.reviewed_by, capacity) if capacity is not None else None


async def _get_or_create(
    session: AsyncSession, entity_type: str, entity_id: str, org_id: int | None
) -> Approval:
    row = (
        await session.execute(
            select(Approval).where(
                Approval.entity_type == entity_type, Approval.entity_id == str(entity_id)
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = Approval(organization_id=org_id, entity_type=entity_type, entity_id=str(entity_id))
        session.add(row)
        await session.flush()
    return row


def out(a: Approval) -> dict[str, Any]:
    return {
        "entity_type": a.entity_type,
        "entity_id": a.entity_id,
        "state": a.state,
        "submitted_by": a.submitted_by,
        "submitted_at": a.submitted_at,
        "reviewed_by": a.reviewed_by,
        "reviewed_at": a.reviewed_at,
        "decision_note": a.decision_note,
    }


async def entity_state(session: AsyncSession, entity_type: str, entity_id: int | str) -> str:
    """Read-time lookup of a governed entity's current approval state.

    This is the visibility half of the workflow (ISSM-07): callers building an
    entity's API payload use this to surface *that* it was approved/rejected/is
    pending review, without owning or fabricating any terminal status transition
    on the entity itself. Mirrors the default ``GET /api/approvals/{type}/{id}``
    returns when no row exists yet: ``"draft"`` (never submitted).
    """
    row = (
        await session.execute(
            select(Approval).where(
                Approval.entity_type == entity_type, Approval.entity_id == str(entity_id)
            )
        )
    ).scalar_one_or_none()
    return row.state if row is not None else "draft"


async def entity_states(
    session: AsyncSession, entity_type: str, entity_ids: Iterable[int | str]
) -> dict[str, str]:
    """Batch form of :func:`entity_state` for list endpoints (avoids N+1 queries).

    Returns a mapping keyed by the *string* entity id (matching
    ``Approval.entity_id``), defaulting missing ids to ``"draft"``.
    """
    ids = [str(i) for i in entity_ids]
    if not ids:
        return {}
    rows = (
        await session.execute(
            select(Approval).where(
                Approval.entity_type == entity_type, Approval.entity_id.in_(ids)
            )
        )
    ).scalars().all()
    found = {r.entity_id: r.state for r in rows}
    return {i: found.get(i, "draft") for i in ids}


async def submit(
    session: AsyncSession,
    *,
    entity_type: str,
    entity_id: str,
    actor: str | None,
    org_id: int | None = None,
) -> Approval:
    if entity_type not in ENTITY_TYPES:
        raise WorkflowError(f"unsupported entity type: {entity_type}")
    await _require_scope(session, entity_type, entity_id, org_id)
    a = await _get_or_create(session, entity_type, entity_id, org_id)
    if a.state == "approved":
        if entity_type not in _RESUBMITTABLE:
            raise WorkflowError("already approved")
        # An unspent approval on a gated record can be the wrong one -- an
        # ISSO's POA&M approval cannot accept risk -- and with no way to ask
        # again the record was stuck. Asking again only voids it; the next
        # gated transition still needs a decision.
        await bus.emit(
            session,
            verb="approval_voided",
            entity_type=entity_type,
            entity_id=entity_id,
            summary=f"{entity_type} {entity_id}: unspent approval by {a.reviewed_by} "
            f"replaced by a new request from {actor}",
            org_id=org_id,
            actor=actor,
            dispatch=False,
        )
    a.state = "submitted"
    a.submitted_by = actor
    a.submitted_at = datetime.now(UTC)
    a.reviewed_by = None
    a.reviewed_at = None
    await bus.emit(
        session,
        verb="submitted",
        entity_type=entity_type,
        entity_id=entity_id,
        summary=f"{entity_type} {entity_id} submitted for review by {actor}",
        org_id=org_id,
        actor=actor,
    )
    await bus.notify(
        session,
        category="approval",
        title=f"Review requested: {entity_type} {entity_id}",
        body=f"Submitted by {actor}.",
        org_id=org_id,
        severity="info",
        entity_type=entity_type,
        entity_id=entity_id,
        dedupe_key=f"review-req:{entity_type}:{entity_id}",
    )
    return a


async def consume(
    session: AsyncSession,
    *,
    entity_type: str,
    entity_id: str | int | None,
    actor: str | None,
    org_id: int | None = None,
    reviewed_by: str | None = None,
) -> bool:
    """Spend an approval on the gated transition it authorizes. True if spent.

    ``reviewed_by`` pins whose approval may be spent (see
    :func:`authorized_reviewer`): an approval re-granted by anyone else since
    the gate looked matches nothing, and the gate refuses.

    This IS the gate's approval check: a caller refuses the transition when it
    returns False. One conditional UPDATE, never a read followed by a write --
    two concurrent requests that both read "approved" would both pass on one
    review. Here the second waits on the row lock, re-evaluates the WHERE, and
    updates nothing. Run it in the transition's own transaction, so a rolled
    back transition leaves the approval unspent. The row returns to draft;
    ``reviewed_by``/``decision_note`` stay until the next submission, and the
    event records who approved what was spent.
    """
    if entity_id is None:
        return False
    conditions = [
        Approval.entity_type == entity_type,
        Approval.entity_id == str(entity_id),
        Approval.state == "approved",
    ]
    if reviewed_by is not None:
        conditions.append(Approval.reviewed_by == reviewed_by)
    row = (
        await session.execute(
            update(Approval)
            .where(*conditions)
            .values(state="draft")
            .returning(Approval.organization_id, Approval.reviewed_by)
            .execution_options(synchronize_session=False)
        )
    ).one_or_none()
    if row is None:
        return False
    await bus.emit(
        session,
        verb="approval_consumed",
        entity_type=entity_type,
        entity_id=str(entity_id),
        summary=f"{entity_type} {entity_id}: approval by {row.reviewed_by} used by {actor}",
        org_id=org_id if org_id is not None else row.organization_id,
        actor=actor,
        dispatch=False,
    )
    return True


async def decide(
    session: AsyncSession,
    *,
    entity_type: str,
    entity_id: str,
    approve: bool,
    actor: str | None,
    role: str | None,
    note: str | None = None,
    org_id: int | None = None,
    user_id: int | None = None,
) -> Approval:
    if entity_type not in ENTITY_TYPES:
        raise WorkflowError(f"unsupported entity type: {entity_type}")
    system_id = await _require_scope(session, entity_type, entity_id, org_id)
    a = await _get_or_create(session, entity_type, entity_id, org_id)
    if a.state != "submitted":
        raise WorkflowError(f"cannot decide from state '{a.state}' (must be submitted)")

    auth_on = get_settings().auth_enabled
    capacity: str | None = None
    if auth_on:
        allowed = APPROVAL_AUTHORITY[entity_type]
        if user_id is not None:
            capacity = await system_roles.acting_as(
                session, system_id=system_id, user_id=user_id, user_role=role, allowed=allowed
            )
        elif role == "admin":
            capacity = "admin"
        else:
            capacity = await system_roles.acting_as_email(
                session, system_id=system_id, email=actor, allowed=allowed
            )
        if capacity is None:
            raise WorkflowError(
                "approver must hold an authorizing role: admin, or the system's "
                + " / ".join(system_roles.ROLE_LABELS[r] for r in allowed)
            )
        if actor and a.submitted_by and actor == a.submitted_by:
            raise WorkflowError("separation of duties: approver must differ from submitter")

    a.state = "approved" if approve else "rejected"
    a.reviewed_by = actor
    a.reviewed_at = datetime.now(UTC)
    a.decision_note = note

    # Reflect the decision on the entity's own status where it has one.
    if approve and entity_type == "ssp_project":
        proj = (
            await session.execute(select(SSPProject).where(SSPProject.id == int(entity_id)))
        ).scalar_one_or_none()
        if proj is not None:
            proj.status = "approved"

    await bus.emit(
        session,
        verb="approved" if approve else "rejected",
        entity_type=entity_type,
        entity_id=entity_id,
        summary=(
            f"{entity_type} {entity_id} {a.state} by {actor}"
            + (f" as {system_roles.ROLE_LABELS.get(capacity, capacity)}" if capacity else "")
        ),
        org_id=org_id,
        actor=actor,
    )
    await bus.notify(
        session,
        category="approval",
        title=f"{entity_type} {entity_id} {a.state}",
        body=(note or ""),
        org_id=org_id,
        severity="info" if approve else "warning",
        entity_type=entity_type,
        entity_id=entity_id,
        dedupe_key=f"decision:{entity_type}:{entity_id}:{a.state}",
    )
    return a
