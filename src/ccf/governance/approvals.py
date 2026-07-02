"""Approval workflow with separation of duties.

A governed entity (SSP project, POA&M, risk, assessment) moves
draft → submitted → approved / rejected. Separation of duties: the approver must
be a different person than the submitter, and must hold an approver role. Both
rules are enforced only when authentication is enabled (single-operator mode has
one principal, so SoD cannot apply). Approving an SSP project also stamps its own
status so downstream views reflect the authorization.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..models import Approval, SSPProject
from . import bus

ENTITY_TYPES = {"ssp_project", "poam", "risk", "assessment"}
APPROVER_ROLES = {"admin", "authorizing_official"}


class WorkflowError(Exception):
    """Raised on an invalid transition or a separation-of-duties violation."""


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
    a = await _get_or_create(session, entity_type, entity_id, org_id)
    if a.state == "approved":
        raise WorkflowError("already approved")
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
) -> Approval:
    if entity_type not in ENTITY_TYPES:
        raise WorkflowError(f"unsupported entity type: {entity_type}")
    a = await _get_or_create(session, entity_type, entity_id, org_id)
    if a.state != "submitted":
        raise WorkflowError(f"cannot decide from state '{a.state}' (must be submitted)")

    auth_on = get_settings().auth_enabled
    if auth_on:
        if role not in APPROVER_ROLES:
            raise WorkflowError("approver must hold an authorizing role")
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
        summary=f"{entity_type} {entity_id} {a.state} by {actor}",
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
