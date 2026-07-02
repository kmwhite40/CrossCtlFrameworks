"""Personnel lifecycle automation — onboarding, offboarding, and posture rollup.

Onboarding a person assigns the baseline security-awareness training (AT-2) and
opens a background-screening task (PS-3) when screening is incomplete; offboarding
opens a high-priority access-revocation task (PS-4/AC-2) and marks the record
offboarded. The rollup drives the personnel compliance summary and (via the
digest) overdue-training / stale-screening alerts.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Task
from ..models_people import AccessReview, AccessReviewItem, Person, TrainingRecord
from . import bus

# Baseline security awareness training assigned on onboarding (AT-2).
BASELINE_TRAINING = "Security Awareness Training"
_TRAINING_DUE_DAYS = 30


async def onboard(session: AsyncSession, person: Person, *, actor: str | None = None) -> None:
    """Activate a person and open their onboarding obligations (AT-2 + PS-3)."""
    today = datetime.now(UTC).date()
    person.status = "active"
    if person.start_date is None:
        person.start_date = today

    # Assign baseline awareness training if they don't already have it. Query
    # directly rather than via the relationship to avoid an async lazy-load.
    has_baseline = (
        await session.execute(
            select(TrainingRecord.id).where(
                TrainingRecord.person_id == person.id,
                TrainingRecord.course == BASELINE_TRAINING,
            )
        )
    ).first() is not None
    if not has_baseline:
        session.add(
            TrainingRecord(
                person_id=person.id,
                course=BASELINE_TRAINING,
                kind="awareness",
                control_ref="AT-2",
                assigned_on=today,
                due_on=today + timedelta(days=_TRAINING_DUE_DAYS),
                status="assigned",
            )
        )

    # Open a screening task when the background check (PS-3) is not yet done.
    if person.background_check_status not in ("completed", "waived"):
        await _ensure_task(
            session,
            person,
            title=f"Complete background screening: {person.full_name}",
            kind="onboarding",
            priority="high" if person.risk_designation == "high" else "medium",
            dedupe=f"onboard-screen:{person.id}",
        )
    await bus.emit(
        session,
        verb="onboarded",
        entity_type="person",
        entity_id=person.id,
        summary=f"Onboarded {person.full_name} ({person.employment_type})",
        org_id=person.organization_id,
        actor=actor,
    )


async def offboard(
    session: AsyncSession, person: Person, *, end_date: date | None = None, actor: str | None = None
) -> None:
    """Mark a person offboarded and open the access-revocation task (PS-4/AC-2)."""
    today = datetime.now(UTC).date()
    person.status = "offboarded"
    person.end_date = end_date or today
    await _ensure_task(
        session,
        person,
        title=f"Revoke all access for offboarded personnel: {person.full_name}",
        kind="offboarding",
        priority="high",
        dedupe=f"offboard-revoke:{person.id}",
    )
    await bus.emit(
        session,
        verb="offboarded",
        entity_type="person",
        entity_id=person.id,
        summary=f"Offboarded {person.full_name}; access revocation task opened",
        org_id=person.organization_id,
        actor=actor,
    )


async def _ensure_task(
    session: AsyncSession,
    person: Person,
    *,
    title: str,
    kind: str,
    priority: str,
    dedupe: str,
) -> None:
    exists = (
        await session.execute(select(Task).where(Task.dedupe_key == dedupe))
    ).scalar_one_or_none()
    if exists is not None:
        return
    session.add(
        Task(
            organization_id=person.organization_id,
            title=title,
            description=f"{person.position or 'Personnel'} — {person.email or person.full_name}",
            kind=kind,
            priority=priority,
            status="open",
            source="auto",
            entity_type="person",
            entity_id=str(person.id),
            dedupe_key=dedupe,
        )
    )


async def summary(
    session: AsyncSession, *, org_id: int | None = None, today: date | None = None
) -> dict[str, Any]:
    """Personnel-security posture rollup for the dashboard / digest."""
    today = today or datetime.now(UTC).date()

    def _scope_person(stmt: Any) -> Any:
        return stmt.where(Person.organization_id == org_id) if org_id is not None else stmt

    active = (
        await session.execute(
            _scope_person(select(func.count()).select_from(Person)).where(Person.status == "active")
        )
    ).scalar_one()
    screening_gaps = (
        await session.execute(
            _scope_person(select(func.count()).select_from(Person)).where(
                Person.status == "active",
                Person.background_check_status.not_in(("completed", "waived")),
            )
        )
    ).scalar_one()

    training_stmt = (
        select(func.count())
        .select_from(TrainingRecord)
        .join(Person, Person.id == TrainingRecord.person_id)
        .where(
            TrainingRecord.status == "assigned",
            TrainingRecord.due_on.is_not(None),
            TrainingRecord.due_on < today,
        )
    )
    if org_id is not None:
        training_stmt = training_stmt.where(Person.organization_id == org_id)
    training_overdue = (await session.execute(training_stmt)).scalar_one()

    reviews_stmt = select(func.count()).select_from(AccessReview).where(
        AccessReview.status != "completed"
    )
    if org_id is not None:
        reviews_stmt = reviews_stmt.where(AccessReview.organization_id == org_id)
    open_reviews = (await session.execute(reviews_stmt)).scalar_one()

    pending_items_stmt = (
        select(func.count())
        .select_from(AccessReviewItem)
        .join(AccessReview, AccessReview.id == AccessReviewItem.review_id)
        .where(AccessReviewItem.decision == "pending")
    )
    if org_id is not None:
        pending_items_stmt = pending_items_stmt.where(AccessReview.organization_id == org_id)
    pending_items = (await session.execute(pending_items_stmt)).scalar_one()

    return {
        "active_personnel": active,
        "screening_incomplete": screening_gaps,
        "training_overdue": training_overdue,
        "open_access_reviews": open_reviews,
        "access_items_pending": pending_items,
    }
