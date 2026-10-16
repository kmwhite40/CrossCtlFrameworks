"""Recording an assessor review or a KSI exception -- one path for API and page.

The page forms used to write these rows themselves and skipped what the API
does around the write: the reviewer's attribution on the KSI state, the
idempotent POA&M an opened finding creates, and the audit event. A 3PAO review
recorded on the page therefore had no reviewer and no audit trail, and a
finding opened there never reached the POA&M list. Both callers now go
through here; each still does its own authorization and scoping first.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..governance import bus
from ..models import KSI, POAM, KSIAssessorReview, KSIException, KSIState


async def maybe_open_finding_poam(
    session: AsyncSession, *, system_id: int, ksi_id: int, review: KSIAssessorReview
) -> None:
    """When an assessor opens a finding, create an idempotent POA&M for the gap."""
    if review.status != "finding_opened":
        return
    ksi = (await session.execute(select(KSI).where(KSI.id == ksi_id))).scalar_one_or_none()
    ident = ksi.identifier if ksi else f"KSI {ksi_id}"
    title = f"{ident} — assessor finding"
    exists = (
        await session.execute(
            select(POAM.id).where(POAM.system_id == system_id, POAM.title == title)
        )
    ).scalar_one_or_none()
    if exists is not None:
        return
    session.add(
        POAM(
            system_id=system_id,
            title=title,
            weakness=(review.finding or f"Assessor opened a finding against {ident}.").strip(),
            severity="moderate",
            status="open",
            source="assessment",
            identified_on=datetime.now(UTC).date(),
        )
    )


async def record_review(
    session: AsyncSession, *, principal: Principal, fields: dict[str, Any]
) -> KSIAssessorReview:
    """Add a review, reflect it on the KSI state, open a POA&M, emit the event."""
    rv = KSIAssessorReview(**fields)
    session.add(rv)
    st = (
        await session.execute(
            select(KSIState).where(
                KSIState.system_id == rv.system_id, KSIState.ksi_id == rv.ksi_id
            )
        )
    ).scalar_one_or_none()
    if st is not None:
        st.assessor_status = rv.status
        st.reviewer_user_id = principal.user_id
    await session.flush()
    await maybe_open_finding_poam(session, system_id=rv.system_id, ksi_id=rv.ksi_id, review=rv)
    await bus.emit(
        session,
        verb="reviewed",
        entity_type="ksi_assessor_review",
        entity_id=rv.id,
        summary=f"Assessor review {rv.status} for KSI {rv.ksi_id}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    return rv


async def record_exception(
    session: AsyncSession,
    *,
    principal: Principal,
    system_id: int,
    ksi_id: int,
    rationale: str,
    status: str,
    risk_id: int | None = None,
    expires_on: date | None = None,
) -> KSIException:
    exc = KSIException(
        system_id=system_id,
        ksi_id=ksi_id,
        rationale=rationale,
        status=status,
        risk_id=risk_id,
        expires_on=expires_on,
    )
    session.add(exc)
    await session.flush()
    await bus.emit(
        session,
        verb="created",
        entity_type="ksi_exception",
        entity_id=exc.id,
        summary=f"KSI exception ({status}) for KSI {ksi_id}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    return exc
