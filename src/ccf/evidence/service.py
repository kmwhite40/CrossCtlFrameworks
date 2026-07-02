"""Evidence-repository service logic — versioning, review, retention, access.

Transport-agnostic (only touches the DB session + storage backend) so it is
unit-testable. Each new version is content-addressed (SHA-256) and stored via the
configured backend; approving an object sets an immutable lock (WORM-ready), after
which no new versions may be added.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_evidence import (
    EvidenceAccessEvent,
    EvidenceObject,
    EvidenceReview,
    EvidenceVersion,
)
from .storage import get_backend


class EvidenceError(ValueError):
    """Raised on an invalid evidence-repository operation (e.g. locked object)."""


async def create_object(
    session: AsyncSession,
    *,
    org_id: int | None,
    title: str,
    description: str | None = None,
    system_id: int | None = None,
    control_id: str | None = None,
    framework: str | None = None,
    owner: str | None = None,
    source_type: str = "manual_upload",
    expires_on: date | None = None,
) -> EvidenceObject:
    obj = EvidenceObject(
        organization_id=org_id,
        title=title,
        description=description,
        system_id=system_id,
        control_id=control_id,
        framework=framework,
        owner=owner,
        source_type=source_type,
        expires_on=expires_on,
        status="draft",
    )
    session.add(obj)
    await session.flush()
    return obj


async def add_version(
    session: AsyncSession,
    obj: EvidenceObject,
    *,
    data: bytes,
    filename: str | None = None,
    media_type: str | None = None,
    uploaded_by: str | None = None,
) -> EvidenceVersion:
    """Store ``data`` as the next immutable version; returns it. Fails if locked."""
    if obj.immutable_lock:
        raise EvidenceError("evidence object is locked (approved); create a new object instead")
    digest = hashlib.sha256(data).hexdigest()
    backend = get_backend()
    ref = backend.put(digest, data, media_type)
    next_no = (
        await session.execute(
            select(func.coalesce(func.max(EvidenceVersion.version), 0)).where(
                EvidenceVersion.evidence_object_id == obj.id
            )
        )
    ).scalar_one() + 1
    version = EvidenceVersion(
        evidence_object_id=obj.id,
        version=next_no,
        sha256=digest,
        media_type=media_type,
        size_bytes=len(data),
        filename=filename,
        storage_backend=backend.name,
        storage_ref=ref,
        uploaded_by=uploaded_by,
    )
    session.add(version)
    await session.flush()
    obj.current_version_id = version.id
    # A new version reopens review unless the object was already terminal.
    if obj.status in ("approved", "rejected", "expired"):
        obj.status = "draft"
    return version


async def submit_object(session: AsyncSession, obj: EvidenceObject) -> EvidenceObject:
    if obj.current_version_id is None:
        raise EvidenceError("cannot submit evidence with no versions")
    obj.status = "submitted"
    await session.flush()
    return obj


async def review_object(
    session: AsyncSession,
    obj: EvidenceObject,
    *,
    decision: str,
    reviewer: str | None = None,
    note: str | None = None,
) -> EvidenceReview:
    if decision not in ("approved", "rejected"):
        raise EvidenceError("decision must be 'approved' or 'rejected'")
    review = EvidenceReview(
        evidence_object_id=obj.id,
        version_id=obj.current_version_id,
        reviewer=reviewer,
        decision=decision,
        note=note,
    )
    session.add(review)
    obj.status = decision
    if decision == "approved":
        obj.immutable_lock = True  # WORM: approved evidence is frozen
    await session.flush()
    return review


async def read_version(
    session: AsyncSession, obj: EvidenceObject, *, version_id: int | None = None
) -> tuple[EvidenceVersion, bytes]:
    """Return (version, bytes) for the given version id (or the current one)."""
    target = version_id or obj.current_version_id
    if target is None:
        raise EvidenceError("evidence object has no versions")
    version = await session.get(EvidenceVersion, target)
    if version is None or version.evidence_object_id != obj.id:
        raise EvidenceError("version not found for this object")
    data = get_backend().get(version.storage_ref)
    if data is None:
        raise EvidenceError("stored content is unavailable")
    return version, data


async def record_access(
    session: AsyncSession,
    obj: EvidenceObject,
    *,
    version_id: int | None,
    actor: str | None,
    action: str = "download",
) -> None:
    session.add(
        EvidenceAccessEvent(
            evidence_object_id=obj.id, version_id=version_id, actor=actor, action=action
        )
    )
    await session.flush()


async def expired_objects(
    session: AsyncSession, *, org_id: int | None = None, today: date | None = None
) -> list[EvidenceObject]:
    today = today or datetime.now(UTC).date()
    stmt = select(EvidenceObject).where(
        EvidenceObject.expires_on.is_not(None), EvidenceObject.expires_on < today
    )
    if org_id is not None:
        stmt = stmt.where(EvidenceObject.organization_id == org_id)
    return list((await session.execute(stmt)).scalars().all())


async def mark_expired(
    session: AsyncSession, *, org_id: int | None = None, today: date | None = None
) -> int:
    """Flip past-freshness objects to ``expired`` (unless already terminal). Count."""
    today = today or datetime.now(UTC).date()
    n = 0
    for obj in await expired_objects(session, org_id=org_id, today=today):
        if obj.status != "expired":
            obj.status = "expired"
            n += 1
    await session.flush()
    return n


def object_summary(obj: EvidenceObject) -> dict[str, Any]:
    return {
        "id": obj.id,
        "title": obj.title,
        "status": obj.status,
        "owner": obj.owner,
        "control_id": obj.control_id,
        "framework": obj.framework,
        "source_type": obj.source_type,
        "system_id": obj.system_id,
        "expires_on": obj.expires_on,
        "immutable_lock": obj.immutable_lock,
        "current_version_id": obj.current_version_id,
        "version_count": len(obj.versions or []),
    }
