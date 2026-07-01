"""Artifact collection + evidence intake.

Content-addresses uploaded artifacts (SHA-256, deduped per org) and links them
to control-implementation evidence, so automated collectors and API clients can
push proof of a control directly instead of a human attaching files by hand.
"""

from __future__ import annotations

import hashlib
from datetime import date
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Artifact, ControlImplementation, Evidence
from . import bus

MAX_INLINE_BYTES = 25 * 1024 * 1024  # 25 MiB inline cap


async def store_artifact(
    session: AsyncSession,
    *,
    filename: str,
    content: bytes,
    media_type: str | None = None,
    org_id: int | None = None,
    uploaded_by: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Artifact:
    """Store bytes content-addressed; dedupe on (org, sha256)."""
    if len(content) > MAX_INLINE_BYTES:
        raise ValueError(f"artifact exceeds {MAX_INLINE_BYTES} byte inline limit")
    sha = hashlib.sha256(content).hexdigest()
    existing = (
        await session.execute(
            select(Artifact).where(Artifact.organization_id == org_id, Artifact.sha256 == sha)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    art = Artifact(
        organization_id=org_id,
        sha256=sha,
        filename=filename,
        media_type=media_type,
        size_bytes=len(content),
        storage="inline",
        content=content,
        uploaded_by=uploaded_by,
        metadata_json=metadata or {},
    )
    session.add(art)
    await session.flush()
    return art


async def collect_evidence(
    session: AsyncSession,
    *,
    implementation_id: int,
    title: str,
    kind: str = "config_export",
    content: bytes | None = None,
    filename: str | None = None,
    media_type: str | None = None,
    uri: str | None = None,
    collected_on: date | None = None,
    expires_on: date | None = None,
    org_id: int | None = None,
    uploaded_by: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[Evidence, Artifact | None]:
    """Attach evidence to a control implementation, optionally storing a file.

    Emits a ``captured`` event so the activity feed / webhooks see the collection.
    """
    impl = (
        await session.execute(
            select(ControlImplementation).where(ControlImplementation.id == implementation_id)
        )
    ).scalar_one_or_none()
    if impl is None:
        raise ValueError("control implementation not found")

    artifact: Artifact | None = None
    hash_sha256: str | None = None
    if content is not None:
        artifact = await store_artifact(
            session,
            filename=filename or title,
            content=content,
            media_type=media_type,
            org_id=org_id,
            uploaded_by=uploaded_by,
            metadata=metadata,
        )
        hash_sha256 = artifact.sha256

    ev = Evidence(
        implementation_id=implementation_id,
        kind=kind,
        title=title,
        uri=uri,
        collected_on=collected_on,
        expires_on=expires_on,
        hash_sha256=hash_sha256,
        artifact_id=artifact.id if artifact else None,
        metadata_json=metadata or {},
    )
    session.add(ev)
    await session.flush()
    await bus.emit(
        session,
        verb="captured",
        entity_type="evidence",
        entity_id=ev.id,
        summary=f"Evidence '{title}' collected for control {impl.control_id}",
        org_id=org_id,
        actor=uploaded_by,
        payload={"implementation_id": implementation_id, "artifact_id": ev.artifact_id},
    )
    return ev, artifact
