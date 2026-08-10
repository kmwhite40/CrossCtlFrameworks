"""Resolve a polymorphic prep source to bytes.

A run addresses its source as ``(source_kind, source_id)`` rather than through a
new document table, so the same pipeline prepares system evidence and enterprise
policy without either library learning about the other. Evidence bytes come from
the configured storage backend; policy versions may carry inline ``body`` text or
a ``uri``, and inline text is preferred because it needs no network.

Deletion is expected, not exceptional: an ``EvidenceVersion`` can be removed
after a run is queued, so :class:`SourceMissing` is raised for the pipeline to
close the run as ``orphaned``.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..evidence.storage import get_backend
from ..models import Policy, PolicyVersion
from ..models_evidence import EvidenceObject, EvidenceVersion
from ..models_prep import PREP_SOURCE_KINDS


class SourceMissing(LookupError):  # noqa: N818 -- name fixed by the interface contract
    """The referenced source row or its content no longer exists."""


@dataclass(slots=True)
class ResolvedSource:
    """Bytes plus the tenancy context a run needs to write org-scoped rows."""

    data: bytes
    filename: str
    media_type: str | None
    organization_id: int
    system_id: int | None


async def _resolve_evidence_version(session: AsyncSession, source_id: int) -> ResolvedSource:
    row = (
        await session.execute(
            select(EvidenceVersion, EvidenceObject)
            .join(EvidenceObject, EvidenceObject.id == EvidenceVersion.evidence_object_id)
            .where(EvidenceVersion.id == source_id)
        )
    ).first()
    if row is None:
        raise SourceMissing(f"evidence_version {source_id} not found")
    version, obj = row
    if obj.organization_id is None:
        raise SourceMissing(f"evidence_version {source_id} has no organization")
    data = get_backend().get(version.storage_ref)
    if data is None:
        raise SourceMissing(f"evidence_version {source_id} content missing from storage")
    return ResolvedSource(
        data=data,
        filename=version.filename or f"evidence-{source_id}",
        media_type=version.media_type,
        organization_id=int(obj.organization_id),
        system_id=int(obj.system_id) if obj.system_id is not None else None,
    )


async def _resolve_policy_version(session: AsyncSession, source_id: int) -> ResolvedSource:
    row = (
        await session.execute(
            select(PolicyVersion, Policy)
            .join(Policy, Policy.id == PolicyVersion.policy_id)
            .where(PolicyVersion.id == source_id)
        )
    ).first()
    if row is None:
        raise SourceMissing(f"policy_version {source_id} not found")
    version, policy = row
    if policy.organization_id is None:
        raise SourceMissing(f"policy_version {source_id} has no organization")
    if not version.body:
        # A URI-only policy points at a document Concord does not hold. Fetching
        # it is a connector concern, not a parser one.
        raise SourceMissing(
            f"policy_version {source_id} has no inline body (uri-only sources are not preparable)"
        )
    return ResolvedSource(
        data=version.body.encode("utf-8"),
        filename=f"{policy.name}-{version.version}.txt",
        media_type="text/plain",
        organization_id=int(policy.organization_id),
        system_id=None,
    )


async def resolve_source(
    session: AsyncSession, source_kind: str, source_id: int
) -> ResolvedSource:
    """Load the bytes and tenancy context for one prep source."""
    if source_kind not in PREP_SOURCE_KINDS:
        raise SourceMissing(f"unknown source kind '{source_kind}'")
    if source_kind == "evidence_version":
        return await _resolve_evidence_version(session, source_id)
    return await _resolve_policy_version(session, source_id)


async def _system_id_for_evidence_version(session: AsyncSession, source_id: int) -> int | None:
    row = (
        await session.execute(
            select(EvidenceObject.system_id, EvidenceObject.organization_id)
            .join(EvidenceVersion, EvidenceVersion.evidence_object_id == EvidenceObject.id)
            .where(EvidenceVersion.id == source_id)
        )
    ).first()
    if row is None:
        raise SourceMissing(f"evidence_version {source_id} not found")
    system_id, organization_id = row
    if organization_id is None:
        raise SourceMissing(f"evidence_version {source_id} has no organization")
    return int(system_id) if system_id is not None else None


async def _system_id_for_policy_version(session: AsyncSession, source_id: int) -> int | None:
    row = (
        await session.execute(
            select(Policy.organization_id)
            .join(PolicyVersion, PolicyVersion.policy_id == Policy.id)
            .where(PolicyVersion.id == source_id)
        )
    ).first()
    if row is None:
        raise SourceMissing(f"policy_version {source_id} not found")
    if row[0] is None:
        raise SourceMissing(f"policy_version {source_id} has no organization")
    # Policy versions have no owning system — PrepUnit.system_id denormalises
    # system evidence only, per _resolve_policy_version above.
    return None


async def resolve_source_system_id(
    session: AsyncSession, source_kind: str, source_id: int
) -> int | None:
    """Look up the owning system id for one prep source without fetching its bytes.

    ``resolve_source`` reads the full document body from the storage backend
    (``get_backend().get(...)``), which for an ``evidence_version`` can be a
    large PDF pulled from S3 or disk. Task 10's expand stage only needs the
    integer ``system_id`` to denormalise onto each ``PrepUnit`` it writes — a
    value already available off the same join ``resolve_source`` performs —
    so re-fetching the whole document on every expand run, after parse already
    read it, wastes a storage round trip for one integer. This performs the
    identical joins and the identical ``SourceMissing`` semantics without ever
    calling ``get_backend()``.
    """
    if source_kind not in PREP_SOURCE_KINDS:
        raise SourceMissing(f"unknown source kind '{source_kind}'")
    if source_kind == "evidence_version":
        return await _system_id_for_evidence_version(session, source_id)
    return await _system_id_for_policy_version(session, source_id)
