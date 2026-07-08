"""Portal orchestration — issue grants, resolve tokens, expose scoped contents.

Security model: an external request arrives unauthenticated (the portal paths are
public), so the DB session starts unscoped (RLS-bypass). Every read/write path
here therefore **re-clamps** the session to the grant's own tenant via
:func:`~ccf.db.set_session_tenant` before touching tenant data, and additionally
returns only the artifacts explicitly shared into the grant. Defence in depth: RLS
plus an explicit allow-list. Every access writes an immutable portal audit event.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import set_session_tenant
from ..models_evidence import EvidenceObject
from ..models_packages import AuthorizationPackage
from ..models_portal import (
    ExternalAccessGrant,
    ExternalComment,
    ExternalEvidenceShare,
    ExternalPackageShare,
    ExternalPortalAuditEvent,
    ExternalPrincipal,
)

_TOKEN_BYTES = 32  # → ~43 url-safe chars, well within the 64-char column


def _now() -> datetime:
    return datetime.now(UTC)


def _gen_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


async def _audit(session: AsyncSession, **kw: Any) -> None:
    from ..api.audit import record_event  # noqa: PLC0415 — avoid import cycle

    await record_event(session, **kw)


async def _clamp(session: AsyncSession, grant: ExternalAccessGrant) -> None:
    """Bind the session's RLS tenant to the grant's org before touching its data."""
    await set_session_tenant(session, grant.organization_id)


# --- admin: issue / list / revoke ------------------------------------------


async def create_grant(
    session: AsyncSession,
    *,
    org_id: int,
    principal_name: str,
    kind: str = "customer",
    email: str | None = None,
    organization_name: str | None = None,
    package_ids: list[int] | tuple[int, ...] = (),
    evidence_ids: list[int] | tuple[int, ...] = (),
    ttl_days: int | None = 30,
    label: str | None = None,
    actor: str | None = None,
) -> ExternalAccessGrant:
    """Issue a scoped, expiring bearer-token grant to an external principal."""
    principal = ExternalPrincipal(
        organization_id=org_id, kind=kind, name=principal_name,
        email=email, organization_name=organization_name,
    )
    session.add(principal)
    await session.flush()

    pkg_ids = [int(p) for p in package_ids]
    ev_ids = [int(e) for e in evidence_ids]
    grant = ExternalAccessGrant(
        organization_id=org_id,
        principal_id=principal.id,
        kind=kind,
        token=_gen_token(),
        label=label,
        expires_at=(_now() + timedelta(days=ttl_days)) if ttl_days else None,
        revoked=False,
        scope={"package_ids": pkg_ids, "evidence_ids": ev_ids},
    )
    session.add(grant)
    await session.flush()

    for pid in pkg_ids:
        session.add(ExternalPackageShare(grant_id=grant.id, package_id=pid))
    for eid in ev_ids:
        session.add(ExternalEvidenceShare(grant_id=grant.id, evidence_object_id=eid))

    await record_access(
        session, grant, action="issued", detail=f"{len(pkg_ids)}pkg/{len(ev_ids)}ev"
    )
    await _audit(
        session, actor=actor or "system", action="create", entity_type="external_grant",
        entity_id=str(grant.id),
        diff={"org": org_id, "kind": kind, "packages": pkg_ids, "evidence": ev_ids},
    )
    await session.flush()
    return grant


async def list_grants(session: AsyncSession, *, org_id: int) -> list[ExternalAccessGrant]:
    return list(
        (
            await session.execute(
                select(ExternalAccessGrant)
                .where(ExternalAccessGrant.organization_id == org_id)
                .order_by(ExternalAccessGrant.id.desc())
            )
        ).scalars().all()
    )


async def revoke_grant(session: AsyncSession, grant_id: int, *, actor: str | None = None) -> bool:
    grant = await session.get(ExternalAccessGrant, grant_id)
    if grant is None:
        return False
    grant.revoked = True
    await record_access(session, grant, action="revoked")
    await _audit(
        session, actor=actor or "system", action="delete", entity_type="external_grant",
        entity_id=str(grant.id), diff={"revoked": True},
    )
    await session.flush()
    return True


# --- portal: token resolution + scoped contents ----------------------------


async def resolve_grant(session: AsyncSession, token: str) -> ExternalAccessGrant | None:
    """Return the grant for a valid token, or None if unknown / revoked / expired.

    Pure validation — no side effects; the read/write paths clamp the tenant.
    """
    if not token:
        return None
    grant = (
        await session.execute(
            select(ExternalAccessGrant).where(ExternalAccessGrant.token == token)
        )
    ).scalar_one_or_none()
    if grant is None or grant.revoked:
        return None
    if grant.expires_at is not None and grant.expires_at < _now():
        return None
    return grant


async def grant_contents(session: AsyncSession, grant: ExternalAccessGrant) -> dict[str, Any]:
    """The packages, evidence, and comment thread explicitly shared into a grant."""
    await _clamp(session, grant)

    pkg_ids = list(
        (
            await session.execute(
                select(ExternalPackageShare.package_id).where(
                    ExternalPackageShare.grant_id == grant.id
                )
            )
        ).scalars().all()
    )
    ev_ids = list(
        (
            await session.execute(
                select(ExternalEvidenceShare.evidence_object_id).where(
                    ExternalEvidenceShare.grant_id == grant.id
                )
            )
        ).scalars().all()
    )

    packages: list[dict[str, Any]] = []
    if pkg_ids:
        rows = (
            await session.execute(
                select(AuthorizationPackage).where(AuthorizationPackage.id.in_(pkg_ids))
            )
        ).scalars().all()
        packages = [
            {"id": p.id, "label": p.label, "kind": p.kind,
             "readiness_pct": p.readiness_pct, "fact_count": p.fact_count,
             "created_at": p.created_at}
            for p in rows
        ]

    evidence: list[dict[str, Any]] = []
    if ev_ids:
        rows_e = (
            await session.execute(
                select(EvidenceObject).where(EvidenceObject.id.in_(ev_ids))
            )
        ).scalars().all()
        evidence = [
            {"id": e.id, "title": e.title, "control_id": e.control_id,
             "framework": e.framework, "status": e.status}
            for e in rows_e
        ]

    comments = (
        await session.execute(
            select(ExternalComment)
            .where(ExternalComment.grant_id == grant.id)
            .order_by(ExternalComment.id.asc())
        )
    ).scalars().all()

    return {
        "grant": {"id": grant.id, "kind": grant.kind, "label": grant.label,
                  "expires_at": grant.expires_at},
        "packages": packages,
        "evidence": evidence,
        "comments": [
            {"id": c.id, "target_type": c.target_type, "target_id": c.target_id,
             "author": c.author, "author_kind": c.author_kind, "body": c.body,
             "created_at": c.created_at}
            for c in comments
        ],
    }


async def record_access(
    session: AsyncSession,
    grant: ExternalAccessGrant,
    *,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: str | None = None,
) -> None:
    """Append one immutable portal audit event for a grant's access."""
    session.add(
        ExternalPortalAuditEvent(
            organization_id=grant.organization_id, grant_id=grant.id, action=action,
            target_type=target_type, target_id=target_id, detail=detail,
        )
    )
    await session.flush()


async def add_comment(
    session: AsyncSession,
    grant: ExternalAccessGrant,
    *,
    target_type: str,
    target_id: str,
    author: str | None,
    body: str,
    author_kind: str = "external",
) -> ExternalComment:
    """Post a comment on shared evidence / a finding / a package, and audit it."""
    await _clamp(session, grant)
    comment = ExternalComment(
        organization_id=grant.organization_id, grant_id=grant.id,
        target_type=target_type, target_id=target_id, author=author,
        author_kind=author_kind, body=body,
    )
    session.add(comment)
    await session.flush()
    await record_access(
        session, grant, action="comment", target_type=target_type, target_id=target_id
    )
    return comment
