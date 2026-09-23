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
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import hash_token
from ..constants import EXTERNAL_PRINCIPAL_KINDS
from ..db import set_session_tenant
from ..models import Organization, System, User
from ..models_evidence import EvidenceObject
from ..models_packages import AuthorizationPackage
from ..models_portal import (
    AssessmentEngagement,
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


async def _audit(
    session: AsyncSession, *, organization_id: int | None, **kw: Any
) -> None:
    """Append a tenant-scoped audit event (see :func:`ccf.api.audit.record_event`).

    ``organization_id`` is required with no default, deliberately: NULL means
    "platform-wide, visible to every tenant" under migration 0044's
    ``tenant_isolation`` policy, so a call site that forgets it would publish
    this event to every organization rather than merely leave it unscoped.
    """
    from ..api.audit import record_event  # noqa: PLC0415 — avoid import cycle

    await record_event(session, organization_id=organization_id, **kw)


async def _clamp(session: AsyncSession, grant: ExternalAccessGrant) -> None:
    """Bind the session's RLS tenant to the grant's org before touching its data."""
    await set_session_tenant(session, grant.organization_id)


def _require_kind(kind: str) -> str:
    """Enforce :data:`~ccf.constants.EXTERNAL_PRINCIPAL_KINDS` on write.

    The columns are plain ``String(16)`` and stay that way (see the constant's
    own note on why this is not a Postgres enum), so this function is the only
    thing standing between a typo and a stored value that looks like a real
    member. Every path that writes a ``kind`` -- principal or grant -- goes
    through it; the route turns the ``ValueError`` into a 422.
    """
    if kind not in EXTERNAL_PRINCIPAL_KINDS:
        raise ValueError(
            f"unknown external principal kind {kind!r}; "
            f"expected one of {', '.join(EXTERNAL_PRINCIPAL_KINDS)}"
        )
    return kind


async def create_principal(
    session: AsyncSession,
    *,
    org_id: int,
    name: str,
    kind: str = "customer",
    email: str | None = None,
    organization_name: str | None = None,
) -> ExternalPrincipal:
    """Create an external principal without issuing it a grant.

    ``create_grant`` creates a principal inline, which is enough for a one-off
    customer share but not for an assessment: an engagement names the assessor
    principal, and the grants come after it. So the principal has to be
    creatable on its own.
    """
    principal = ExternalPrincipal(
        organization_id=org_id,
        kind=_require_kind(kind),
        name=name,
        email=email,
        organization_name=organization_name,
    )
    session.add(principal)
    await session.flush()
    return principal


# --- admin: engagements ----------------------------------------------------


def _domain(email: str | None) -> str | None:
    """The domain part of an email address, lower-cased, or None."""
    if not email or "@" not in email:
        return None
    return email.rsplit("@", 1)[1].strip().lower() or None


async def _independence_note(
    session: AsyncSession, org_id: int, principal: ExternalPrincipal
) -> str | None:
    """What the platform OBSERVED about this assessor's relationship to the CSP.

    FedRAMP requires the 3PAO be independent of the CSP. Concord cannot verify
    that — independence is a matter of ownership, contracts and staffing, and no
    field here records any of it. The one signal available is whether the
    assessor's email domain, or its ``organization_name``, matches the tenant's
    own. That is weak evidence in both directions: a legitimate assessor may use
    a shared mail domain, and a genuinely conflicted one may not.

    So this **records and never blocks** (spec §5, following the SCN rule:
    check, name, and never refuse). Refusing on a domain match would make a real
    engagement unrecordable on evidence that does not support the conclusion.

    The text is phrased as an observation for that reason, and must stay that
    way — it is a string match, not a finding, a warning, or an opinion about
    the firm. Returns None when nothing matched.
    """
    observations: list[str] = []

    assessor_domain = _domain(principal.email)
    if assessor_domain is not None:
        tenant_domains = {
            d
            for d in (
                _domain(e)
                for e in (
                    await session.execute(select(User.email).where(User.organization_id == org_id))
                ).scalars().all()
            )
            if d is not None
        }
        if assessor_domain in tenant_domains:
            observations.append(
                f"the assessor's email domain ({assessor_domain}) also appears on "
                "user accounts in this organization"
            )

    org = await session.get(Organization, org_id)
    stated = (principal.organization_name or "").strip()
    if org is not None and stated and stated.casefold() == (org.name or "").strip().casefold():
        observations.append(
            f"the assessor's stated organization name matches this organization's "
            f"name ({org.name})"
        )

    if not observations:
        return None
    return (
        "Observed at engagement creation: "
        + "; ".join(observations)
        + ". Recorded as an observation only: Concord compares strings and does "
        "not determine independence."
    )


async def create_engagement(
    session: AsyncSession,
    *,
    org_id: int,
    system_id: int,
    assessor_principal_id: int,
    period_from: datetime,
    period_to: datetime,
    authorized_by: str | None = None,
    actor: str | None = None,
) -> AssessmentEngagement:
    """Record that one assessor firm assesses one system over one period.

    The principal must exist, belong to this tenant, and be of kind
    ``assessor``: an engagement is the one place the vocabulary of §2 carries a
    rule, and a customer or vendor principal here would be an assessment
    credential issued to a party that is not an assessor.

    The system must belong to this tenant too. Both ids the caller supplies are
    checked against ``org_id`` here, for the same reason: the row is a federal
    assessment record, and either id from another tenant makes it a false one.
    """
    principal = await session.get(ExternalPrincipal, assessor_principal_id)
    if principal is None or principal.organization_id != org_id:
        raise ValueError(
            f"external principal {assessor_principal_id} not found in organization {org_id}"
        )
    if principal.kind != "assessor":
        raise ValueError(
            f"external principal {assessor_principal_id} is kind {principal.kind!r}; "
            "an assessment engagement requires kind 'assessor'"
        )

    # ``system_id`` is written, never read, by the rest of this function, so a
    # foreign one reaches the row untouched: RLS refuses reads, and there was
    # no read to refuse. The row would then assert that this tenant's assessor
    # assesses a system this tenant does not own, and §6 resolves the grant's
    # packages through it. Checked here as the same org-consistency invariant
    # ``assessor_principal_id`` above and ``engagement_id`` in ``create_grant``
    # already carry; the route additionally applies the canonical
    # ``require_system_in_scope`` (404 + soft-delete) before calling in.
    system = await session.get(System, system_id)
    if system is None or system.organization_id != org_id:
        raise ValueError(f"system {system_id} not found in organization {org_id}")

    engagement = AssessmentEngagement(
        organization_id=org_id,
        system_id=system_id,
        assessor_principal_id=assessor_principal_id,
        period_from=period_from,
        period_to=period_to,
        authorized_by=authorized_by,
        independence_note=await _independence_note(session, org_id, principal),
    )
    session.add(engagement)
    await session.flush()
    await _audit(
        session, organization_id=org_id,
        actor=actor or "system", action="create",
        entity_type="assessment_engagement", entity_id=str(engagement.id),
        diff={"org": org_id, "system": system_id, "principal": assessor_principal_id,
              "period_from": period_from.isoformat(), "period_to": period_to.isoformat()},
    )
    await session.flush()
    return engagement


async def list_engagements(
    session: AsyncSession, *, org_id: int
) -> list[AssessmentEngagement]:
    return list(
        (
            await session.execute(
                select(AssessmentEngagement)
                .where(AssessmentEngagement.organization_id == org_id)
                .order_by(AssessmentEngagement.id.desc())
            )
        ).scalars().all()
    )


async def revoke_engagement(
    session: AsyncSession, engagement_id: int, *, actor: str | None = None
) -> bool:
    """End the relationship, and with it every credential issued under it.

    One action ends an engagement. A token rotation or a second assessor from
    the same firm means several live grants hang off one engagement, and ending
    the relationship while any of them still resolves would leave access with no
    remaining reason behind it (spec §4 rule 3).

    ``_valid`` independently rejects grants under a revoked engagement (rule 4),
    so this loop is not the only thing standing between a revoked engagement and
    a working token — but a revoked grant is what an operator sees in the admin
    list, so the rows say what is true.
    """
    engagement = await session.get(AssessmentEngagement, engagement_id)
    if engagement is None:
        return False
    engagement.revoked_at = _now()
    grant_ids = list(
        (
            await session.execute(
                select(ExternalAccessGrant.id).where(
                    ExternalAccessGrant.engagement_id == engagement_id,
                    ExternalAccessGrant.revoked.is_(False),
                )
            )
        ).scalars().all()
    )
    for gid in grant_ids:
        await revoke_grant(session, gid, actor=actor)
    await _audit(
        session, organization_id=engagement.organization_id,
        actor=actor or "system", action="delete",
        entity_type="assessment_engagement", entity_id=str(engagement_id),
        diff={"revoked_at": engagement.revoked_at.isoformat(), "grants_revoked": len(grant_ids)},
    )
    await session.flush()
    return True


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
    engagement_id: int | None = None,
    principal_id: int | None = None,
    actor: str | None = None,
) -> ExternalAccessGrant:
    """Issue a scoped, expiring bearer-token grant to an external principal.

    Pass ``engagement_id`` to issue an assessment credential. Three rules then
    apply at issuance (spec §4); ``_valid`` applies the fourth at resolution.

    1. ``ttl_days=None`` is **refused**, not defaulted. For a customer share a
       never-expiring grant may be deliberate; for an assessment credential it
       is access with no remaining reason once the engagement ends, and
       silently substituting a TTL would put an expiry nobody chose on a
       federal assessment credential.
    2. ``expires_at`` is **capped at the engagement's ``period_to``**, and the
       caller is told (``grant.expiry_capped``).
    3. ``package_ids`` is refused: an engagement-backed grant's packages
       resolve through the engagement's ``system_id`` (§6), so a hand-picked
       list would be silently ignored. Evidence keeps its explicit list —
       evidence objects are not system-scoped the same way, and narrowing is
       the safe direction.

    ``principal_id`` reuses an existing principal (the one the engagement
    names) instead of creating a new one; without it a second grant under the
    same engagement would invent a second identity for the same firm.
    """
    _require_kind(kind)

    engagement: AssessmentEngagement | None = None
    if engagement_id is not None:
        engagement = await session.get(AssessmentEngagement, engagement_id)
        if engagement is None or engagement.organization_id != org_id:
            raise ValueError(
                f"assessment engagement {engagement_id} not found in organization {org_id}"
            )
        if ttl_days is None:
            raise ValueError(
                "an engagement-backed grant must be given a ttl_days: an assessment "
                "credential that never expires outlives the engagement it belongs to, "
                "and Concord will not choose an expiry for one on your behalf"
            )
        if package_ids:
            raise ValueError(
                "an engagement-backed grant does not take package_ids: its packages "
                "resolve through the engagement's system_id, so a hand-picked list "
                "would be silently ignored"
            )

    if principal_id is None and not principal_name:
        raise ValueError("a grant needs either principal_id or principal_name")
    if principal_id is not None:
        existing = await session.get(ExternalPrincipal, principal_id)
        if existing is None or existing.organization_id != org_id:
            raise ValueError(
                f"external principal {principal_id} not found in organization {org_id}"
            )
        principal = existing
    else:
        principal = ExternalPrincipal(
            organization_id=org_id, kind=kind, name=principal_name,
            email=email, organization_name=organization_name,
        )
        session.add(principal)
        await session.flush()

    pkg_ids = [int(p) for p in package_ids]
    ev_ids = [int(e) for e in evidence_ids]

    expires_at = (_now() + timedelta(days=ttl_days)) if ttl_days else None
    capped = False
    if engagement is not None and expires_at is not None and expires_at > engagement.period_to:
        expires_at = engagement.period_to
        capped = True

    scope: dict[str, Any] = {"package_ids": pkg_ids, "evidence_ids": ev_ids}
    if engagement is not None:
        scope["system_id"] = engagement.system_id
    grant = ExternalAccessGrant(
        organization_id=org_id,
        principal_id=principal.id,
        kind=kind,
        engagement_id=engagement_id,
        token=_gen_token(),
        label=label,
        expires_at=expires_at,
        revoked=False,
        scope=scope,
    )
    grant.expiry_capped = capped
    session.add(grant)
    await session.flush()

    for pid in pkg_ids:
        session.add(ExternalPackageShare(grant_id=grant.id, package_id=pid))
    for eid in ev_ids:
        session.add(ExternalEvidenceShare(grant_id=grant.id, evidence_object_id=eid))

    detail = f"{len(pkg_ids)}pkg/{len(ev_ids)}ev"
    if capped and expires_at is not None:
        detail += f" expiry capped at engagement period_to {expires_at.isoformat()}"
    await record_access(session, grant, action="issued", detail=detail)
    await _audit(
        session, organization_id=org_id,
        actor=actor or "system", action="create", entity_type="external_grant",
        entity_id=str(grant.id),
        diff={"org": org_id, "kind": kind, "packages": pkg_ids, "evidence": ev_ids,
              "engagement": engagement_id, "expiry_capped": capped},
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
        session, organization_id=grant.organization_id,
        actor=actor or "system", action="delete", entity_type="external_grant",
        entity_id=str(grant.id), diff={"revoked": True},
    )
    await session.flush()
    return True


# --- portal: token resolution + scoped contents ----------------------------


def grant_status(grant: ExternalAccessGrant, current_engagement_ids: set[int]) -> str:
    """Why a grant does or does not resolve, in one word.

    **The single rule.** ``_valid`` decides access with it and the portal-admin
    page labels rows with it, so the two cannot disagree. They did: the admin
    page classified a grant from its own row alone, so one whose *engagement*
    had ended displayed as ``active`` while resolving to nothing -- an operator
    surface asserting live access that does not exist.

    ``current_engagement_ids`` is passed in rather than looked up so this stays
    pure and a caller rendering a list can resolve every engagement in one
    query instead of one per row.
    """
    if grant.revoked:
        return "revoked"
    if grant.expires_at is not None and grant.expires_at < _now():
        return "expired"
    if grant.engagement_id is not None and grant.engagement_id not in current_engagement_ids:
        return "engagement ended"
    return "active"


async def current_engagement_ids(session: AsyncSession, ids: Iterable[int]) -> set[int]:
    """Which of ``ids`` still authorize anything -- one query, for list rendering."""
    wanted = {i for i in ids if i is not None}
    if not wanted:
        return set()
    rows = (
        await session.execute(
            select(AssessmentEngagement.id).where(
                AssessmentEngagement.id.in_(wanted),
                AssessmentEngagement.revoked_at.is_(None),
                AssessmentEngagement.period_to >= _now(),
            )
        )
    ).scalars().all()
    return set(rows)


async def _valid(
    session: AsyncSession, grant: ExternalAccessGrant | None
) -> ExternalAccessGrant | None:
    """Shared revoked/expired check used by every grant-lookup path.

    The engagement check (spec §4 rule 4) is deliberately here, at *resolution*,
    and not only at issuance. Rules 1-3 are enforced when a grant is created, so
    they protect only the rows this code wrote: a row written before this change,
    or by some future path that forgets them, would otherwise still resolve. The
    engagement is the authority; the token merely carries it, so a grant whose
    engagement is revoked or elapsed must stop resolving **regardless of the
    grant's own expiry**.

    Delegates the classification to :func:`grant_status` so the rule has one
    home; anything that reports a grant's state reports what this enforces.
    """
    if grant is None:
        return None
    current = (
        await current_engagement_ids(session, [grant.engagement_id])
        if grant.engagement_id is not None
        else set()
    )
    return grant if grant_status(grant, current) == "active" else None


async def resolve_grant(session: AsyncSession, token: str) -> ExternalAccessGrant | None:
    """Return the grant for a valid token, or None if unknown / revoked / expired.

    Pure validation — no side effects; the read/write paths clamp the tenant.
    """
    if not token:
        return None
    grant = (
        await session.execute(
            select(ExternalAccessGrant).where(
                ExternalAccessGrant.token_hash == hash_token(token)
            )
        )
    ).scalar_one_or_none()
    return await _valid(session, grant)


async def resolve_grant_by_id(session: AsyncSession, grant_id: int) -> ExternalAccessGrant | None:
    """Re-validate a grant by id, or None if unknown / revoked / expired.

    Used to authenticate a portal request off a signed session cookie (which
    carries only the grant id, not the bearer token): the cookie's signature
    proves it was issued by us, but *not* that the grant is still good, so
    every cookie-authenticated request re-checks revocation/expiry here
    against the current DB row rather than trusting anything baked into the
    cookie itself.
    """
    grant = await session.get(ExternalAccessGrant, grant_id)
    return await _valid(session, grant)


async def _engagement_package_ids(
    session: AsyncSession, grant: ExternalAccessGrant, engagement_id: int
) -> list[int]:
    """The packages an engagement-backed grant can see: this system's, this tenant's.

    Scope follows the system (spec §6) rather than a hand-picked share list.
    That list permitted two silent failures: an operator who built a package
    mid-assessment had to remember to re-share it, and a package belonging to a
    *different system in the same tenant* could be added to an assessor's grant
    by mistake — a cross-system disclosure the portal's tenant isolation cannot
    catch, because both systems are in the same tenant. The ``system_id`` filter
    below is what makes the second unrepresentable; drop it and an assessor sees
    every package their tenant owns.
    """
    engagement = await session.get(AssessmentEngagement, engagement_id)
    if engagement is None:
        return []
    return list(
        (
            await session.execute(
                select(AuthorizationPackage.id).where(
                    AuthorizationPackage.organization_id == grant.organization_id,
                    AuthorizationPackage.system_id == engagement.system_id,
                )
            )
        ).scalars().all()
    )


async def grant_contents(session: AsyncSession, grant: ExternalAccessGrant) -> dict[str, Any]:
    """The packages, evidence, and comment thread a grant can see.

    For an ordinary grant that is exactly what was shared into it. For an
    engagement-backed one the packages resolve through the engagement's system
    (§6) — which means an assessor sees packages created *after* the engagement
    began. That widening is deliberate: an assessment is of a system, not of a
    snapshot, and ``period_to`` is what bounds it.
    """
    await _clamp(session, grant)

    if grant.engagement_id is not None:
        pkg_ids = await _engagement_package_ids(session, grant, grant.engagement_id)
    else:
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
                  "expires_at": grant.expires_at, "engagement_id": grant.engagement_id},
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
