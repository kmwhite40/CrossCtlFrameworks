"""Policy management API -- policies, versions, the template library, activation
and attestation.

Every route resolves the policy in the caller's organization first. Before
this, ``add_version`` and ``attest`` looked a row up by id alone, so a member of
one tenant could publish a version into, or attest to, another tenant's policy
(RLS was the only backstop), and ``attest`` recorded whatever ``user_id`` or
``attestor`` the body named. A policy is created as a draft and put in force
only through ``POST .../activate``, which with authentication on spends an
approval of that exact version (``/api/approvals/policy_version/{id}/...``).
"""

from __future__ import annotations

from datetime import date
from typing import Any, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import bus
from ...models import Organization, Policy, PolicyVersion
from ...policies import service
from ...policies.docx import to_docx
from ...policies.library import TEMPLATES
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/policies", tags=["policies"])


class PolicyIn(BaseModel):
    name: str
    description: str | None = None
    category: str | None = None
    owner_user_id: int | None = None
    status: str = "draft"
    review_frequency: str | None = None
    next_review_on: date | None = None
    linked_controls: list[str] = []


class VersionIn(BaseModel):
    version: str
    body: str | None = None
    uri: str | None = None
    effective_on: date | None = None


class AttestIn(BaseModel):
    #: Ignored when authentication is on: the attestor is the signed-in person.
    user_id: int | None = None
    attestor: str | None = None
    note: str | None = None


class FromTemplateIn(BaseModel):
    template_key: str
    name: str | None = None
    owner_user_id: int | None = None
    parameters: dict[str, Any] = {}


class ParametersIn(BaseModel):
    parameters: dict[str, Any]


def _out(p: Policy) -> dict[str, Any]:
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "category": p.category,
        "owner_user_id": p.owner_user_id,
        "status": p.status,
        "review_frequency": p.review_frequency,
        "next_review_on": p.next_review_on,
        "linked_controls": list(p.linked_controls or []),
        "template_key": p.template_key,
        "parameters": dict(p.parameters or {}),
        "active_version_id": p.active_version_id,
    }


def version_out(v: PolicyVersion) -> dict[str, Any]:
    return {
        "id": v.id, "version": v.version, "effective_on": v.effective_on, "uri": v.uri,
        "body_sha256": v.body_sha256, "unresolved_parameters": list(v.unresolved_parameters or []),
        "created_by": v.created_by, "created_at": v.created_at,
    }


async def require_policy(session: AsyncSession, policy_id: int, principal: Principal) -> Policy:
    stmt = select(Policy).where(Policy.id == policy_id)
    if principal.org_id is not None:
        stmt = stmt.where(Policy.organization_id == principal.org_id)
    p = (await session.execute(stmt)).scalar_one_or_none()
    if p is None:
        raise HTTPException(404, "policy not found")
    return p


async def require_version(
    session: AsyncSession, version_id: int, principal: Principal
) -> tuple[Policy, PolicyVersion]:
    v = await session.get(PolicyVersion, version_id)
    if v is None:
        raise HTTPException(404, "policy version not found")
    try:
        p = await require_policy(session, v.policy_id, principal)
    except HTTPException as exc:
        raise HTTPException(404, "policy version not found") from exc
    return p, v


def _raise(e: service.PolicyError) -> NoReturn:
    raise HTTPException(e.status, str(e)) from e


@router.get("")
async def list_policies(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(Policy).order_by(Policy.name)
    if principal.org_id is not None:
        stmt = stmt.where(Policy.organization_id == principal.org_id)
    return [_out(p) for p in (await session.execute(stmt)).scalars().all()]


@router.get("/templates")
async def list_templates(_: Principal = Depends(get_principal)) -> list[dict[str, Any]]:
    return [
        {
            "key": t.key, "title": t.title, "kind": t.kind, "family": t.family,
            "summary": t.summary, "controls": list(t.controls),
            "requirements_171": list(t.requirements_171),
            "parameters": [{"key": p.key, "label": p.label, "hint": p.hint} for p in t.parameters],
            "review_frequency": t.review_frequency, "provenance": t.provenance,
        }
        for t in TEMPLATES
    ]


@router.post("", status_code=201)
async def create_policy(
    body: PolicyIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    if body.status != "draft":
        # A policy enters force through an approved activation, never by
        # naming a status at creation.
        raise HTTPException(409, "a new policy is a draft; put a version in force with activate")
    p = Policy(organization_id=principal.org_id, **body.model_dump())
    session.add(p)
    await session.flush()
    await bus.emit(
        session,
        verb="created",
        entity_type="policy",
        entity_id=p.id,
        summary=f"Policy created: {p.name}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return _out(p)


@router.post("/from-template", status_code=201)
async def create_from_template(
    body: FromTemplateIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    try:
        p, v = await service.create_from_template(
            session, org_id=principal.org_id, template_key=body.template_key, name=body.name,
            parameters=body.parameters, owner_user_id=body.owner_user_id, principal=principal,
        )
    except service.PolicyError as e:
        _raise(e)
    await session.commit()
    return {**_out(p), "version": version_out(v)}


@router.get("/{policy_id}")
async def get_policy(
    policy_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = await require_policy(session, policy_id, principal)
    versions = (
        (
            await session.execute(
                select(PolicyVersion)
                .where(PolicyVersion.policy_id == policy_id)
                .order_by(PolicyVersion.id.desc())
            )
        )
        .scalars()
        .all()
    )
    return {**_out(p), "versions": [version_out(v) for v in versions]}


@router.put("/{policy_id}/parameters")
async def set_parameters(
    policy_id: int,
    body: ParametersIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = await require_policy(session, policy_id, principal)
    try:
        v = await service.set_parameters(session, p, body.parameters, principal)
    except service.PolicyError as e:
        _raise(e)
    await session.commit()
    return {**_out(p), "version": version_out(v)}


@router.post("/{policy_id}/versions", status_code=201)
async def add_version(
    policy_id: int,
    body: VersionIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = await require_policy(session, policy_id, principal)
    v = PolicyVersion(
        policy_id=p.id, **body.model_dump(), body_sha256=service.sha256(body.body),
        created_by=principal.email,
    )
    session.add(v)
    await session.flush()
    await bus.emit(
        session,
        verb="updated",
        entity_type="policy",
        entity_id=p.id,
        summary=f"Policy '{p.name}' version {v.version} added",
        org_id=p.organization_id,
        actor=principal.email,
    )
    await session.commit()
    return {"id": v.id, "version": v.version}


@router.post("/{policy_id}/versions/{version_id}/activate")
async def activate(
    policy_id: int,
    version_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = await require_policy(session, policy_id, principal)
    _, v = await require_version(session, version_id, principal)
    try:
        await service.activate(session, policy=p, version=v, principal=principal)
    except service.PolicyError as e:
        _raise(e)
    await session.commit()
    return _out(p)


@router.post("/{policy_id}/retire")
async def retire(
    policy_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = await require_policy(session, policy_id, principal)
    try:
        await service.retire(session, policy=p, principal=principal)
    except service.PolicyError as e:
        _raise(e)
    await session.commit()
    return _out(p)


@router.get("/{policy_id}/versions/{version_id}/document")
async def document(
    policy_id: int,
    version_id: int,
    fmt: str = "docx",
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> Response:
    p, v = await require_version(session, version_id, principal)
    if p.id != policy_id:
        raise HTTPException(404, "policy version not found")
    safe = "".join(c if c.isalnum() else "_" for c in p.name)[:60] + f"_v{v.version}"
    if fmt == "md":
        return Response(
            v.body or "", media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{safe}.md"'},
        )
    org = None
    if p.organization_id is not None:
        org = (
            await session.execute(
                select(Organization.name).where(Organization.id == p.organization_id)
            )
        ).scalar_one_or_none()
    return Response(
        to_docx(p, v, organization=org),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{safe}.docx"'},
    )


@router.post("/versions/{version_id}/attest", status_code=201)
async def attest(
    version_id: int,
    body: AttestIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p, v = await require_version(session, version_id, principal)
    try:
        a = await service.attest(
            session, policy=p, version=v, principal=principal,
            attestor=body.attestor, note=body.note,
        )
    except service.PolicyError as e:
        _raise(e)
    await session.commit()
    return {"id": a.id, "attested_at": a.attested_at, "attestor": a.attestor}
