"""Server-rendered policy documents: the register, the template library, and
one policy's versions, parameters, review, activation and attestations.

Concord had a policy API and no page for it (only a count on /governance).
Every form here calls ``ccf.policies.service`` or ``governance.approvals`` --
the same rules the API enforces -- and a refusal redirects back with the reason.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import approvals
from ...models import PolicyAttestation, PolicyVersion, User
from ...policies import service
from ...policies.library import BY_KEY
from ..auth_deps import get_principal
from ..deps import get_session
from .policies import require_policy, require_version
from .ui import templates

router = APIRouter(include_in_schema=False)


def _back(path: str, error: str | None = None) -> RedirectResponse:
    return RedirectResponse(
        path + (f"?error={quote(error)}" if error else ""), status_code=303
    )


@router.post("/policies/from-template")
async def policies_from_template(
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> RedirectResponse:
    form = await request.form()
    key = str(form.get("template_key") or "")
    try:
        p, _ = await service.create_from_template(
            session, org_id=principal.org_id, template_key=key,
            name=str(form.get("name") or "") or None, parameters={},
            owner_user_id=None, principal=principal,
        )
    except service.PolicyError as e:
        return _back("/policies", str(e))
    await session.commit()
    return _back(f"/policies/{p.id}")


@router.get("/policies/{policy_id}", response_class=HTMLResponse)
async def policy_page(
    policy_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> HTMLResponse:
    p = await require_policy(session, policy_id, principal)
    versions = list(
        (
            await session.execute(
                select(PolicyVersion)
                .where(PolicyVersion.policy_id == p.id)
                .order_by(PolicyVersion.id.desc())
            )
        ).scalars()
    )
    latest = versions[0] if versions else None
    states = await approvals.entity_states(session, "policy_version", [v.id for v in versions])
    attest_counts: dict[int, int] = dict(
        (
            await session.execute(
                select(PolicyAttestation.policy_version_id, func.count(PolicyAttestation.id))
                .where(PolicyAttestation.policy_version_id.in_([v.id for v in versions] or [0]))
                .group_by(PolicyAttestation.policy_version_id)
            )
        ).tuples().all()
    )
    mine = False
    if p.active_version_id is not None and principal.user_id is not None:
        mine = (
            await session.execute(
                select(PolicyAttestation.id).where(
                    PolicyAttestation.policy_version_id == p.active_version_id,
                    PolicyAttestation.user_id == principal.user_id,
                )
            )
        ).first() is not None
    owners = list(
        (
            await session.execute(
                select(User)
                .where(User.organization_id == p.organization_id, User.active.is_(True))
                .order_by(User.email)
            )
        ).scalars()
    ) if p.organization_id is not None else []
    template = BY_KEY.get(p.template_key or "")
    params: list[dict[str, Any]] = [
        {"key": t.key, "label": t.label, "hint": t.hint,
         "value": (p.parameters or {}).get(t.key, "")}
        for t in (template.parameters if template else ())
    ]
    # The context tokens Concord could not derive (no organization on an
    # org-less policy, no owner): offered as fields rather than left stuck.
    unresolved = set(latest.unresolved_parameters or []) if latest is not None else set()
    for token, label in (("organization", "Organization name"),
                         ("policy_owner", "Document owner (name)")):
        if token in unresolved or token in (p.parameters or {}):
            params.insert(0, {"key": token, "label": label, "hint": "",
                              "value": (p.parameters or {}).get(token, "")})
    return templates.TemplateResponse(
        request,
        "policy_detail.html",
        {
            "active": "policies", "p": p, "versions": versions, "latest": latest,
            "states": states, "attest_counts": attest_counts, "attested": mine,
            "template": template, "params": params, "owners": owners,
            "me": principal.email, "error": request.query_params.get("error"),
        },
    )


@router.post("/policies/{policy_id}/parameters")
async def policy_parameters(
    policy_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> RedirectResponse:
    p = await require_policy(session, policy_id, principal)
    form = await request.form()
    owner = str(form.get("owner_user_id") or "").strip()
    if owner:
        u = await session.get(User, int(owner))
        if u is None or u.organization_id != p.organization_id:
            return _back(f"/policies/{policy_id}", "No such owner in this organization.")
        p.owner_user_id = u.id
    values = {k[6:]: v for k, v in form.items() if k.startswith("param:")}
    try:
        await service.set_parameters(session, p, values, principal)
    except service.PolicyError as e:
        return _back(f"/policies/{policy_id}", str(e))
    await session.commit()
    return _back(f"/policies/{policy_id}")


@router.post("/policies/{policy_id}/versions/{version_id}/{action}")
async def policy_version_action(  # noqa: PLR0917 -- FastAPI binds these by keyword
    policy_id: int,
    version_id: int,
    action: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> RedirectResponse:
    p = await require_policy(session, policy_id, principal)
    _, v = await require_version(session, version_id, principal)
    if v.policy_id != p.id:
        raise HTTPException(404, "policy version not found")
    form = await request.form()
    note = str(form.get("note") or "").strip() or None
    back = f"/policies/{policy_id}"
    try:
        if action == "submit":
            await approvals.submit(
                session, entity_type="policy_version", entity_id=str(v.id),
                actor=principal.email, org_id=principal.org_id,
            )
        elif action in ("approve", "reject"):
            await approvals.decide(
                session, entity_type="policy_version", entity_id=str(v.id),
                approve=action == "approve", actor=principal.email, role=principal.role,
                note=note, org_id=principal.org_id, user_id=principal.user_id,
            )
        elif action == "activate":
            await service.activate(session, policy=p, version=v, principal=principal)
        elif action == "attest":
            await service.attest(session, policy=p, version=v, principal=principal, note=note)
        else:
            raise HTTPException(404, "unknown action")
    except approvals.WorkflowError as e:
        return _back(back, str(e))
    except service.PolicyError as e:
        return _back(back, str(e))
    await session.commit()
    return _back(back)


@router.post("/policies/{policy_id}/retire")
async def policy_retire(
    policy_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> RedirectResponse:
    p = await require_policy(session, policy_id, principal)
    try:
        await service.retire(session, policy=p, principal=principal)
    except service.PolicyError as e:
        return _back(f"/policies/{policy_id}", str(e))
    await session.commit()
    return _back(f"/policies/{policy_id}")
