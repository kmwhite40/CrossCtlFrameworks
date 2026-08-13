"""Organization AI settings — admin surface over the AI credential vault + gateway.

Two surfaces, mirroring the ``portal`` module's pattern:

* ``/api/ai-settings`` — admin-gated (``require_role("admin")``) JSON API, scoped to
  the caller's organization. Every mutation goes through ``ccf.ai.gateway``
  (``set_credential`` / ``validate_credential`` / ``masked_view``) — this module never
  touches a provider adapter or the cipher directly, and never returns
  ``encrypted_credential``.
* ``/admin/ai-settings`` — a minimal server-rendered admin page (list + add/test/
  rotate/revoke forms), consistent with the existing HTMX/Alpine admin UI style.

Tenant isolation is structural, not filtered after the fact: the organization id
always comes from the authenticated principal (never from client input), and
``gateway.set_credential`` upserts on ``(organization_id, provider)`` — so one org's
admin can never see or mutate another org's row.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...ai import gateway
from ...ai.cipher import CredentialStorageError
from ...auth import Principal
from ...models_ai_actions import AiProviderConfig
from ..auth_deps import require_role
from ..deps import get_session
from .ui import templates  # shared Jinja env (carries `settings`/`asset_v` globals base.html needs)

router = APIRouter(prefix="/api/ai-settings", tags=["ai-settings"])
ui_router = APIRouter(tags=["ai-settings"])

_SUPPORTED_PROVIDERS = ("anthropic", "openai")


def _org_id(principal: Principal) -> int:
    """The org to scope this request to — always the principal's, never client input."""
    if principal.org_id is None:
        raise HTTPException(400, "organization context required")
    return principal.org_id


async def _list_configs(session: AsyncSession, org_id: int) -> list[AiProviderConfig]:
    stmt = (
        select(AiProviderConfig)
        .where(AiProviderConfig.organization_id == org_id)
        .order_by(AiProviderConfig.provider)
    )
    return list((await session.execute(stmt)).scalars().all())


# --- JSON API ----------------------------------------------------------------


class ProviderUpsertIn(BaseModel):
    api_key: str | None = None
    enabled: bool | None = None
    default_model: str | None = None
    allowed_models: list[str] | None = None


class ProviderRotateIn(BaseModel):
    api_key: str


@router.get("/providers")
async def list_providers(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> list[dict[str, Any]]:
    org_id = _org_id(principal)
    return [gateway.masked_view(c) for c in await _list_configs(session, org_id)]


@router.post("/providers/{provider}")
async def upsert_provider(
    provider: str,
    body: ProviderUpsertIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    org_id = _org_id(principal)
    try:
        cfg = await gateway.set_credential(
            session, org_id, provider,
            api_key=body.api_key, enabled=body.enabled,
            default_model=body.default_model, allowed_models=body.allowed_models,
            actor=principal.email,
        )
    except CredentialStorageError as exc:
        raise HTTPException(400, str(exc)) from exc
    await session.commit()
    return gateway.masked_view(cfg)


@router.post("/providers/{provider}/rotate")
async def rotate_provider(
    provider: str,
    body: ProviderRotateIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    org_id = _org_id(principal)
    try:
        cfg = await gateway.set_credential(
            session, org_id, provider, api_key=body.api_key, actor=principal.email
        )
    except CredentialStorageError as exc:
        raise HTTPException(400, str(exc)) from exc
    await session.commit()
    return gateway.masked_view(cfg)


@router.post("/providers/{provider}/test")
async def test_provider(
    provider: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    org_id = _org_id(principal)
    try:
        valid = await gateway.validate_credential(session, org_id, provider)
    except gateway.GatewayError as exc:
        raise HTTPException(400, str(exc)) from exc
    await session.commit()
    return {"provider": provider, "valid": valid}


@router.post("/providers/{provider}/revoke")
async def revoke_provider(
    provider: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    org_id = _org_id(principal)
    cfg = await gateway.set_credential(
        session, org_id, provider, enabled=False, actor=principal.email
    )
    await session.commit()
    return gateway.masked_view(cfg)


# --- UI (server-rendered admin page) ------------------------------------------


@ui_router.get("/admin/ai-settings", response_class=HTMLResponse)
async def ai_settings_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> HTMLResponse:
    org_id = _org_id(principal)
    configs = [gateway.masked_view(c) for c in await _list_configs(session, org_id)]
    return templates.TemplateResponse(
        request, "ai_settings.html",
        {"active": "ai_settings", "configs": configs, "providers": _SUPPORTED_PROVIDERS,
         "error": request.query_params.get("error")},
    )


@ui_router.post("/admin/ai-settings/providers")
async def ai_settings_add(
    *,
    provider: str = Form(...),
    api_key: str = Form(""),
    default_model: str = Form(""),
    enabled: bool = Form(False),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    org_id = _org_id(principal)
    try:
        await gateway.set_credential(
            session, org_id, provider,
            api_key=api_key or None, enabled=enabled,
            default_model=default_model or None, actor=principal.email,
        )
    except CredentialStorageError as exc:
        await session.rollback()
        return RedirectResponse(f"/admin/ai-settings?error={exc}", status_code=303)
    await session.commit()
    return RedirectResponse("/admin/ai-settings", status_code=303)


@ui_router.post("/admin/ai-settings/providers/{provider}/rotate")
async def ai_settings_rotate(
    provider: str,
    api_key: str = Form(...),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    org_id = _org_id(principal)
    try:
        await gateway.set_credential(
            session, org_id, provider, api_key=api_key, actor=principal.email
        )
    except CredentialStorageError as exc:
        await session.rollback()
        return RedirectResponse(f"/admin/ai-settings?error={exc}", status_code=303)
    await session.commit()
    return RedirectResponse("/admin/ai-settings", status_code=303)


@ui_router.post("/admin/ai-settings/providers/{provider}/test")
async def ai_settings_test(
    provider: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    org_id = _org_id(principal)
    try:
        valid = await gateway.validate_credential(session, org_id, provider)
    except gateway.GatewayError as exc:
        await session.rollback()
        return RedirectResponse(f"/admin/ai-settings?error={exc}", status_code=303)
    await session.commit()
    status = "valid" if valid else "invalid"
    return RedirectResponse(f"/admin/ai-settings?error=test:{status}", status_code=303)


@ui_router.post("/admin/ai-settings/providers/{provider}/revoke")
async def ai_settings_revoke(
    provider: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    org_id = _org_id(principal)
    await gateway.set_credential(session, org_id, provider, enabled=False, actor=principal.email)
    await session.commit()
    return RedirectResponse("/admin/ai-settings", status_code=303)
