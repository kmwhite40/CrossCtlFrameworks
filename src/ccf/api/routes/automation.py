"""Profile-driven automation API — intake questionnaire, derivation, coverage,
and an uploadable framework-controls catalog.

The questionnaire is the simplistic front door: answer it and the app creates the
system, saves the profile, derives applicable controls + inheritance (from the
cloud platform AND every linked vendor), seeds SPRS state, and opens POA&M
placeholders for the gaps — one call.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import automation
from ...models import Framework, FrameworkControl, Organization, System, SystemProfile
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["automation"])


class ProfileIn(BaseModel):
    environment_type: str | None = None
    cloud_platform: str | None = None
    tenant_ref: str | None = None
    identity_model: str | None = None
    connectivity: str | None = None
    cui_present: bool = True
    workloads: list[str] = []
    endpoint_scope: list[str] = []
    data_types: list[str] = []
    inherited_sources: list[str] = []
    frameworks: list[str] = []


class IntakeIn(ProfileIn):
    system_name: str
    organization_id: int | None = None
    generate_ssp: bool = True


async def _resolve_org(session: AsyncSession, principal: Principal, org_id: int | None) -> int:
    if principal.org_id is not None:
        return principal.org_id
    if org_id is not None:
        return org_id
    latest = (
        await session.execute(select(Organization).order_by(Organization.id.desc()).limit(1))
    ).scalar_one_or_none()
    if latest is not None:
        return latest.id
    org = Organization(name="Default Organization")
    session.add(org)
    await session.flush()
    return org.id


async def _get_profile(session: AsyncSession, system_id: int) -> SystemProfile | None:
    return (
        await session.execute(select(SystemProfile).where(SystemProfile.system_id == system_id))
    ).scalar_one_or_none()


@router.get("/intake/questionnaire")
async def questionnaire() -> dict[str, Any]:
    """The intake questionnaire that drives system definition + derivation."""
    return {"questions": automation.QUESTIONNAIRE}


@router.post("/intake/systems", status_code=201)
async def intake_system(
    body: IntakeIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """One-shot: create system + profile, then derive controls/inheritance/SPRS."""
    org_id = await _resolve_org(session, principal, body.organization_id)
    system = System(organization_id=org_id, name=body.system_name)
    session.add(system)
    await session.flush()

    prof_data = body.model_dump(exclude={"system_name", "organization_id", "generate_ssp"})
    profile = SystemProfile(system_id=system.id, answers=body.model_dump(), **prof_data)
    session.add(profile)
    await session.flush()

    result = await automation.derive_system(
        session,
        system_id=system.id,
        org_id=org_id,
        profile=profile,
        actor=principal.email,
    )
    ssp_project_id = None
    if body.generate_ssp:
        ssp_project_id = await automation.generate_ssp(
            session, system=system, profile=profile, actor=principal.email
        )
    await session.commit()
    return {
        "system_id": system.id,
        "profile_id": profile.id,
        "ssp_project_id": ssp_project_id,
        "derivation": result,
    }


@router.put("/systems/{system_id}/profile")
async def upsert_profile(
    system_id: int,
    body: ProfileIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    system = (
        await session.execute(select(System).where(System.id == system_id))
    ).scalar_one_or_none()
    if system is None:
        raise HTTPException(404, "system not found")
    profile = await _get_profile(session, system_id)
    data = body.model_dump()
    if profile is None:
        profile = SystemProfile(system_id=system_id, answers=data, **data)
        session.add(profile)
    else:
        for k, v in data.items():
            setattr(profile, k, v)
        profile.answers = data
    await session.commit()
    return {"system_id": system_id, "profile_saved": True}


@router.post("/systems/{system_id}/derive")
async def derive(
    system_id: int,
    create_poams: bool = True,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Re-run derivation from the saved profile (idempotent)."""
    system = (
        await session.execute(select(System).where(System.id == system_id))
    ).scalar_one_or_none()
    if system is None:
        raise HTTPException(404, "system not found")
    profile = await _get_profile(session, system_id)
    if profile is None:
        raise HTTPException(400, "system has no profile; complete the questionnaire first")
    result = await automation.derive_system(
        session,
        system_id=system_id,
        org_id=system.organization_id,
        profile=profile,
        create_poams=create_poams,
        actor=principal.email,
    )
    await session.commit()
    return result


@router.get("/systems/{system_id}/coverage")
async def coverage(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Coverage rollup (responsibility / state) from the derivation snapshot."""
    profile = await _get_profile(session, system_id)
    if profile is None:
        raise HTTPException(404, "system has no profile")
    return {"system_id": system_id, **automation.coverage(profile)}


@router.post("/systems/{system_id}/generate-ssp", status_code=201)
async def generate_ssp(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Auto-generate an SSP project seeded from the profile's derivation."""
    system = (
        await session.execute(select(System).where(System.id == system_id))
    ).scalar_one_or_none()
    if system is None:
        raise HTTPException(404, "system not found")
    profile = await _get_profile(session, system_id)
    if profile is None or not profile.derivation:
        raise HTTPException(400, "derive the system profile first")
    project_id = await automation.generate_ssp(
        session, system=system, profile=profile, actor=principal.email
    )
    await session.commit()
    return {"project_id": project_id}


@router.get("/systems/{system_id}/impact")
async def impact(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """How each control affects the SPRS score, ranked by recoverable points."""
    return await automation.control_impact(session, system_id)


@router.get("/systems/{system_id}/evidence-requirements")
async def evidence_requirements(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Derived evidence checklist for the system's non-inherited controls."""
    profile = await _get_profile(session, system_id)
    if profile is None:
        raise HTTPException(404, "system has no profile")
    return await automation.evidence_requirements(session, system_id, profile)


# --- Uploadable framework controls (add new frameworks in future) ------------


class FrameworkControlIn(BaseModel):
    identifier: str
    title: str | None = None
    description: str | None = None
    family: str | None = None
    baseline: str | None = None
    default_responsibility: str | None = None


class FrameworkUpload(BaseModel):
    name: str | None = None  # framework display name (created if new)
    controls: list[FrameworkControlIn]


async def _ensure_framework(session: AsyncSession, code: str, name: str | None) -> None:
    fw = (
        await session.execute(select(Framework).where(Framework.code == code))
    ).scalar_one_or_none()
    if fw is None:
        session.add(Framework(code=code, name=name or code, family="Custom"))
        await session.flush()


async def _upsert_controls(
    session: AsyncSession, code: str, rows: list[dict[str, Any]], source: str
) -> dict[str, int]:
    existing = {
        fc.identifier: fc
        for fc in (
            await session.execute(
                select(FrameworkControl).where(FrameworkControl.framework_code == code)
            )
        )
        .scalars()
        .all()
    }
    created = updated = 0
    for r in rows:
        ident = str(r.get("identifier") or "").strip()
        if not ident:
            continue
        cur = existing.get(ident)
        if cur is None:
            session.add(
                FrameworkControl(
                    framework_code=code,
                    identifier=ident,
                    source=source,
                    **{
                        k: r.get(k)
                        for k in (
                            "title",
                            "description",
                            "family",
                            "baseline",
                            "default_responsibility",
                        )
                    },
                )
            )
            created += 1
        else:
            for k in ("title", "description", "family", "baseline", "default_responsibility"):
                if r.get(k) is not None:
                    setattr(cur, k, r.get(k))
            updated += 1
    return {"created": created, "updated": updated}


@router.post("/framework-controls/{code}", status_code=201)
async def upload_framework_controls_json(
    code: str,
    body: FrameworkUpload,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Upload/replace a framework's controls as JSON (adds the framework if new)."""
    await _ensure_framework(session, code.upper(), body.name)
    counts = await _upsert_controls(
        session, code.upper(), [c.model_dump() for c in body.controls], source="json_upload"
    )
    await session.commit()
    return {"framework": code.upper(), **counts}


@router.post("/framework-controls/{code}/csv", status_code=201)
async def upload_framework_controls_csv(
    code: str,
    file: UploadFile,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Upload a framework's controls as CSV (cols: identifier,title,description,family,baseline)."""
    raw = (await file.read()).decode("utf-8-sig", errors="replace")
    rows = list(csv.DictReader(io.StringIO(raw)))
    if not rows:
        raise HTTPException(400, "empty or unparseable CSV")
    await _ensure_framework(session, code.upper(), None)
    counts = await _upsert_controls(session, code.upper(), rows, source=f"csv:{file.filename}")
    await session.commit()
    return {"framework": code.upper(), **counts}


@router.get("/framework-controls/{code}")
async def list_framework_controls(
    code: str,
    limit: int = 500,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    total = (
        await session.execute(
            select(func.count(FrameworkControl.id)).where(
                FrameworkControl.framework_code == code.upper()
            )
        )
    ).scalar_one()
    rows = (
        (
            await session.execute(
                select(FrameworkControl)
                .where(FrameworkControl.framework_code == code.upper())
                .order_by(FrameworkControl.identifier)
                .limit(min(limit, 2000))
            )
        )
        .scalars()
        .all()
    )
    return {
        "framework": code.upper(),
        "total": total,
        "controls": [
            {
                "identifier": c.identifier,
                "title": c.title,
                "family": c.family,
                "baseline": c.baseline,
                "default_responsibility": c.default_responsibility,
            }
            for c in rows
        ],
    }
