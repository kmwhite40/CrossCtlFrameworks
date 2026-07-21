"""SSP authoring + document generation API.

Workflow: create a project for a customer/system → entries are auto-seeded from
the scoring matrix → edit per-control content (responsible role, status,
origination, per-part narratives) → generate the FedRAMP Appendix A ``.docx``.
Projects persist, so a customer's SSP can be reopened and re-generated.
"""

from __future__ import annotations

import asyncio
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from slugify import slugify
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...connectors import get_connector, list_connectors
from ...governance import automation
from ...models import (
    Control,
    ControlImplementation,
    Evidence,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    StatementTemplate,
    System,
    SystemProfile,
)
from ...ssp import completeness as ssp_completeness
from ...ssp import constants
from ...ssp.generator import generate_ssp_docx
from ...ssp.odp import render as render_template
from ...ssp.platforms import (
    GOV_ENVIRONMENTS,
    PLATFORMS,
    normalize_platform,
    platform_label,
    services_for,
)
from ...ssp.seed import entry_to_dict, seed_project_entries
from ...ssp.statements import STYLES
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/ssp", tags=["ssp"])

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


class ProjectCreate(BaseModel):
    customer_name: str
    system_id: int | None = None
    system_name: str | None = None
    platform: str = "m365"
    title: str = "System Security Plan (SSP)"
    version: str = "0.1"
    prepared_by: str | None = None
    document_date: date | None = None


class ProjectUpdate(BaseModel):
    customer_name: str | None = None
    system_name: str | None = None
    platform: str | None = None
    title: str | None = None
    version: str | None = None
    prepared_by: str | None = None
    document_date: date | None = None
    status: str | None = None


class EntryUpdate(BaseModel):
    responsible_role: str | None = None
    implementation_status: list[str] | None = None
    control_origination: list[str] | None = None
    part_narratives: list[dict[str, str]] | None = None
    odp_values: dict[str, str] | None = None


class ApplyTemplate(BaseModel):
    template_key: str
    # When true, replace the control's narratives with the rendered statement;
    # otherwise append it as an additional part.
    replace: bool = False


class ProjectOut(BaseModel):
    id: int
    system_id: int | None
    customer_name: str
    system_name: str | None
    platform: str
    title: str
    version: str
    prepared_by: str | None
    document_date: date | None
    status: str

    model_config = {"from_attributes": True}


async def _require_project(
    session: AsyncSession, project_id: int, principal: Principal
) -> SSPProject:
    proj = (
        await session.execute(select(SSPProject).where(SSPProject.id == project_id))
    ).scalar_one_or_none()
    if proj is None or (principal.org_id is not None and proj.organization_id != principal.org_id):
        raise HTTPException(404, "SSP project not found")
    return proj


@router.get("/options")
async def options() -> dict[str, Any]:
    """Vocabulary for the editor (status + origination check-all-that-apply)."""
    return {
        "implementation_status": list(constants.IMPLEMENTATION_STATUS_OPTIONS),
        "control_origination": list(constants.CONTROL_ORIGINATION_OPTIONS),
        "origination_definitions": [
            {"name": n, "definition": d} for n, d in constants.ORIGINATION_DEFINITIONS
        ],
        "platforms": [{"code": c, "label": label} for c, label in PLATFORMS.items()],
    }


@router.get("/projects", response_model=list[ProjectOut])
async def list_projects(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[ProjectOut]:
    stmt = select(SSPProject).order_by(SSPProject.created_at.desc())
    if principal.org_id is not None:
        stmt = stmt.where(SSPProject.organization_id == principal.org_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [ProjectOut.model_validate(r) for r in rows]


@router.post("/projects", response_model=ProjectOut, status_code=201)
async def create_project(
    body: ProjectCreate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> ProjectOut:
    system_name = body.system_name
    org_id = principal.org_id
    if body.system_id is not None:
        sys = (
            await session.execute(select(System).where(System.id == body.system_id))
        ).scalar_one_or_none()
        if sys is None or (
            principal.org_id is not None and sys.organization_id != principal.org_id
        ):
            raise HTTPException(404, "system not found")
        system_name = system_name or sys.name
        if org_id is None:
            org_id = sys.organization_id

    proj = SSPProject(
        organization_id=org_id,
        system_id=body.system_id,
        customer_name=body.customer_name,
        system_name=system_name,
        platform=normalize_platform(body.platform),
        title=body.title,
        version=body.version,
        prepared_by=body.prepared_by,
        document_date=body.document_date,
    )
    session.add(proj)
    await session.flush()
    await seed_project_entries(session, proj)
    await session.refresh(proj)
    return ProjectOut.model_validate(proj)


@router.get("/projects/{project_id}")
async def get_project(
    project_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    proj = await _require_project(session, project_id, principal)
    entries = (
        (
            await session.execute(
                select(SSPControlEntry)
                .where(SSPControlEntry.project_id == project_id)
                .order_by(SSPControlEntry.sort_order)
            )
        )
        .scalars()
        .all()
    )
    # Attach each control's organization-defined parameter slots (reference data
    # from the scoring catalog) so the editor can render fill-in-the-blank fields.
    odp_map: dict[str, Any] = {
        row[0]: row[1]
        for row in (
            await session.execute(
                select(ScoringControl.control_id, ScoringControl.odp_definitions)
            )
        ).all()
    }
    out_entries = []
    for e in entries:
        d = entry_to_dict(e)
        d["odp_definitions"] = list(odp_map.get(e.control_id) or [])
        out_entries.append(d)
    return {
        "project": ProjectOut.model_validate(proj).model_dump(),
        "entries": out_entries,
    }


async def _render_context(proj: SSPProject, domain: str | None) -> dict[str, str]:
    """Context tokens available to every template body ({{environment}}, …)."""
    plat = normalize_platform(proj.platform)
    return {
        "environment": GOV_ENVIRONMENTS.get(plat, platform_label(plat)),
        "platform": platform_label(plat),
        "services": services_for(plat, domain),
    }


def _template_matches(t: StatementTemplate, control_id: str, domain: str | None) -> bool:
    if t.scope == "control":
        return t.control_id == control_id
    if t.scope == "domain":
        return t.domain == domain
    return True  # global


@router.get("/projects/{project_id}/completeness")
async def completeness(
    project_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """SSP readiness score + exactly what front matter / controls are missing."""
    proj = await _require_project(session, project_id, principal)
    entries = (
        (
            await session.execute(
                select(SSPControlEntry).where(SSPControlEntry.project_id == project_id)
            )
        )
        .scalars()
        .all()
    )
    odp_map: dict[str, Any] = {
        row[0]: row[1]
        for row in (
            await session.execute(
                select(ScoringControl.control_id, ScoringControl.odp_definitions)
            )
        ).all()
    }

    # Real evidence linkage: a control counts as evidenced when its system's
    # ControlImplementation (matched by catalog identifier == this entry's
    # control_id, the same best-effort join ``governance/control_tests.py``
    # uses) has at least one linked Evidence row. Without this, entries built
    # by ``entry_to_dict`` carry no evidence_ref/control_implementation keys at
    # all and ``_has_linked_evidence`` always reads as false.
    evidence_by_control: dict[str, list[dict[str, Any]]] = {}
    if proj.system_id is not None:
        evidence_rows = (
            await session.execute(
                select(Control.identifier, Evidence.id)
                .join(ControlImplementation, ControlImplementation.control_id == Control.id)
                .join(Evidence, Evidence.implementation_id == ControlImplementation.id)
                .where(ControlImplementation.system_id == proj.system_id)
            )
        ).all()
        for identifier, evidence_id in evidence_rows:
            evidence_by_control.setdefault(identifier, []).append({"id": evidence_id})

    rows = []
    for e in entries:
        d = entry_to_dict(e)
        d["odp_definitions"] = list(odp_map.get(e.control_id) or [])
        linked = evidence_by_control.get(e.control_id)
        if linked:
            d["control_implementation"] = {"evidence": linked}
        rows.append(d)
    return ssp_completeness.assess(proj.metadata_json or {}, rows)


class MetadataIn(BaseModel):
    metadata_json: dict[str, Any]
    autofill: bool = True


@router.put("/projects/{project_id}/metadata")
async def set_metadata(
    project_id: int,
    body: MetadataIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Set SSP front matter; optionally auto-fill from the linked system + profile."""
    proj = await _require_project(session, project_id, principal)
    meta = {**(proj.metadata_json or {}), **body.metadata_json}
    if body.autofill and proj.system_id is not None:
        sysm = (
            await session.execute(select(System).where(System.id == proj.system_id))
        ).scalar_one_or_none()
        if sysm is not None:
            fips = meta.setdefault("fips199", {})
            fips.setdefault("confidentiality", sysm.fips199_confidentiality or "moderate")
            fips.setdefault("integrity", sysm.fips199_integrity or "moderate")
            fips.setdefault("availability", sysm.fips199_availability or "moderate")
            levels = [
                fips["confidentiality"],
                fips["integrity"],
                fips["availability"],
            ]
            order = {"low": 0, "moderate": 1, "high": 2}
            fips.setdefault("overall", max(levels, key=lambda x: order.get(x, 1)))
            meta.setdefault("system_type", "Cloud information system (CUI)")
        prof = (
            await session.execute(
                select(SystemProfile).where(SystemProfile.system_id == proj.system_id)
            )
        ).scalar_one_or_none()
        if prof is not None and not meta.get("authorization_boundary"):
            env = GOV_ENVIRONMENTS.get(normalize_platform(proj.platform), proj.platform)
            meta["authorization_boundary"] = (
                f"The authorization boundary is the {env} tenant/account and the managed "
                f"endpoints, identities ({prof.identity_model or 'enterprise IdP'}), and "
                f"security tooling that store, process, or transmit "
                f"{', '.join(prof.data_types or ['CUI'])}."
            )
    proj.metadata_json = meta
    await session.commit()
    return {"metadata_json": proj.metadata_json}


class RevisionIn(BaseModel):
    version: str
    date: str | None = None
    author: str | None = None
    notes: str | None = None


@router.post("/projects/{project_id}/revisions", status_code=201)
async def add_revision(
    project_id: int,
    body: RevisionIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Append a revision-history entry (and bump the project version)."""
    proj = await _require_project(session, project_id, principal)
    rev = body.model_dump()
    rev["author"] = rev.get("author") or principal.email
    proj.revision_history = [*(proj.revision_history or []), rev]
    proj.version = body.version
    await session.commit()
    return {"version": proj.version, "revisions": len(proj.revision_history)}


@router.post("/projects/{project_id}/auto-statements")
async def auto_statements(
    project_id: int,
    use_ai: bool = False,
    style: str = "standard",
    include_captured: bool = True,
    mark_draft: bool = True,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """(Re)compose every control's implementation statement from the derivation.

    Options: ``style`` (concise|standard|detailed), ``use_ai`` (Claude drafting
    when configured), ``include_captured`` (fold in live connector captures), and
    ``mark_draft`` (prefix customer/shared statements with [DRAFT]).
    """
    if style not in STYLES:
        raise HTTPException(422, f"style must be one of {', '.join(STYLES)}")
    proj = await _require_project(session, project_id, principal)
    profile = None
    if proj.system_id is not None:
        profile = (
            await session.execute(
                select(SystemProfile).where(SystemProfile.system_id == proj.system_id)
            )
        ).scalar_one_or_none()
    if profile is None:
        raise HTTPException(400, "project's system has no profile; run intake/derive first")
    result = await automation.generate_statements(
        session,
        project=proj,
        profile=profile,
        use_ai=use_ai,
        style=style,
        include_captured=include_captured,
        mark_draft=mark_draft,
    )
    await session.commit()
    return result


@router.get("/connectors")
async def connectors() -> list[dict[str, Any]]:
    """Available config-capture connectors and whether each is configured."""
    return [
        {
            "key": c.key,
            "label": c.label,
            "configured": c.is_configured(),
            "parameter_map": c.PARAMETER_MAP,
        }
        for c in list_connectors()
    ]


@router.post("/connectors/{key}/verify")
async def verify_connector(key: str) -> dict[str, Any]:
    """Prove connectivity into the target environment (e.g. an AWS GovCloud account)."""
    conn = get_connector(key)
    if conn is None:
        raise HTTPException(404, "unknown connector")
    return {"connector": conn.key, "configured": conn.is_configured(), **(await conn.verify())}


@router.post("/projects/{project_id}/autofill")
async def autofill_from_connector(
    project_id: int,
    connector: str,
    apply: bool = False,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Capture live config via a connector and map it onto the project's ODPs.

    With ``apply=false`` (default) this is a dry run: it returns what *would* be
    set per control without writing. With ``apply=true`` it merges captured
    values into each matching control's ``odp_values``. If the connector is not
    configured, returns ``configured=false`` plus its ``parameter_map`` so the
    caller can see what it would pull once credentials are set.
    """
    proj = await _require_project(session, project_id, principal)
    conn = get_connector(connector)
    if conn is None:
        raise HTTPException(404, "unknown connector")
    if not conn.is_configured():
        return {
            "connector": conn.key,
            "configured": False,
            "parameter_map": conn.PARAMETER_MAP,
            "captured": [],
            "applied": 0,
        }

    captured = await conn.capture()
    entries = (
        (
            await session.execute(
                select(SSPControlEntry).where(SSPControlEntry.project_id == proj.id)
            )
        )
        .scalars()
        .all()
    )
    by_nist = {e.nist_id: e for e in entries if e.nist_id}

    applied = 0
    results: list[dict[str, Any]] = []
    for cap in captured:
        entry = by_nist.get(cap.nist_id or "")
        if entry is not None and apply:
            entry.odp_values = {**(entry.odp_values or {}), cap.odp_key: cap.value}
            applied += 1
        results.append({**cap.to_dict(), "matched_control": entry.control_id if entry else None})
    if apply and applied:
        await session.commit()

    return {
        "connector": conn.key,
        "configured": True,
        "captured": results,
        "applied": applied,
        "dry_run": not apply,
    }


@router.get("/templates")
async def list_templates(
    control_id: str | None = None,
    domain: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    """Canned statement templates, optionally filtered to a control/domain."""
    rows = (
        (await session.execute(select(StatementTemplate).order_by(StatementTemplate.sort_order)))
        .scalars()
        .all()
    )
    if control_id or domain:
        rows = [t for t in rows if _template_matches(t, control_id or "", domain)]
    return [
        {
            "key": t.key,
            "title": t.title,
            "scope": t.scope,
            "domain": t.domain,
            "control_id": t.control_id,
            "body": t.body,
            "tags": list(t.tags or []),
        }
        for t in rows
    ]


@router.post("/projects/{project_id}/entries/{control_id}/apply-template")
async def apply_template(
    project_id: int,
    control_id: str,
    body: ApplyTemplate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Render a canned template with the entry's ODP values and add it as a part.

    Returns the updated entry plus ``missing_odps`` — parameters the customer
    still has to fill before the statement is complete.
    """
    proj = await _require_project(session, project_id, principal)
    entry = (
        await session.execute(
            select(SSPControlEntry)
            .where(SSPControlEntry.project_id == project_id)
            .where(SSPControlEntry.control_id == control_id)
        )
    ).scalar_one_or_none()
    if entry is None:
        raise HTTPException(404, "control entry not found in project")
    tmpl = (
        await session.execute(
            select(StatementTemplate).where(StatementTemplate.key == body.template_key)
        )
    ).scalar_one_or_none()
    if tmpl is None:
        raise HTTPException(404, "template not found")

    context = await _render_context(proj, entry.domain)
    text, missing = render_template(tmpl.body, dict(entry.odp_values or {}), context)
    new_part = {"label": tmpl.title, "text": text}
    if body.replace:
        entry.part_narratives = [new_part]
    else:
        entry.part_narratives = [*(entry.part_narratives or []), new_part]
    await session.commit()
    await session.refresh(entry)
    result = entry_to_dict(entry)
    result["missing_odps"] = missing
    return result


@router.patch("/projects/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: int,
    body: ProjectUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> ProjectOut:
    proj = await _require_project(session, project_id, principal)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(proj, k, normalize_platform(v) if k == "platform" else v)
    await session.commit()
    await session.refresh(proj)
    return ProjectOut.model_validate(proj)


@router.delete("/projects/{project_id}", status_code=204)
async def delete_project(
    project_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> None:
    proj = await _require_project(session, project_id, principal)
    await session.delete(proj)
    await session.commit()


@router.post("/projects/{project_id}/reseed")
async def reseed_project(
    project_id: int,
    overwrite: bool = False,
    platform: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, int | str]:
    """Regenerate sample statements, optionally switching the target platform."""
    proj = await _require_project(session, project_id, principal)
    if platform is not None:
        proj.platform = normalize_platform(platform)
        await session.flush()
    touched = await seed_project_entries(session, proj, overwrite=overwrite, platform=proj.platform)
    return {"touched": touched, "platform": proj.platform}


@router.put("/projects/{project_id}/entries/{control_id}")
async def update_entry(
    project_id: int,
    control_id: str,
    body: EntryUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_project(session, project_id, principal)
    entry = (
        await session.execute(
            select(SSPControlEntry)
            .where(SSPControlEntry.project_id == project_id)
            .where(SSPControlEntry.control_id == control_id)
        )
    ).scalar_one_or_none()
    if entry is None:
        raise HTTPException(404, "control entry not found in project")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(entry, k, v)
    await session.commit()
    await session.refresh(entry)
    return entry_to_dict(entry)


@router.get("/projects/{project_id}/document", response_model=None)
async def generate_document(
    project_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> StreamingResponse:
    """Generate and download the SSP ``.docx`` for this customer's project."""
    proj = await _require_project(session, project_id, principal)
    entries = (
        (
            await session.execute(
                select(SSPControlEntry)
                .where(SSPControlEntry.project_id == project_id)
                .order_by(SSPControlEntry.sort_order)
            )
        )
        .scalars()
        .all()
    )
    project_meta = {
        "customer_name": proj.customer_name,
        "system_name": proj.system_name,
        "platform": PLATFORMS.get(proj.platform, proj.platform),
        "title": proj.title,
        "version": proj.version,
        "prepared_by": proj.prepared_by,
        "document_date": proj.document_date.strftime("%m/%d/%Y") if proj.document_date else "",
        "metadata_json": proj.metadata_json or {},
        "revision_history": proj.revision_history or [],
    }
    # python-docx is synchronous CPU work — keep it off the event loop.
    data = await asyncio.to_thread(
        generate_ssp_docx, project_meta, [entry_to_dict(e) for e in entries]
    )
    slug = slugify(f"{proj.customer_name}-ssp-appendix-a-v{proj.version}") or "ssp"
    return StreamingResponse(
        iter([data]),
        media_type=DOCX_MIME,
        headers={"Content-Disposition": f'attachment; filename="{slug}.docx"'},
    )
