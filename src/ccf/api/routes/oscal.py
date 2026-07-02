"""OSCAL Component Definition export (#16).

Emits a minimal OSCAL 1.1 Component Definition describing Concord's view of a
given system: the list of implemented / inherited controls with their
implementation narratives. Not a full OSCAL profile — targets auditor intake.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...auth import Principal
from ...models import (
    POAM,
    Control,
    ControlImplementation,
    SSPControlEntry,
    SSPProject,
    System,
)
from ...oscal import validate_document
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/oscal", tags=["oscal"])


@router.post("/validate")
async def validate_oscal_endpoint(
    body: dict[str, Any],
    kind: str = "auto",
    _principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Validate a posted OSCAL document (SSP / Component Definition / POA&M /
    assessment) against the official schema when configured, else structural
    checks. ``kind`` defaults to auto-detection from the document root key."""
    return validate_document(body, kind=kind).as_dict()

# OSCAL POA&M item status maps to the assessment-log lifecycle NIST expects.
_OSCAL_POAM_STATE = {
    "open": "open",
    "in_progress": "investigating",
    "completed": "closed",
    "closed": "closed",
    "risk_accepted": "risk-accepted",
}
_OSCAL_SEVERITY = {"low": "low", "moderate": "moderate", "high": "high", "critical": "critical"}


@router.get("/component-definition/{system_id}")
async def component_definition(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    # Scope to the caller's org (global/auth-off principals are unscoped).
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")

    impls = (
        (
            await session.execute(
                select(ControlImplementation)
                .where(ControlImplementation.system_id == system_id)
                .options(selectinload(ControlImplementation.control))
            )
        )
        .scalars()
        .all()
    )

    implemented_reqs = [
        {
            "uuid": str(uuid.uuid4()),
            "control-id": (i.control.identifier if i.control else "").lower().replace(" ", ""),
            "description": i.narrative or "",
            "props": [
                {"name": "implementation-status", "value": i.status},
                {"name": "responsibility", "value": i.responsibility or ""},
            ],
        }
        for i in impls
    ]

    now = datetime.now(UTC).isoformat()
    return _component_definition_doc(sys, implemented_reqs, now)


def _component_definition_doc(
    sys: System, implemented_reqs: list[dict[str, Any]], now: str
) -> dict[str, Any]:
    return {
        "component-definition": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"Concord Component Definition — {sys.name}",
                "last-modified": now,
                "version": "0.1.0",
                "oscal-version": "1.1.2",
                "published": now,
            },
            "components": [
                {
                    "uuid": str(uuid.uuid4()),
                    "type": "software",
                    "title": sys.name,
                    "description": sys.description or sys.name,
                    "control-implementations": [
                        {
                            "uuid": str(uuid.uuid4()),
                            "source": "https://doi.org/10.6028/NIST.SP.800-53r5",
                            "description": "NIST SP 800-53 Rev 5 baseline as captured by Concord.",
                            "implemented-requirements": implemented_reqs,
                        }
                    ],
                }
            ],
        }
    }


@router.get("/ssp/{project_id}")
async def ssp_export(
    project_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Emit an OSCAL 1.1 System Security Plan from a saved SSP project."""
    proj = (
        await session.execute(select(SSPProject).where(SSPProject.id == project_id))
    ).scalar_one_or_none()
    # Scope to the caller's org (global/auth-off principals are unscoped).
    if proj is None or (principal.org_id is not None and proj.organization_id != principal.org_id):
        raise HTTPException(404, "SSP project not found")
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

    implemented_reqs: list[dict[str, Any]] = []
    for e in entries:
        nist = (e.nist_id or e.control_id).strip()
        statements = [
            {
                "statement-id": f"{nist}_smt.{part.get('label')}"
                if part.get("label")
                else f"{nist}_smt",
                "uuid": str(uuid.uuid4()),
                "description": part.get("text", ""),
            }
            for part in (e.part_narratives or [])
        ]
        implemented_reqs.append(
            {
                "uuid": str(uuid.uuid4()),
                "control-id": nist,
                "props": [
                    {"name": "responsible-role", "value": e.responsible_role or ""},
                    {
                        "name": "implementation-status",
                        "value": ", ".join(e.implementation_status or []) or "planned",
                    },
                    {
                        "name": "control-origination",
                        "value": ", ".join(e.control_origination or []),
                    },
                ],
                "statements": statements,
            }
        )

    now = datetime.now(UTC).isoformat()
    return {
        "system-security-plan": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"{proj.customer_name} — {proj.title}",
                "last-modified": now,
                "version": proj.version,
                "oscal-version": "1.1.2",
                "published": now,
            },
            "import-profile": {
                "href": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
                "nist.gov/SP800-171/rev2/json/NIST_SP-800-171_rev2_PROFILE.json"
            },
            "system-characteristics": {
                "system-ids": [
                    {"identifier-type": "https://ietf.org/rfc/rfc4122", "id": str(proj.id)}
                ],
                "system-name": proj.system_name or proj.customer_name,
                "description": f"CMMC Level 2 enclave for {proj.customer_name} "
                f"({proj.platform}).",
                "security-sensitivity-level": "cui",
                "system-information": {
                    "information-types": [
                        {
                            "uuid": str(uuid.uuid4()),
                            "title": "Controlled Unclassified Information",
                            "description": "CUI processed, stored, or transmitted by the system.",
                        }
                    ]
                },
                "status": {"state": "operational"},
            },
            "control-implementation": {
                "description": "CMMC L2 (NIST SP 800-171 Rev. 2) control implementations.",
                "implemented-requirements": implemented_reqs,
            },
        }
    }


@router.get("/poam/{system_id}")
async def poam_export(
    system_id: int,
    include_closed: bool = False,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Emit an OSCAL 1.1 Plan of Action and Milestones for a system's POA&Ms."""
    sys = (
        await session.execute(select(System).where(System.id == system_id))
    ).scalar_one_or_none()
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")

    stmt = (
        select(POAM)
        .where(POAM.system_id == system_id)
        .options(selectinload(POAM.milestones))
        .order_by(POAM.id)
    )
    if not include_closed:
        stmt = stmt.where(POAM.status.not_in(("closed", "completed")))
    poams = (await session.execute(stmt)).scalars().all()

    # Resolve control identifiers for POA&Ms tied to a catalog control.
    control_ids = {p.control_id for p in poams if p.control_id is not None}
    ctl_map: dict[int, str] = {}
    if control_ids:
        rows = (
            await session.execute(
                select(Control.id, Control.identifier).where(Control.id.in_(control_ids))
            )
        ).all()
        ctl_map = {cid: ident for cid, ident in rows}

    poam_items = [_poam_item(p, ctl_map) for p in poams]
    now = datetime.now(UTC).isoformat()
    return {
        "plan-of-action-and-milestones": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"Plan of Action and Milestones — {sys.name}",
                "last-modified": now,
                "version": "1.0.0",
                "oscal-version": "1.1.2",
                "published": now,
            },
            "system-id": {
                "identifier-type": "https://ietf.org/rfc/rfc4122",
                "id": str(sys.id),
            },
            "poam-items": poam_items,
        }
    }


def _poam_item(p: POAM, ctl_map: dict[int, str]) -> dict[str, Any]:
    props = [
        {"name": "severity", "value": _OSCAL_SEVERITY.get(p.severity, p.severity)},
        {"name": "status", "value": _OSCAL_POAM_STATE.get(p.status, p.status)},
    ]
    if p.control_id is not None and p.control_id in ctl_map:
        props.append({"name": "control-id", "value": ctl_map[p.control_id].lower()})
    if p.source:
        props.append({"name": "origin", "value": p.source})
    if p.scanner:
        props.append({"name": "scanner", "value": p.scanner})
    if p.due_on is not None:
        props.append({"name": "scheduled-completion-date", "value": p.due_on.isoformat()})
    if p.identified_on is not None:
        props.append({"name": "identified-date", "value": p.identified_on.isoformat()})

    item: dict[str, Any] = {
        "uuid": str(uuid.uuid4()),
        "title": p.title,
        "description": p.weakness or p.title,
        "props": props,
    }
    milestones = list(p.milestones or [])
    if milestones:
        item["remarks"] = "\n".join(
            f"- Milestone: {m.description} [{m.status}]"
            + (f" due {m.due_on.isoformat()}" if m.due_on else "")
            for m in milestones
        )
    return item
