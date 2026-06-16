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

from ...models import ControlImplementation, SSPControlEntry, SSPProject, System
from ..deps import get_session

router = APIRouter(prefix="/api/oscal", tags=["oscal"])


@router.get("/component-definition/{system_id}")
async def component_definition(
    system_id: int,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    if sys is None:
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
) -> dict[str, Any]:
    """Emit an OSCAL 1.1 System Security Plan from a saved SSP project."""
    proj = (
        await session.execute(select(SSPProject).where(SSPProject.id == project_id))
    ).scalar_one_or_none()
    if proj is None:
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
