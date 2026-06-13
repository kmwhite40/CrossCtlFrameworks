"""Build default per-control SSP entries for a project from the scoring matrix.

Each entry is pre-populated with assessor-facing *draft* content (responsible
role, control origination derived from the Microsoft 365 placemat, and one
narrative per NIST 800-171A determination part) so a customer engagement starts
from a tailorable baseline rather than a blank page. The narratives are written
for the project's target platform (Microsoft 365, Azure, or AWS GovCloud).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ScoringControl, SSPControlEntry, SSPProject
from . import constants
from .platforms import sample_statement


def _narratives(rec: ScoringControl, platform: str) -> list[dict[str, str]]:
    parts: list[dict[str, str]] = list(rec.objective_parts or [])
    out = [
        {"label": p.get("label", ""), "text": sample_statement(platform, rec, p)} for p in parts
    ]
    return out or [
        {"label": "", "text": sample_statement(platform, rec, {"text": rec.requirement or ""})}
    ]


def build_entries(rec: ScoringControl, order: int, platform: str) -> SSPControlEntry:
    return SSPControlEntry(
        control_id=rec.control_id,
        nist_id=rec.nist_id,
        domain=rec.domain,
        title=rec.title,
        requirement=rec.requirement,
        responsible_role=constants.responsible_role_for(rec.domain),
        implementation_status=["Planned"],
        control_origination=constants.default_origination(rec.m365_coverage_status),
        part_narratives=_narratives(rec, platform),
        sort_order=order,
    )


async def seed_project_entries(
    session: AsyncSession,
    project: SSPProject,
    *,
    overwrite: bool = False,
    platform: str | None = None,
) -> int:
    """Seed SSP entries for every scoring control. Returns the count created/updated.

    Without ``overwrite`` only missing controls are created. With ``overwrite``
    the seeded fields (narratives, origination, responsible role) of existing
    entries are regenerated for ``platform`` while the assessor's implementation
    status is preserved.
    """
    plat = platform or project.platform or "m365"
    controls = (
        (await session.execute(select(ScoringControl).order_by(ScoringControl.sort_order)))
        .scalars()
        .all()
    )
    existing = {
        e.control_id: e
        for e in (
            await session.execute(
                select(SSPControlEntry).where(SSPControlEntry.project_id == project.id)
            )
        )
        .scalars()
        .all()
    }

    touched = 0
    for order, rec in enumerate(controls):
        current = existing.get(rec.control_id)
        if current is not None:
            if not overwrite:
                continue
            current.part_narratives = _narratives(rec, plat)
            current.control_origination = constants.default_origination(rec.m365_coverage_status)
            current.responsible_role = constants.responsible_role_for(rec.domain)
            current.sort_order = order
        else:
            entry = build_entries(rec, order, plat)
            entry.project_id = project.id
            session.add(entry)
        touched += 1

    await session.commit()
    return touched


def entry_to_dict(entry: SSPControlEntry) -> dict[str, Any]:
    return {
        "control_id": entry.control_id,
        "nist_id": entry.nist_id,
        "domain": entry.domain,
        "title": entry.title,
        "requirement": entry.requirement,
        "responsible_role": entry.responsible_role,
        "implementation_status": list(entry.implementation_status or []),
        "control_origination": list(entry.control_origination or []),
        "part_narratives": list(entry.part_narratives or []),
    }
