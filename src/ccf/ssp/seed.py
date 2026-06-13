"""Build default per-control SSP entries for a project from the scoring matrix.

Each entry is pre-populated with assessor-facing *draft* content (responsible
role, control origination derived from the Microsoft 365 placemat, and one
narrative per NIST 800-171A determination part) so a customer engagement starts
from a tailorable baseline rather than a blank page.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ScoringControl, SSPControlEntry, SSPProject
from . import constants


def _draft_part_text(rec: ScoringControl, part: dict[str, str]) -> str:
    """Compose a tailorable draft narrative for one determination part."""
    obj = (part.get("text") or "").strip().rstrip(".")
    stmt = (rec.m365_implementation_statement or "").strip()
    lead = (
        f"Draft — tailor to the environment. The organization satisfies this objective by "
        f"ensuring that {obj}."
        if obj
        else "Draft — describe how this objective is met."
    )
    if stmt:
        lead += f" Microsoft 365 reference: {stmt}"
    return lead


def build_entries(rec: ScoringControl, order: int) -> SSPControlEntry:
    parts: list[dict[str, str]] = list(rec.objective_parts or [])
    narratives: list[dict[str, str]] = [
        {"label": p.get("label", ""), "text": _draft_part_text(rec, p)} for p in parts
    ] or [{"label": "", "text": _draft_part_text(rec, {"text": rec.requirement or ""})}]

    return SSPControlEntry(
        control_id=rec.control_id,
        nist_id=rec.nist_id,
        domain=rec.domain,
        title=rec.title,
        requirement=rec.requirement,
        responsible_role=constants.responsible_role_for(rec.domain),
        implementation_status=["Planned"],
        control_origination=constants.default_origination(rec.m365_coverage_status),
        part_narratives=narratives,
        sort_order=order,
    )


async def seed_project_entries(
    session: AsyncSession, project: SSPProject, *, overwrite: bool = False
) -> int:
    """Create SSP entries for every scoring control. Returns the count created.

    Skips controls that already have an entry unless ``overwrite`` is set.
    """
    controls = (
        (await session.execute(select(ScoringControl).order_by(ScoringControl.sort_order)))
        .scalars()
        .all()
    )
    existing = {
        e.control_id
        for e in (
            await session.execute(
                select(SSPControlEntry).where(SSPControlEntry.project_id == project.id)
            )
        )
        .scalars()
        .all()
    }

    created = 0
    for order, rec in enumerate(controls):
        if rec.control_id in existing and not overwrite:
            continue
        entry = build_entries(rec, order)
        entry.project_id = project.id
        session.add(entry)
        created += 1

    await session.commit()
    return created


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
