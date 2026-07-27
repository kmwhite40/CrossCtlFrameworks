"""Build default per-control SSP entries for a project from the scoring matrix.

Each entry is pre-populated with assessor-facing *draft* content (responsible
role, control origination, and one narrative per NIST 800-171A determination
part) so a customer engagement starts from a tailorable baseline rather than a
blank page. Both the narratives *and* the control origination are derived for
the project's actual target platform (Microsoft 365, Azure, or AWS GovCloud) —
Microsoft 365 is the only platform with per-practice coverage data (the M365
placemat's ``m365_coverage_status``); every other platform uses its own
domain-level responsibility table in :mod:`ccf.ssp.constants`, so an AWS/Azure
project's origination is never a copy of the M365 responsibility split.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.oscal import OscalCatalog, load_oscal_catalog
from ..models import ScoringControl, SSPControlEntry, SSPProject, System
from . import constants
from .nist80053 import build_80053_entries
from .platforms import customer_responsibility_statement, normalize_platform, sample_statement

# Column names of SSPControlEntry that build_80053_entries populates — guards
# against passing any extra keys the model doesn't have.
_ENTRY_COLUMNS = {
    "control_id",
    "nist_id",
    "domain",
    "title",
    "requirement",
    "responsible_role",
    "implementation_status",
    "control_origination",
    "part_narratives",
    "odp_values",
    "sort_order",
}

_FIPS_ORDER = {"low": 0, "moderate": 1, "high": 2}


def _needs_customer_lead_in(rec: ScoringControl, platform: str) -> bool:
    """Whether to lead the narrative with a draft customer-responsibility
    statement, reflecting the *selected* platform's own responsibility split —
    never the Microsoft 365 coverage status when the project targets another
    platform (FR-04/FR-12)."""
    if platform == "m365":
        return (rec.m365_coverage_status or "") == "Customer Responsibility"
    # Not fully provider-inherited on this platform — either genuinely shared
    # with the organization, or unknown/unflagged and needing a human to
    # assign it — either way the organization may need to act, so lead with
    # the draft customer-responsibility statement for review.
    return constants.platform_responsibility(platform, rec.domain) != "inherited"


def _narratives(rec: ScoringControl, platform: str) -> list[dict[str, str]]:
    parts: list[dict[str, str]] = list(rec.objective_parts or [])
    out = [
        {"label": p.get("label", ""), "text": sample_statement(platform, rec, p)} for p in parts
    ]
    if not out:
        out = [
            {"label": "", "text": sample_statement(platform, rec, {"text": rec.requirement or ""})}
        ]
    # For controls the provider doesn't fully cover, lead with a draft-flagged
    # customer-responsibility statement scoped to the Government-cloud environment.
    if _needs_customer_lead_in(rec, platform):
        out.insert(
            0,
            {
                "label": "Customer Responsibility",
                "text": customer_responsibility_statement(platform, rec),
            },
        )
    return out


def _named_role_from_metadata(project_metadata: dict[str, Any] | None) -> str | None:
    """The project's real named responsible party from SSP front-matter
    ``roles`` metadata (FR-13) — prefers the named System Owner, falling back
    to the named ISSO, so seeding never has to guess a generic label when a
    real name is already on file."""
    roles = (project_metadata or {}).get("roles") or {}
    owner = (roles.get("system_owner") or {}).get("name")
    if owner and str(owner).strip():
        return f"{str(owner).strip()} (System Owner)"
    isso = (roles.get("isso") or {}).get("name")
    if isso and str(isso).strip():
        return f"{str(isso).strip()} (ISSO)"
    return None


def _responsible_role(
    rec: ScoringControl, platform: str, project_metadata: dict[str, Any] | None = None
) -> str:
    named = _named_role_from_metadata(project_metadata)
    role = constants.responsible_role_for(rec.domain, named_role=named)
    if constants.needs_manual_responsibility_assignment(platform, rec.domain):
        role = f"{role} — {constants.MANUAL_RESPONSIBILITY_FLAG}"
    return role


def build_entries(
    rec: ScoringControl,
    order: int,
    platform: str,
    project_metadata: dict[str, Any] | None = None,
) -> SSPControlEntry:
    plat = normalize_platform(platform)
    return SSPControlEntry(
        control_id=rec.control_id,
        nist_id=rec.nist_id,
        domain=rec.domain,
        title=rec.title,
        requirement=rec.requirement,
        responsible_role=_responsible_role(rec, plat, project_metadata),
        implementation_status=["Planned"],
        control_origination=constants.platform_origination(
            plat, rec.m365_coverage_status, rec.domain
        ),
        part_narratives=_narratives(rec, plat),
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
    plat = normalize_platform(platform or project.platform or "m365")
    project_metadata = project.metadata_json or {}
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
            current.control_origination = constants.platform_origination(
                plat, rec.m365_coverage_status, rec.domain
            )
            current.responsible_role = _responsible_role(rec, plat, project_metadata)
            current.sort_order = order
        else:
            entry = build_entries(rec, order, plat, project_metadata)
            entry.project_id = project.id
            session.add(entry)
        touched += 1

    await session.commit()
    return touched


def _fips_high_water(system: System) -> str | None:
    """The FIPS-199 high-water mark across confidentiality/integrity/availability
    (low < moderate < high), or ``None`` when all three are unset."""
    levels = [
        lvl
        for lvl in (
            system.fips199_confidentiality,
            system.fips199_integrity,
            system.fips199_availability,
        )
        if lvl
    ]
    if not levels:
        return None
    return max(levels, key=lambda lvl: _FIPS_ORDER.get(lvl.lower(), -1))


async def seed_80053_project(
    session: AsyncSession,
    project: SSPProject,
    *,
    catalog: OscalCatalog | None = None,
) -> int:
    """Seed ``SSPControlEntry`` rows for a NIST 800-53r5 project from its
    system's FIPS-199 baseline. Idempotent: only controls missing from the
    project are inserted — existing (possibly human-edited) rows are never
    touched. Returns the count of rows inserted."""
    if project.system_id is None:
        raise ValueError("project has no system_id — cannot resolve a baseline")
    system = await session.get(System, project.system_id)
    if system is None:
        raise ValueError(f"system {project.system_id} not found")

    level = system.baseline or _fips_high_water(system)
    if level is None:
        raise ValueError("system has no baseline or FIPS-199 categorization")
    level = level.lower()

    cat = catalog or load_oscal_catalog()
    entries, _odp_defs = build_80053_entries(cat, level)

    existing_ids = set(
        (
            await session.execute(
                select(SSPControlEntry.control_id).where(
                    SSPControlEntry.project_id == project.id
                )
            )
        )
        .scalars()
        .all()
    )

    inserted = 0
    for entry in entries:
        if entry["control_id"] in existing_ids:
            continue
        session.add(
            SSPControlEntry(
                project_id=project.id,
                **{k: v for k, v in entry.items() if k in _ENTRY_COLUMNS},
            )
        )
        inserted += 1

    await session.flush()
    return inserted


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
        "odp_values": dict(entry.odp_values or {}),
    }
