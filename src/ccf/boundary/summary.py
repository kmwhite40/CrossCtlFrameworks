"""Boundary summary + FIPS-199 categorization rollup/reconciliation.

``categorization_rollup`` computes the high-water-mark confidentiality /
integrity / availability impact across a system's ``InformationType`` rows.
``reconcile_categorization`` compares that rollup against the system's
``fips199_*`` triad and reports mismatches as findings — it never mutates
``system`` or silently "fixes" the categorization; that decision belongs to a
human.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import InformationType, Interconnection, InventoryItem, System, SystemComponent
from . import service

_LEVEL_ORDER: dict[str, int] = {"low": 0, "moderate": 1, "high": 2}
_LEVELS: tuple[str, str, str] = ("confidentiality", "integrity", "availability")
_IMPACT_ATTR: dict[str, str] = {
    "confidentiality": "confidentiality_impact",
    "integrity": "integrity_impact",
    "availability": "availability_impact",
}


@dataclass
class BoundarySummary:
    components: list[SystemComponent] = field(default_factory=list)
    inventory: list[InventoryItem] = field(default_factory=list)
    info_types: list[InformationType] = field(default_factory=list)
    interconnections: list[Interconnection] = field(default_factory=list)


async def system_boundary_summary(session: AsyncSession, system_id: int) -> BoundarySummary:
    """Assemble the full boundary picture for a system."""
    components = await service.list_components(session, system_id)
    inventory = await service.list_inventory_items(session, system_id)
    info_types = await service.list_information_types(session, system_id)
    interconnections = await service.list_interconnections(session, system_id)
    return BoundarySummary(
        components=list(components),
        inventory=list(inventory),
        info_types=list(info_types),
        interconnections=list(interconnections),
    )


def categorization_rollup(info_types: list[InformationType]) -> dict[str, str | None]:
    """High-water-mark C/I/A across ``info_types``.

    A level is ``None`` when there are no information types, or when every
    information type leaves that level's impact unset.
    """
    rollup: dict[str, str | None] = dict.fromkeys(_LEVELS)
    for level in _LEVELS:
        attr = _IMPACT_ATTR[level]
        impacts = [
            getattr(it, attr) for it in info_types if getattr(it, attr) is not None
        ]
        if impacts:
            rollup[level] = max(impacts, key=lambda lvl: _LEVEL_ORDER[lvl])
    return rollup


def reconcile_categorization(
    system: System, info_types: list[InformationType]
) -> list[dict[str, Any]]:
    """Findings where the information-type rollup disagrees with ``system``'s
    ``fips199_*`` triad. Read-only — ``system`` is never mutated."""
    rollup = categorization_rollup(info_types)
    findings: list[dict[str, Any]] = []
    for level in _LEVELS:
        rollup_lvl = rollup[level]
        system_lvl = getattr(system, f"fips199_{level}")
        if rollup_lvl is None or system_lvl is None:
            continue
        if rollup_lvl == system_lvl:
            continue
        kind = (
            "under_categorized"
            if _LEVEL_ORDER[rollup_lvl] > _LEVEL_ORDER[system_lvl]
            else "over_categorized"
        )
        findings.append(
            {"level": level, "rollup": rollup_lvl, "system": system_lvl, "kind": kind}
        )
    return findings
