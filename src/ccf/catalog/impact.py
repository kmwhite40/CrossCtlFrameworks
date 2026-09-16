"""What adopting a catalog revision would do to this deployment's own content.

A :class:`~ccf.catalog.diff.CatalogDiff` says what changed upstream. This says
what that *means here*: which systems' baselines gain or lose controls, which
authored SSP entries are orphaned or now carry stale narrative, which
cross-framework mappings would dangle, and which KSIs reference controls that
went away.

Read-only and side-effect free -- it is computed for a human to review before
adoption, and the reviewed result is stored on the revision row as the record of
what was actually approved.

Dangling-mapping detection deliberately calls
:func:`ccf.catalog.reconcile.check_mapping_endpoints` against the *candidate*
catalog rather than reimplementing the same question. That engine already knows
what a valid 800-53 endpoint looks like, including which mapping columns even
target NIST.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import KSI, Control, Framework, FrameworkMapping, SSPControlEntry, SSPProject, System
from .diff import CatalogDiff
from .oscal import OscalCatalog
from .reconcile import MappingRow, check_mapping_endpoints


@dataclass
class AdoptionImpact:
    """Per-deployment consequences of adopting one revision."""

    systems_affected: list[dict[str, Any]] = field(default_factory=list)
    orphaned_entries: list[dict[str, Any]] = field(default_factory=list)
    stale_narratives: list[dict[str, Any]] = field(default_factory=list)
    param_drift: list[dict[str, Any]] = field(default_factory=list)
    dangling_mappings: list[dict[str, Any]] = field(default_factory=list)
    ksi_references: list[dict[str, Any]] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (
            self.systems_affected
            or self.orphaned_entries
            or self.stale_narratives
            or self.param_drift
            or self.dangling_mappings
            or self.ksi_references
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "systems_affected": self.systems_affected,
            "orphaned_entries": self.orphaned_entries,
            "stale_narratives": self.stale_narratives,
            "param_drift": self.param_drift,
            "dangling_mappings": self.dangling_mappings,
            "ksi_references": self.ksi_references,
            "empty": self.is_empty(),
        }


async def _entries_for(
    session: AsyncSession, control_ids: set[str]
) -> list[tuple[SSPControlEntry, int | None]]:
    """Authored entries touching any of ``control_ids``, with their org id."""
    if not control_ids:
        return []
    rows = (
        await session.execute(
            select(SSPControlEntry, SSPProject.organization_id)
            .join(SSPProject, SSPProject.id == SSPControlEntry.project_id)
            .where(SSPControlEntry.control_id.in_(control_ids))
        )
    ).all()
    return [(r[0], r[1]) for r in rows]


def _entry_row(entry: SSPControlEntry, org_id: int | None, **extra: Any) -> dict[str, Any]:
    return {
        "entry_id": entry.id,
        "project_id": entry.project_id,
        "organization_id": org_id,
        "control_id": entry.control_id,
        **extra,
    }


async def _affected_systems(session: AsyncSession, diff: CatalogDiff) -> list[dict[str, Any]]:
    """Systems whose baseline set gains or loses controls under this revision."""
    touched = {
        lvl
        for lvl in set(diff.baseline_entered) | set(diff.baseline_left)
        if diff.baseline_entered.get(lvl) or diff.baseline_left.get(lvl)
    }
    if not touched:
        return []
    systems = (
        await session.execute(
            select(System).where(
                System.baseline.in_(touched),
                # DATA-04 soft delete: a deleted system is not affected by anything.
                System.deleted_at.is_(None),
            )
        )
    ).scalars().all()
    return [
        {
            "system_id": s.id,
            "organization_id": s.organization_id,
            "name": s.name,
            "baseline": s.baseline or "",
            "entering": list(diff.baseline_entered.get(s.baseline or "", ())),
            "leaving": list(diff.baseline_left.get(s.baseline or "", ())),
        }
        for s in systems
    ]


async def _dangling_mappings(
    session: AsyncSession, candidate: OscalCatalog
) -> list[dict[str, Any]]:
    """Cross-framework mappings whose NIST endpoint the candidate lacks.

    Reuses the reconciliation engine's endpoint check rather than re-deciding
    what a valid 800-53 target is.
    """
    rows = (
        await session.execute(
            select(
                Control.identifier,
                FrameworkMapping.column_key,
                Framework.code,
                FrameworkMapping.value,
            )
            .join(Control, Control.id == FrameworkMapping.control_id)
            .outerjoin(Framework, Framework.id == FrameworkMapping.framework_id)
        )
    ).all()
    mappings = [
        MappingRow(control_number=r[0], column_key=r[1], framework_code=r[2], value=r[3])
        for r in rows
    ]
    findings, _uncovered = check_mapping_endpoints(candidate, mappings)
    # CatalogFinding already knows how to serialise itself.
    return [f.as_dict() for f in findings]


async def _ksi_references(session: AsyncSession, gone: set[str]) -> list[dict[str, Any]]:
    """KSIs whose ``nist_refs`` point at a control that is going away."""
    if not gone:
        return []
    # The KSI catalog is small (tens of rows), so filtering in Python is
    # clearer than a JSONB containment query and costs nothing.
    ksis = (await session.execute(select(KSI))).scalars().all()
    out: list[dict[str, Any]] = []
    for k in ksis:
        lost = sorted(gone.intersection(str(r) for r in (k.nist_refs or [])))
        if lost:
            out.append({"ksi_id": k.id, "ksi_key": k.identifier, "lost_refs": lost})
    return out


async def build_adoption_impact(
    session: AsyncSession, *, diff: CatalogDiff, candidate: OscalCatalog
) -> AdoptionImpact:
    """Compute what adopting the revision behind ``diff`` would affect.

    ``candidate`` is the loaded catalog of the revision being considered; it is
    needed to ask the reconciliation engine which mapping endpoints would become
    invalid, which the diff alone cannot answer.
    """
    impact = AdoptionImpact()
    impact.systems_affected = await _affected_systems(session, diff)

    removed = set(diff.removed)
    gone = removed | set(diff.newly_withdrawn)
    for entry, org_id in await _entries_for(session, gone):
        impact.orphaned_entries.append(
            _entry_row(
                entry,
                org_id,
                reason="removed" if entry.control_id in removed else "withdrawn",
            )
        )

    prose_changed = {
        c.canonical_id for c in diff.changed if c.statement_changed or c.guidance_changed
    }
    param_changed = {
        c.canonical_id
        for c in diff.changed
        if c.params_added or c.params_removed or c.params_changed
    }
    for entry, org_id in await _entries_for(session, prose_changed):
        impact.stale_narratives.append(_entry_row(entry, org_id))
    for entry, org_id in await _entries_for(session, param_changed):
        impact.param_drift.append(_entry_row(entry, org_id))

    impact.dangling_mappings = await _dangling_mappings(session, candidate)
    impact.ksi_references = await _ksi_references(session, gone)
    return impact
