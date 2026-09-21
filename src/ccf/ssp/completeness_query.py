"""Gather :func:`ccf.ssp.completeness.assess`'s real inputs from the database.

:mod:`ccf.ssp.completeness` is deliberately pure — no ``AsyncSession`` anywhere
in it — which is what makes ``assess`` trivially testable and safe for
:mod:`ccf.cr26.sdr` to import. This module is the other half: the queries that
turn a persisted :class:`~ccf.models.SSPProject` into the ``entries`` rows and
``boundary`` summary ``assess`` expects, and nothing else.

It lives here rather than in a route handler because an SSP's completeness
score is a property of the plan, not of one HTTP endpoint. A second page
needing the same number must call :func:`project_completeness`, not grow its
own copy of these joins — two completeness numbers in one product diverge the
first time either side is edited.

:mod:`ccf.ssp.seed` and :mod:`ccf.ssp.templates_seed` are the precedent for a
DB-backed module in this package.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..boundary.summary import reconcile_categorization, system_boundary_summary
from ..models import (
    Control,
    ControlImplementation,
    Evidence,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    System,
)
from . import completeness as ssp_completeness
from .seed import entry_to_dict


async def project_completeness(session: AsyncSession, project: SSPProject) -> dict[str, Any]:
    """SSP readiness score + exactly what front matter / controls are missing.

    ``project`` must already be authorized for the caller — this function does
    no tenancy check of its own (the route's ``_require_project`` is what scopes
    a project to the caller's organization).
    """
    entries = (
        (
            await session.execute(
                # Ordered, like every other read of this table (ssp.py:285, :728).
                # Without it Postgres gives no row-order guarantee, so the order
                # of ``control_gaps`` -- which reads as a checklist -- was
                # whatever the plan happened to produce, and could change after a
                # vacuum, a plan flip, or an unrelated entry update. A compliance
                # tool that lists the same gaps in a different order each refresh
                # invites a reader to wonder what changed.
                select(SSPControlEntry)
                .where(SSPControlEntry.project_id == project.id)
                .order_by(SSPControlEntry.sort_order)
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
    #
    # Scoped to this project's system: an "evidenced" claim must mean THIS
    # tenant's system captured something. Widening this join to every
    # implementation of the control would let one tenant's evidence satisfy
    # another's SSP.
    evidence_by_control: dict[str, list[dict[str, Any]]] = {}
    if project.system_id is not None:
        evidence_rows = (
            await session.execute(
                select(Control.identifier, Evidence.id)
                .join(ControlImplementation, ControlImplementation.control_id == Control.id)
                .join(Evidence, Evidence.implementation_id == ControlImplementation.id)
                .where(ControlImplementation.system_id == project.system_id)
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

    boundary = await _boundary_summary_dict(session, project)
    return ssp_completeness.assess(project.metadata_json or {}, rows, boundary=boundary)


async def _boundary_summary_dict(
    session: AsyncSession, project: SSPProject
) -> dict[str, Any] | None:
    """The small boundary dict ``assess`` scores, or ``None`` when the project
    has no linked system (in which case ``assess`` skips the boundary
    dimension entirely)."""
    if project.system_id is None:
        return None
    summary = await system_boundary_summary(session, project.system_id)
    system_row = await session.get(System, project.system_id)
    # No System row to compare against (e.g. it was deleted out from under
    # the project, which SET NULLs system_id) -> nothing to reconcile, so
    # don't hold the boundary check against the SSP.
    reconciles = (
        reconcile_categorization(system_row, summary.info_types) == []
        if system_row is not None
        else True
    )
    ic_total = len(summary.interconnections)
    ic_with_agreement = sum(
        1
        for ic in summary.interconnections
        if ic.agreement_type not in (None, "", "none") and (ic.agreement_ref or "").strip()
    )
    return {
        "components": len(summary.components),
        "info_types": len(summary.info_types),
        "categorization_reconciles": reconciles,
        "interconnections_with_agreements": (ic_with_agreement, ic_total),
    }
