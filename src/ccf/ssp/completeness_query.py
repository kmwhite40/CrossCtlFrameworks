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

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..boundary.summary import reconcile_categorization, system_boundary_summary
from ..constants import POAM_ACTIVE_STATUSES
from ..models import (
    POAM,
    Control,
    ControlImplementation,
    Evidence,
    SSPControlEntry,
    SSPProject,
    System,
)
from ..models_grc import ControlTest, ControlTestResult
from . import completeness as ssp_completeness
from . import constants as ssp_constants
from .odp_defs import odp_definitions_for_project
from .seed import entry_to_dict

#: Verdicts that gate readiness. Mirrors ``governance.automation._SSP_GAP_STATUSES``
#: -- the same distinction the narrative draws, so the gate and the paragraph
#: cannot disagree about what counts as a gap.
_GAP_STATUSES = ("fail", "warn", "manual_review_required")


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
    # Reference data, resolved per framework (ssp/odp_defs.py): the CMMC
    # scoring matrix, or the parsed OSCAL catalog for 800-53. The inline
    # ScoringControl join this replaces could only ever match a CMMC id, so an
    # 800-53 project's "unfilled parameter(s)" gap could not fire at all --
    # ``defined`` was always empty and the gate measured nothing.
    odp_map = await odp_definitions_for_project(
        session, project, [e.control_id for e in entries]
    )

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
    machine = await _machine_evidence_dict(session, project)
    return ssp_completeness.assess(
        project.metadata_json or {},
        rows,
        boundary=boundary,
        machine_evidence=machine,
    )


async def _machine_evidence_dict(
    session: AsyncSession, project: SSPProject
) -> dict[str, Any] | None:
    """What the platform observed that gates declaring this SSP ready.

    ``None`` when the project has no linked system: with nothing scanned and no
    POA&Ms to reach, every count would be zero, and a report of "no blockers"
    would read as conditions cleared rather than conditions unmeasurable. The
    boundary dimension above takes the same position for the same reason.

    Counts controls, not tests: three failing checks on one control is one
    control an assessor cannot accept, and reporting three would overstate the
    breadth of the problem while saying nothing more about its depth.
    """
    if project.system_id is None:
        return None
    control_ids = [
        c
        for (c,) in (
            await session.execute(
                select(SSPControlEntry.control_id).where(
                    SSPControlEntry.project_id == project.id
                )
            )
        ).all()
        if c
    ]
    missing_templates = [
        {
            "control_id": entry.control_id,
            "domain": entry.domain,
            "platform": project.platform,
            "framework": project.framework,
        }
        for entry in (
            await session.execute(
                select(SSPControlEntry).where(SSPControlEntry.project_id == project.id)
            )
        ).scalars()
        if ssp_constants.needs_manual_responsibility_assignment(project.platform, entry.domain)
    ]
    # Sets, not a row count: `.distinct()` over (control_id, status) pairs would
    # count a control carrying both a `fail` and a `warn` twice, which is the
    # opposite of what the docstring above promises. A control is also only
    # counted as unverified when it has *no* finding -- an open finding is the
    # stronger statement, and reporting the same control under both headings
    # would inflate the blocker list without adding a fact.
    failing_controls: set[str] = set()
    unverified_controls: set[str] = set()
    if control_ids:
        latest_result_id = (
            select(ControlTestResult.id)
            .where(ControlTestResult.control_test_id == ControlTest.id)
            .order_by(ControlTestResult.run_at.desc(), ControlTestResult.id.desc())
            .limit(1)
            .correlate(ControlTest)
            .scalar_subquery()
        )
        for control_id, result_status, last_status in (
            await session.execute(
                select(
                    ControlTest.control_id,
                    ControlTestResult.status,
                    ControlTest.last_status,
                )
                .outerjoin(ControlTestResult, ControlTestResult.id == latest_result_id)
                .where(
                    ControlTest.system_id == project.system_id,
                    (
                        ControlTestResult.status.in_(_GAP_STATUSES)
                        | (
                            ControlTestResult.id.is_(None)
                            & ControlTest.last_status.in_(_GAP_STATUSES)
                        )
                    ),
                    ControlTest.control_id.in_(control_ids),
                )
            )
        ).all():
            status = result_status or last_status
            if status == "manual_review_required":
                unverified_controls.add(str(control_id))
            else:
                failing_controls.add(str(control_id))
    unverified_controls -= failing_controls
    findings, unverified = len(failing_controls), len(unverified_controls)
    by_severity: dict[str, int] = {}
    for severity, count in (
        await session.execute(
            select(POAM.severity, func.count(POAM.id))
            .where(
                POAM.system_id == project.system_id,
                POAM.status.in_(POAM_ACTIVE_STATUSES),
            )
            .group_by(POAM.severity)
        )
    ).all():
        by_severity[str(severity)] = int(count)
    return {
        "controls_with_open_findings": findings,
        "controls_not_machine_verified": unverified,
        "open_poams_by_severity": by_severity,
        "missing_responsibility_templates": missing_templates,
    }


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
