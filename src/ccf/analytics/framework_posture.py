"""Posture measured against a framework baseline, not against what we happened to check.

The gap report answers "of the controls Concord assessed, which failed".
That is the wrong denominator for a compliance tool: a tenant with six
machine-tested controls and eight failures reads as "8 of 14" when the
baseline it is being held to has 288. The number an assessor and a customer
both need is *coverage of the baseline* -- what is satisfied, what failed,
and what has not been addressed at all.

The baseline is computable from data already loaded: ``ccf.controls`` carries
``fisma_low`` / ``fisma_mod`` / ``fisma_high`` membership flags. What it does
**not** carry is one row per control -- rows are assessment objectives and ODP
placeholders (``AC-02f.[01]``, ``AC-06(01)_ODP_02``), so counting them
overstates a baseline roughly fourfold. :func:`fold_to_control` reduces a row
identifier to the control it belongs to, keeping enhancements distinct because
a baseline names them separately.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.crosswalk import (
    CROSSWALK_COLUMN,
    CROSSWALK_FRAMEWORK,
    practices_for_controls,
)
from ..models import (
    Control,
    ControlImplementation,
    Framework,
    FrameworkMapping,
    ScoringControl,
    ScoringStatus,
    System,
    SystemProfile,
)
from ..models_grc import ControlTest
from ..scoring.engine import MET_STATES

#: Baseline name -> the catalog column that records membership.
BASELINE_COLUMNS = {
    "low": Control.fisma_low,
    "moderate": Control.fisma_mod,
    "high": Control.fisma_high,
}

#: A catalog row identifier reduced to its control: `AC-02f.[01]` -> `AC-2`,
#: `AC-02(03)(c)` -> `AC-2(3)`. Enhancements survive; objective suffixes and
#: ODP markers do not.
_FOLD = re.compile(r"^([A-Z]{2,3})-0*(\d+)(?:\(0*(\d+)\))?")

#: Implementation statuses that count as the control being addressed.
ADDRESSED_STATUSES = frozenset({"implemented", "inherited", "partially_implemented"})


def fold_to_control(identifier: str) -> str | None:
    """The control a catalog row belongs to, or ``None`` if it names no control."""
    if not identifier:
        return None
    cleaned = identifier.strip().upper().split("_ODP")[0]
    m = _FOLD.match(cleaned)
    if not m:
        return None
    family, number, enhancement = m.group(1), int(m.group(2)), m.group(3)
    return f"{family}-{number}({int(enhancement)})" if enhancement else f"{family}-{number}"


async def baseline_controls(session: AsyncSession, baseline: str) -> set[str]:
    """Every control in a FIPS-199 baseline, folded and deduplicated."""
    column = BASELINE_COLUMNS.get((baseline or "").lower())
    if column is None:
        return set()
    identifiers = (
        await session.execute(select(Control.identifier).where(column.is_(True)))
    ).scalars().all()
    return {c for c in (fold_to_control(i) for i in identifiers) if c}


async def framework_posture(
    session: AsyncSession, *, org_id: int | None, system_id: int
) -> dict[str, Any]:
    """Where one system stands against its declared baseline.

    A control is *satisfied* when a machine test passed or an implementation
    record claims it; *failing* when a machine test failed; and otherwise
    *unaddressed* -- which is the category the product had no way to show, and
    the one a customer most needs, because it is everything nobody has looked
    at yet.
    """
    system = await session.get(System, system_id)
    if system is None or (org_id is not None and system.organization_id != org_id):
        return _empty(None)
    baseline = (system.baseline.value if hasattr(system.baseline, "value") else system.baseline) or ""
    controls = await baseline_controls(session, baseline)
    if not controls:
        return _empty(baseline or None)

    tested: dict[str, set[str]] = {}
    for control_id, status in (
        await session.execute(
            select(ControlTest.control_id, ControlTest.last_status).where(
                ControlTest.system_id == system_id,
                ControlTest.control_id.is_not(None),
                ControlTest.last_status.is_not(None),
            )
        )
    ).all():
        folded = fold_to_control(control_id)
        if folded:
            tested.setdefault(folded, set()).add(status)

    implemented = {
        folded
        for identifier, status in (
            await session.execute(
                select(Control.identifier, ControlImplementation.status)
                .join(Control, Control.id == ControlImplementation.control_id)
                .where(ControlImplementation.system_id == system_id)
            )
        ).all()
        if status in ADDRESSED_STATUSES and (folded := fold_to_control(identifier))
    }

    # A control with any failing test is failing, whatever else claims it: a
    # documented implementation does not survive evidence that it is not
    # operating. That is the opposite precedence from the KSI rule, which only
    # ever *adds* satisfaction -- there, a rule must not overrule an assessor;
    # here, the customer is being told what to fix.
    failing = {c for c, statuses in tested.items() if "fail" in statuses} & controls
    passing = {c for c, statuses in tested.items() if statuses == {"pass"}} & controls
    documented = (implemented & controls) - failing - passing
    unaddressed = controls - failing - passing - documented

    return {
        "baseline": baseline,
        "total": len(controls),
        "passing": sorted(passing),
        "failing": sorted(failing),
        "documented": sorted(documented),
        "unaddressed": sorted(unaddressed),
        "addressed_pct": round(100 * (len(passing) + len(documented)) / len(controls), 1),
        "assessed_pct": round(100 * (len(passing) + len(failing)) / len(controls), 1),
    }


def _empty(baseline: str | None) -> dict[str, Any]:
    return {
        "baseline": baseline,
        "total": 0,
        "passing": [],
        "failing": [],
        "documented": [],
        "unaddressed": [],
        "addressed_pct": 0.0,
        "assessed_pct": 0.0,
    }


# ---------------------------------------------------------------------------
# Which framework applies, and the same answer in that framework's own terms
# ---------------------------------------------------------------------------
#
# `framework_posture` above answers for a FIPS-199 baseline, which is the only
# framework it can express: the denominator comes from `Control.fisma_*`. That
# left the systems most likely to be scanned answering nothing at all. The
# system this was found on declares `NIST_800_171` in its intake profile and
# has **no** FIPS-199 baseline, so the function returned its empty shape -- zero
# controls, zero failing, 0.0% -- which reads on a page and over an API as
# "nothing wrong" rather than "this framework is not one I can measure".
#
# So: resolve the framework a system is actually held to, then answer in that
# framework's units. 800-171 and CMMC Level 2 assess the same 110 requirements,
# and Concord already holds them one row per requirement in `scoring_controls`,
# so the denominator needs no invention. Placing 800-53-keyed scan results onto
# those requirements does need a crosswalk, and `catalog.crosswalk` uses the
# sourced one, reporting what it could not map.


#: Framework codes an intake profile may declare that mean the 110 NIST SP
#: 800-171 requirements. CMMC Level 2 assesses exactly those requirements, so
#: the two share a denominator -- they differ in who assesses and how it is
#: scored, not in what is required.
_NIST_171_CODES = frozenset({"NIST_800_171", "NIST_800_171_R2", "CMMC_L2", "CMMC"})


@dataclass(frozen=True)
class AppliedFramework:
    """The framework a system is held to, and how Concord knows.

    ``source`` is carried because the two ways of knowing are not equally
    strong: a FIPS-199 baseline on the system record is an authorization
    decision, while a framework named in an intake questionnaire is an
    intention someone typed. A consumer that cites this is entitled to know
    which it is reading.
    """

    key: str
    label: str
    #: ``"fips199_baseline"`` or ``"nist_800_171"`` -- what the denominator is.
    denominator: str
    source: str
    baseline: str | None = None


async def resolve_applied_framework(
    session: AsyncSession, system: System
) -> AppliedFramework | None:
    """The framework this system is measured against, or ``None`` if none is set.

    A declared FIPS-199 baseline wins: it is the authorization boundary's own
    categorization, and a system carrying one is being held to 800-53 whatever
    else a questionnaire said. Only when there is no baseline does the intake
    profile's framework list decide.

    ``None`` means no framework is declared -- which a caller must report as
    exactly that. It is the case that produced the original defect: an
    unmeasurable system rendering as a clean one.
    """
    baseline = (
        system.baseline.value if hasattr(system.baseline, "value") else system.baseline
    ) or ""
    if baseline.lower() in BASELINE_COLUMNS:
        return AppliedFramework(
            key=f"fedramp_{baseline.lower()}",
            label=f"NIST SP 800-53 Rev. 5, FedRAMP/FISMA {baseline.title()} baseline",
            denominator="fips199_baseline",
            source="system.baseline",
            baseline=baseline.lower(),
        )
    declared = (
        await session.execute(
            select(SystemProfile.frameworks).where(SystemProfile.system_id == system.id)
        )
    ).scalars().first() or []
    for code in declared:
        if str(code).strip().upper() in _NIST_171_CODES:
            return AppliedFramework(
                key="nist_800_171",
                label="NIST SP 800-171 Rev. 2 (110 requirements)",
                denominator="nist_800_171",
                source="profile.frameworks",
            )
    return None


async def _nist_171_posture(
    session: AsyncSession, *, system_id: int, applied: AppliedFramework
) -> dict[str, Any]:
    """Posture against the 110 requirements, from scan results and claimed states.

    Precedence matches the 800-53 path deliberately: a requirement any failing
    test bears on is failing, whatever else claims it. A documented state that
    machine evidence contradicts is not a satisfied requirement.

    Two things are reported that the baseline path has no equivalent for:
    ``unmappable_controls`` names tested controls the crosswalk could not place,
    and ``unreachable`` names requirements no 800-53 control maps to at all --
    the ceiling on what any scan can evidence here.
    """
    practices = {
        nist_id: control_id
        for nist_id, control_id in (
            await session.execute(
                select(ScoringControl.nist_id, ScoringControl.control_id).where(
                    ScoringControl.nist_id.is_not(None)
                )
            )
        ).all()
    }
    if not practices:
        return _empty_framework(applied, reason="the 800-171 requirement matrix is not loaded")

    tested: dict[str, set[str]] = {}
    for control_id, status in (
        await session.execute(
            select(ControlTest.control_id, ControlTest.last_status).where(
                ControlTest.system_id == system_id,
                ControlTest.control_id.is_not(None),
                ControlTest.last_status.is_not(None),
            )
        )
    ).all():
        tested.setdefault(control_id, set()).add(status)

    mapped, unmappable = await practices_for_controls(session, set(tested))
    by_requirement: dict[str, set[str]] = {}
    for control_id, statuses in tested.items():
        for requirement in mapped.get(control_id, ()):  # unmapped contribute nothing
            by_requirement.setdefault(requirement, set()).update(statuses)

    # A claimed implementation state, from the SPRS matrix. Only an *assessed*
    # state counts: a state the intake derivation computed from a platform
    # placemat is not somebody's claim about this system (see migration 0089),
    # and crediting it here would put the same unassessed credit into a second
    # report.
    claimed = {
        nist_id
        for nist_id, state, source in (
            await session.execute(
                select(ScoringControl.nist_id, ScoringStatus.state, ScoringStatus.source)
                .join(ScoringStatus, ScoringStatus.scoring_control_id == ScoringControl.id)
                .where(ScoringStatus.system_id == system_id)
            )
        ).all()
        if nist_id and source != "derived" and state in _CLAIMED_STATES
    }

    total = set(practices)
    failing = {r for r, statuses in by_requirement.items() if "fail" in statuses} & total
    passing = {r for r, statuses in by_requirement.items() if statuses == {"pass"}} & total
    documented = (claimed & total) - failing - passing
    unaddressed = total - failing - passing - documented
    reachable = set((await _crosswalk_reachable(session)) & total)

    return {
        "framework": applied.key,
        "framework_label": applied.label,
        "framework_source": applied.source,
        "denominator": applied.denominator,
        "unit": "requirement",
        "baseline": None,
        "total": len(total),
        "passing": sorted(passing, key=_requirement_sort),
        "failing": sorted(failing, key=_requirement_sort),
        "documented": sorted(documented, key=_requirement_sort),
        "unaddressed": sorted(unaddressed, key=_requirement_sort),
        "addressed_pct": round(100 * (len(passing) + len(documented)) / len(total), 1),
        "assessed_pct": round(100 * (len(passing) + len(failing)) / len(total), 1),
        # The honest limits of this view, beside the numbers rather than in a
        # footnote somebody has to go and find.
        "unmappable_controls": sorted(unmappable),
        "unreachable": sorted(total - reachable, key=_requirement_sort),
        "practice_ids": {r: practices[r] for r in sorted(total, key=_requirement_sort)},
        "reason": None,
    }


#: SPRS states that count as the requirement being claimed as in place. Mirrors
#: ``scoring.engine._MET`` plus ``partial``, which is what `ssp_present` already
#: treats as present -- restating the set here would let the two drift.
_CLAIMED_STATES = MET_STATES | {"partial"}


def _requirement_sort(requirement: str) -> tuple[int, ...]:
    """``3.10.2`` sorts after ``3.9.1``, which a string sort gets wrong."""
    try:
        return tuple(int(p) for p in requirement.split("."))
    except ValueError:
        return (0,)


async def _crosswalk_reachable(session: AsyncSession) -> set[str]:
    """Every 800-171 requirement some 800-53 control maps to."""
    rows = (
        await session.execute(
            select(Control.identifier)
            .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
            .join(Framework, Framework.id == FrameworkMapping.framework_id)
            .where(
                Framework.code == CROSSWALK_FRAMEWORK,
                FrameworkMapping.column_key == CROSSWALK_COLUMN,
            )
        )
    ).scalars().all()
    mapped, _ = await practices_for_controls(session, set(rows))
    return {r for reqs in mapped.values() for r in reqs}


def _empty_framework(
    applied: AppliedFramework | None, *, reason: str
) -> dict[str, Any]:
    """No measurable framework -- and the payload says why, in the payload.

    Never zeros alone. A consumer reading ``failing: []`` with no explanation
    concludes nothing is wrong, which is precisely the reading that made this
    worth fixing.
    """
    return {
        "framework": applied.key if applied else None,
        "framework_label": applied.label if applied else None,
        "framework_source": applied.source if applied else None,
        "denominator": applied.denominator if applied else None,
        "unit": None,
        "baseline": applied.baseline if applied else None,
        "total": 0,
        "passing": [],
        "failing": [],
        "documented": [],
        "unaddressed": [],
        "addressed_pct": 0.0,
        "assessed_pct": 0.0,
        "unmappable_controls": [],
        "unreachable": [],
        "practice_ids": {},
        "reason": reason,
    }


async def system_framework_posture(
    session: AsyncSession, *, org_id: int | None, system_id: int
) -> dict[str, Any]:
    """One system's scan results, expressed in its own framework's units.

    The API's per-system answer. Resolves the framework first, then measures in
    that framework -- so an 800-171 system is reported over 110 requirements and
    a Moderate system over its 800-53 baseline, rather than one shape being
    forced onto both.
    """
    system = await session.get(System, system_id)
    if system is None or (org_id is not None and system.organization_id != org_id):
        # No name to give: naming a system across a tenant boundary would
        # confirm it exists. `system_id` is the caller's own input, so echoing
        # it discloses nothing.
        return {
            **_empty_framework(None, reason="system not found"),
            "system_id": system_id,
            "system": None,
        }

    # Every path below returns through here, so `system_id` and `system` are on
    # the payload whatever happened. They were once set only after the branches,
    # and the early returns skipped them -- which put entries into the
    # organization-wide list that a consumer could not attribute to a system.
    def _answer(payload: dict[str, Any]) -> dict[str, Any]:
        return {**payload, "system_id": system_id, "system": system.name}

    applied = await resolve_applied_framework(session, system)
    if applied is None:
        return _answer(
            _empty_framework(
                None,
                reason=(
                    "no framework is declared for this system: set a FIPS-199 baseline, "
                    "or name a framework in its intake profile"
                ),
            )
        )
    if applied.denominator == "nist_800_171":
        return _answer(
            await _nist_171_posture(session, system_id=system_id, applied=applied)
        )
    base = await framework_posture(session, org_id=org_id, system_id=system_id)
    if not base["total"]:
        return _answer(
            _empty_framework(
                applied,
                reason=(
                    f"the {applied.baseline} baseline resolves to no controls: "
                    "the 800-53 catalog is not loaded with FIPS-199 membership"
                ),
            )
        )
    return _answer(
        {
            **base,
            "framework": applied.key,
            "framework_label": applied.label,
            "framework_source": applied.source,
            "denominator": applied.denominator,
            "unit": "control",
            "unmappable_controls": [],
            "unreachable": [],
            "practice_ids": {},
            "reason": None,
        }
    )


async def org_framework_posture(
    session: AsyncSession, org_id: int | None
) -> dict[str, Any]:
    """Every live system in the organization, each in its own framework's units.

    ``org_id`` of ``None`` returns the empty shape. That is a **contract**, not
    a security boundary, and the difference is worth stating plainly: because
    ``systems.organization_id`` is ``NOT NULL`` and SQLAlchemy renders
    ``== None`` as ``IS NULL``, deleting the guard makes this return *nothing*
    rather than everything. Mutation testing said so, against an earlier version
    of this docstring that claimed the guard stopped a caller with no
    organization from reading every tenant's posture. It does not, and nothing
    should be read as protected by it. What actually scopes the answer is the
    ``organization_id`` predicate on the query below and the per-system check
    inside :func:`system_framework_posture`.

    There is deliberately **no cross-system total**. Two systems on different
    frameworks have different denominators and different units, and adding a
    requirement count to a control count produces a number that means nothing
    while looking authoritative. What is summed is per framework.
    """
    if org_id is None:
        return {"systems": [], "by_framework": {}, "systems_without_a_framework": []}
    systems = (
        await session.execute(
            select(System)
            .where(System.organization_id == org_id, System.deleted_at.is_(None))
            .order_by(System.id)
        )
    ).scalars().all()

    out: list[dict[str, Any]] = []
    by_framework: dict[str, dict[str, Any]] = {}
    undeclared: list[dict[str, Any]] = []
    for system in systems:
        entry = await system_framework_posture(session, org_id=org_id, system_id=system.id)
        out.append(entry)
        if entry["framework"] is None:
            undeclared.append(
                {"system_id": system.id, "system": system.name, "reason": entry["reason"]}
            )
            continue
        bucket = by_framework.setdefault(
            entry["framework"],
            {
                "label": entry["framework_label"],
                "unit": entry["unit"],
                "systems": 0,
                "total": 0,
                "passing": 0,
                "failing": 0,
                "documented": 0,
                "unaddressed": 0,
            },
        )
        bucket["systems"] += 1
        bucket["total"] += entry["total"]
        for key in ("passing", "failing", "documented", "unaddressed"):
            bucket[key] += len(entry[key])
    return {
        "systems": out,
        "by_framework": by_framework,
        "systems_without_a_framework": undeclared,
    }


__all__ = [
    "ADDRESSED_STATUSES",
    "BASELINE_COLUMNS",
    "AppliedFramework",
    "baseline_controls",
    "fold_to_control",
    "framework_posture",
    "org_framework_posture",
    "resolve_applied_framework",
    "system_framework_posture",
]
