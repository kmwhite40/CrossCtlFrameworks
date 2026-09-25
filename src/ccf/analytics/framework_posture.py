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
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Control, ControlImplementation, System
from ..models_grc import ControlTest

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


__all__ = [
    "ADDRESSED_STATUSES",
    "BASELINE_COLUMNS",
    "baseline_controls",
    "fold_to_control",
    "framework_posture",
]
