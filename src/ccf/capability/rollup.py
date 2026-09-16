"""Roll capability statuses up into one derived control status.

Pure -- no database, no I/O -- so the rule is unit-testable and cheap to reason
about. The rule is deliberately conservative: a control covered by one
``planned`` capability among ``implemented`` ones derives ``partial``, not
``implemented``. Over-claiming control status in an authorization package is
the dangerous direction; under-claiming is merely cautious, and
``derived_from`` records which capability lowered the result.

Capabilities are treated as *jointly* required for a control, which is the safe
reading when the model cannot yet express "alternative means".
"""

from __future__ import annotations

from collections.abc import Iterable

#: Statuses that mean the capability is in place.
SATISFIED: frozenset[str] = frozenset({"implemented", "inherited"})

#: Worst-to-best. Position is the rank used to pick the winning status.
RANK: tuple[str, ...] = (
    "not_implemented",
    "planned",
    "partial",
    "implemented",
    "inherited",
)

#: Excluded from the rollup entirely rather than ranked.
EXCLUDED: frozenset[str] = frozenset({"not_applicable"})


def roll_up(statuses: Iterable[str]) -> str | None:
    """The derived status for one control, or ``None`` to write nothing.

    ``None`` -- for no contributors, or only ``not_applicable`` ones -- is the
    honest answer and deliberately distinct from ``not_implemented``, which
    would assert something about a control nobody has claimed.
    """
    considered: list[str] = []
    for s in statuses:
        if s in EXCLUDED:
            continue
        if s not in RANK:
            raise ValueError(f"unknown capability status: {s!r}")
        considered.append(s)
    if not considered:
        return None

    worst = min(considered, key=RANK.index)
    # A mix of satisfied and unsatisfied is partial, not the worst member:
    # some of the control *is* in place, which "not_implemented" would deny.
    if worst not in SATISFIED and any(s in SATISFIED for s in considered):
        return "partial"
    return worst
