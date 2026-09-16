"""Roll per-resource verdicts into one verdict for a check.

Pure -- no database, no I/O. Conservative by design: one failing resource
fails the check, because over-claiming posture in an authorization package is
the dangerous direction.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..fedramp20x import VALIDATION_STATUSES
from ..fedramp20x.validation import VERDICT_RANK

#: Excluded from the rollup entirely rather than ranked. They sit at rank 0,
#: *below* ``fail``, because VERDICT_RANK exists for ``any_of``'s "best wins".
#: Ranking them here would report "not applicable" for a failing check.
EXCLUDED_FROM_ROLLUP: frozenset[str] = frozenset({"not_applicable", "not_tested"})


def roll_up_findings(verdicts: Iterable[str]) -> str:
    """The check-level verdict for a set of per-resource verdicts.

    Returns ``not_applicable`` when nothing was in scope -- zero resources
    evaluated is not a passing check, and saying ``pass`` would assert
    something the scan never observed.
    """
    considered: list[str] = []
    for v in verdicts:
        if v not in VALIDATION_STATUSES:
            raise ValueError(f"unknown verdict: {v!r}")
        if v in EXCLUDED_FROM_ROLLUP:
            continue
        considered.append(v)
    if not considered:
        return "not_applicable"
    # Worst wins: the opposite selection from evaluate_rule's any_of.
    return min(considered, key=lambda v: VERDICT_RANK[v])
