"""Measure how often the engine's proposed findings match assessors' decisions.

There is no new pipeline here. The acceptance gate already produces labelled data
as a side effect of work assessors do anyway -- an accepted proposal is someone
saying the verdict was right, a rejected one says it was wrong and records what
should have been there instead. Calibration is a query over those rows.

The two error directions are reported separately and never averaged, because
their costs differ sharply. A control passing that should not is a missed finding
in an authorization package. The reverse is wasted remediation effort. Collapsing
them into one accuracy figure hides the number actually worth watching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models_assessment_engine import AssessmentControlProposal
from ...prep.screen import normalize_control_identifier


def control_family(control_identifier: str) -> str:
    """The family prefix (``AC``, ``SC``) a control belongs to.

    Folds through the shared identifier normaliser first, so ``AC-02`` and
    ``AC-2`` group together and surrounding whitespace does not produce a
    family of its own. CMMC-style identifiers (``AC.L2-3.1.1``) keep their
    leading alphabetic run, which is the family there too.

    The prefix is upper-cased because the family is a grouping key, not a
    display value: without it ``ac-2`` and ``AC-2`` would land in two separate
    buckets and each would report half of that family's real counts. The
    shared normaliser deliberately preserves case for identifier matching, so
    the folding has to happen here.
    """
    canonical = normalize_control_identifier(control_identifier)
    prefix = ""
    for char in canonical:
        if char.isalpha():
            prefix += char
        else:
            break
    return (prefix or canonical).upper()


@dataclass(slots=True)
class FamilyMetrics:
    """One control family's agreement, split by error direction."""

    decided: int = 0
    agreed: int = 0
    missed_findings: int = 0
    false_alarms: int = 0


@dataclass(slots=True)
class CalibrationMetrics:
    """Agreement between proposed findings and assessors' decisions."""

    decided: int = 0
    agreed: int = 0
    agreement_rate: float = 0.0
    #: Proposed satisfied, corrected to other_than_satisfied -- a control passes
    #: that should not. The number to watch.
    missed_findings: int = 0
    #: Proposed other_than_satisfied, corrected to satisfied -- wasted effort.
    false_alarms: int = 0
    #: Any other corrected pair, e.g. a correction to not_applicable.
    other_disagreements: int = 0
    by_family: dict[str, FamilyMetrics] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """A JSONB-safe view, for storing on a snapshot."""
        return {
            "decided": self.decided,
            "agreed": self.agreed,
            "agreement_rate": self.agreement_rate,
            "missed_findings": self.missed_findings,
            "false_alarms": self.false_alarms,
            "other_disagreements": self.other_disagreements,
            "by_family": {
                name: {
                    "decided": f.decided,
                    "agreed": f.agreed,
                    "missed_findings": f.missed_findings,
                    "false_alarms": f.false_alarms,
                }
                for name, f in sorted(self.by_family.items())
            },
        }


async def compute_metrics(
    session: AsyncSession, *, organization_id: int
) -> CalibrationMetrics:
    """Compute calibration over one organization's decided proposals.

    ``organization_id`` must come from the caller's principal (derived from
    ``Assessment -> System -> Organization``, per this table's application-layer
    isolation -- see ``models_assessment_engine.py``'s module docstring), never
    from an argument a caller could forge.
    """
    rows = (
        (
            await session.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.organization_id == organization_id,
                    AssessmentControlProposal.state.in_(("accepted", "rejected")),
                )
            )
        )
        .scalars()
        .all()
    )

    metrics = CalibrationMetrics()
    for row in rows:
        family = metrics.by_family.setdefault(
            control_family(row.control_identifier), FamilyMetrics()
        )
        metrics.decided += 1
        family.decided += 1

        if row.state == "accepted":
            metrics.agreed += 1
            family.agreed += 1
            continue

        proposed, corrected = row.proposed_finding, row.corrected_finding
        if proposed == "satisfied" and corrected == "other_than_satisfied":
            metrics.missed_findings += 1
            family.missed_findings += 1
        elif proposed == "other_than_satisfied" and corrected == "satisfied":
            metrics.false_alarms += 1
            family.false_alarms += 1
        else:
            metrics.other_disagreements += 1

    if metrics.decided:
        metrics.agreement_rate = metrics.agreed / metrics.decided
    return metrics
