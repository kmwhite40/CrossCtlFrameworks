"""Measure how often the engine's proposed findings match assessors' decisions.

There is no new pipeline here. The acceptance gate already produces labelled data
as a side effect of work assessors do anyway -- an accepted proposal is someone
saying the verdict was right, a rejected one says it was wrong and records what
should have been there instead. Calibration is a query over those rows.

The two error directions are reported separately and never averaged, because
their costs differ sharply. A control passing that should not is a missed finding
in an authorization package. The reverse is wasted remediation effort. Collapsing
them into one accuracy figure hides the number actually worth watching.

Nothing here is retrofitted: a proposal decided before the reject path existed
carries no recorded disagreement, so the first snapshot taken against existing
data starts with a small ``decided`` count. That is expected, not a bug.

A snapshot's ``config_fingerprint`` is what makes a later comparison meaningful.
Two measurements are comparable only if what was being measured -- the screen
threshold, the rollup policy, the evaluation model -- did not change underneath
them; a changed fingerprint reports as "not comparable", never as drift. See
:func:`config_fingerprint` and :func:`compare_snapshots`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import get_settings
from ...models_assessment_engine import AssessmentControlProposal, CalibrationSnapshot
from ...prep.screen import normalize_control_identifier
from .rollup import ROLLUP_POLICY_VERSION


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


def config_fingerprint(*, model: str | None = None) -> str:
    """A SHA-256 digest over what a calibration measurement depends on.

    A metric is comparable to an earlier one only if what was being measured
    did not change underneath it. Three things determine that here:
    ``prep_screen_threshold`` (the screening cutoff decides which passages ever
    reach evaluation), the rollup policy identity (the rule that turns objective
    verdicts into a proposed finding), and the evaluation model name (a different
    model is a different measuring instrument). Anything read but not folded into
    this digest is invisible to a comparison -- it can change and the comparison
    will keep reporting drift instead of "not comparable".

    The three inputs are serialised through a fixed set of dict keys and hashed
    with ``sort_keys=True`` so the digest never depends on dict iteration order --
    the same configuration must always produce the same digest, or every
    comparison degrades to "not comparable" even when nothing changed.

    ``model`` defaults to ``get_settings().ai_model``, mirroring how
    ``ccf.ai.gateway.resolve`` falls back to it when a caller does not pin a
    model explicitly.
    """
    settings = get_settings()
    payload = {
        "prep_screen_threshold": settings.prep_screen_threshold,
        "rollup_policy_version": ROLLUP_POLICY_VERSION,
        "model": model if model is not None else settings.ai_model,
    }
    canonical = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def take_snapshot(
    session: AsyncSession, *, organization_id: int, model: str | None = None
) -> CalibrationSnapshot:
    """Compute and store one calibration measurement for one organization.

    ``organization_id`` carries the same requirement as ``compute_metrics``'s:
    it must come from the caller's principal, never from a caller-supplied
    argument at the API layer, so one organization's snapshot can never be
    populated from another's decided proposals.
    """
    metrics = await compute_metrics(session, organization_id=organization_id)
    snapshot = CalibrationSnapshot(
        organization_id=organization_id,
        config_fingerprint=config_fingerprint(model=model),
        metrics=metrics.as_dict(),
    )
    session.add(snapshot)
    await session.flush()
    return snapshot


async def compare_snapshots(session: AsyncSession, a_id: int, b_id: int) -> dict[str, Any]:
    """Compare two stored snapshots, refusing to compute a delta across configurations.

    Returns ``{"comparable": False, ...}`` -- a distinct outcome, not a number --
    when the two snapshots' fingerprints differ, because a metric moving is not
    meaningful when what was being measured changed underneath it. This is not
    hypothetical: ``prep_screen_threshold`` was derived once against a single
    catalog snapshot with a measured margin of about 0.03, so it will be
    re-derived, and that re-derivation must read as an explained configuration
    change rather than an unexplained accuracy shift.
    """
    a = await session.get(CalibrationSnapshot, a_id)
    b = await session.get(CalibrationSnapshot, b_id)
    if a is None or b is None:
        missing = [i for i, s in ((a_id, a), (b_id, b)) if s is None]
        raise ValueError(f"unknown calibration snapshot id(s): {missing}")

    if a.config_fingerprint != b.config_fingerprint:
        return {
            "comparable": False,
            "reason": "configuration changed between snapshots",
            "a_fingerprint": a.config_fingerprint,
            "b_fingerprint": b.config_fingerprint,
        }

    numeric_keys = ("decided", "agreed", "agreement_rate", "missed_findings", "false_alarms")
    deltas = {
        key: b.metrics[key] - a.metrics[key]
        for key in numeric_keys
        if key in a.metrics and key in b.metrics
    }

    return {
        "comparable": True,
        "config_fingerprint": a.config_fingerprint,
        "a": a.metrics,
        "b": b.metrics,
        "deltas": deltas,
    }
