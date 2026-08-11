"""Roll objective verdicts into a proposed control finding.

Deliberately a pure function over a list of verdict strings: the policy that turns
analysis into a proposed finding is application code, and a model cannot reach it.

NIST SP 800-53A semantics are strict -- a control is satisfied only when every one
of its objectives is satisfied -- so the default policy is unanimity, not a
threshold. ``insufficient_evidence`` is a proposal-only outcome: it means the
engine could not tell, which is different from the control failing, and conflating
them would manufacture POA&Ms out of missing evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...models_assessment_engine import OBJECTIVE_VERDICTS


@dataclass(slots=True)
class Rollup:
    """A proposed control finding and why the policy reached it."""

    finding: str
    rationale: str


def roll_up(verdicts: list[str]) -> Rollup:
    """Apply the assessment policy to one control's objective verdicts."""
    unknown = [v for v in verdicts if v not in OBJECTIVE_VERDICTS]
    if unknown:
        raise ValueError(f"unknown objective verdict(s): {sorted(set(unknown))}")

    total = len(verdicts)
    counts = {v: verdicts.count(v) for v in OBJECTIVE_VERDICTS}
    summary = (
        f"{total} objective(s): "
        + ", ".join(f"{n} {v}" for v, n in counts.items() if n)
        if total
        else "0 objectives"
    )

    if total == 0:
        return Rollup(
            finding="insufficient_evidence",
            rationale=f"{summary} -- a control with no objectives cannot be proposed as satisfied.",
        )
    if counts["not_satisfied"]:
        return Rollup(
            finding="other_than_satisfied",
            rationale=f"{summary} -- 800-53A requires every objective to be satisfied.",
        )
    if counts["insufficient_evidence"]:
        return Rollup(
            finding="insufficient_evidence",
            rationale=f"{summary} -- evidence did not settle every objective.",
        )
    if counts["not_applicable"] == total:
        return Rollup(finding="not_applicable", rationale=f"{summary} -- all objectives N/A.")
    return Rollup(finding="satisfied", rationale=f"{summary} -- every applicable objective met.")
