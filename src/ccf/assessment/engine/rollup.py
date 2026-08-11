"""Roll objective verdicts into a proposed control finding.

Deliberately a pure function over a list of verdict strings (plus a failure
count -- see below): the policy that turns analysis into a proposed finding is
application code, and a model cannot reach it.

NIST SP 800-53A semantics are strict -- a control is satisfied only when every one
of its objectives is satisfied -- so the default policy is unanimity, not a
threshold. ``insufficient_evidence`` is a proposal-only outcome: it means the
engine could not tell, which is different from the control failing, and conflating
them would manufacture POA&Ms out of missing evidence.

``failed`` -- objectives the caller could not evaluate at all (a provider fault,
a malformed response; see ``ccf.assessment.engine.service``) -- is coverage, not
a verdict, and is deliberately a separate parameter rather than a fifth entry in
``verdicts``: an unevaluated objective did not settle on anything, so it cannot
be counted the same way a real ``insufficient_evidence`` verdict is. Any nonzero
``failed`` forces the whole rollup to ``insufficient_evidence`` regardless of
what the *evaluated* objectives showed -- a control cannot be honestly proposed
``satisfied`` (this module's caller previously used ``len(verdicts)``, the
*surviving* count, as the total, so a control with 24 of 25 objectives failing
to evaluate could still roll up ``satisfied`` on the strength of the one that
did; that is exactly the failure this parameter exists to close) or even
``other_than_satisfied`` on partial coverage -- the engine does not know what the
unevaluated objectives would have shown, and acceptance already refuses
``insufficient_evidence`` outright (see ``service.accept_control_proposal``), so
this is the one rollup outcome that can never leak a partial evaluation into a
finding.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...models_assessment_engine import OBJECTIVE_VERDICTS


@dataclass(slots=True)
class Rollup:
    """A proposed control finding and why the policy reached it."""

    finding: str
    rationale: str


def roll_up(verdicts: list[str], *, failed: int = 0) -> Rollup:
    """Apply the assessment policy to one control's objective verdicts.

    ``failed`` is the count of objectives that raised during evaluation and so
    contributed no verdict at all -- see the module docstring. The proposal's
    real total objective count is ``len(verdicts) + failed``, not
    ``len(verdicts)`` alone; a caller inferring "how many objectives this
    control has" from ``len(verdicts)`` silently drops every failed one from
    the denominator.
    """
    unknown = [v for v in verdicts if v not in OBJECTIVE_VERDICTS]
    if unknown:
        raise ValueError(f"unknown objective verdict(s): {sorted(set(unknown))}")
    if failed < 0:
        raise ValueError(f"failed must be >= 0, got {failed}")

    evaluated = len(verdicts)
    total = evaluated + failed
    counts = {v: verdicts.count(v) for v in OBJECTIVE_VERDICTS}
    verdict_breakdown = ", ".join(f"{n} {v}" for v, n in counts.items() if n)

    if failed:
        coverage = f"{evaluated} of {total} objectives evaluated, {failed} failed"
        detail = f" ({verdict_breakdown} among those evaluated)" if verdict_breakdown else ""
        return Rollup(
            finding="insufficient_evidence",
            rationale=(
                f"{coverage}{detail} -- an objective that could not be evaluated means "
                "this control cannot be proposed as satisfied or as other than satisfied."
            ),
        )

    summary = f"{total} objective(s): {verdict_breakdown}" if total else "0 objectives"

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
