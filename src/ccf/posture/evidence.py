"""Which controls a recorded test is evidence about.

A :class:`~ccf.posture.types.PostureCheck` declares ``control_ids`` -- the
controls it evidences. A scan stores the first of them in
``ControlTest.control_id`` and the whole tuple in ``ControlTest.control_ids``
(migration 0092). This module is the one place that reconciles the two, so a
reader never has to decide what a null means.

**The asymmetry is deliberate, and it is the point of the module.**

A check that does *not* pass reaches every control it declares. The
guest-invitation check declares ``AC-3`` and ``AC-6``; a tenant that lets any
member invite external guests has a finding against both, and reporting it
against only ``AC-3`` leaves a real gap out of the coverage report. The same
holds for ``manual_review_required``: if Concord could not judge the check, it
could not judge any control the check bears on, and saying so under one of them
while the others read clean is the same understatement in a quieter form.

A check that *passes* credits only its primary control. One check rarely
satisfies a whole control, and the further down a check's declared tuple a
control sits, the more partial the evidence: restricted guest invitations are
some evidence for ``AC-3`` and very little for ``AC-6`` (least privilege).
Crediting the whole tuple on a pass would let a single narrow check mark
several controls satisfied -- a value that validates and is wrong, in a
document a regulator acts on.

This mirrors the precedence the rollups already apply to documented claims: a
documented implementation does not survive evidence that it is not operating.
Evidence of failure is conclusive about what it touches; evidence of success is
partial.
"""

from __future__ import annotations

from collections.abc import Iterable


def evidenced_controls(control_id: str | None, control_ids: Iterable[str] | None) -> list[str]:
    """Every control a test is evidence about, primary first, deduplicated.

    ``control_ids`` is null on rows written before migration 0092 and on
    authored (human) tests, which have exactly one control. Both mean the same
    thing here -- the primary control alone -- so neither needs a special case
    at the call site.

    A ``control_ids`` that does not contain ``control_id`` is not corrected
    into agreement: both are returned, primary first. Silently dropping either
    would hide a scan/registry disagreement rather than report it, and the
    caller is asking what this row is evidence about, not which of two records
    it trusts.
    """
    primary = (control_id or "").strip()
    out: list[str] = [primary] if primary else []
    for raw in control_ids or ():
        candidate = str(raw).strip()
        if candidate and candidate not in out:
            out.append(candidate)
    return out


def non_passing_attribution(
    control_id: str | None, control_ids: Iterable[str] | None
) -> list[str]:
    """Controls a non-``pass`` verdict reaches: all of them.

    Covers ``fail`` and ``warn`` (the platform saying the control is not
    operating as expected) and ``manual_review_required`` (the platform saying
    it could not judge). What they share is that none of them is evidence the
    control is satisfied, so none of them may be narrowed to the primary.
    """
    return evidenced_controls(control_id, control_ids)


def pass_attribution(control_id: str | None) -> list[str]:
    """Controls a ``pass`` verdict credits: the primary one only.

    Takes no ``control_ids`` on purpose. A caller cannot widen pass credit by
    passing the tuple, because there is no parameter to pass it to.
    """
    primary = (control_id or "").strip()
    return [primary] if primary else []
