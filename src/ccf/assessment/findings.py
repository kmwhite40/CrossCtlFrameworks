"""The objective-grain finding vocabulary, shared by the assessor form and the API.

It lives here, not in ``api.routes.ui``, because both ``api.routes.ui`` and
``api.routes.assessments`` need it and ``ui`` imports from ``assessments``:
defining it in either route module makes the two import each other.
"""

from __future__ import annotations

from ..models_assessment_engine import OBJECTIVE_VERDICTS
from .seed import FINDINGS

# ---------------------------------------------------------------------------
# Objective-grain finding vocabulary -- the per-objective <select> on the
# assessor form. DISTINCT from _FINDING_META above, which is control grain and
# deliberately unchanged.
#
# ``AssessmentControlResult.objective_findings`` has TWO producers with two
# vocabularies: the seeder and this form write ``ccf.assessment.seed.FINDINGS``;
# the assessment engine writes ``ccf.models_assessment_engine
# .OBJECTIVE_VERDICTS`` into the same JSONB on acceptance (see
# ``ccf.assessment.engine.service._objective_finding_record``). The select was
# built from the first list alone, so an objective holding ``not_satisfied`` or
# ``insufficient_evidence`` rendered with NO matching <option>; a browser then
# submits the first one, and the next save wrote ``not_assessed`` over it. A
# real failure, or a real "the evidence did not settle this", downgraded to
# "nobody looked" by an assessor merely opening the page and pressing Save --
# and since the SAR is built at objective grain (``oscal.build_sar_doc``) that
# value reaches the artifact an assessor ingests.
#
# The list is the UNION of the two constants, DERIVED from them rather than
# restated, so a future member of either is offered here without a second edit.
#
# BOTH failure spellings are offered, deliberately. They are one determination
# in two standards' words -- ``constants._FINDING_ALIASES`` maps
# ``not_satisfied`` onto ``OTHER_THAN_SATISFIED``, and nothing downstream
# branches on which spelling was stored. Offering only one was considered and
# rejected twice over: it makes the other unrepresentable, which is precisely
# the defect being fixed, and a row-dependent list (show the stored spelling
# only) would leave an assessor unable to record ``not_satisfied`` on an
# objective currently ``satisfied`` while the engine records exactly that on
# the objective beside it. The labels name the standard, so the choice is
# informed rather than a coin toss.
#
# ``insufficient_evidence`` and ``not_assessed`` are NOT merged, although both
# canonicalize to NOT_ASSESSED (``constants._FINDING_ALIASES``): one means the
# evidence was examined and did not settle the question, the other that nobody
# looked. The OSCAL layer keeps them apart with a ``determination`` prop, and
# the form an assessor types into must be able to say each.
_OBJECTIVE_FINDING_DISPLAY: dict[str, tuple[str, str]] = {
    "not_assessed": ("Not assessed", "chip--ghost"),
    "satisfied": ("Satisfied", "chip--ok"),
    "other_than_satisfied": ("Other than satisfied (800-171A)", "chip--err"),
    "not_satisfied": ("Not satisfied (800-53A)", "chip--err"),
    "insufficient_evidence": ("Insufficient evidence", "chip--warn"),
    "not_applicable": ("N/A", "chip--info"),
}

#: Both producers' vocabularies, deduplicated in first-seen order.
_OBJECTIVE_FINDINGS: tuple[str, ...] = tuple(dict.fromkeys((*FINDINGS, *OBJECTIVE_VERDICTS)))


def _objective_finding_option(key: str) -> tuple[str, str, str]:
    """One <option>. An unlisted key still gets a readable label, never a
    blank one -- a nameless determination beside an objective is worse than an
    ugly one."""
    label, cls = _OBJECTIVE_FINDING_DISPLAY.get(key, (key.replace("_", " "), "chip--ghost"))
    return key, label, cls


def objective_finding_options(stored: str | None) -> list[tuple[str, str, str]]:
    """The options one objective's <select> renders, given what the row holds.

    ``_OBJECTIVE_FINDINGS`` plus ``stored`` itself whenever it falls outside
    it. The column is free JSONB with no DB constraint, so "outside it" is
    reachable -- a legacy import, or a producer added after this list -- and
    appending it is what makes the rendered select able to represent EVERY
    value the data can actually hold, not merely the two vocabularies known
    today. The stored value is therefore ALWAYS selectable, so a select nobody
    touched always submits back exactly what it was rendered from. That
    property, not the width of the list, is what stops a save from rewriting a
    finding the assessor never looked at.

    ``assessment_save_result`` builds its accept-list from this same function,
    so the page and the handler cannot drift into disagreeing about what was
    offerable -- the drift that caused the original defect.
    """
    key = stored or "not_assessed"
    options = [_objective_finding_option(k) for k in _OBJECTIVE_FINDINGS]
    if key not in _OBJECTIVE_FINDINGS:
        options.append((key, f"{key} (as recorded)", "chip--ghost"))
    return options
