"""Canonical finding-status vocabulary shared across finding sources (ISSM-13/DATA-05).

A control's "finding" status is modeled three different ways in the schema:

- ``AssessmentResult.finding`` — a DB enum (``ccf.finding_status``):
  ``satisfied | other_than_satisfied | not_applicable``. No ``not_assessed``
  variant — the row simply doesn't exist yet for an un-worked control.
- ``AssessmentControlResult.finding`` — a free ``String`` covering the same
  three determinations plus ``not_assessed`` (app-validated against
  ``ccf.assessment.seed.FINDINGS``, not DB-enforced).
- ``ScoringStatus.state`` — a free ``String`` implementation-state vocabulary
  used to drive SPRS scoring (``ccf.scoring.engine.STATES``):
  ``not_assessed | not_implemented | planned | partial | implemented |
  inherited | not_applicable``.

None of the three columns changes here — that would be a breaking DB/enum
migration and is explicitly out of scope. This module defines ONE canonical
set those three vocabularies map onto, plus a normalization helper, so a
rollup that counts findings *across* sources doesn't double-count a control
just because one source spells "satisfied" as ``implemented`` and another
spells it ``satisfied``.

Per-source storage and per-source display are untouched by this module —
callers that only ever read one source (e.g. ``ccf.assessment.seed
.summarize_results`` for ``AssessmentControlResult``) keep using the raw
value as-is. ``normalize_finding`` is for call sites that combine sources.
"""

from __future__ import annotations

# Canonical finding-status vocabulary (NIST SP 800-171A determination
# language), extended with the two "no determination yet" buckets every
# rollup needs to be able to express.
SATISFIED = "satisfied"
OTHER_THAN_SATISFIED = "other_than_satisfied"
NOT_APPLICABLE = "not_applicable"
NOT_ASSESSED = "not_assessed"
UNKNOWN = "unknown"

# The "real" determinations + not_assessed — what AssessmentControlResult.finding
# is already validated against (see ccf.assessment.seed.FINDINGS).
CANONICAL_FINDINGS = (SATISFIED, OTHER_THAN_SATISFIED, NOT_APPLICABLE, NOT_ASSESSED)

# Every canonical bucket normalize_finding() can return, including the
# fallback for a recognized-but-unmappable raw value.
ALL_CANONICAL_FINDINGS = (*CANONICAL_FINDINGS, UNKNOWN)

# Every raw spelling seen across AssessmentResult.finding,
# AssessmentControlResult.finding, and ScoringStatus.state, mapped onto the
# canonical vocabulary above. Keys are lower-cased/stripped before lookup.
_FINDING_ALIASES: dict[str, str] = {
    # AssessmentResult (DB enum) / AssessmentControlResult (free string) —
    # already canonical spellings, listed for completeness/documentation.
    "satisfied": SATISFIED,
    "other_than_satisfied": OTHER_THAN_SATISFIED,
    "not_applicable": NOT_APPLICABLE,
    "not_assessed": NOT_ASSESSED,
    # ScoringStatus.state (SPRS implementation-state vocabulary): a control
    # actually built out (implemented, or its responsibility inherited from a
    # vendor/CSP) counts as a "satisfied" determination; a control that's
    # missing, merely planned, or only partially built counts as
    # "other_than_satisfied" — it does not yet meet the requirement.
    "implemented": SATISFIED,
    "inherited": SATISFIED,
    "not_implemented": OTHER_THAN_SATISFIED,
    "planned": OTHER_THAN_SATISFIED,
    "partial": OTHER_THAN_SATISFIED,
}


def normalize_finding(value: str | None) -> str:
    """Map any known finding/state spelling onto the canonical vocabulary.

    - ``None`` or an empty/whitespace-only string maps to ``"not_assessed"``
      (matching every source's own "nothing recorded yet" default).
    - A non-empty value not found in the alias table maps to ``"unknown"``
      rather than raising or silently folding into ``not_assessed`` — so a
      rollup over mixed/dirty data degrades gracefully and stays visible as
      its own bucket instead of either crashing or under-counting.
    - Matching is case-insensitive and whitespace-trimmed so
      ``" Satisfied "`` and ``"satisfied"`` land in the same bucket.
    """
    if value is None:
        return NOT_ASSESSED
    key = value.strip().lower()
    if not key:
        return NOT_ASSESSED
    return _FINDING_ALIASES.get(key, UNKNOWN)


# ---------------------------------------------------------------------------
# POA&M status vocabulary (ISSM). The DB enum ``ccf.poam_status`` is the source
# of truth; ``models.POAM.status`` is built from POAM_STATUSES below so the
# column, the API validator and every filter cannot drift apart.
#
# TWO "open" sets exist, and the split is DELIBERATE — do not collapse them:
#
#   POAM_ACTIVE_STATUSES     the remediation backlog. Excludes risk_accepted,
#                            which is residual risk leadership has formally
#                            accepted rather than work still to do. Every
#                            dashboard rollup uses this (see
#                            analytics/posture.py, which buckets accepted
#                            separately and says so).
#   POAM_UNRESOLVED_STATUSES not yet remediated. INCLUDES risk_accepted,
#                            because OSCAL has a first-class "risk-accepted"
#                            item state and the authorization package is
#                            expected to render it (see _OSCAL_POAM_STATE).
#
# They answer different questions. Unifying them would either hide accepted risk
# from the AO or count it as outstanding work on the dashboard.
POAM_STATUSES: tuple[str, ...] = (
    "open",
    "in_progress",
    "completed",
    "risk_accepted",
    "closed",
)
POAM_ACTIVE_STATUSES: tuple[str, ...] = ("open", "in_progress")
POAM_UNRESOLVED_STATUSES: tuple[str, ...] = ("open", "in_progress", "risk_accepted")
POAM_CLOSED_STATUSES: tuple[str, ...] = ("completed", "closed")
