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


def poam_leaves_risk_accepted(old_status: str, new_status: str) -> bool:
    """True when a status transition moves a POA&M OUT of ``risk_accepted``.

    The ONE rule behind "clear ``acceptance_rationale`` on any transition out
    of ``risk_accepted``" (CR26 spec §9.1) -- expressed once here so its two
    call sites cannot drift apart: ``ccf.api.routes.poams.update_poam`` (an
    operator's PATCH) and ``ccf.ingest.scanners`` (a scan re-detecting a
    vulnerability and reopening it, ``poam.status = "open"``, with no
    operator in the loop at all to notice a stale rationale riding along).
    Both would otherwise let a superseded acceptance's reason survive,
    unlabelled, to be read as the justification for a DIFFERENT decision it
    was never written for -- this project's dominant defect shape, and the
    kind of thing that has already drifted apart twice on this one branch.

    Pure and value-only, not POAM-object-shaped, so it can live in this
    constants module without pulling ``ccf.models`` into it (``models.py``
    already imports FROM here) -- each call site decides how to apply the
    answer to its own object.
    """
    return old_status == "risk_accepted" and new_status != "risk_accepted"

# ---------------------------------------------------------------------------
# CR26 Certification vocabulary.
#
# A Certification Class describes the DEPTH, FREQUENCY and QUALITY of the
# assurance data a provider commits to supplying -- not the sensitivity of the
# information a system holds. FedRAMP is explicit that the two are different
# axes:
#   "Agencies should not treat Certification Classes as one-for-one
#    replacements for Low, Moderate, or High impact levels."
#   "FedRAMP Certification Classes are not aligned to how secure a cloud
#    service offering is!"
# The published definitions are deliberately overlapping adequacy ranges: B is
# adequate for most Low and SOME Moderate or High; C for most Low or Moderate
# and SOME High; D for most systems regardless of impact level.
#
# So NOTHING may derive a Class from ``System.baseline``, or a baseline from a
# Class. Such a derivation is wrong in both directions, and
# tests/test_certification_class_is_independent.py enforces it.
CERTIFICATION_CLASSES: tuple[str, ...] = ("A", "B", "C", "D")

#: Program certification, or an agency-sponsored path to one.
CERTIFICATION_PATHS: tuple[str, ...] = ("program", "agency")

# ---------------------------------------------------------------------------
# Concord pipeline stage.
#
# NOT a FedRAMP vocabulary. FedRAMP has published no status enumeration: the
# brand pages give two marketplace designations (Certified (Rev5), Validated
# (20x)) and nothing more, and the only place the five-per-regime status lists
# appear is RFC-0020, which is a PROPOSAL -- "March 18, 2026 (tentatively)",
# no adoption banner. See docs/superpowers/specs/2026-09-21-pipeline-stage-design.md
# §1, checked at source 2026-09-21.
#
# So this field answers Concord's own question -- "where does Concord
# understand this system to be?" -- and borrows RFC-0020's words only so the
# values are recognisable to an operator. It deliberately does NOT answer "what
# does the FedRAMP Marketplace say about this system?", which is a fact about a
# register Concord does not ingest. One field answering both would be an
# operator's private note read as a federal fact, which is this programme's
# recurring claim-versus-rendering defect in its purest form. That is also why
# the column is named ``pipeline_stage`` and not ``certification_status``, and
# why the old name is not kept as an alias.
#
# RFC-0020 gives TWO five-member lists, overlapping on three words and
# differing on two each: Continuous Monitoring is Rev5-only, Persistent
# Validation and Prioritized are 20x-only. A flat seven-member union would make
# "Rev5 + Persistent Validation" storable -- a value that validates while
# asserting something that cannot be true. Carrying the regime INSIDE the value
# makes that pair unrepresentable: no check constraint to write, no second
# column to disagree with, nothing to keep in sync. A ``certification_type``
# column was considered and rejected (spec §3): certificationType is a
# declaration the provider makes, deliberately absent from the CPO seeder, and
# a column for it would smuggle that declaration in through a side door.
#
# NULL means "nobody has said" -- the only honest default on a field no
# platform signal can populate. Nothing derives a stage from anything
# (tests/test_certification_class_is_independent.py enforces it), and no stage
# may ever reach a filed CR26 document
# (tests/test_pipeline_stage_is_never_filed.py enforces that).
PIPELINE_STAGES: tuple[str, ...] = (
    "rev5:preparation",
    "rev5:agency-authorization-in-process",
    "rev5:assessment-by-fedramp",
    "rev5:continuous-monitoring",
    "rev5:remediation",
    "20x:preparation",
    "20x:prioritized",
    "20x:assessment-by-fedramp",
    "20x:persistent-validation",
    "20x:remediation",
)

# ---------------------------------------------------------------------------
# External portal principal / grant kinds.
#
# ``ExternalPrincipal.kind`` and ``ExternalAccessGrant.kind`` carried this
# vocabulary in a trailing ``# customer|assessor|vendor`` comment only: nothing
# validated it and nothing branched on it, so ``kind="assesor"`` stored fine and
# behaved identically to every other value. That is the same defect shape as an
# ``issm``/``isso`` typo -- an authorization-adjacent vocabulary that exists
# only in prose, where a misspelling is indistinguishable from a real member.
#
# Deliberately NOT a Postgres enum. Both are pre-existing ``String(16)`` columns
# that may already hold unknown values in live databases, and a migration
# converting them would fail on the first such row -- blocking an upgrade over
# data the operator cannot see. Migration 0083 therefore COUNTS and REPORTS
# out-of-vocabulary rows and leaves them untouched; enforcement is at the
# service layer, on write (``ccf.portal.service._require_kind``), with 422 at
# the route. Existing odd rows keep working and stay visible; new ones cannot
# be created.
#
# ``assessor`` here is an EXTERNAL party -- an independent assessment firm
# reached through the portal. It is not the internal ``user_role`` member of the
# same name, which is the CSP's own assessment staff. See
# docs/superpowers/specs/2026-09-21-3pao-engagement-design.md §1.1: the two must
# not be merged, because merging them would put an independent firm inside the
# tenant's own user table.
EXTERNAL_PRINCIPAL_KINDS: tuple[str, ...] = ("customer", "assessor", "vendor")
