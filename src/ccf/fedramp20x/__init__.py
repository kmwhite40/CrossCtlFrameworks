"""FedRAMP 20x support — Key Security Indicators (KSIs), deterministic validation,
readiness scoring, authorized-dependency tracking, assessor review, and a
machine-readable authorization-package foundation.

FedRAMP 20x is kept logically separate from the traditional FedRAMP Rev. 5
baseline/scoring (``ccf.scoring`` + ``systems.baseline``) but stays traceable to
NIST SP 800-53 through the KSI catalog's ``nist_refs`` mapping. FedRAMP 20x is an
evolving pilot; catalog wording/mappings are representative and updated via the
seed file, not business logic. Nothing here claims official FedRAMP authorization
or validated OSCAL output.
"""

from __future__ import annotations

# Vocabularies enforced at the API layer (statuses are strings because the 20x
# program is still evolving — see module docstring).
VALIDATION_STATUSES = (
    "pass",
    "warn",
    "fail",
    "not_tested",
    "manual_review_required",
    "not_applicable",
)

READINESS_STATUSES = (
    "not_started",
    "initial_build",
    "evidence_collection",
    "validation_in_progress",
    "assessor_review",
    "ready_for_submission",
    "submitted",
    "authorized",
    "continuous_monitoring",
)

ASSESSOR_STATUSES = (
    "not_reviewed",
    "in_review",
    "accepted",
    "rejected",
    "needs_clarification",
    "retest_required",
    "finding_opened",
    "closed",
)

DEPENDENCY_STATUSES = ("authorized", "in_process", "not_authorized", "unknown")

# --- FedRAMP CR26 display labels (FR-14) ------------------------------------
#
# FedRAMP CR26 (effective 2026-07-04, enforced 2027-01-01) renames the
# program's own vocabulary: "Authorized" -> "Certified" and "Continuous
# Monitoring" -> "Ongoing Certification". This is a *display-only* rename
# scoped to the fedramp20x UI surfaces (FR-14): the stored/returned enum
# values (``authorized``, ``continuous_monitoring`` in READINESS_STATUSES and
# DEPENDENCY_STATUSES) are left unchanged so the database, API contracts, and
# scoring/validation logic are unaffected. Only how a fedramp20x-specific
# template renders those values should change.
#
# NOT included here: CR26 also introduces an impact-level -> Certification-
# Class (A/B/C/D) mapping. That mapping needs primary-source confirmation
# before it can be hardcoded, so it is deliberately left out — this is a
# follow-up, not an oversight.
CR26_DISPLAY_LABELS: dict[str, str] = {
    "authorized": "Certified",
    "continuous_monitoring": "Ongoing Certification",
}


def cr26_display_label(value: str | None) -> str:
    """Map a fedramp20x status VALUE to its CR26 display label.

    Only affects rendering: values with no CR26 rename (e.g. ``not_started``,
    ``in_process``) pass through unchanged, and the stored value itself is
    never modified — callers should keep using the raw value for persistence,
    filtering, and API responses.
    """
    if value is None:
        return ""
    return CR26_DISPLAY_LABELS.get(value, value)


__all__ = [
    "ASSESSOR_STATUSES",
    "CR26_DISPLAY_LABELS",
    "DEPENDENCY_STATUSES",
    "READINESS_STATUSES",
    "VALIDATION_STATUSES",
    "cr26_display_label",
]
