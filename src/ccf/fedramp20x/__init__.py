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

__all__ = [
    "ASSESSOR_STATUSES",
    "DEPENDENCY_STATUSES",
    "READINESS_STATUSES",
    "VALIDATION_STATUSES",
]
