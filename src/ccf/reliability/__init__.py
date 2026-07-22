"""System reliability / operational-readiness checks.

A single ``run_checks`` entrypoint produces a list of :class:`Check` results
(name, status pass/warn/fail, message, remediation hint, timestamp). Surfaced via
the CLI (``ccf reliability-check``), the API (``/api/admin/reliability``), and the
admin UI. Includes both platform checks (DB connectivity, migration status, core
tables, catalog sanity, service availability) and FedRAMP 20x checks (KSI catalog
loaded, validation/readiness/package services, dependency + assessor + conmon
availability, OSCAL-shaped export).

``run_blocking_checks`` runs a small, cheap subset (``BLOCKING_CHECKS``) of
checks whose FAIL means the instance is unsafe to serve traffic — used by
``/readyz`` to gate rotation. The full suite stays behind ``/api/admin/reliability``.
"""

from __future__ import annotations

from .checks import BLOCKING_CHECKS, Check, run_blocking_checks, run_checks, summarize

__all__ = ["BLOCKING_CHECKS", "Check", "run_blocking_checks", "run_checks", "summarize"]
