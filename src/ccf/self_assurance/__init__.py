"""Concord-on-Concord self-assurance — seed, assess, and export Concord's own package.

Ties together the pack runtime (the ``concord-self-assurance`` pack), the reliability
checks (which supply the evidence), the evidence repository + confidence scoring, and
authorization-package export — so Concord can continuously assess itself.
"""

from __future__ import annotations

from .service import export_package, init_self_assurance, run_self_assessment, status

__all__ = ["export_package", "init_self_assurance", "run_self_assessment", "status"]
