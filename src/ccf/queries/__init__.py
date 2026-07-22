"""Assurance query layer — deterministic, parameterized queries over the data.

A registry of named, typed query templates (:mod:`ccf.queries.registry`) that
auditors/AOs run to answer canned questions about the authorization posture —
tenant-scoped, exportable, and reproducible (same template + params → same answer).
No AI: every runner is plain parameterized SQL.
"""

from __future__ import annotations

from .registry import REGISTRY, TEMPLATES
from .service import export_csv, list_templates, run_query

__all__ = ["REGISTRY", "TEMPLATES", "export_csv", "list_templates", "run_query"]
