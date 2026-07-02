"""Compliance pack runtime — validate, install, upgrade, coverage, test.

Packs are JSON manifests (bundled under ``ccf/packs/bundled/`` or supplied via a
path). :mod:`ccf.packs.catalog` loads + validates them; :mod:`ccf.packs.service`
installs them idempotently, computes per-system coverage, and runs pack tests.
Packs can never create cross-tenant data — everything is written under the
installing tenant's ``organization_id`` (and RLS enforces it).
"""

from __future__ import annotations

from .catalog import list_available, load_pack, validate_manifest
from .service import coverage, install_pack, run_tests

__all__ = [
    "coverage",
    "install_pack",
    "list_available",
    "load_pack",
    "run_tests",
    "validate_manifest",
]
