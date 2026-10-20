"""Pages for the GRC program build-out.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md.

Filled in by the tprmprog workstream; registered in ccf.api.main.
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(include_in_schema=False)
