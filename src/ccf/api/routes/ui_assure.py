"""Pages for the GRC program build-out.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md (section H).
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(include_in_schema=False)
