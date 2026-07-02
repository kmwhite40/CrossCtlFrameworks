"""Typed agentic GRC actions — auditable, citation-first, human-approved.

:mod:`ccf.ai_actions.registry` declares the typed actions; :mod:`provider` renders
output deterministically (a citation-first stub by default, safe for local/dev and
tests); :mod:`service` runs actions, enforces guardrails, and applies the declared
mutation *only after human approval*.
"""

from __future__ import annotations

from .registry import ACTIONS, ActionDef, get_action, seed_definitions
from .service import approve_run, reject_run, run_action

__all__ = [
    "ACTIONS",
    "ActionDef",
    "approve_run",
    "get_action",
    "reject_run",
    "run_action",
    "seed_definitions",
]
