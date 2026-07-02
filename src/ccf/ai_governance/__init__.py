"""AI agent governance — inventory, risk scoring, approval, monitoring, kill-switch.

:func:`score_agent` is a pure risk scorer over the agent's autonomy, data access,
external-action capability, oversight, and monitoring coverage; the service layer
persists assessments, drives the approval workflow, and records monitoring events,
incidents, and kill-switch events (each audited).
"""

from __future__ import annotations

from .service import (
    engage_kill_switch,
    rating_for,
    review_agent,
    risk_assess,
    score_agent,
)

__all__ = [
    "engage_kill_switch",
    "rating_for",
    "review_agent",
    "risk_assess",
    "score_agent",
]
