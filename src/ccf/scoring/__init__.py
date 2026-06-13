"""CMMC Level 2 live scoring engine.

Replaces the static *CMMC L2 Assessment Methods Scoring Matrix* spreadsheet with
a real-time, per-system SPRS scoring model:

- ``parser``  — read the workbook (or the committed seed) into structured records.
- ``engine``  — pure SPRS-score functions (start at 110, deduct per finding).
- ``seed``    — load the reference matrix into ``ccf.scoring_controls``.
"""

from __future__ import annotations

from .engine import (
    MAX_SPRS_SCORE,
    ControlScore,
    ScoreSummary,
    deduction_for,
    score_system,
)

__all__ = [
    "MAX_SPRS_SCORE",
    "ControlScore",
    "ScoreSummary",
    "deduction_for",
    "score_system",
]
