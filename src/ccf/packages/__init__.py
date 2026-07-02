"""Authorization package provenance, diff, and replay.

:func:`capture_facts` snapshots a system's authorization posture into normalized
facts; :func:`create_package` persists a package + its facts; :func:`diff_packages`
compares two; :func:`replay_package` re-derives facts from the live DB to detect
drift (read-only — never mutates authoritative state); :func:`delta_memo` renders
an assessor-facing change summary.
"""

from __future__ import annotations

from .service import (
    capture_facts,
    create_package,
    delta_memo,
    diff_packages,
    replay_package,
)

__all__ = [
    "capture_facts",
    "create_package",
    "delta_memo",
    "diff_packages",
    "replay_package",
]
