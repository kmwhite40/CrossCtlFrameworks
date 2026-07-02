"""Assurance graph — build + query the authorization digital twin.

:mod:`ccf.assurance.builder` (re)builds the tenant-scoped node/edge graph from
Concord's existing records, and :mod:`ccf.assurance.impact` traverses it for
impact analysis. Both degrade gracefully when an optional module/table is absent.
"""

from __future__ import annotations

from .builder import rebuild, rebuild_org, snapshot_system
from .impact import impact_for, latest_build

__all__ = ["impact_for", "latest_build", "rebuild", "rebuild_org", "snapshot_system"]
