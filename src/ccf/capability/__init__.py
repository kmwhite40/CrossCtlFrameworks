"""Assurance capability ontology — the thing the organization *does*.

A :class:`~ccf.models_capability.Capability` is authored once at the
organization level and reused across every system, project, and framework,
replacing narrative duplicated per control. Its edges point at canonical
controls, system components, risks, and KSIs; cross-framework reach resolves
through Concord's existing ``framework_mappings`` crosswalk rather than a
second mapping table.
"""

from __future__ import annotations

from .rollup import roll_up

__all__ = ["roll_up"]
