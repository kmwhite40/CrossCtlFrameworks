"""Mermaid diagram generation for the system boundary (Keystone #1).

``boundary_mermaid``/``data_flow_mermaid`` are **pure functions** over a
``BoundarySummary`` — no DB access, no I/O. Because the diagrams are derived
straight from the same rows the boundary API/UI serve, they can never drift
from the inventory. Both are fully unit-testable string builders and both
degrade to a minimal, non-crashing diagram when the summary is empty.

Mermaid is picky about syntax, so every emitted identifier and label goes
through ``_sanitize_id``/``_sanitize_label``:

- Node ids are derived from the entity's persisted ``oscal_uuid`` (dashes and
  any other non-``[A-Za-z0-9_]`` characters replaced with ``_``) or, when
  that isn't set (e.g. an unsaved ORM instance in a test), a positional
  fallback like ``c0``/``ext1``. Raw titles are never used as ids.
- Labels are quoted, have embedded ``"`` and newlines stripped/escaped, and
  are capped to a short length so diagrams stay legible.

Entities are sorted by their display name before emission so the generated
Mermaid source (and therefore any assertions against it) is deterministic.
"""

from __future__ import annotations

import re

from ..models import InformationType, Interconnection, InventoryItem, SystemComponent
from .summary import BoundarySummary

_ID_UNSAFE_RE = re.compile(r"[^A-Za-z0-9_]")
_WHITESPACE_RE = re.compile(r"\s+")
_MAX_LABEL_LEN = 40


def _sanitize_id(oscal_uuid: str | None, prefix: str, index: int) -> str:
    """A Mermaid-safe node id: derived from ``oscal_uuid`` when present, else
    a positional fallback (``c0``, ``ext1``, ...). Never a raw title."""
    if oscal_uuid:
        cleaned = _ID_UNSAFE_RE.sub("_", oscal_uuid).strip("_")
        if cleaned:
            return f"{prefix}_{cleaned}"
    return f"{prefix}{index}"


def _sanitize_label(text: str | None, fallback: str) -> str:
    """A Mermaid-safe quoted-label body: no raw ``"``/newlines, capped length."""
    if not text:
        return fallback
    flat = text.replace('"', "'").replace("\n", " ").replace("\r", " ")
    flat = _WHITESPACE_RE.sub(" ", flat).strip()
    if not flat:
        return fallback
    if len(flat) > _MAX_LABEL_LEN:
        flat = flat[: _MAX_LABEL_LEN - 1].rstrip() + "…"
    return flat


def _sorted_components(components: list[SystemComponent]) -> list[SystemComponent]:
    return sorted(components, key=lambda c: (c.title or "", c.id or 0))


def _sorted_interconnections(interconnections: list[Interconnection]) -> list[Interconnection]:
    return sorted(interconnections, key=lambda ic: (ic.remote_system_name or "", ic.id or 0))


def _sorted_info_types(info_types: list[InformationType]) -> list[InformationType]:
    return sorted(info_types, key=lambda it: (it.title or "", it.id or 0))


def _interconnection_edge(ic: Interconnection, ext_id: str, boundary_id: str) -> str:
    """A boundary<->external edge; arrow direction follows ``ic.direction``."""
    label = _sanitize_label(f"{ic.direction}/{ic.agreement_type}", "interconnection")
    if ic.direction == "incoming":
        return f'    {ext_id} -->|"{label}"| {boundary_id}'
    return f'    {boundary_id} -->|"{label}"| {ext_id}'


def boundary_mermaid(summary: BoundarySummary, system_name: str) -> str:
    """The authorization-boundary diagram: a subgraph for ``system_name``
    containing one node per component (with inventory items collapsed
    underneath), and interconnections as edges to external nodes.

    Never raises: an empty summary renders a minimal safe diagram (a single
    placeholder node inside the boundary subgraph).
    """
    boundary_id = "boundary"
    boundary_label = _sanitize_label(system_name, "System Boundary")
    lines = ["flowchart TD", f'    subgraph {boundary_id}["{boundary_label}"]']

    components = _sorted_components(summary.components)
    if components:
        node_ids: dict[int, str] = {}
        for idx, comp in enumerate(components):
            node_id = _sanitize_id(comp.oscal_uuid, "c", idx)
            node_ids[comp.id] = node_id
            type_tag = _sanitize_label(comp.type, "component")
            title = _sanitize_label(comp.title, "Component")
            label = _sanitize_label(f"{title} [{type_tag}]", f"{title} [{type_tag}]")
            lines.append(f'        {node_id}["{label}"]')

        inventory_by_component: dict[int, list[InventoryItem]] = {}
        for item in sorted(summary.inventory, key=lambda i: (i.asset_id or "", i.id or 0)):
            if item.component_id is not None:
                inventory_by_component.setdefault(item.component_id, []).append(item)
        for comp in components:
            items = inventory_by_component.get(comp.id, [])
            comp_node_id = node_ids[comp.id]
            for jdx, item in enumerate(items):
                inv_id = _sanitize_id(item.oscal_uuid, f"{comp_node_id}i", jdx)
                asset_label = _sanitize_label(item.asset_id, "Asset")
                lines.append(f'        {inv_id}["{asset_label}"]')
                lines.append(f"        {comp_node_id} -.-> {inv_id}")
    else:
        placeholder_label = _sanitize_label(system_name, "System")
        lines.append(f'        boundary_placeholder["{placeholder_label}"]')

    lines.append("    end")

    for idx, ic in enumerate(_sorted_interconnections(summary.interconnections)):
        ext_id = _sanitize_id(ic.oscal_uuid, "ext", idx)
        ext_label = _sanitize_label(ic.remote_system_name, "External System")
        lines.append(f'    {ext_id}["{ext_label}"]')
        lines.append(_interconnection_edge(ic, ext_id, boundary_id))

    return "\n".join(lines)


def data_flow_mermaid(summary: BoundarySummary, system_name: str) -> str:
    """The data-flow diagram: information types as flows between the
    boundary's components, and interconnections as cross-boundary flows
    labeled with ``data_description``/``direction``.

    Never raises: an empty summary renders a minimal safe diagram (a single
    node for ``system_name``).
    """
    boundary_id = "boundary"
    boundary_label = _sanitize_label(system_name, "System Boundary")
    lines = ["flowchart LR", f'    {boundary_id}(["{boundary_label}"])']

    info_types = _sorted_info_types(summary.info_types)
    flow_label = "; ".join(
        _sanitize_label(it.title, "Information") for it in info_types[:3]
    )
    if len(info_types) > 3:
        flow_label += "; …"
    flow_label = _sanitize_label(flow_label, "data")

    components = _sorted_components(summary.components)
    for idx, comp in enumerate(components):
        node_id = _sanitize_id(comp.oscal_uuid, "c", idx)
        label = _sanitize_label(comp.title, "Component")
        lines.append(f'    {node_id}["{label}"]')
        if info_types:
            lines.append(f'    {boundary_id} -->|"{flow_label}"| {node_id}')
        else:
            lines.append(f"    {boundary_id} --> {node_id}")

    for idx, ic in enumerate(_sorted_interconnections(summary.interconnections)):
        ext_id = _sanitize_id(ic.oscal_uuid, "ext", idx)
        ext_label = _sanitize_label(ic.remote_system_name, "External System")
        lines.append(f'    {ext_id}["{ext_label}"]')
        edge_label = _sanitize_label(ic.data_description, ic.direction or "data")
        if ic.direction == "incoming":
            lines.append(f'    {ext_id} -->|"{edge_label}"| {boundary_id}')
        else:
            lines.append(f'    {boundary_id} -->|"{edge_label}"| {ext_id}')

    return "\n".join(lines)
