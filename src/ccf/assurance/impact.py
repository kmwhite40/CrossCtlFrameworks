"""Impact analysis over the assurance graph — breadth-first blast radius.

Given a root entity, walk the tenant's edges (treated as undirected for reach)
up to ``max_hops`` and return the affected nodes grouped by type — e.g. which
controls / KSIs / systems / packages depend on a piece of stale evidence.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_assurance import AssuranceEdge, AssuranceGraphBuildRun, AssuranceNode


async def latest_build(
    session: AsyncSession, org_id: int | None
) -> AssuranceGraphBuildRun | None:
    stmt = select(AssuranceGraphBuildRun).order_by(AssuranceGraphBuildRun.id.desc()).limit(1)
    if org_id is not None:
        stmt = stmt.where(AssuranceGraphBuildRun.organization_id == org_id)
    return (await session.execute(stmt)).scalars().first()


def _node_out(n: AssuranceNode) -> dict[str, Any]:
    return {
        "id": n.id,
        "entity_type": n.entity_type,
        "entity_id": n.entity_id,
        "label": n.label,
        "status": n.status,
        "metadata": dict(n.node_metadata or {}),
    }


async def impact_for(
    session: AsyncSession,
    *,
    org_id: int | None,
    entity_type: str,
    entity_id: str,
    max_hops: int = 3,
) -> dict[str, Any]:
    """Return the blast radius of ``(entity_type, entity_id)`` grouped by type."""
    root_stmt = select(AssuranceNode).where(
        AssuranceNode.entity_type == entity_type, AssuranceNode.entity_id == str(entity_id)
    )
    if org_id is not None:
        root_stmt = root_stmt.where(AssuranceNode.organization_id == org_id)
    root = (await session.execute(root_stmt)).scalars().first()
    if root is None:
        return {"root": None, "affected": {}, "affected_count": 0, "hops": max_hops}

    edge_stmt = select(AssuranceEdge)
    if org_id is not None:
        edge_stmt = edge_stmt.where(AssuranceEdge.organization_id == org_id)
    edges = (await session.execute(edge_stmt)).scalars().all()

    adj: dict[int, list[tuple[int, str]]] = {}
    for e in edges:
        adj.setdefault(e.source_node_id, []).append((e.target_node_id, e.relationship_type))
        adj.setdefault(e.target_node_id, []).append((e.source_node_id, e.relationship_type))

    # BFS out to max_hops.
    seen: set[int] = {root.id}
    queue: deque[tuple[int, int]] = deque([(root.id, 0)])
    reached: set[int] = set()
    while queue:
        nid, depth = queue.popleft()
        if depth >= max_hops:
            continue
        for neighbor, _rel in adj.get(nid, []):
            if neighbor not in seen:
                seen.add(neighbor)
                reached.add(neighbor)
                queue.append((neighbor, depth + 1))

    affected: dict[str, list[dict[str, Any]]] = {}
    if reached:
        nodes = (
            await session.execute(select(AssuranceNode).where(AssuranceNode.id.in_(reached)))
        ).scalars().all()
        for n in nodes:
            affected.setdefault(n.entity_type, []).append(_node_out(n))

    return {
        "root": _node_out(root),
        "hops": max_hops,
        "affected": affected,
        "affected_count": len(reached),
    }


async def subgraph(
    session: AsyncSession,
    *,
    org_id: int | None,
    entity_type: str,
    entity_id: str,
    max_hops: int = 5,
    within_system: int | None = None,
) -> dict[str, Any]:
    """Return the connected subgraph (nodes + edges) around a root entity.

    ``within_system`` keeps the walk inside one system. Capabilities,
    connectors and agents join systems together, so an unscoped walk from one
    system reaches another's controls and tests. Scoped, a node belonging to
    another system (``metadata.system_id``) is not returned, and another
    system's own node is returned as a boundary but not walked past.
    """
    root_stmt = select(AssuranceNode).where(
        AssuranceNode.entity_type == entity_type, AssuranceNode.entity_id == str(entity_id)
    )
    if org_id is not None:
        root_stmt = root_stmt.where(AssuranceNode.organization_id == org_id)
    root = (await session.execute(root_stmt)).scalars().first()
    if root is None:
        return {"root": None, "nodes": [], "edges": []}

    edge_stmt = select(AssuranceEdge).where(
        AssuranceEdge.organization_id == root.organization_id
    )
    edges = (await session.execute(edge_stmt)).scalars().all()
    adj: dict[int, list[int]] = {}
    for e in edges:
        adj.setdefault(e.source_node_id, []).append(e.target_node_id)
        adj.setdefault(e.target_node_id, []).append(e.source_node_id)

    foreign: set[int] = set()
    boundary: set[int] = set()
    if within_system is not None:
        for nid, etype, eid, meta in (
            await session.execute(
                select(AssuranceNode.id, AssuranceNode.entity_type, AssuranceNode.entity_id,
                       AssuranceNode.node_metadata)
                .where(AssuranceNode.organization_id == root.organization_id)
            )
        ).all():
            owner = (meta or {}).get("system_id")
            if etype == "system" and eid != str(within_system):
                boundary.add(nid)
            elif owner is not None and int(owner) != within_system:
                foreign.add(nid)

    seen: set[int] = {root.id}
    queue: deque[tuple[int, int]] = deque([(root.id, 0)])
    while queue:
        nid, depth = queue.popleft()
        if depth >= max_hops:
            continue
        for neighbor in adj.get(nid, []):
            if neighbor in seen or neighbor in foreign:
                continue
            seen.add(neighbor)
            if neighbor not in boundary:
                queue.append((neighbor, depth + 1))

    nodes = (
        await session.execute(select(AssuranceNode).where(AssuranceNode.id.in_(seen)))
    ).scalars().all()
    kept_edges = [
        {"source": e.source_node_id, "target": e.target_node_id,
         "relationship_type": e.relationship_type, "provenance": e.source}
        for e in edges
        if e.source_node_id in seen and e.target_node_id in seen
    ]
    return {
        "root": _node_out(root),
        "nodes": [_node_out(n) for n in nodes],
        "edges": kept_edges,
    }


async def system_view(
    session: AsyncSession, *, system: Any, hops: int = 6, within_system: bool = True
) -> dict[str, Any]:
    """One system's graph plus the build it came from. The page and the API
    both call this, so their nodes, edges and states cannot disagree."""
    graph = await subgraph(
        session, org_id=system.organization_id, entity_type="system",
        entity_id=str(system.id), max_hops=hops,
        within_system=system.id if within_system else None,
    )
    run = await latest_build(session, system.organization_id)
    graph["built_at"] = run.finished_at.isoformat() if run and run.finished_at else None
    graph["build_status"] = run.status if run else None
    graph["failed_contributors"] = dict((run.detail or {}).get("failed") or {}) if run else {}
    return graph
