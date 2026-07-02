"""(Re)build the assurance graph from Concord's existing records.

Each source contributor is isolated in its own try/except so a missing optional
module or table degrades that slice of the graph rather than failing the whole
build. The build is per-tenant and idempotent: an org's nodes/edges are replaced
wholesale each run (small graphs; correctness over incrementalism).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import Organization
from ..models_assurance import (
    AssuranceEdge,
    AssuranceGraphBuildRun,
    AssuranceNode,
    AssuranceSnapshot,
)

log = get_logger(__name__)

# A node spec keyed by (entity_type, entity_id); an edge spec references those keys.
NodeKey = tuple[str, str]


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[NodeKey, dict[str, Any]] = {}
        self.edges: list[tuple[NodeKey, NodeKey, str, float]] = []

    def node(
        self, entity_type: str, entity_id: Any, label: str,
        status: str | None = None, **meta: Any,
    ) -> NodeKey:
        key = (entity_type, str(entity_id))
        self.nodes[key] = {
            "entity_type": entity_type, "entity_id": str(entity_id),
            "label": label[:512], "status": status, "metadata": meta,
        }
        return key

    def edge(self, src: NodeKey, tgt: NodeKey, rel: str, confidence: float = 1.0) -> None:
        if src in self.nodes and tgt in self.nodes:
            self.edges.append((src, tgt, rel, confidence))


async def _contribute(session: AsyncSession, org_id: int, g: _Graph) -> dict[str, int]:
    """Populate ``g`` from every available source; returns per-source node counts."""
    stats: dict[str, int] = {}

    async def run(name: str, coro: Any) -> None:
        try:
            before = len(g.nodes)
            await coro
            stats[name] = len(g.nodes) - before
        except Exception as exc:  # optional module/table absent → skip this slice
            log.warning("assurance.source_failed", source=name, error=str(exc)[:200])
            stats[name] = 0

    await run("systems", _systems(session, org_id, g))
    await run("controls", _controls(session, org_id, g))
    await run("ksis", _ksis(session, org_id, g))
    await run("poams", _poams(session, org_id, g))
    await run("risks", _risks(session, org_id, g))
    await run("vendors", _vendors(session, org_id, g))
    await run("connectors", _connectors(session, org_id, g))
    await run("scans", _scans(session, org_id, g))
    await run("control_tests", _control_tests(session, org_id, g))
    await run("evidence_objects", _evidence_objects(session, org_id, g))
    return stats


async def _systems(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models import System  # noqa: PLC0415

    for s in (
        await session.execute(select(System).where(System.organization_id == org_id))
    ).scalars().all():
        g.node("system", s.id, s.name, s.ato_status, baseline=s.baseline)


async def _controls(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from sqlalchemy.orm import selectinload  # noqa: PLC0415

    from ..models import ControlImplementation, Evidence, System  # noqa: PLC0415

    sys_ids = [
        r for r in (
            await session.execute(select(System.id).where(System.organization_id == org_id))
        ).scalars().all()
    ]
    if not sys_ids:
        return
    impls = (
        await session.execute(
            select(ControlImplementation)
            .options(
                selectinload(ControlImplementation.control),
                selectinload(ControlImplementation.evidence),
            )
            .where(ControlImplementation.system_id.in_(sys_ids))
        )
    ).scalars().all()
    for impl in impls:
        label = impl.control.identifier if impl.control else f"impl-{impl.id}"
        ck = g.node("control", impl.id, label, impl.status, system_id=impl.system_id)
        g.edge(("system", str(impl.system_id)), ck, "has_control")
        for ev in impl.evidence or []:
            ek = g.node("evidence", ev.id, ev.title or f"evidence-{ev.id}", ev.kind)
            g.edge(ck, ek, "supported_by")
            _ = Evidence  # keep import meaningful for type-checkers


async def _ksis(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models import KSIState, System  # noqa: PLC0415

    sys_ids = [
        r for r in (
            await session.execute(select(System.id).where(System.organization_id == org_id))
        ).scalars().all()
    ]
    if not sys_ids:
        return
    for st in (
        await session.execute(select(KSIState).where(KSIState.system_id.in_(sys_ids)))
    ).scalars().all():
        kk = g.node("ksi", f"{st.system_id}:{st.ksi_id}", f"KSI {st.ksi_id}", st.status)
        g.edge(("system", str(st.system_id)), kk, "assessed_by")


async def _poams(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models import POAM, System  # noqa: PLC0415

    sys_ids = [
        r for r in (
            await session.execute(select(System.id).where(System.organization_id == org_id))
        ).scalars().all()
    ]
    if not sys_ids:
        return
    for p in (
        await session.execute(select(POAM).where(POAM.system_id.in_(sys_ids)))
    ).scalars().all():
        pk = g.node("poam", p.id, p.title, p.status, severity=p.severity)
        g.edge(("system", str(p.system_id)), pk, "has_poam")


async def _risks(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models import Risk, System  # noqa: PLC0415

    sys_ids = [
        r for r in (
            await session.execute(select(System.id).where(System.organization_id == org_id))
        ).scalars().all()
    ]
    if not sys_ids:
        return
    for r in (
        await session.execute(select(Risk).where(Risk.system_id.in_(sys_ids)))
    ).scalars().all():
        rk = g.node("risk", r.id, r.title, r.status)
        if r.system_id is not None:
            g.edge(rk, ("system", str(r.system_id)), "threatens")


async def _vendors(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models import Vendor  # noqa: PLC0415

    for v in (
        await session.execute(select(Vendor).where(Vendor.organization_id == org_id))
    ).scalars().all():
        g.node("vendor", v.id, v.name, v.status, criticality=v.criticality,
               risk_rating=v.risk_rating)


async def _connectors(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models import System  # noqa: PLC0415
    from ..models_grc import ConnectorConfig  # noqa: PLC0415

    conns = (
        await session.execute(
            select(ConnectorConfig).where(ConnectorConfig.organization_id == org_id)
        )
    ).scalars().all()
    sys_ids = [
        r for r in (
            await session.execute(select(System.id).where(System.organization_id == org_id))
        ).scalars().all()
    ]
    for c in conns:
        ck = g.node("connector", c.id, c.name, c.status, connector_type=c.connector_type)
        for sid in sys_ids:  # connector feeds evidence for the org's systems
            g.edge(ck, ("system", str(sid)), "feeds_evidence_for", 0.6)


async def _scans(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models import ScanIngestion, System  # noqa: PLC0415

    sys_ids = [
        r for r in (
            await session.execute(select(System.id).where(System.organization_id == org_id))
        ).scalars().all()
    ]
    if not sys_ids:
        return
    for s in (
        await session.execute(select(ScanIngestion).where(ScanIngestion.system_id.in_(sys_ids)))
    ).scalars().all():
        sk = g.node("scan", s.id, f"{s.scanner} scan #{s.id}", scanner=s.scanner)
        g.edge(sk, ("system", str(s.system_id)), "scanned")


async def _control_tests(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models_grc import ControlTest  # noqa: PLC0415

    for t in (
        await session.execute(select(ControlTest).where(ControlTest.organization_id == org_id))
    ).scalars().all():
        tk = g.node("control_test", t.id, t.name, t.last_status, control_id=t.control_id)
        if t.system_id is not None:
            g.edge(tk, ("system", str(t.system_id)), "tests")


async def _evidence_objects(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models_evidence import EvidenceObject  # noqa: PLC0415

    for o in (
        await session.execute(
            select(EvidenceObject).where(EvidenceObject.organization_id == org_id)
        )
    ).scalars().all():
        ek = g.node("evidence_object", o.id, o.title, o.status, framework=o.framework)
        if o.system_id is not None:
            g.edge(("system", str(o.system_id)), ek, "documented_by")


async def rebuild_org(session: AsyncSession, org_id: int) -> AssuranceGraphBuildRun:
    """Rebuild the assurance graph for one organization (idempotent)."""
    run = AssuranceGraphBuildRun(organization_id=org_id, status="running")
    session.add(run)
    await session.flush()

    g = _Graph()
    stats = await _contribute(session, org_id, g)

    # Replace the org's graph wholesale.
    await session.execute(delete(AssuranceEdge).where(AssuranceEdge.organization_id == org_id))
    await session.execute(delete(AssuranceNode).where(AssuranceNode.organization_id == org_id))
    await session.flush()

    key_to_id: dict[NodeKey, int] = {}
    for key, spec in g.nodes.items():
        node = AssuranceNode(
            organization_id=org_id, build_run_id=run.id,
            entity_type=spec["entity_type"], entity_id=spec["entity_id"],
            label=spec["label"], status=spec["status"], node_metadata=spec["metadata"],
        )
        session.add(node)
        await session.flush()
        key_to_id[key] = node.id

    seen: set[tuple[int, int, str]] = set()
    edge_count = 0
    for src, tgt, rel, conf in g.edges:
        sid, tid = key_to_id.get(src), key_to_id.get(tgt)
        if sid is None or tid is None or (sid, tid, rel) in seen:
            continue
        seen.add((sid, tid, rel))
        session.add(
            AssuranceEdge(
                organization_id=org_id, source_node_id=sid, target_node_id=tid,
                relationship_type=rel, confidence=conf,
            )
        )
        edge_count += 1

    run.node_count = len(g.nodes)
    run.edge_count = edge_count
    run.status = "ok"
    run.finished_at = datetime.now(UTC)
    run.detail = {"sources": stats}
    await session.flush()
    return run


async def rebuild(session: AsyncSession, *, org_id: int | None = None) -> list[dict[str, Any]]:
    """Rebuild the graph for one org, or every org when ``org_id`` is None."""
    if org_id is not None:
        org_ids = [org_id]
    else:
        org_ids = [
            r for r in (await session.execute(select(Organization.id))).scalars().all()
        ]
    out: list[dict[str, Any]] = []
    for oid in org_ids:
        run = await rebuild_org(session, oid)
        out.append(
            {"organization_id": oid, "nodes": run.node_count, "edges": run.edge_count,
             "status": run.status}
        )
    return out


async def snapshot_system(
    session: AsyncSession, *, org_id: int | None, system_id: int
) -> AssuranceSnapshot:
    """Capture a per-system subgraph summary (node/edge counts by type)."""
    nodes = (
        await session.execute(
            select(AssuranceNode).where(AssuranceNode.organization_id == org_id)
        )
    ).scalars().all()
    by_type: dict[str, int] = {}
    for n in nodes:
        by_type[n.entity_type] = by_type.get(n.entity_type, 0) + 1
    edge_total = (
        await session.execute(
            select(AssuranceEdge).where(AssuranceEdge.organization_id == org_id)
        )
    ).scalars().all()
    snap = AssuranceSnapshot(
        organization_id=org_id, system_id=system_id,
        node_count=len(nodes), edge_count=len(edge_total), summary={"by_type": by_type},
    )
    session.add(snap)
    await session.flush()
    return snap
