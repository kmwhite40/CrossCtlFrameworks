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

from ..catalog.canonical import canonicalize
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
        self.edges: list[tuple[NodeKey, NodeKey, str, str]] = []
        #: implementation row id -> the control node it folded into
        self.impl_index: dict[str, NodeKey] = {}

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

    def edge(self, src: NodeKey, tgt: NodeKey, rel: str, source: str) -> None:
        """Record a sourced edge between two nodes already in the graph.

        Both endpoints must exist when this is called, so contributor order in
        :func:`_contribute` matters: an edge to a node added later is dropped.
        """
        if not source:
            raise ValueError(f"edge {src} -> {tgt} ({rel}) has no source")
        if src in self.nodes and tgt in self.nodes:
            self.edges.append((src, tgt, rel, source))


async def _contribute(
    session: AsyncSession, org_id: int, g: _Graph
) -> tuple[dict[str, int], dict[str, str]]:
    """Populate ``g`` from every source: ``(node counts, failed contributors)``.

    Each contributor runs in its own savepoint. A failed statement aborts a
    Postgres transaction, so without one, every contributor after the first
    failure would fail too, and the rebuild's own deletes with them.
    """
    stats: dict[str, int] = {}
    failed: dict[str, str] = {}

    async def run(name: str, contributor: Any) -> None:
        before = len(g.nodes)
        try:
            async with session.begin_nested():
                await contributor(session, org_id, g)
            stats[name] = len(g.nodes) - before
        except Exception as exc:  # recorded and shown, never silent
            log.warning("assurance.source_failed", source=name, error=str(exc)[:200])
            stats[name] = 0
            failed[name] = f"{type(exc).__name__}: {str(exc)[:200]}"

    await run("systems", _systems)
    await run("controls", _controls)
    await run("ksis", _ksis)
    await run("poams", _poams)
    await run("risks", _risks)
    await run("vendors", _vendors)
    await run("scans", _scans)
    await run("control_tests", _control_tests)
    await run("connectors", _connectors)
    await run("evidence_objects", _evidence_objects)
    await run("ai_agents", _ai_agents)
    return stats, failed


async def _systems(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models import System  # noqa: PLC0415

    for s in (
        await session.execute(select(System).where(System.organization_id == org_id))
    ).scalars().all():
        g.node("system", s.id, s.name, s.ato_status, baseline=s.baseline)


#: Worst first. A control is only as implemented as its least-implemented row.
STATUS_ORDER: tuple[str, ...] = (
    "not_implemented", "planned", "partial", "inherited", "implemented", "not_applicable",
)


def _worst(statuses: Any) -> str | None:
    ranked = [s for s in statuses if s in STATUS_ORDER]
    return min(ranked, key=STATUS_ORDER.index) if ranked else None


def fold_control(identifier: str, sequence_control: str | None) -> tuple[str, bool]:
    """The control a catalog row belongs to: ``(id, placed)``.

    ``controls`` holds assessment objectives and ODP rows as well as controls,
    so one node per row overstates the graph about fourfold. A row is the
    control it names; otherwise it attaches through ``sequence_control`` (the
    same rule as ``catalog/baseline_delta.py``); otherwise it is shown as
    recorded with ``placed=False`` -- reported, never guessed or dropped.
    """
    for raw in (identifier, sequence_control):
        c = canonicalize(raw)
        if c is not None:
            return c.value, True
    return identifier, False


async def _controls(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from sqlalchemy.orm import selectinload  # noqa: PLC0415

    from ..models import Control, ControlImplementation, System, User  # noqa: PLC0415

    rows = (
        await session.execute(
            select(ControlImplementation, Control.identifier, Control.sequence_control)
            .join(Control, Control.id == ControlImplementation.control_id)
            .join(System, System.id == ControlImplementation.system_id)
            .where(System.organization_id == org_id)
            .options(selectinload(ControlImplementation.evidence))
        )
    ).all()
    owner_ids = {r[0].owner_user_id for r in rows if r[0].owner_user_id is not None}
    owners: dict[int, str] = {}
    if owner_ids:
        for u in (
            await session.execute(select(User).where(User.id.in_(owner_ids)))
        ).scalars():
            owners[u.id] = u.full_name or u.email

    grouped: dict[tuple[int, str], list[Any]] = {}
    placed: dict[tuple[int, str], bool] = {}
    for impl, identifier, sequence_control in rows:
        cid, ok = fold_control(identifier, sequence_control)
        grouped.setdefault((impl.system_id, cid), []).append(impl)
        placed[(impl.system_id, cid)] = ok

    for (sid, cid), impls in grouped.items():
        ck = g.node(
            "control", f"{sid}:{cid}", cid, _worst(i.status for i in impls),
            system_id=sid, rows=len(impls), placed=placed[(sid, cid)],
            owners=sorted({owners[i.owner_user_id] for i in impls
                           if i.owner_user_id in owners}),
        )
        g.edge(("system", str(sid)), ck, "has_control", "control_implementations")
        for impl in impls:
            g.impl_index[str(impl.id)] = ck
            for ev in impl.evidence or []:
                ek = g.node("evidence", ev.id, ev.title or f"evidence-{ev.id}", ev.kind)
                g.edge(ck, ek, "supported_by", "evidence")


async def _ksis(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..fedramp20x.catalog import current_ksi_ids  # noqa: PLC0415
    from ..models import KSIState, System  # noqa: PLC0415

    sys_ids = [
        r for r in (
            await session.execute(select(System.id).where(System.organization_id == org_id))
        ).scalars().all()
    ]
    if not sys_ids:
        return
    for st in (
        await session.execute(
            select(KSIState).where(
                KSIState.system_id.in_(sys_ids), KSIState.ksi_id.in_(current_ksi_ids())
            )
        )
    ).scalars().all():
        kk = g.node("ksi", f"{st.system_id}:{st.ksi_id}", f"KSI {st.ksi_id}", st.status)
        g.edge(("system", str(st.system_id)), kk, "assessed_by", "ksi_states")


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
        g.edge(("system", str(p.system_id)), pk, "has_poam", "poams")


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
            g.edge(rk, ("system", str(r.system_id)), "threatens", "risks")


async def _vendors(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models import Vendor  # noqa: PLC0415

    for v in (
        await session.execute(select(Vendor).where(Vendor.organization_id == org_id))
    ).scalars().all():
        g.node("vendor", v.id, v.name, v.status, criticality=v.criticality,
               risk_rating=v.risk_rating)


async def _connectors(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models_grc import ConnectorConfig  # noqa: PLC0415

    for c in (
        await session.execute(
            select(ConnectorConfig).where(ConnectorConfig.organization_id == org_id)
        )
    ).scalars().all():
        g.node("connector", c.id, c.name, c.status, connector_type=c.connector_type)


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
        g.edge(sk, ("system", str(s.system_id)), "scanned", "scan_ingestions")


async def _control_tests(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models_grc import ControlTest  # noqa: PLC0415

    for t in (
        await session.execute(select(ControlTest).where(ControlTest.organization_id == org_id))
    ).scalars().all():
        tk = g.node("control_test", t.id, t.name, t.last_status, control_id=t.control_id)
        if t.system_id is not None:
            g.edge(tk, ("system", str(t.system_id)), "tests", "control_tests")


async def _evidence_objects(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models_evidence import EvidenceObject  # noqa: PLC0415

    for o in (
        await session.execute(
            select(EvidenceObject).where(EvidenceObject.organization_id == org_id)
        )
    ).scalars().all():
        ek = g.node("evidence_object", o.id, o.title, o.status, framework=o.framework)
        if o.system_id is not None:
            g.edge(("system", str(o.system_id)), ek, "documented_by", "evidence_objects")


async def _ai_agents(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models_ai_agents import AiAgent  # noqa: PLC0415

    for a in (
        await session.execute(select(AiAgent).where(AiAgent.organization_id == org_id))
    ).scalars().all():
        ak = g.node("ai_agent", a.id, a.name, a.approval_status,
                    risk_rating=a.risk_rating, autonomy=a.autonomy_level)
        targets: list[tuple[str, list[Any], str]] = [
            ("system", list(a.system_ids or []), "accesses"),
            ("vendor", list(a.vendor_ids or []), "depends_on"),
            ("poam", [], "n/a"),
        ]
        if a.system_id is not None:
            g.edge(ak, ("system", str(a.system_id)), "accesses", "ai_agents")
        for ttype, ids, rel in targets:
            for tid in ids:
                # Only connect to nodes the builder already created this run.
                g.edge(ak, (ttype, str(tid)), rel, "ai_agents")
        # control_ids is free-form: an implementation row id (what the graph
        # keyed controls by before) or a control id. Neither is guessed past.
        agent_systems = {str(s) for s in [a.system_id, *(a.system_ids or [])] if s is not None}
        for tid in a.control_ids or []:
            key = g.impl_index.get(str(tid))
            if key is not None:
                g.edge(ak, key, "governed_by", "ai_agents")
                continue
            c = canonicalize(str(tid))
            if c is None:
                continue
            for sid in agent_systems:
                g.edge(ak, ("control", f"{sid}:{c.value}"), "governed_by", "ai_agents")
        for rid in list(a.risk_ids or []):
            g.edge(ak, ("risk", str(rid)), "introduces_risk", "ai_agents")


async def rebuild_org(session: AsyncSession, org_id: int) -> AssuranceGraphBuildRun:
    """Rebuild the assurance graph for one organization (idempotent)."""
    run = AssuranceGraphBuildRun(organization_id=org_id, status="running")
    session.add(run)
    await session.flush()

    g = _Graph()
    stats, failed = await _contribute(session, org_id, g)

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
    for src, tgt, rel, source in g.edges:
        sid, tid = key_to_id.get(src), key_to_id.get(tgt)
        if sid is None or tid is None or (sid, tid, rel) in seen:
            continue
        seen.add((sid, tid, rel))
        session.add(
            AssuranceEdge(
                organization_id=org_id, source_node_id=sid, target_node_id=tid,
                relationship_type=rel, source=source,
            )
        )
        edge_count += 1

    run.node_count = len(g.nodes)
    run.edge_count = edge_count
    # "partial", not "ok": a slice is missing, and the page says which.
    run.status = "partial" if failed else "ok"
    run.finished_at = datetime.now(UTC)
    run.detail = {"sources": stats, "failed": failed}
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
