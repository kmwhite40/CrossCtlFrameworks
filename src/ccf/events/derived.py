"""The derived-view consumers: recompute a view from current records, never decide.

Four consumers, each a full recompute of its scope (spec 5.1), so running one
twice is harmless and two jobs of ONE consumer may run in either order.

Order between consumers does matter where one reads what another writes: the
graph draws KSI state, which ``fedramp20x`` writes. That dependency is an
event, not an ordering assumption: after re-scoring, ``fedramp20x`` emits the
internal ``system ksi_rescored`` (``dispatch=False``), which the graph
triggers on, so a graph rebuilt before the re-score is rebuilt again after it.

* ``assurance_graph`` (``org:N``): :func:`ccf.assurance.builder.rebuild_org`.
* ``capability_derive`` (``system:N``, or ``org:N`` for a capability edit):
  :func:`ccf.capability.derive.derive_for_system` / ``derive_for_org``.
* ``fedramp20x`` (``system:N``): that system's slice of
  :func:`ccf.fedramp20x.monitoring.scan`; a no-op for a system with no 20x
  footprint.
* ``cr26_documents`` (``system:N``): re-seeds the VER-derived deliverables a
  provider has already started, through the seeders and so through
  ``store.put_document`` (validation still applies). Only rows a seeder last
  wrote are refreshed; a row a person authored is kept and they are told it
  is out of date (ruling R22).

A system-scoped job for a soft-deleted system finishes ``{"skipped": "system
deleted"}`` rather than failing into a dead letter (ruling R24).

**Triggers** are module-level frozensets of ``(entity_type, verb)`` read off the
emit sites; ``tests/test_event_derived_consumers.py`` pins them and checks that
something emits each one. **Scope** is read off the event: its organization,
a ``system`` entity's id, or a payload ``system_id`` that names the system.
The payload only ever names the scope; every ``run`` re-reads current records
(spec section 4, "a second source of truth").

**Never a gated decision** (spec section 4). None of these consumers closes a
POA&M, accepts a risk, approves anything, or writes a status a human gate
owns, and ``cr26_documents`` never touches SCN, incident, OCR, SDR or CPO: a
valid OCR is a filing (it takes a certification snapshot), and a filing is a
person's act.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Event, System
from ..models_cr26 import Cr26Document
from ..models_outbox import OutboxJob
from .consumers import Consumer, register

#: Entity types whose ``entity_id`` IS a system id.
SYSTEM_ENTITY_TYPES = frozenset({"system", "fedramp20x_profile"})

#: The assurance graph's contributors (``assurance/builder.py``): systems,
#: implementations, KSI state, capabilities, POA&Ms, risks, vendors,
#: connectors, scans, control tests, evidence objects and AI agents. Rebuilding
#: replaces the org's graph, so this lists the writers of those records and
#: nothing else. A package decision moves its system's ``ato_status``.
ASSURANCE_GRAPH_TRIGGERS: frozenset[tuple[str, str]] = frozenset(
    {
        ("system", "created"),
        ("system", "deleted"),
        ("system", "authorized"),
        ("system", "validated"),  # writes KSI state
        ("system", "drift"),  # written by a KSI re-validation
        ("system", "derived"),  # bulk implementations, POA&Ms, vendors
        ("system", "implementations_imported"),
        ("system", "ksi_rescored"),  # fedramp20x re-scored KSI state (internal)
        ("control_implementation", "updated"),
        ("poam", "created"),
        ("poam", "updated"),
        ("poam", "closed"),
        ("poam", "extension_decided"),
        ("risk", "created"),
        ("risk", "updated"),
        ("vendor", "created"),
        ("vendor", "updated"),  # a review moves its risk rating
        ("connector_config", "created"),
        ("connector_config", "updated"),  # status
        ("connector_config", "synced"),
        ("scan_ingestion", "ingested"),  # bulk POA&M create / reopen / close
        ("monitoring_run", "scanned"),  # ConMon opens POA&Ms
        ("control_test", "created"),
        ("control_test", "tested"),
        ("ai_agent", "created"),
        ("ai_agent", "updated"),
        ("evidence_object", "created"),
        ("evidence_object", "updated"),  # status
        ("system_component", "deleted"),  # unbinds capabilities from its system
        ("authorization_package", "package_submit"),
        ("authorization_package", "package_return"),
        ("authorization_package", "package_authorize"),
        ("authorization_package", "package_authorize_conditional"),
        ("authorization_package", "package_deny"),
        ("ksi_assessor_review", "reviewed"),  # KSI assessor status, finding POA&M
        ("ksi_assessor_review", "updated"),
        ("capability", "created"),
        ("capability", "updated"),
        ("capability", "deleted"),
        ("capability", "controls_set"),
        ("capability", "components_set"),
        ("capability", "risks_set"),
        ("capability", "ksis_set"),
    }
)

#: Changes that alter which implementation rows a system's derivation can
#: annotate. ``derive_for_system`` reads capabilities and their edges and
#: writes ``derived_*`` onto EXISTING implementation rows, so a new row (an
#: upsert, a bulk import, a profile derivation) is new work. Deleting a bound
#: component unbinds its capabilities from the system. It reads no control
#: tests.
CAPABILITY_SYSTEM_TRIGGERS: frozenset[tuple[str, str]] = frozenset(
    {
        ("control_implementation", "updated"),
        ("system", "implementations_imported"),
        ("system", "derived"),
        ("system_component", "deleted"),
    }
)

#: Capability edits. A capability belongs to an organization and reaches any
#: number of its systems through components, so one event cannot name one
#: system: these scope to ``org:N`` and re-derive every live system there.
#: Creating a capability binds nothing (no edges yet), and its risk and KSI
#: edges do not enter the derivation.
CAPABILITY_ORG_TRIGGERS: frozenset[tuple[str, str]] = frozenset(
    {
        ("capability", "updated"),
        ("capability", "deleted"),
        ("capability", "controls_set"),
        ("capability", "components_set"),
    }
)

#: What KSI validation and readiness read: implementations, control tests,
#: evidence, the CSO profile, dependencies, assessor reviews, exceptions, the
#: waivers in force, and which parameters the org's connectors have captured.
#: Not POA&Ms (neither reads them). Not ``system validated`` or ``drift``:
#: the first already ran this validation inline, the second is this
#: consumer's own output.
FEDRAMP20X_TRIGGERS: frozenset[tuple[str, str]] = frozenset(
    {
        ("control_implementation", "updated"),
        ("system", "implementations_imported"),
        ("control_test", "tested"),
        ("evidence", "captured"),
        ("evidence", "deleted"),
        ("capture_snapshot", "created"),
        ("waiver", "approved"),
        ("waiver", "revoked"),
        ("fedramp20x_profile", "updated"),
        ("fedramp_dependency", "created"),
        ("fedramp_dependency", "linked"),
        ("fedramp_dependency", "unlinked"),
        ("ksi_assessor_review", "reviewed"),
        ("ksi_assessor_review", "updated"),
        ("ksi_exception", "created"),
        ("ksi_exception", "updated"),
        ("system", "derived"),
    }
)

#: What the VER seeders read: the system's POA&Ms, their VDR evaluations, and
#: due dates (KEV tightening). Every writer of a POA&M that emits is listed.
CR26_TRIGGERS: frozenset[tuple[str, str]] = frozenset(
    {
        ("poam", "created"),
        ("poam", "updated"),
        ("poam", "closed"),
        ("poam", "extension_decided"),
        ("vdr_evaluation", "recorded"),
        ("vdr_evaluation", "confirmed"),
        ("scan_ingestion", "ingested"),
        ("system", "vdr_due_tightened"),
        ("system", "derived"),  # opens control-deficiency POA&Ms
        ("ksi_assessor_review", "reviewed"),  # may open a finding POA&M
        ("ksi_assessor_review", "updated"),
    }
)


def system_of(ev: Event) -> int | None:
    """The system an event names, or ``None``.

    A payload ``system_id`` (an int, never a bool) names it; otherwise a
    ``system``-like entity's own id does. Any other entity id (a POA&M's, a
    test's) is never read as a system id.
    """
    payload = ev.payload if isinstance(ev.payload, dict) else {}
    raw = payload.get("system_id")
    if type(raw) is int and raw > 0:
        return raw
    eid = ev.entity_id
    if ev.entity_type in SYSTEM_ENTITY_TYPES and eid and eid.isascii() and eid.isdigit():
        return int(eid)
    return None


def _system_scope(ev: Event) -> str | None:
    sid = system_of(ev)
    return None if sid is None else f"system:{sid}"


def _org_scope(ev: Event) -> str | None:
    return None if ev.organization_id is None else f"org:{ev.organization_id}"


def _ident(scope_key: str, kind: str) -> int:
    got, _, raw = scope_key.partition(":")
    if got != kind or not raw.isdigit():
        raise ValueError(f"expected a {kind} scope, got {scope_key!r}")
    return int(raw)


async def _live_system(session: AsyncSession, system_id: int) -> System | None:
    """The system, or ``None`` when it is gone or soft-deleted (ruling R24).

    The worker already skips a scope whose system was deleted before the
    claim; this covers one deleted between the claim and the run, where a
    seeder's ``put_document`` would raise and the job would retry into a dead
    letter, and ``derive_for_system`` would annotate a deleted system.
    """
    system = await session.get(System, system_id)
    return None if system is None or system.deleted_at is not None else system


_DELETED = "system deleted"


# ── assurance_graph ──────────────────────────────────────────────────────────


async def _run_graph(session: AsyncSession, scope_key: str, job: OutboxJob) -> dict[str, Any]:
    from ..assurance.builder import rebuild_org  # noqa: PLC0415 -- heavy, lazy

    run = await rebuild_org(session, _ident(scope_key, "org"))
    return {
        "build_run_id": run.id,
        "nodes": run.node_count,
        "edges": run.edge_count,
        "status": run.status,
    }


# ── capability_derive ────────────────────────────────────────────────────────


def _capability_scope(ev: Event) -> str | None:
    pair = (ev.entity_type, ev.verb)
    if pair in CAPABILITY_ORG_TRIGGERS:
        return _org_scope(ev)
    return _system_scope(ev)


async def _run_capability(session: AsyncSession, scope_key: str, job: OutboxJob) -> dict[str, Any]:
    from ..capability import derive  # noqa: PLC0415

    if scope_key.startswith("org:"):
        return await derive.derive_for_org(session, organization_id=_ident(scope_key, "org"))
    sid = _ident(scope_key, "system")
    if await _live_system(session, sid) is None:
        return {"system_id": sid, "skipped": _DELETED}
    return {
        "system_id": sid,
        "rows_annotated": await derive.derive_for_system(session, system_id=sid),
    }


# ── fedramp20x ───────────────────────────────────────────────────────────────


async def _run_fedramp20x(session: AsyncSession, scope_key: str, job: OutboxJob) -> dict[str, Any]:
    from ..fedramp20x import monitoring  # noqa: PLC0415
    from ..governance import bus  # noqa: PLC0415 -- avoid an import cycle

    sid = _ident(scope_key, "system")
    system = await _live_system(session, sid)
    if system is None:
        return {"system_id": sid, "skipped": _DELETED}
    if not await monitoring.is_20x_system(session, sid):
        return {"system_id": sid, "skipped": "no 20x footprint"}
    out = await monitoring.scan_system(session, system_id=sid, actor="event:fedramp20x")
    # KSI state changed under the graph: tell it. Internal (no webhook); the
    # graph triggers on it and this consumer does not.
    await bus.emit(
        session,
        verb="ksi_rescored",
        entity_type="system",
        entity_id=sid,
        summary=f"KSI state re-scored for {system.name}",
        org_id=system.organization_id,
        actor="event:fedramp20x",
        payload={"system_id": sid},
        dispatch=False,
    )
    return out


# ── cr26_documents ───────────────────────────────────────────────────────────

#: The kinds this consumer may write. Everything else (SCN, incident, OCR,
#: SDR, CPO) is authored or filed by a person and is never re-seeded here.
CR26_RESEEDED_KINDS = ("vdr", "avi", "ver_history")


#: ``updated_by`` this consumer writes, and the rows it may therefore refresh:
#: these, or ``None`` (a seeder run from the route, which records no author).
#: Anything else was written by a person (``PUT /cr26-documents``).
CR26_AUTHOR = "event:cr26_documents"

_LABEL = {"vdr": "VDR", "avi": "AVI", "ver_history": "VER history"}


async def _locked_rows(session: AsyncSession, system_id: int) -> dict[str, Cr26Document]:
    """This system's stored VER rows, locked ``FOR UPDATE`` in one statement.

    Locked before anything is read, so a person's ``PUT`` committing between
    this read and the seeder's write cannot be overwritten: it waits for this
    transaction, or this one waits for it and then sees its author.
    """
    rows = (
        (
            await session.execute(
                select(Cr26Document)
                .where(
                    Cr26Document.system_id == system_id,
                    Cr26Document.kind.in_(CR26_RESEEDED_KINDS),
                    Cr26Document.document_key.is_(None),
                )
                .order_by(Cr26Document.id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    return {r.kind: r for r in rows}


def _seeder_written(row: Cr26Document) -> bool:
    return row.updated_by is None or row.updated_by == CR26_AUTHOR


async def _tell_author(session: AsyncSession, system: System, row: Cr26Document) -> None:
    from ..governance import bus  # noqa: PLC0415 -- avoid an import cycle

    label = _LABEL[row.kind]
    await bus.notify(
        session,
        category="cr26",
        title=f"{label} is out of date with this system's POA&Ms",
        body=(
            f"The {label} for {system.name} was last edited by {row.updated_by}, so it "
            "was not refreshed automatically. Re-seed it to refresh."
        ),
        org_id=system.organization_id,
        severity="warning",
        entity_type="cr26_document",
        entity_id=row.id,
        dedupe_key=f"cr26-stale:{system.id}:{row.kind}",
    )


def _instant(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None


def stored_period(document: dict[str, Any]) -> tuple[datetime, datetime] | None:
    """The document's own ``reportPeriod``, or ``None`` when it has no usable one.

    Never computed or defaulted: the period says which activity a filed report
    covers, and that is the provider's choice, made when they seeded it.
    """
    period = document.get("reportPeriod")
    if not isinstance(period, dict):
        return None
    start, end = _instant(period.get("from")), _instant(period.get("to"))
    if start is None or end is None:
        return None
    return start, end


async def _run_cr26(session: AsyncSession, scope_key: str, job: OutboxJob) -> dict[str, Any]:
    from ..cr26 import ver  # noqa: PLC0415 -- avoid an import cycle

    sid = _ident(scope_key, "system")
    system = await _live_system(session, sid)
    if system is None:
        return {"system_id": sid, "skipped": _DELETED}
    rows = await _locked_rows(session, sid)
    out: dict[str, Any] = {"system_id": sid}
    omitted = 0
    # VDR and AVI before ver_history: ver_history reads its acceptance
    # rationales from the stored AVI.
    for kind in CR26_RESEEDED_KINDS:
        row = rows.get(kind)
        if row is None:
            out[kind] = "absent"  # never start a deliverable the provider has not
            continue
        if not _seeder_written(row):
            await _tell_author(session, system, row)
            out[kind] = "author-edited"
            continue
        if kind == "ver_history":
            result = await ver.seed_ver_history(session, system_id=sid, updated_by=CR26_AUTHOR)
        else:
            period = stored_period(row.document if isinstance(row.document, dict) else {})
            if period is None:
                out[kind] = "no stored period"
                continue
            seeder = ver.seed_vdr if kind == "vdr" else ver.seed_avi
            result = await seeder(
                session,
                system_id=sid,
                period_from=period[0],
                period_to=period[1],
                updated_by=CR26_AUTHOR,
            )
        omitted += len(result.omitted_poam_ids)
        out[kind] = "reseeded"
    if "author-edited" in out.values():
        out["skipped"] = "author-edited"
    out["omitted_rows"] = omitted
    return out


assurance_graph = register(
    Consumer(
        name="assurance_graph",
        matches=lambda et, verb: (et, verb) in ASSURANCE_GRAPH_TRIGGERS,
        scope=_org_scope,
        run=_run_graph,
    )
)
capability_derive = register(
    Consumer(
        name="capability_derive",
        matches=lambda et, verb: (
            (et, verb) in CAPABILITY_SYSTEM_TRIGGERS or (et, verb) in CAPABILITY_ORG_TRIGGERS
        ),
        scope=_capability_scope,
        run=_run_capability,
    )
)
fedramp20x = register(
    Consumer(
        name="fedramp20x",
        matches=lambda et, verb: (et, verb) in FEDRAMP20X_TRIGGERS,
        scope=_system_scope,
        run=_run_fedramp20x,
    )
)
cr26_documents = register(
    Consumer(
        name="cr26_documents",
        matches=lambda et, verb: (et, verb) in CR26_TRIGGERS,
        scope=_system_scope,
        run=_run_cr26,
    )
)
