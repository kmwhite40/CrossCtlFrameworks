"""Authorization-package facts, diff, replay, and delta memos.

``capture_facts`` produces a deterministic list of normalized facts from the live
database; the rest build on it. Each fact source is isolated so a missing optional
module degrades that slice, not the whole capture. Replay is strictly read-only.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..logging import get_logger
from ..models_packages import (
    AuthorizationDeltaMemo,
    AuthorizationPackage,
    AuthorizationPackageDiff,
    AuthorizationPackageFact,
    AuthorizationPackageReplayRun,
)

log = get_logger(__name__)

# A fact is a (fact_type, fact_key) → value/digest snapshot.
Fact = dict[str, Any]


async def capture_facts(session: AsyncSession, system_id: int) -> list[Fact]:
    """Snapshot a system's authorization posture into normalized facts."""
    facts: list[Fact] = []

    async def source(name: str, coro: Any) -> None:
        try:
            facts.extend(await coro)
        except Exception as exc:  # optional module/table absent → skip this slice
            log.warning("packages.fact_source_failed", source=name, error=str(exc)[:200])

    await source("ksis", _ksi_facts(session, system_id))
    await source("controls", _control_facts(session, system_id))
    await source("evidence", _evidence_facts(session, system_id))
    await source("dependencies", _dependency_facts(session, system_id))
    await source("risks", _risk_facts(session, system_id))
    await source("poams", _poam_facts(session, system_id))
    await source("readiness", _readiness_fact(session, system_id))
    return facts


def _fact(ftype: str, key: str, value: str | None, digest: str | None = None, **meta: Any) -> Fact:
    return {"fact_type": ftype, "fact_key": key, "value": value, "digest": digest, "metadata": meta}


async def _ksi_facts(session: AsyncSession, system_id: int) -> list[Fact]:
    from ..models import KSIState  # noqa: PLC0415

    rows = (
        await session.execute(select(KSIState).where(KSIState.system_id == system_id))
    ).scalars().all()
    return [_fact("ksi", str(r.ksi_id), r.status) for r in rows]


async def _control_facts(session: AsyncSession, system_id: int) -> list[Fact]:
    from ..models import ControlImplementation  # noqa: PLC0415

    rows = (
        await session.execute(
            select(ControlImplementation)
            .options(selectinload(ControlImplementation.control))
            .where(ControlImplementation.system_id == system_id)
        )
    ).scalars().all()
    out: list[Fact] = []
    for r in rows:
        key = r.control.identifier if r.control else f"impl-{r.id}"
        out.append(_fact("control", key, r.status))
    return out


async def _evidence_facts(session: AsyncSession, system_id: int) -> list[Fact]:
    from ..models_evidence import EvidenceObject, EvidenceVersion  # noqa: PLC0415

    objs = (
        await session.execute(
            select(EvidenceObject).where(EvidenceObject.system_id == system_id)
        )
    ).scalars().all()
    out: list[Fact] = []
    for o in objs:
        digest = None
        if o.current_version_id is not None:
            ver = await session.get(EvidenceVersion, o.current_version_id)
            digest = ver.sha256 if ver else None
        out.append(_fact("evidence", str(o.id), o.status, digest, title=o.title))
    return out


async def _dependency_facts(session: AsyncSession, system_id: int) -> list[Fact]:
    from ..models import FedRAMPDependency  # noqa: PLC0415

    rows = (
        await session.execute(
            select(FedRAMPDependency).where(FedRAMPDependency.system_id == system_id)
        )
    ).scalars().all()
    return [_fact("dependency", r.name, r.fedramp_status) for r in rows]


async def _risk_facts(session: AsyncSession, system_id: int) -> list[Fact]:
    from ..models import Risk  # noqa: PLC0415

    rows = (
        await session.execute(select(Risk).where(Risk.system_id == system_id))
    ).scalars().all()
    return [_fact("risk", str(r.id), r.status, title=r.title) for r in rows]


async def _poam_facts(session: AsyncSession, system_id: int) -> list[Fact]:
    from ..models import POAM  # noqa: PLC0415

    rows = (
        await session.execute(select(POAM).where(POAM.system_id == system_id))
    ).scalars().all()
    return [_fact("poam", str(r.id), r.status, severity=r.severity) for r in rows]


async def _readiness_fact(session: AsyncSession, system_id: int) -> list[Fact]:
    try:
        from ..fedramp20x.readiness import score_system  # noqa: PLC0415

        readiness = await score_system(session, system_id=system_id, persist=False)
        pct = readiness.get("readiness_pct") if isinstance(readiness, dict) else None
        if pct is not None:
            return [_fact("readiness", "readiness_pct", str(pct))]
    except Exception:
        pass
    return []


def _readiness_from_facts(facts: list[Fact]) -> float | None:
    for f in facts:
        if f["fact_type"] == "readiness" and f["fact_key"] == "readiness_pct":
            try:
                return float(f["value"])
            except (TypeError, ValueError):
                return None
    return None


async def create_package(
    session: AsyncSession,
    *,
    org_id: int | None,
    system_id: int,
    kind: str = "fedramp20x",
    label: str | None = None,
    created_by: str | None = None,
) -> AuthorizationPackage:
    """Capture facts and persist an authorization package (provenance)."""
    facts = await capture_facts(session, system_id)
    counts: dict[str, int] = {}
    for f in facts:
        counts[f["fact_type"]] = counts.get(f["fact_type"], 0) + 1
    pkg = AuthorizationPackage(
        organization_id=org_id,
        system_id=system_id,
        kind=kind,
        label=label or f"{kind} package (system {system_id})",
        readiness_pct=_readiness_from_facts(facts),
        fact_count=len(facts),
        created_by=created_by,
        summary={"fact_counts": counts},
    )
    session.add(pkg)
    await session.flush()
    for f in facts:
        session.add(
            AuthorizationPackageFact(
                package_id=pkg.id, fact_type=f["fact_type"], fact_key=f["fact_key"],
                value=f["value"], digest=f["digest"], fact_metadata=f["metadata"],
            )
        )
    await session.flush()
    return pkg


async def _facts_map(session: AsyncSession, package_id: int) -> dict[tuple[str, str], Fact]:
    rows = (
        await session.execute(
            select(AuthorizationPackageFact).where(
                AuthorizationPackageFact.package_id == package_id
            )
        )
    ).scalars().all()
    return {
        (r.fact_type, r.fact_key): {"value": r.value, "digest": r.digest} for r in rows
    }


def _diff_maps(
    a: dict[tuple[str, str], Fact], b: dict[tuple[str, str], Fact]
) -> dict[str, Any]:
    """Return per-fact-type added/removed/changed between two fact maps."""
    changes: dict[str, dict[str, list[Any]]] = {}

    def bucket(ftype: str) -> dict[str, list[Any]]:
        return changes.setdefault(ftype, {"added": [], "removed": [], "changed": []})

    for key, bval in b.items():
        ftype, fkey = key
        if key not in a:
            bucket(ftype)["added"].append({"key": fkey, "to": bval})
        elif a[key] != bval:
            bucket(ftype)["changed"].append({"key": fkey, "from": a[key], "to": bval})
    for key, aval in a.items():
        if key not in b:
            ftype, fkey = key
            bucket(ftype)["removed"].append({"key": fkey, "from": aval})
    return changes


def _summary(changes: dict[str, Any]) -> dict[str, int]:
    added = sum(len(v["added"]) for v in changes.values())
    removed = sum(len(v["removed"]) for v in changes.values())
    changed = sum(len(v["changed"]) for v in changes.values())
    return {"added": added, "removed": removed, "changed": changed,
            "total": added + removed + changed}


async def diff_packages(
    session: AsyncSession, *, org_id: int | None, from_id: int, to_id: int
) -> AuthorizationPackageDiff:
    a = await _facts_map(session, from_id)
    b = await _facts_map(session, to_id)
    changes = _diff_maps(a, b)
    diff = AuthorizationPackageDiff(
        organization_id=org_id, from_package_id=from_id, to_package_id=to_id,
        summary=_summary(changes), changes=changes,
    )
    session.add(diff)
    await session.flush()
    return diff


async def replay_package(
    session: AsyncSession, *, org_id: int | None, package: AuthorizationPackage
) -> AuthorizationPackageReplayRun:
    """Re-derive facts from the live DB and report drift. Read-only — no mutation."""
    original = await _facts_map(session, package.id)
    current_facts = (
        await capture_facts(session, package.system_id) if package.system_id else []
    )
    current = {(f["fact_type"], f["fact_key"]): {"value": f["value"], "digest": f["digest"]}
               for f in current_facts}
    changes = _diff_maps(original, current)
    summary = _summary(changes)
    if summary["changed"]:
        status = "drifted"
    elif summary["removed"]:
        status = "missing"
    else:
        status = "reproducible"
    run = AuthorizationPackageReplayRun(
        organization_id=org_id, package_id=package.id, status=status,
        drift={"summary": summary, "changes": changes},
    )
    session.add(run)
    await session.flush()
    return run


def _render_memo(pkg_from: int | None, pkg_to: int, changes: dict[str, Any]) -> str:
    lines = [
        "# Authorization Delta Memo",
        "",
        f"Comparing package {pkg_from or '(baseline)'} → {pkg_to}.",
        "",
    ]
    if not any(_summary({k: v})["total"] for k, v in changes.items()):
        lines.append("No changes detected in captured authorization facts.")
        return "\n".join(lines)
    for ftype, buckets in sorted(changes.items()):
        s = _summary({ftype: buckets})
        if not s["total"]:
            continue
        lines.append(f"## {ftype} — +{s['added']} / -{s['removed']} / ~{s['changed']}")
        for c in buckets["changed"][:20]:
            frm, to = c["from"].get("value"), c["to"].get("value")
            lines.append(f"- changed `{c['key']}`: {frm} → {to}")
        for c in buckets["added"][:20]:
            lines.append(f"- new `{c['key']}`: {c['to'].get('value')}")
        for c in buckets["removed"][:20]:
            lines.append(f"- removed `{c['key']}` (was {c['from'].get('value')})")
        lines.append("")
    return "\n".join(lines)


async def delta_memo(
    session: AsyncSession, *, org_id: int | None, system_id: int, since: date | None = None
) -> AuthorizationDeltaMemo:
    """Build an assessor-facing memo diffing the two latest packages for a system."""
    stmt = (
        select(AuthorizationPackage)
        .where(AuthorizationPackage.system_id == system_id)
        .order_by(AuthorizationPackage.id.desc())
    )
    pkgs = (await session.execute(stmt)).scalars().all()
    if not pkgs:
        # No prior package — capture a fresh one as the baseline "to".
        to_pkg = await create_package(session, org_id=org_id, system_id=system_id)
        from_id: int | None = None
        changes: dict[str, Any] = {}
    else:
        to_pkg = pkgs[0]
        older = [p for p in pkgs[1:] if since is None or (p.created_at.date() <= since)]
        from_pkg = older[0] if older else (pkgs[1] if len(pkgs) > 1 else None)
        from_id = from_pkg.id if from_pkg else None
        a = await _facts_map(session, from_id) if from_id else {}
        b = await _facts_map(session, to_pkg.id)
        changes = _diff_maps(a, b)
    memo = AuthorizationDeltaMemo(
        organization_id=org_id, system_id=system_id, from_package_id=from_id,
        to_package_id=to_pkg.id, since=since,
        body=_render_memo(from_id, to_pkg.id, changes), summary=_summary(changes),
    )
    session.add(memo)
    await session.flush()
    return memo


def now() -> datetime:
    return datetime.now(UTC)
