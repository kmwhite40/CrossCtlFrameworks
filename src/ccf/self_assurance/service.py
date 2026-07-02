"""Self-assurance orchestration — seed, run, status, export.

``init`` seeds the Concord Platform system + installs the self-assurance pack +
creates control implementations and evidence objects. ``run`` executes Concord's
reliability checks, maps them onto the self-controls (updating implementation
status + attaching the check output as scored evidence), and records a run. All
of it reuses existing modules — no bespoke assessment engine.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..evidence import confidence as ev_confidence
from ..evidence import service as ev_service
from ..models import Control, ControlImplementation, Organization, System
from ..models_evidence import EvidenceObject
from ..models_self_assurance import SelfAssuranceRun
from ..packs import catalog as pack_catalog
from ..packs import service as pack_service
from ..reliability.checks import run_checks

SELF_ORG = "Concord Platform"
SELF_SYSTEM = "Concord Platform"
SELF_PACK = "concord-self-assurance"

# self-control id → substrings of reliability-check names that evidence it.
_CONTROL_CHECKS: dict[str, list[str]] = {
    "CSA-RLS": ["required_tables", "database_connectivity"],
    "CSA-AUDIT": ["audit_log_write_path"],
    "CSA-MIGRATIONS": ["alembic_migration_status"],
    "CSA-SUPPLY": [],  # verified in CI (SBOM/Trivy/pip-audit) — no runtime check
    "CSA-AI": ["ai_disabled_safe_default", "ai_guardrail_violations"],
}
_STATUS_FROM = {"pass": "implemented", "warn": "partial", "fail": "not_implemented"}


async def _audit(session: AsyncSession, **kw: Any) -> None:
    from ..api.audit import record_event  # noqa: PLC0415 — avoid import cycle

    await record_event(session, **kw)


async def _self_ids(session: AsyncSession) -> tuple[int, int]:
    org = (
        await session.execute(select(Organization).where(Organization.name == SELF_ORG))
    ).scalar_one_or_none()
    if org is None:
        org = Organization(name=SELF_ORG, description="Concord's own assurance boundary.")
        session.add(org)
        await session.flush()
    sysm = (
        await session.execute(
            select(System).where(System.organization_id == org.id, System.name == SELF_SYSTEM)
        )
    ).scalar_one_or_none()
    if sysm is None:
        sysm = System(organization_id=org.id, name=SELF_SYSTEM, baseline="moderate")
        session.add(sysm)
        await session.flush()
    return org.id, sysm.id


async def init_self_assurance(session: AsyncSession, *, actor: str | None = None) -> dict[str, Any]:
    """Seed the Concord Platform system, install the self pack, and stub controls/evidence."""
    org_id, system_id = await _self_ids(session)
    manifest = pack_catalog.load_pack(SELF_PACK)
    await pack_service.install_pack(
        session, org_id=org_id, manifest=manifest, source="bundled", actor=actor
    )

    controls = manifest.get("controls", [])
    ev_reqs = {e["control_id"]: e["description"] for e in manifest.get("evidence_requirements", [])}
    for c in controls:
        cid = str(c["control_id"])
        control = (
            await session.execute(select(Control).where(Control.identifier == cid))
        ).scalar_one_or_none()
        if control is None:
            control = Control(identifier=cid, control_name=c.get("title", cid))
            session.add(control)
            await session.flush()
        impl = (
            await session.execute(
                select(ControlImplementation).where(
                    ControlImplementation.system_id == system_id,
                    ControlImplementation.control_id == control.id,
                )
            )
        ).scalar_one_or_none()
        if impl is None:
            session.add(ControlImplementation(
                system_id=system_id, control_id=control.id, status="not_implemented"))
        # An evidence object per control that has an evidence requirement.
        if cid in ev_reqs:
            exists = (
                await session.execute(
                    select(EvidenceObject).where(
                        EvidenceObject.system_id == system_id,
                        EvidenceObject.control_id == cid,
                        EvidenceObject.framework == "CONCORD",
                    )
                )
            ).scalar_one_or_none()
            if exists is None:
                await ev_service.create_object(
                    session, org_id=org_id, title=ev_reqs[cid], system_id=system_id,
                    control_id=cid, framework="CONCORD", source_type="api_import",
                )
    await _audit(
        session, actor=actor or "system", action="create", entity_type="self_assurance",
        entity_id=str(system_id), diff={"event": "init", "pack": SELF_PACK},
    )
    await session.flush()
    return {"organization_id": org_id, "system_id": system_id, "controls": len(controls)}


async def run_self_assessment(
    session: AsyncSession, *, actor: str | None = None
) -> SelfAssuranceRun:
    """Run reliability checks, map them to self-controls, and record a run."""
    await init_self_assurance(session, actor=actor)
    org_id, system_id = await _self_ids(session)
    checks = {c.name: c for c in await run_checks(session)}

    control_status: dict[str, str] = {}
    for cid, names in _CONTROL_CHECKS.items():
        matched = [checks[n] for kw in names for n in checks if kw in n]
        if not matched:
            control_status[cid] = "planned"  # manual / CI-verified only
            continue
        statuses = {m.status for m in matched}
        if "fail" in statuses:
            control_status[cid] = "not_implemented"
        elif "warn" in statuses:
            control_status[cid] = "partial"
        else:
            control_status[cid] = "implemented"

    # Update implementations + attach reliability output as scored evidence.
    for cid, status in control_status.items():
        control = (
            await session.execute(select(Control).where(Control.identifier == cid))
        ).scalar_one_or_none()
        if control is None:
            continue
        impl = (
            await session.execute(
                select(ControlImplementation).where(
                    ControlImplementation.system_id == system_id,
                    ControlImplementation.control_id == control.id,
                )
            )
        ).scalar_one_or_none()
        if impl is not None:
            impl.status = status
        obj = (
            await session.execute(
                select(EvidenceObject).where(
                    EvidenceObject.system_id == system_id, EvidenceObject.control_id == cid,
                    EvidenceObject.framework == "CONCORD",
                )
            )
        ).scalar_one_or_none()
        if obj is not None and not obj.immutable_lock:
            detail = "; ".join(
                f"{n}={checks[n].status}" for kw in _CONTROL_CHECKS[cid] for n in checks if kw in n
            ) or "manual/CI-verified"
            await ev_service.add_version(
                session, obj, data=f"{cid}: {detail}".encode(),
                filename=f"{cid}-reliability.txt", media_type="text/plain",
                uploaded_by="self-assess",
            )
            await ev_confidence.score_object(session, obj)

    total = len(control_status)
    passed = sum(1 for s in control_status.values() if s in ("implemented", "inherited"))
    readiness = round(100 * passed / total, 1) if total else 0.0
    checks_passed = sum(1 for c in checks.values() if c.status == "pass")
    run = SelfAssuranceRun(
        organization_id=org_id, system_id=system_id, readiness_pct=readiness,
        checks_total=len(checks), checks_passed=checks_passed,
        summary={"control_status": control_status,
                 "checks": {n: c.status for n, c in checks.items()}},
    )
    session.add(run)
    await _audit(
        session, actor=actor or "system", action="create", entity_type="self_assurance",
        entity_id=str(system_id), diff={"event": "run", "readiness_pct": readiness},
    )
    await session.flush()
    return run


async def status(session: AsyncSession) -> dict[str, Any]:
    """Latest self-assessment status + control breakdown."""
    org = (
        await session.execute(select(Organization).where(Organization.name == SELF_ORG))
    ).scalar_one_or_none()
    if org is None:
        return {"initialized": False}
    latest = (
        await session.execute(
            select(SelfAssuranceRun)
            .where(SelfAssuranceRun.organization_id == org.id)
            .order_by(SelfAssuranceRun.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return {
        "initialized": True,
        "organization_id": org.id,
        "readiness_pct": latest.readiness_pct if latest else 0.0,
        "checks_total": latest.checks_total if latest else 0,
        "checks_passed": latest.checks_passed if latest else 0,
        "control_status": (latest.summary or {}).get("control_status", {}) if latest else {},
        "last_run": latest.created_at if latest else None,
    }


async def export_package(session: AsyncSession, *, actor: str | None = None) -> dict[str, Any]:
    """Export Concord's own authorization package (captures self-assurance facts)."""
    from ..packages import service as pkg_service  # noqa: PLC0415

    org_id, system_id = await _self_ids(session)
    pkg = await pkg_service.create_package(
        session, org_id=org_id, system_id=system_id, kind="json",
        label="Concord self-assurance package", created_by=actor,
    )
    return {"package_id": pkg.id, "readiness_pct": pkg.readiness_pct, "fact_count": pkg.fact_count}


def now() -> datetime:
    return datetime.now(UTC)
