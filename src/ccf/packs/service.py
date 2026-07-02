"""Pack install/upgrade + coverage + conformance tests.

Install is idempotent (re-installing the same manifest is a no-op beyond a fresh
version record) and strictly tenant-scoped — every row is written under the
installing org's ``organization_id``, so a pack can never create cross-tenant
data. Coverage compares a pack's controls to a system's implementations.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_packs import (
    CompliancePack,
    CompliancePackVersion,
    PackControl,
    PackEvidenceRequirement,
    PackInstallRun,
    PackMapping,
    PackRule,
    PackTestResult,
)
from .catalog import manifest_sha, validate_manifest


class PackError(ValueError):
    """Raised on an invalid pack or install operation."""


async def _audit(session: AsyncSession, **kw: Any) -> None:
    from ..api.audit import record_event  # noqa: PLC0415 — avoid import cycle

    await record_event(session, **kw)


async def install_pack(
    session: AsyncSession,
    *,
    org_id: int | None,
    manifest: dict[str, Any],
    source: str | None = None,
    actor: str | None = None,
) -> CompliancePack:
    """Install (or idempotently upgrade) a pack for a tenant."""
    errors = validate_manifest(manifest)
    if errors:
        raise PackError("; ".join(errors))

    key = str(manifest["id"])
    sha = manifest_sha(manifest)
    existing = (
        await session.execute(
            select(CompliancePack).where(
                CompliancePack.organization_id == org_id, CompliancePack.pack_key == key
            )
        )
    ).scalar_one_or_none()
    action = "install"
    if existing is None:
        pack = CompliancePack(organization_id=org_id, pack_key=key)
        session.add(pack)
    else:
        pack = existing
        action = "upgrade"

    pack.name = str(manifest.get("name", key))
    pack.version = str(manifest.get("version", "0"))
    pack.schema_version = str(manifest.get("schema_version", "1"))
    pack.source = source
    pack.manifest_sha = sha
    pack.status = "installed"
    pack.manifest = manifest
    await session.flush()  # assign pack.id (new) with required fields set

    if existing is not None:
        # Replace materialized children; keeps other packs untouched.
        for model in (PackControl, PackMapping, PackEvidenceRequirement, PackRule):
            await session.execute(delete(model).where(model.pack_id == pack.id))

    for c in manifest.get("controls", []):
        session.add(PackControl(
            pack_id=pack.id, control_id=str(c["control_id"]),
            title=c.get("title"), family=c.get("family")))
    for m in manifest.get("mappings", []):
        session.add(PackMapping(
            pack_id=pack.id, control_id=str(m.get("control_id", "")),
            framework=str(m.get("framework", "")), reference=m.get("reference")))
    for e in manifest.get("evidence_requirements", []):
        session.add(PackEvidenceRequirement(
            pack_id=pack.id, control_id=str(e.get("control_id", "")),
            description=str(e.get("description", ""))))
    for r in manifest.get("rules", []):
        session.add(PackRule(
            pack_id=pack.id, rule_key=str(r.get("key", "")), kind=r.get("kind"),
            definition=r.get("definition", {})))

    session.add(CompliancePackVersion(pack_id=pack.id, version=pack.version, manifest_sha=sha))
    session.add(PackInstallRun(
        organization_id=org_id, pack_key=key, action=action, status="ok",
        summary={"controls": len(manifest.get("controls", [])),
                 "mappings": len(manifest.get("mappings", [])),
                 "version": pack.version}))
    await _audit(
        session, actor=actor or "system", action="create", entity_type="compliance_pack",
        entity_id=str(pack.id),
        diff={"event": action, "pack": key, "version": pack.version, "sha": sha},
    )
    await session.flush()
    return pack


async def coverage(
    session: AsyncSession, *, pack: CompliancePack, system_id: int
) -> dict[str, Any]:
    """Coverage of a pack's controls by a system's implementations."""
    from ..models import Control, ControlImplementation  # noqa: PLC0415

    pack_controls = (
        await session.execute(select(PackControl).where(PackControl.pack_id == pack.id))
    ).scalars().all()

    # Map system implementations by normalized control identifier.
    rows = (
        await session.execute(
            select(Control.identifier, ControlImplementation.status)
            .join(ControlImplementation, ControlImplementation.control_id == Control.id)
            .where(ControlImplementation.system_id == system_id)
        )
    ).all()
    satisfied_states = {"implemented", "inherited"}
    impl = {str(ident): status for ident, status in rows}

    covered = []
    gaps = []
    for pc in pack_controls:
        status = impl.get(pc.control_id)
        if status in satisfied_states:
            covered.append(pc.control_id)
        else:
            gaps.append(pc.control_id)
    total = len(pack_controls)
    return {
        "pack_key": pack.pack_key,
        "system_id": system_id,
        "total_controls": total,
        "covered": len(covered),
        "coverage_pct": round(100 * len(covered) / total, 1) if total else 0.0,
        "gaps": gaps,
    }


def _eval_assert(expr: str, counts: dict[str, int]) -> tuple[bool, str]:
    """Evaluate a simple ``<key><op><number>`` assertion against manifest counts."""
    for op in (">=", "<=", "==", ">", "<"):
        if op in expr:
            left, right = expr.split(op, 1)
            key = left.strip()
            try:
                want = int(right.strip())
            except ValueError:
                return False, f"bad number in '{expr}'"
            have = counts.get(key, 0)
            ok = {
                ">=": have >= want, "<=": have <= want, "==": have == want,
                ">": have > want, "<": have < want,
            }[op]
            return ok, f"{key}={have} {op} {want}"
    return False, f"unrecognized assertion '{expr}'"


async def run_tests(session: AsyncSession, pack: CompliancePack) -> list[PackTestResult]:
    """Run a pack's conformance tests against its installed content."""
    manifest = pack.manifest or {}
    counts = {k: len(manifest.get(k, [])) for k in (
        "controls", "mappings", "evidence_requirements", "rules",
        "policy_templates", "questionnaire_templates", "connector_mappings", "tests",
    )}
    results: list[PackTestResult] = []
    for t in manifest.get("tests", []):
        key = str(t.get("key", "test"))
        ok, detail = _eval_assert(str(t.get("assert", "")), counts)
        res = PackTestResult(
            pack_id=pack.id, test_key=key, status="pass" if ok else "fail", detail=detail
        )
        session.add(res)
        results.append(res)
    await session.flush()
    return results


def now() -> datetime:
    return datetime.now(UTC)
