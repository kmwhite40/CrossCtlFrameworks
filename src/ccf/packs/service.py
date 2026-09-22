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

from ..catalog.canonical import canonicalize
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


def _posture_rule_keys(manifest: dict[str, Any]) -> set[str]:
    return {
        str(r["key"])
        for r in manifest.get("rules", [])
        if isinstance(r, dict) and r.get("kind") == "posture" and r.get("key")
    }


async def _rule_key_collisions(
    session: AsyncSession, *, org_id: int | None, pack_key: str, rule_keys: set[str]
) -> list[str]:
    """Posture rule keys already claimed by a *different* installed pack.

    ``packs.catalog.validate_manifest`` only checks uniqueness within one
    manifest (its ``seen_keys`` is per-call and has no database). Two
    separately installed packs declaring the same key would otherwise
    collapse to one ``ControlTest`` row (unique on ``system_id, check_key``)
    with whichever pack's verdict happened to run last -- silently discarding
    the other pack's finding. Excludes this pack's own key so a reinstall or
    upgrade of the same pack never conflicts with itself.
    """
    if not rule_keys:
        return []
    rows = (
        await session.execute(
            select(PackRule.rule_key, CompliancePack.pack_key)
            .join(CompliancePack, CompliancePack.id == PackRule.pack_id)
            .where(
                CompliancePack.organization_id == org_id,
                CompliancePack.pack_key != pack_key,
                PackRule.rule_key.in_(rule_keys),
            )
        )
    ).all()
    return [
        f"posture rule key {rule_key!r} is already claimed by installed pack {other!r}"
        for rule_key, other in rows
    ]


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
    collisions = await _rule_key_collisions(
        session, org_id=org_id, pack_key=key, rule_keys=_posture_rule_keys(manifest)
    )
    if collisions:
        raise PackError("; ".join(collisions))
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
        # PackTestResult is included: a verdict computed against a superseded
        # manifest must not outlive the manifest it described.
        for model in (
            PackControl, PackMapping, PackEvidenceRequirement, PackRule, PackTestResult
        ):
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

    # The manifest, not only its sha: desired-state diff needs the content of
    # the version it is diffing against (see packs.diff).
    session.add(
        CompliancePackVersion(
            pack_id=pack.id, version=pack.version, manifest_sha=sha, manifest=manifest
        )
    )
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
    """Coverage of a pack's controls by a system's implementations.

    Both sides of the comparison are canonicalized, the same contract
    :mod:`ccf.capability.service` documents: ``controls.identifier`` is
    zero-padded in the real 800-53 catalog (``AC-01``, and 3747 of the dev
    catalog's 5430 rows carry that form) while a pack manifest declares the
    canonical unpadded id (``AC-2``). A raw string compare matched nothing, so
    against the real catalog every pack control reported as a gap and
    ``coverage_pct`` was 0.

    A pack ``control_id`` that does not canonicalize is *not* an 800-53 id at
    all -- the bundled packs deliberately declare native namespaces
    (``AIG-1``, ``CSA-RLS``, ``PS.1``), and ``catalog._validate_control_ids``
    only insists on canonical ids for posture *rules*, not for a pack's own
    control list. Such an id is neither a gap by default nor covered by
    default: it falls back to exact catalog identity, which is the only
    meaning it can have outside the canonical key space. It is also listed in
    ``unparseable_control_ids`` so an operator is told which rows were matched
    by identity alone and would therefore miss a padded catalog row.
    """
    from ..models import Control, ControlImplementation  # noqa: PLC0415

    pack_controls = (
        await session.execute(select(PackControl).where(PackControl.pack_id == pack.id))
    ).scalars().all()

    rows = (
        await session.execute(
            select(Control.identifier, ControlImplementation.status)
            .join(ControlImplementation, ControlImplementation.control_id == Control.id)
            .where(ControlImplementation.system_id == system_id)
        )
    ).all()
    satisfied_states = {"implemented", "inherited"}

    # Two indexes over this system's implementations. ``by_canonical`` is the
    # authoritative one; ``by_identifier`` serves only the ids that cannot
    # canonicalize. A catalog can carry two spellings of one control (``AC-01``
    # and ``AC-1``), so a satisfied row is never shadowed by an unsatisfied
    # duplicate that happened to be read second.
    by_canonical: dict[str, str] = {}
    by_identifier: dict[str, str] = {}
    for ident, status in rows:
        identifier = str(ident)
        by_identifier[identifier] = status
        c = canonicalize(identifier)
        if c is not None and by_canonical.get(c.value) not in satisfied_states:
            by_canonical[c.value] = status

    covered: list[str] = []
    gaps: list[str] = []
    unparseable: list[str] = []
    for pc in pack_controls:
        c = canonicalize(pc.control_id)
        if c is None:
            unparseable.append(pc.control_id)
            status = by_identifier.get(pc.control_id)
        else:
            status = by_canonical.get(c.value)
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
        "unparseable_control_ids": unparseable,
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
    # Conformance results are CURRENT STATE per pack, not history: the only
    # consumer counts rows with status='fail' across all time, so appending a
    # fresh set each run made one past failure warn forever, unclearable by
    # fixing the manifest. Replace rather than accumulate.
    await session.execute(delete(PackTestResult).where(PackTestResult.pack_id == pack.id))
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
