"""Profile-driven compliance automation.

A system's :class:`SystemProfile` (captured via the intake questionnaire) drives
everything: which controls are *applicable*, which are *inherited* from the cloud
platform and from every linked vendor, the resulting SPRS score, a coverage
rollup, and auto-generated POA&M placeholders for the gaps. The derivation is a
pure function of the profile + the vendor register, so re-running is idempotent
and the snapshot on the profile is the single source of truth SSP/coverage read.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    POAM,
    CaptureSnapshot,
    ControlImplementation,
    Evidence,
    Policy,
    ScoringControl,
    ScoringStatus,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
    Vendor,
)
from ..scoring.engine import deduction_for, score_system
from ..ssp import constants as ssp_constants
from ..ssp import statements as stmt
from ..ssp.platforms import (
    MANUAL_EVIDENCE_NOTE,
    environment_for,
    has_capture_connector,
    services_for,
)
from ..ssp.seed import seed_project_entries
from . import ai, bus

# --- The questionnaire that makes intake simplistic --------------------------
QUESTIONNAIRE: list[dict[str, Any]] = [
    {"id": "system_name", "prompt": "What is the system / enclave name?", "type": "text"},
    {
        "id": "environment_type",
        "prompt": "Where does the system run?",
        "type": "single",
        "field": "environment_type",
        "options": ["cloud", "hybrid", "on_prem", "enclave"],
    },
    {
        "id": "cloud_platform",
        "prompt": "Primary cloud platform?",
        "type": "single",
        "field": "cloud_platform",
        "options": ["m365_gcc_high", "azure_gov", "aws_govcloud", "none"],
    },
    {
        "id": "identity_model",
        "prompt": "Identity provider?",
        "type": "single",
        "field": "identity_model",
        "options": ["entra_id", "okta", "ad_federated", "aws_iam", "other"],
    },
    {
        "id": "data_types",
        "prompt": "What data types are handled?",
        "type": "multi",
        "field": "data_types",
        "options": ["CUI", "CDI", "FCI", "PII", "PHI"],
    },
    {
        "id": "endpoint_scope",
        "prompt": "Which endpoints are in scope?",
        "type": "multi",
        "field": "endpoint_scope",
        "options": ["managed_windows", "servers", "mobile", "byod"],
    },
    {
        "id": "connectivity",
        "prompt": "Connectivity?",
        "type": "single",
        "field": "connectivity",
        "options": ["internet", "wireless", "isolated"],
    },
    {
        "id": "workloads",
        "prompt": "Workload types?",
        "type": "multi",
        "field": "workloads",
        "options": ["saas", "paas", "iaas", "containers", "database"],
    },
    {
        "id": "frameworks",
        "prompt": "Target framework(s)?",
        "type": "multi",
        "field": "frameworks",
        # Only frameworks the SSP pipeline actually produces are selectable here.
        # The generator is hardwired to the 110 CMMC L2 / NIST 800-171 Rev.2
        # practices; it does not produce a FedRAMP SSP or an 800-53 catalog, so
        # those are intentionally not offered as SSP-target frameworks.
        "options": ["CMMC_L2", "NIST_800_171", "CIS"],
    },
]

# m365 GCC High coverage status (per practice) -> (scoring state, responsibility).
_COVERAGE_TO_STATE: dict[str, tuple[str, str]] = {
    "Microsoft Coverage": ("inherited", "inherited"),
    "Shared Coverage": ("partial", "shared"),
    "Customer Responsibility": ("not_implemented", "customer"),
    "Not Applicable": ("not_applicable", "customer"),
}

# Intake-questionnaire cloud_platform code -> SSP authoring platform code (see
# ssp/platforms.py PLATFORMS). Defined here (rather than only near
# generate_ssp/generate_statements below, where it's also used) because
# _PLATFORM_DOMAIN needs it to translate into ssp/constants.py's canonical
# per-platform domain responsibility table.
PLATFORM_TO_SSP = {
    "m365_gcc_high": "m365",
    "azure_gov": "azure",
    "aws_govcloud": "aws_govcloud",
}

_RESP_TO_STATE = {"inherited": "inherited", "shared": "partial"}

# For platforms without per-practice data, a per-CMMC-domain default.
# domain -> (state, responsibility). Sourced from ssp/constants.py's
# PLATFORM_DOMAIN_RESPONSIBILITY (translated from this module's cloud_platform
# codes to SSP platform codes via PLATFORM_TO_SSP) so this module's SPRS-scoring
# responsibility and ssp/seed.py's SSP control origination never disagree — one
# table, not two hand-maintained copies.
_PLATFORM_DOMAIN: dict[str, dict[str, tuple[str, str]]] = {
    cloud_code: {
        domain: (_RESP_TO_STATE[resp], resp)
        for domain, resp in ssp_constants.PLATFORM_DOMAIN_RESPONSIBILITY.get(ssp_code, {}).items()
    }
    for cloud_code, ssp_code in PLATFORM_TO_SSP.items()
    if ssp_code in ssp_constants.PLATFORM_DOMAIN_RESPONSIBILITY
}
_DEFAULT_CUSTOMER = ("not_implemented", "customer")
_DEFAULT_UNKNOWN = ("not_implemented", "unknown")

# Applicability (N/A) rules: predicate over the profile -> CMMC control ids N/A.
_MOBILE_CTRLS = {"AC.L2-3.1.18", "AC.L2-3.1.19"}
_WIRELESS_CTRLS = {"AC.L2-3.1.16", "AC.L2-3.1.17"}


def na_control_ids(profile: SystemProfile) -> set[str]:
    """CMMC practices marked Not Applicable given the profile's scope."""
    na: set[str] = set()
    scope = set(profile.endpoint_scope or [])
    if "mobile" not in scope and "byod" not in scope:
        na |= _MOBILE_CTRLS
    if (profile.connectivity or "") != "wireless":
        na |= _WIRELESS_CTRLS
    return na


async def _vendor_inheritance(session: AsyncSession, org_id: int | None) -> dict[str, str]:
    """control_id -> vendor name, aggregated across ALL vendors in the org.

    Any control listed in a vendor's ``linked_controls`` is treated as inherited
    from that vendor — so inheritance loads from every vendor, not just the
    cloud platform.
    """
    stmt = select(Vendor)
    if org_id is not None:
        # Include org-scoped vendors and global (unscoped) shared services.
        stmt = stmt.where((Vendor.organization_id == org_id) | (Vendor.organization_id.is_(None)))
    out: dict[str, str] = {}
    for v in (await session.execute(stmt)).scalars().all():
        if v.status == "offboarded":
            continue
        for cid in v.linked_controls or []:
            out[str(cid)] = v.name
    return out


def _platform_state(platform: str | None, sc: ScoringControl) -> tuple[str, str, str]:
    """Return (state, responsibility, source) from the cloud platform inheritance."""
    if platform == "m365_gcc_high":
        state, resp = _COVERAGE_TO_STATE.get(sc.m365_coverage_status or "", _DEFAULT_CUSTOMER)
        return state, resp, "platform:m365_gcc_high"
    if platform in _PLATFORM_DOMAIN:
        dom = _PLATFORM_DOMAIN[platform]
        if sc.domain in dom:
            state, resp = dom[sc.domain]
            return state, resp, f"platform:{platform}"
        # A recognized cloud platform with no per-control or per-domain coverage
        # data for this domain — don't silently guess "customer" (FR-12); flag
        # it "unknown" so SSP origination and coverage rollups surface it for
        # manual responsibility assignment instead of a false-confident default.
        return (*_DEFAULT_UNKNOWN, f"platform:{platform}")
    # No cloud platform selected (or an unrecognized code) — nothing can be
    # inherited, so "customer" is the correct, non-guessed default here.
    return (*_DEFAULT_CUSTOMER, "customer")


_SEV_FOR_PV = {"5": "high", "3": "moderate", "1": "low", "3/5": "high", "Special": "moderate"}


async def derive_system(
    session: AsyncSession,
    *,
    system_id: int,
    org_id: int | None,
    profile: SystemProfile,
    create_poams: bool = True,
    actor: str | None = None,
) -> dict[str, Any]:
    """Derive applicability + inheritance + SPRS + coverage from the profile."""
    practices = (
        (await session.execute(select(ScoringControl).order_by(ScoringControl.sort_order)))
        .scalars()
        .all()
    )
    na_ids = na_control_ids(profile)
    vendor_map = await _vendor_inheritance(session, org_id)

    existing_status = {
        s.scoring_control_id: s
        for s in (
            await session.execute(select(ScoringStatus).where(ScoringStatus.system_id == system_id))
        )
        .scalars()
        .all()
    }

    derivation: dict[str, Any] = {}
    score_states: dict[str, str] = {}
    score_rows: list[dict[str, Any]] = []
    by_resp: dict[str, int] = {}
    by_state: dict[str, int] = {}
    gaps: list[ScoringControl] = []

    for sc in practices:
        if sc.control_id in na_ids:
            state, resp, source = "not_applicable", "not_applicable", "profile:not_applicable"
        elif sc.control_id in vendor_map:
            state, resp, source = "inherited", "inherited", f"vendor:{vendor_map[sc.control_id]}"
        else:
            state, resp, source = _platform_state(profile.cloud_platform, sc)

        derivation[sc.control_id] = {
            "state": state,
            "responsibility": resp,
            "source": source,
            "domain": sc.domain,
            "point_value": sc.point_value,
        }
        score_states[sc.control_id] = state
        score_rows.append(
            {"control_id": sc.control_id, "domain": sc.domain, "point_value": sc.point_value}
        )
        by_resp[resp] = by_resp.get(resp, 0) + 1
        by_state[state] = by_state.get(state, 0) + 1
        # "unknown" (no per-control/per-domain coverage data) is a gap too — it
        # still needs a POA&M/triage entry, just like customer/shared, rather
        # than being silently treated as covered.
        if state in ("not_implemented", "planned") and resp in ("customer", "shared", "unknown"):
            gaps.append(sc)

        # Upsert the CMMC scoring state so SPRS reflects the derivation.
        st = existing_status.get(sc.id)
        if st is None:
            session.add(
                ScoringStatus(
                    system_id=system_id,
                    scoring_control_id=sc.id,
                    state=state,
                    notes=f"derived: {source}",
                )
            )
        elif st.state == "not_assessed":  # don't clobber a human assessment
            st.state = state
            st.notes = f"derived: {source}"

    summary = score_system(score_rows, score_states)

    # Persist the snapshot on the profile.
    profile.derivation = derivation
    profile.derived_at = datetime.now(UTC)
    await session.flush()

    poams_created = 0
    if create_poams:
        poams_created = await _seed_gap_poams(session, system_id, gaps, derivation)

    result = {
        "controls_total": len(practices),
        "applicable": len(practices) - by_state.get("not_applicable", 0),
        "by_responsibility": by_resp,
        "by_state": by_state,
        "sprs_score": summary.score,
        "sprs_percentage": summary.percentage,
        "ssp_present": summary.ssp_present,
        "gaps": len(gaps),
        "poams_created": poams_created,
        "vendors_inherited": len(set(vendor_map.values())),
    }
    await bus.emit(
        session,
        verb="derived",
        entity_type="system",
        entity_id=system_id,
        summary=(
            f"Profile derived: SPRS {summary.score}/110, {len(gaps)} gaps, "
            f"{by_resp.get('inherited', 0)} inherited"
        ),
        org_id=org_id,
        actor=actor,
        payload=result,
    )
    return result


async def _seed_gap_poams(
    session: AsyncSession,
    system_id: int,
    gaps: list[ScoringControl],
    derivation: dict[str, Any],
) -> int:
    """Create an open POA&M placeholder per gap (idempotent by title)."""
    existing = {
        t
        for (t,) in (
            await session.execute(select(POAM.title).where(POAM.system_id == system_id))
        ).all()
    }
    today = date.today()
    created = 0
    for sc in gaps:
        title = f"{sc.control_id} — {sc.title or 'gap'}"
        if title in existing:
            continue
        session.add(
            POAM(
                system_id=system_id,
                title=title,
                weakness=f"Practice {sc.control_id} ({sc.nist_id}) not yet implemented "
                f"(responsibility: {derivation[sc.control_id]['responsibility']}).",
                severity=_SEV_FOR_PV.get(sc.point_value, "moderate"),
                status="open",
                source="profile_gap",
                identified_on=today,
            )
        )
        created += 1
    return created


# --- Profile -> SSP projection ----------------------------------------------
# (PLATFORM_TO_SSP is defined earlier, alongside _PLATFORM_DOMAIN, which needs
# it too.)
_RESP_TO_ORIGINATION = {
    "inherited": ["Inherited"],
    "shared": ["Shared"],
    "customer": ["Configured by Customer / Business Owner"],
    "not_applicable": [],
    # No per-control/per-domain coverage data (see ssp/constants.py
    # needs_manual_responsibility_assignment) — leave origination unset rather
    # than overwriting seed.py's manual-assignment flag with a confident guess.
    "unknown": [],
}
_STATE_TO_STATUS = {
    "inherited": ["Implemented"],
    "implemented": ["Implemented"],
    "partial": ["Partially Implemented"],
    "not_implemented": ["Planned"],
    "planned": ["Planned"],
    "not_applicable": ["Not Applicable"],
}


def ssp_overlay_for(control_id: str, derivation: dict[str, Any]) -> dict[str, list[str]]:
    """Origination + implementation status an SSP entry should inherit from derivation."""
    row = derivation.get(control_id)
    if not row:
        return {}
    return {
        "control_origination": _RESP_TO_ORIGINATION.get(row["responsibility"], []),
        "implementation_status": _STATE_TO_STATUS.get(row["state"], ["Planned"]),
    }


async def generate_ssp(
    session: AsyncSession, *, system: System, profile: SystemProfile, actor: str | None = None
) -> int:
    """Create an SSP project seeded from the derivation (origination + status)."""
    plat = PLATFORM_TO_SSP.get(profile.cloud_platform or "", "m365")
    proj = SSPProject(
        organization_id=system.organization_id,
        system_id=system.id,
        customer_name=system.name,
        system_name=system.name,
        platform=plat,
    )
    session.add(proj)
    await session.flush()
    await seed_project_entries(session, proj)  # seeds one entry per practice
    entries = (
        (
            await session.execute(
                select(SSPControlEntry).where(SSPControlEntry.project_id == proj.id)
            )
        )
        .scalars()
        .all()
    )
    derivation = profile.derivation or {}
    for e in entries:
        ov = ssp_overlay_for(e.control_id, derivation)
        if ov:
            e.control_origination = ov["control_origination"]
            e.implementation_status = ov["implementation_status"]
    await session.flush()
    # Auto-compose the implementation statements from the derivation.
    await generate_statements(session, project=proj, profile=profile)
    await bus.emit(
        session,
        verb="generated",
        entity_type="ssp_project",
        entity_id=proj.id,
        summary=f"SSP auto-generated for {system.name} from profile ({len(entries)} controls)",
        org_id=system.organization_id,
        actor=actor,
    )
    return proj.id


async def generate_statements(
    session: AsyncSession,
    *,
    project: SSPProject,
    profile: SystemProfile,
    use_ai: bool = False,
    style: str = "standard",
    include_captured: bool = True,
    mark_draft: bool = True,
) -> dict[str, Any]:
    """Compose each entry's implementation statement from the derivation + config.

    Reflects responsibility/inheritance source, environment, services, filled
    ODP values, and live captured config; optionally drafts via AI when enabled.
    """
    ssp_plat = PLATFORM_TO_SSP.get(profile.cloud_platform or "", project.platform or "m365")
    environment = environment_for(ssp_plat, profile.cloud_platform)
    # No live capture connector exists for this platform (Azure/GCP/etc. today —
    # see ssp/platforms.py CONNECTOR_PLATFORMS) — every statement composed below
    # gets an explicit manual-evidence flag rather than reading as auto-evidenced
    # (FR-06).
    connector_backed = has_capture_connector(ssp_plat)
    derivation = profile.derivation or {}

    # Live captured config indexed by NIST id (from the connector collection loop).
    caps_by_nist: dict[str, list[dict[str, str]]] = {}
    for snap in (
        (
            await session.execute(
                select(CaptureSnapshot).where(
                    CaptureSnapshot.organization_id == project.organization_id
                )
            )
        )
        .scalars()
        .all()
    ):
        if snap.nist_id:
            caps_by_nist.setdefault(snap.nist_id, []).append(
                {"odp_key": snap.odp_key, "value": snap.value, "connector": snap.connector}
            )

    # Real vendors, by name, for the ``crm_ref``/``frequency`` of a
    # vendor-inherited control (source ``vendor:<name>`` — see
    # ``_vendor_inheritance``) — ``authorization`` (e.g. "FedRAMP High
    # Authorized") and ``review_frequency`` are only used when actually on
    # file for that vendor, never fabricated (FR-11).
    vendors_by_name: dict[str, Vendor] = {
        v.name: v
        for v in (
            (
                await session.execute(
                    select(Vendor).where(
                        (Vendor.organization_id == project.organization_id)
                        | (Vendor.organization_id.is_(None))
                    )
                )
            )
            .scalars()
            .all()
        )
        if v.status != "offboarded"
    }

    # Real governing policies, by control id, for ``policy_ref``/``frequency`` —
    # only an active policy's name/review cadence is used, never fabricated.
    policy_by_control: dict[str, Policy] = {}
    for p in (
        (
            await session.execute(
                select(Policy).where(
                    (Policy.organization_id == project.organization_id)
                    | (Policy.organization_id.is_(None))
                )
            )
        )
        .scalars()
        .all()
    ):
        if p.status != "active":
            continue
        for cid in p.linked_controls or []:
            policy_by_control.setdefault(str(cid), p)

    entries = (
        (
            await session.execute(
                select(SSPControlEntry).where(SSPControlEntry.project_id == project.id)
            )
        )
        .scalars()
        .all()
    )
    ai_ready = use_ai and ai.is_configured()
    drafts = ai_used = manual_evidence_required = 0
    for e in entries:
        row = derivation.get(e.control_id) or {}
        responsibility = row.get("responsibility", "customer")
        services = services_for(ssp_plat, e.domain)
        captured = caps_by_nist.get(e.nist_id or "", [])
        source = row.get("source")
        policy = policy_by_control.get(e.control_id)
        # A vendor-inherited control's real authorization reference/review
        # cadence (only when actually on file for that vendor) — lets the
        # inherited statement recognize the leveraged authorization instead
        # of always reporting nothing linked (FR-11).
        vendor = None
        if str(source or "").startswith("vendor:"):
            vendor = vendors_by_name.get(str(source).split(":", 1)[1])
        crm_ref = vendor.authorization.strip() if vendor and vendor.authorization else None
        vendor_frequency = vendor.review_frequency if vendor and vendor.review_frequency else None
        frequency = vendor_frequency or (policy.review_frequency if policy else None)
        text, needs_review = stmt.compose(
            control_id=e.control_id,
            requirement=e.requirement,
            responsibility=responsibility,
            source=source,
            environment=environment,
            services=services,
            odp_values=dict(e.odp_values or {}),
            captured=captured,
            style=style,
            include_captured=include_captured,
            mark_draft=mark_draft,
            # e.responsible_role is the project's real named role (or the
            # honestly-flagged generic fallback) already resolved by
            # ssp/seed.py from front-matter metadata — pass it through so the
            # narrative reflects it verbatim instead of re-deriving a fresh
            # unnamed generic label here (FR-13).
            responsible_role=e.responsible_role,
            frequency=frequency,
            policy_ref=policy.name if policy else None,
            crm_ref=crm_ref,
        )
        if ai_ready and responsibility in ("customer", "shared", "unknown"):
            ai_text = await ai.draft_narrative(
                e.control_id,
                e.requirement or "",
                environment,
                services,
                session=session,
                organization_id=project.organization_id,
            )
            if ai_text:
                text = (stmt.DRAFT_PREFIX if mark_draft else "") + ai_text
                ai_used += 1
        if not connector_backed:
            # Nothing about this platform has been technically verified by any
            # capture connector — force review and make that explicit in the
            # narrative itself, even for statements (e.g. "inherited") that
            # would otherwise read as already evidenced (FR-06).
            needs_review = True
            if mark_draft and not text.startswith(stmt.DRAFT_PREFIX):
                text = stmt.DRAFT_PREFIX + text
            text = f"{text} {MANUAL_EVIDENCE_NOTE}"
            manual_evidence_required += 1
            # A platform-derived "Implemented" status (never a vendor-linked
            # one — see coverage()'s identical ``is_platform_sourced`` check)
            # can't actually be evidenced without a capture connector; keep
            # the docx status column consistent with the manual-evidence flag
            # instead of still claiming full "Implemented" (Finding 2).
            is_platform_sourced = str(source or "").startswith("platform:")
            if is_platform_sourced and "Implemented" in (e.implementation_status or []):
                e.implementation_status = ["Partially Implemented"]
        if needs_review:
            drafts += 1
        e.part_narratives = [{"label": "Implementation", "text": text}]
    await session.flush()
    return {
        "entries": len(entries),
        "drafts": drafts,
        "ai_used": ai_used,
        "manual_evidence_required": manual_evidence_required,
    }


async def control_impact(session: AsyncSession, system_id: int) -> dict[str, Any]:
    """Per-control score contribution + the delta if it were implemented."""
    practices = (await session.execute(select(ScoringControl))).scalars().all()
    states = {
        s.scoring_control_id: s.state
        for s in (
            await session.execute(select(ScoringStatus).where(ScoringStatus.system_id == system_id))
        )
        .scalars()
        .all()
    }
    rows: list[dict[str, Any]] = []
    for sc in practices:
        state = states.get(sc.id, "not_assessed")
        current = deduction_for(sc.point_value, state)
        implemented = deduction_for(sc.point_value, "implemented")
        rows.append(
            {
                "control_id": sc.control_id,
                "domain": sc.domain,
                "point_value": sc.point_value,
                "state": state,
                "current_deduction": current,
                "gain_if_implemented": current - implemented,
            }
        )
    rows.sort(key=lambda r: r["gain_if_implemented"], reverse=True)
    return {
        "total_deduction": sum(r["current_deduction"] for r in rows),
        "recoverable": sum(r["gain_if_implemented"] for r in rows),
        "controls": rows,
    }


async def evidence_requirements(
    session: AsyncSession, system_id: int, profile: SystemProfile
) -> dict[str, Any]:
    """Derived evidence checklist: what each non-inherited control needs + status."""
    practices = {
        sc.control_id: sc for sc in (await session.execute(select(ScoringControl))).scalars()
    }
    have = {
        e.title
        for e in (
            await session.execute(
                select(Evidence)
                .join(ControlImplementation, ControlImplementation.id == Evidence.implementation_id)
                .where(ControlImplementation.system_id == system_id)
            )
        )
        .scalars()
        .all()
    }
    items: list[dict[str, Any]] = []
    for cid, row in (profile.derivation or {}).items():
        if row["responsibility"] == "inherited" or row["state"] == "not_applicable":
            continue
        sc = practices.get(cid)
        rec = (sc.recommended_customer_evidence if sc else None) or "Evidence of implementation"
        items.append(
            {
                "control_id": cid,
                "responsibility": row["responsibility"],
                "required_evidence": rec,
                "satisfied": any(cid in t for t in have),
            }
        )
    items.sort(key=lambda i: i["satisfied"])
    return {
        "required": len(items),
        "satisfied": sum(1 for i in items if i["satisfied"]),
        "items": items,
    }


def coverage(profile: SystemProfile) -> dict[str, Any]:
    """Read the derivation snapshot into a coverage rollup for dashboards."""
    d = profile.derivation or {}
    ssp_plat = PLATFORM_TO_SSP.get(profile.cloud_platform or "", "")
    # No live capture connector exists for this platform (Azure/GCP/etc. — see
    # ssp/platforms.py CONNECTOR_PLATFORMS): a "platform:"-sourced inherited
    # state here is the derivation's own default assumption, never anything a
    # connector actually captured, so it must not silently count as "covered"
    # (FR-06). An explicit vendor inheritance (a customer-linked vendor's
    # ``linked_controls``) is a deliberate human action, not a platform default,
    # and is unaffected.
    connector_backed = has_capture_connector(ssp_plat)
    by_resp: dict[str, int] = {}
    by_state: dict[str, int] = {}
    covered = 0
    manual_evidence_required = 0
    for row in d.values():
        by_resp[row["responsibility"]] = by_resp.get(row["responsibility"], 0) + 1
        by_state[row["state"]] = by_state.get(row["state"], 0) + 1
        if row["state"] not in ("inherited", "implemented"):
            continue
        is_platform_sourced = str(row.get("source") or "").startswith("platform:")
        if not connector_backed and is_platform_sourced:
            manual_evidence_required += 1
        else:
            covered += 1
    total = len(d)
    return {
        "total": total,
        "by_responsibility": by_resp,
        "by_state": by_state,
        "covered": covered,
        "coverage_pct": round(100 * covered / total, 1) if total else None,
        "manual_evidence_required": manual_evidence_required,
        "derived_at": profile.derived_at.isoformat() if profile.derived_at else None,
    }
