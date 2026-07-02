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
    ControlImplementation,
    Evidence,
    ScoringControl,
    ScoringStatus,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
    Vendor,
)
from ..scoring.engine import deduction_for, score_system
from ..ssp.seed import seed_project_entries
from . import bus

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
        "options": ["CMMC_L2", "NIST_800_171", "NIST_800_53", "FedRAMP", "CIS"],
    },
]

# m365 GCC High coverage status (per practice) -> (scoring state, responsibility).
_COVERAGE_TO_STATE: dict[str, tuple[str, str]] = {
    "Microsoft Coverage": ("inherited", "inherited"),
    "Shared Coverage": ("partial", "shared"),
    "Customer Responsibility": ("not_implemented", "customer"),
    "Not Applicable": ("not_applicable", "customer"),
}

# For platforms without per-practice data, a per-CMMC-domain default.
# domain -> (state, responsibility)
_PLATFORM_DOMAIN: dict[str, dict[str, tuple[str, str]]] = {
    "azure_gov": {
        "PE": ("inherited", "inherited"),
        "MA": ("partial", "shared"),
        "SC": ("partial", "shared"),
        "AU": ("partial", "shared"),
        "CM": ("partial", "shared"),
        "SI": ("partial", "shared"),
    },
    "aws_govcloud": {
        "PE": ("inherited", "inherited"),
        "MA": ("partial", "shared"),
        "SC": ("partial", "shared"),
        "AU": ("partial", "shared"),
        "CM": ("partial", "shared"),
        "SI": ("partial", "shared"),
    },
}
_DEFAULT_CUSTOMER = ("not_implemented", "customer")

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
    dom = _PLATFORM_DOMAIN.get(platform or "", {})
    if sc.domain in dom:
        state, resp = dom[sc.domain]
        return state, resp, f"platform:{platform}"
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
        if state in ("not_implemented", "planned") and resp in ("customer", "shared"):
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

# profile cloud platform -> SSP authoring platform code.
PLATFORM_TO_SSP = {
    "m365_gcc_high": "m365",
    "azure_gov": "azure",
    "aws_govcloud": "aws_govcloud",
}
_RESP_TO_ORIGINATION = {
    "inherited": ["Inherited"],
    "shared": ["Shared"],
    "customer": ["Configured by Customer / Business Owner"],
    "not_applicable": [],
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
    by_resp: dict[str, int] = {}
    by_state: dict[str, int] = {}
    for row in d.values():
        by_resp[row["responsibility"]] = by_resp.get(row["responsibility"], 0) + 1
        by_state[row["state"]] = by_state.get(row["state"], 0) + 1
    total = len(d)
    covered = by_state.get("inherited", 0) + by_state.get("implemented", 0)
    return {
        "total": total,
        "by_responsibility": by_resp,
        "by_state": by_state,
        "covered": covered,
        "coverage_pct": round(100 * covered / total, 1) if total else None,
        "derived_at": profile.derived_at.isoformat() if profile.derived_at else None,
    }
