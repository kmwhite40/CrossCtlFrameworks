"""OSCAL Component Definition export (#16).

Emits a minimal OSCAL 1.1 Component Definition describing Concord's view of a
given system: the list of implemented / inherited controls with their
implementation narratives. Not a full OSCAL profile — targets auditor intake.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...auth import Principal
from ...boundary.summary import BoundarySummary, system_boundary_summary
from ...catalog.canonical import canonical_to_oscal_id, canonicalize
from ...models import (
    POAM,
    Assessment,
    AssessmentResult,
    Control,
    ControlImplementation,
    SSPControlEntry,
    SSPProject,
    System,
)
from ...models_evidence import EvidenceObject
from ...oscal import validate_document
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/oscal", tags=["oscal"])


@router.post("/validate")
async def validate_oscal_endpoint(
    body: dict[str, Any],
    kind: str = "auto",
    _principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Validate a posted OSCAL document (SSP / Component Definition / POA&M /
    assessment) against the official schema when configured, else structural
    checks. ``kind`` defaults to auto-detection from the document root key."""
    return validate_document(body, kind=kind).as_dict()

# OSCAL POA&M item status maps to the assessment-log lifecycle NIST expects.
_OSCAL_POAM_STATE = {
    "open": "open",
    "in_progress": "investigating",
    "completed": "closed",
    "closed": "closed",
    "risk_accepted": "risk-accepted",
}
_OSCAL_SEVERITY = {"low": "low", "moderate": "moderate", "high": "high", "critical": "critical"}

# AssessmentResult.finding -> OSCAL finding target.status.state. "not_applicable"
# has no direct OSCAL state — it is encoded as "not-satisfied" plus an
# "applicability" prop (see build_sar_doc) rather than dropped.
_OSCAL_FINDING_STATE = {
    "satisfied": "satisfied",
    "other_than_satisfied": "not-satisfied",
    "not_applicable": "not-satisfied",
}

# Both OSCAL exports must cite the same catalog the project is actually built
# against — CMMC Level 2 / NIST SP 800-171 Rev. 2 — not NIST SP 800-53.
_OSCAL_BASELINE_NAME = "CMMC Level 2 (NIST SP 800-171 Rev. 2)"
_OSCAL_PROFILE_HREF = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-171/rev2/json/NIST_SP-800-171_rev2_PROFILE.json"
)

# Marker used when a docx-front-matter field is absent from ``metadata_json`` —
# never fall back to a false constant like "cui"/"operational".
_PLACEHOLDER = "UNSPECIFIED"

# metadata_json["roles"] key -> (OSCAL role-id, human title). Mirrors the roles
# rendered in ssp/generator.py's "1.2 Roles and Responsibilities" table.
_OSCAL_ROLES: tuple[tuple[str, str, str], ...] = (
    ("system_owner", "system-owner", "System Owner"),
    ("isso", "isso", "Information System Security Officer"),
    ("issm", "issm", "Information System Security Manager"),
    ("authorizing_official", "authorizing-official", "Authorizing Official"),
)

# metadata_json["operational_status"] (free text) -> OSCAL status.state enum.
_OSCAL_STATUS_STATES = {
    "operational": "operational",
    "under development": "under-development",
    "under-development": "under-development",
    "under major modification": "under-major-modification",
    "under-major-modification": "under-major-modification",
    "disposition": "disposition",
    "other": "other",
}


def _oscal_control_id(identifier: str | None) -> str:
    """A control identifier in OSCAL form: canonicalized 800-53 ids go through
    ``canonical_to_oscal_id`` (``AC-2(1)`` -> ``ac-2.1``); anything that doesn't
    canonicalize (CMMC-style ids, free text) is just lowercased — never dropped."""
    raw = identifier or ""
    canon = canonicalize(raw)
    return canonical_to_oscal_id(canon.value) if canon is not None else raw.lower()


def _placeholder(what: str) -> str:
    return f"{_PLACEHOLDER} — {what} not set in SSP project metadata"


def _meta_str(value: Any, what: str) -> str:
    """Return ``value`` stripped, or a clearly-marked placeholder when absent."""
    text = str(value).strip() if value not in (None, "") else ""
    return text or _placeholder(what)


def _oscal_status(meta: dict[str, Any]) -> dict[str, Any]:
    raw = str(meta.get("operational_status") or "").strip()
    if not raw:
        return {"state": "other", "remarks": _placeholder("operational_status")}
    state = _OSCAL_STATUS_STATES.get(raw.lower())
    if state is None:
        return {"state": "other", "remarks": raw}
    return {"state": state}


def _oscal_information_types(
    meta: dict[str, Any], summary: BoundarySummary | None
) -> list[dict[str, Any]]:
    """Build OSCAL information-types from the real boundary inventory when one
    exists; otherwise fall back to the single type synthesized from
    ``fips199``. ``base`` is an OSCAL token — it must never hold a
    human-readable placeholder sentence (spaces/em-dash aren't valid token
    characters). When a level's categorization is absent, the impact object is
    omitted entirely (never fabricated)."""
    if summary and summary.info_types:
        info_types: list[dict[str, Any]] = []
        for it in summary.info_types:
            node: dict[str, Any] = {
                "uuid": it.oscal_uuid,
                "title": it.title,
                "description": it.description or it.title,
            }
            for key, value in (
                ("confidentiality-impact", it.confidentiality_impact),
                ("integrity-impact", it.integrity_impact),
                ("availability-impact", it.availability_impact),
            ):
                if value:
                    node[key] = {"base": value}
            if it.adjustment_justification:
                node["remarks"] = it.adjustment_justification
            info_types.append(node)
        return info_types

    fips = meta.get("fips199") or {}
    title = _meta_str(meta.get("system_type"), "system_type")

    info_type: dict[str, Any] = {
        "uuid": str(uuid.uuid4()),
        "title": title,
        "description": title,
    }
    missing_levels: list[str] = []
    for level, key in (
        ("confidentiality", "confidentiality-impact"),
        ("integrity", "integrity-impact"),
        ("availability", "availability-impact"),
    ):
        value = str(fips.get(level) or "").strip()
        if value:
            info_type[key] = {"base": value}
        else:
            missing_levels.append(level)
    if missing_levels:
        info_type["remarks"] = _placeholder(
            ", ".join(f"fips199.{level}" for level in missing_levels)
        )
    return [info_type]


def _oscal_roles_and_parties(
    meta: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Build OSCAL metadata roles/parties/responsible-parties from
    ``metadata_json["roles"]`` — the same source the docx "Roles and
    Responsibilities" table reads."""
    roles_meta = meta.get("roles") or {}
    roles: list[dict[str, Any]] = []
    parties: list[dict[str, Any]] = []
    responsible_parties: list[dict[str, Any]] = []
    for key, role_id, title in _OSCAL_ROLES:
        roles.append({"id": role_id, "title": title})
        entry = roles_meta.get(key) or {}
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        party_uuid = str(uuid.uuid4())
        party: dict[str, Any] = {"uuid": party_uuid, "type": "person", "name": name}
        email = str(entry.get("email") or "").strip()
        if email:
            party["email-addresses"] = [email]
        parties.append(party)
        responsible_parties.append({"role-id": role_id, "party-uuids": [party_uuid]})
    return roles, parties, responsible_parties


def _oscal_system_implementation(
    proj: SSPProject,
    meta: dict[str, Any],
    responsible_parties: list[dict[str, Any]],
    summary: BoundarySummary | None,
) -> dict[str, Any]:
    """system-implementation built from the real boundary inventory (System
    components + interconnections + inventory items) when one has been
    enumerated for the project's system, plus one user per filled responsible
    role. Falls back to the single synthesized placeholder component when the
    boundary is empty — annotated with ``remarks`` so the gap is visible."""
    users = [
        {
            "uuid": str(uuid.uuid4()),
            "title": rp["role-id"],
            "role-ids": [rp["role-id"]],
        }
        for rp in responsible_parties
    ]

    if summary and (summary.components or summary.interconnections):
        comp_uuid_by_id: dict[int, str] = {}
        components: list[dict[str, Any]] = []
        for c in summary.components:
            comp_uuid_by_id[c.id] = c.oscal_uuid
            components.append(
                {
                    "uuid": c.oscal_uuid,
                    "type": c.type,
                    "title": c.title,
                    "description": c.description or c.title,
                    "status": {"state": c.status},
                }
            )
        for icx in summary.interconnections:
            components.append(
                {
                    "uuid": icx.oscal_uuid,
                    "type": "interconnection",
                    "title": icx.remote_system_name,
                    "description": icx.data_description or icx.remote_system_name,
                    "status": {"state": "operational"},
                    "props": [
                        {"name": "direction", "value": icx.direction},
                        {"name": "agreement-type", "value": icx.agreement_type},
                    ],
                }
            )
        result: dict[str, Any] = {"users": users, "components": components}
        if summary.inventory:
            inventory_items: list[dict[str, Any]] = []
            for item in summary.inventory:
                inv: dict[str, Any] = {
                    "uuid": item.oscal_uuid,
                    "description": item.description or item.asset_id,
                }
                if item.component_id is not None and item.component_id in comp_uuid_by_id:
                    inv["implemented-components"] = [
                        {"component-uuid": comp_uuid_by_id[item.component_id]}
                    ]
                inventory_items.append(inv)
            result["inventory-items"] = inventory_items
        return result

    return {
        "users": users,
        "components": [
            {
                "uuid": str(uuid.uuid4()),
                "type": "software",
                "title": proj.system_name or proj.customer_name,
                "description": _meta_str(meta.get("system_type"), "system_type"),
                "status": _oscal_status(meta),
                "remarks": (
                    f"{_PLACEHOLDER} — system boundary not yet enumerated "
                    "in the boundary inventory"
                ),
            }
        ],
    }


@router.get("/component-definition/{system_id}")
async def component_definition(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    # Scope to the caller's org (global/auth-off principals are unscoped).
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")

    return await build_component_definition_doc(session, sys)


async def build_component_definition_doc(session: AsyncSession, sys: System) -> dict[str, Any]:
    impls = (
        (
            await session.execute(
                select(ControlImplementation)
                .where(ControlImplementation.system_id == sys.id)
                .options(selectinload(ControlImplementation.control))
            )
        )
        .scalars()
        .all()
    )

    implemented_reqs = [
        {
            "uuid": str(uuid.uuid4()),
            "control-id": (i.control.identifier if i.control else "").lower().replace(" ", ""),
            "description": i.narrative or "",
            "props": [
                {"name": "implementation-status", "value": i.status},
                {"name": "responsibility", "value": i.responsibility or ""},
            ],
        }
        for i in impls
    ]

    now = datetime.now(UTC).isoformat()
    return _component_definition_doc(sys, implemented_reqs, now)


def _component_definition_doc(
    sys: System, implemented_reqs: list[dict[str, Any]], now: str
) -> dict[str, Any]:
    return {
        "component-definition": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"Concord Component Definition — {sys.name}",
                "last-modified": now,
                "version": "0.1.0",
                "oscal-version": "1.1.2",
                "published": now,
            },
            "components": [
                {
                    "uuid": str(uuid.uuid4()),
                    "type": "software",
                    "title": sys.name,
                    "description": sys.description or sys.name,
                    "control-implementations": [
                        {
                            "uuid": str(uuid.uuid4()),
                            "source": _OSCAL_PROFILE_HREF,
                            "description": f"{_OSCAL_BASELINE_NAME} baseline as captured by "
                            "Concord.",
                            "implemented-requirements": implemented_reqs,
                        }
                    ],
                }
            ],
        }
    }


@router.get("/ssp/{project_id}")
async def ssp_export(
    project_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Emit an OSCAL 1.1 System Security Plan from a saved SSP project."""
    proj = (
        await session.execute(select(SSPProject).where(SSPProject.id == project_id))
    ).scalar_one_or_none()
    # Scope to the caller's org (global/auth-off principals are unscoped).
    if proj is None or (principal.org_id is not None and proj.organization_id != principal.org_id):
        raise HTTPException(404, "SSP project not found")
    return await build_ssp_doc(session, proj)


async def build_ssp_doc(session: AsyncSession, proj: SSPProject) -> dict[str, Any]:
    entries = (
        (
            await session.execute(
                select(SSPControlEntry)
                .where(SSPControlEntry.project_id == proj.id)
                .order_by(SSPControlEntry.sort_order)
            )
        )
        .scalars()
        .all()
    )

    implemented_reqs: list[dict[str, Any]] = []
    is_80053 = proj.framework == "nist-800-53r5"
    for e in entries:
        nist = (e.nist_id or e.control_id).strip()
        # On the 800-53 path the OSCAL id (lowercased/dotted) must drive BOTH the
        # control-id AND the statement-id prefix — a statement-id like "AC-2(1)_smt"
        # is an invalid OSCAL token (parens are illegal), so enhancements would emit
        # non-conformant ids if we reused the canonical form here.
        oscal_cid = canonical_to_oscal_id(e.control_id) if is_80053 else nist
        statements = [
            {
                "statement-id": f"{oscal_cid}_smt.{part.get('label')}"
                if part.get("label")
                else f"{oscal_cid}_smt",
                "uuid": str(uuid.uuid4()),
                "description": part.get("text", ""),
            }
            for part in (e.part_narratives or [])
        ]
        req: dict[str, Any] = {
            "uuid": str(uuid.uuid4()),
            "control-id": oscal_cid,
            "props": [
                {"name": "responsible-role", "value": e.responsible_role or ""},
                {
                    "name": "implementation-status",
                    "value": ", ".join(e.implementation_status or []) or "planned",
                },
                {
                    "name": "control-origination",
                    "value": ", ".join(e.control_origination or []),
                },
            ],
            "statements": statements,
        }
        if is_80053:
            set_parameters = [
                {"param-id": pid, "values": [str(v)]}
                for pid, v in (e.odp_values or {}).items()
                if v not in (None, "")
            ]
            if set_parameters:
                req["set-parameters"] = set_parameters
        implemented_reqs.append(req)

    # Source categorization, boundary, and roles from the same
    # project.metadata_json the docx SSP (ssp/generator.py) renders, so the two
    # exports report the same facts about the system.
    meta: dict[str, Any] = proj.metadata_json or {}
    fips = meta.get("fips199") or {}
    roles, parties, responsible_parties = _oscal_roles_and_parties(meta)
    summary = (
        await system_boundary_summary(session, proj.system_id) if proj.system_id else None
    )

    now = datetime.now(UTC).isoformat()
    metadata: dict[str, Any] = {
        "title": f"{proj.customer_name} — {proj.title}",
        "last-modified": now,
        "version": proj.version,
        "oscal-version": "1.1.2",
        "published": now,
        "roles": roles,
    }
    if parties:
        metadata["parties"] = parties
    if responsible_parties:
        metadata["responsible-parties"] = responsible_parties

    return {
        "system-security-plan": {
            "uuid": str(uuid.uuid4()),
            "metadata": metadata,
            "import-profile": {"href": _OSCAL_PROFILE_HREF},
            "system-characteristics": {
                "system-ids": [
                    {"identifier-type": "https://ietf.org/rfc/rfc4122", "id": str(proj.id)}
                ],
                "system-name": proj.system_name or proj.customer_name,
                "description": f"CMMC Level 2 enclave for {proj.customer_name} "
                f"({proj.platform}).",
                "security-sensitivity-level": _meta_str(fips.get("overall"), "fips199.overall"),
                "system-information": {
                    "information-types": _oscal_information_types(meta, summary)
                },
                "status": _oscal_status(meta),
                "authorization-boundary": {
                    "description": _meta_str(
                        meta.get("authorization_boundary"), "authorization_boundary"
                    )
                },
            },
            "system-implementation": _oscal_system_implementation(
                proj, meta, responsible_parties, summary
            ),
            "control-implementation": {
                "description": f"{_OSCAL_BASELINE_NAME} control implementations.",
                "implemented-requirements": implemented_reqs,
            },
        }
    }


@router.get("/poam/{system_id}")
async def poam_export(
    system_id: int,
    include_closed: bool = False,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Emit an OSCAL 1.1 Plan of Action and Milestones for a system's POA&Ms."""
    sys = (
        await session.execute(select(System).where(System.id == system_id))
    ).scalar_one_or_none()
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")

    return await build_poam_doc(session, sys, open_only=not include_closed)


async def build_poam_doc(
    session: AsyncSession, sys: System, *, open_only: bool = True
) -> dict[str, Any]:
    stmt = (
        select(POAM)
        .where(POAM.system_id == sys.id)
        .options(selectinload(POAM.milestones))
        .order_by(POAM.id)
    )
    if open_only:
        stmt = stmt.where(POAM.status.not_in(("closed", "completed")))
    poams = (await session.execute(stmt)).scalars().all()

    # Resolve control identifiers for POA&Ms tied to a catalog control.
    control_ids = {p.control_id for p in poams if p.control_id is not None}
    ctl_map: dict[int, str] = {}
    if control_ids:
        rows = (
            await session.execute(
                select(Control.id, Control.identifier).where(Control.id.in_(control_ids))
            )
        ).all()
        ctl_map = {cid: ident for cid, ident in rows}

    poam_items = [_poam_item(p, ctl_map) for p in poams]
    now = datetime.now(UTC).isoformat()
    return {
        "plan-of-action-and-milestones": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"Plan of Action and Milestones — {sys.name}",
                "last-modified": now,
                "version": "1.0.0",
                "oscal-version": "1.1.2",
                "published": now,
            },
            "system-id": {
                "identifier-type": "https://ietf.org/rfc/rfc4122",
                "id": str(sys.id),
            },
            "poam-items": poam_items,
        }
    }


def _poam_item(p: POAM, ctl_map: dict[int, str]) -> dict[str, Any]:
    props = [
        {"name": "severity", "value": _OSCAL_SEVERITY.get(p.severity, p.severity)},
        {"name": "status", "value": _OSCAL_POAM_STATE.get(p.status, p.status)},
    ]
    if p.control_id is not None and p.control_id in ctl_map:
        props.append({"name": "control-id", "value": ctl_map[p.control_id].lower()})
    if p.source:
        props.append({"name": "origin", "value": p.source})
    if p.scanner:
        props.append({"name": "scanner", "value": p.scanner})
    if p.due_on is not None:
        props.append({"name": "scheduled-completion-date", "value": p.due_on.isoformat()})
    if p.identified_on is not None:
        props.append({"name": "identified-date", "value": p.identified_on.isoformat()})

    item: dict[str, Any] = {
        "uuid": str(uuid.uuid4()),
        "title": p.title,
        "description": p.weakness or p.title,
        "props": props,
    }
    milestones = list(p.milestones or [])
    if milestones:
        item["remarks"] = "\n".join(
            f"- Milestone: {m.description} [{m.status}]"
            + (f" due {m.due_on.isoformat()}" if m.due_on else "")
            for m in milestones
        )
    return item


@router.get("/sar/system/{system_id}")
async def sar_export_latest(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Emit the OSCAL Assessment-Results (SAR) for a system's most recent
    assessment (by ``finished_on``, falling back to the newest id when several
    are still open)."""
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")

    assessment = (
        await session.execute(
            select(Assessment)
            .where(Assessment.system_id == system_id)
            .order_by(Assessment.finished_on.desc().nullslast(), Assessment.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if assessment is None:
        raise HTTPException(404, "no assessment found for system")

    return await build_sar_doc(session, assessment)


@router.get("/sar/{assessment_id}")
async def sar_export(
    assessment_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Emit an OSCAL 1.1 Assessment-Results (SAR) document for one assessment."""
    assessment = (
        await session.execute(select(Assessment).where(Assessment.id == assessment_id))
    ).scalar_one_or_none()
    if assessment is None:
        raise HTTPException(404, "assessment not found")

    sys = (
        await session.execute(select(System).where(System.id == assessment.system_id))
    ).scalar_one_or_none()
    # Scope to the caller's org via the assessment's system (global/auth-off
    # principals are unscoped).
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "assessment not found")

    return await build_sar_doc(session, assessment)


async def build_sar_doc(session: AsyncSession, assessment: Assessment) -> dict[str, Any]:
    """Build an OSCAL ``assessment-results`` document for ``assessment``:
    control-level findings from its ``AssessmentResult`` rows, evidence-backed
    observations, and open-POA&M risks. Mirrors ``build_ssp_doc``/
    ``build_poam_doc`` — no OSCAL assessment-plan (SAP) is fabricated; the
    ``import-ap`` is an honest placeholder."""
    results = (
        (
            await session.execute(
                select(AssessmentResult)
                .where(AssessmentResult.assessment_id == assessment.id)
                .options(
                    selectinload(AssessmentResult.implementation).selectinload(
                        ControlImplementation.control
                    )
                )
                .order_by(AssessmentResult.id)
            )
        )
        .scalars()
        .all()
    )

    now = datetime.now(UTC).isoformat()

    # Distinct assessed controls, in first-seen order, for reviewed-controls.
    oscal_cid_by_impl: dict[int, str] = {}
    include_controls: list[dict[str, str]] = []
    seen_cids: set[str] = set()
    for r in results:
        impl = r.implementation
        control = impl.control if impl else None
        oscal_cid = _oscal_control_id(control.identifier if control else None)
        oscal_cid_by_impl[r.implementation_id] = oscal_cid
        if oscal_cid not in seen_cids:
            seen_cids.add(oscal_cid)
            include_controls.append({"control-id": oscal_cid})

    # Observations: one per EvidenceObject tied to an assessed implementation.
    impl_ids = list(oscal_cid_by_impl)
    evidence_rows = (
        (
            await session.execute(
                select(EvidenceObject)
                .where(EvidenceObject.implementation_id.in_(impl_ids))
                .order_by(EvidenceObject.id)
            )
        )
        .scalars()
        .all()
        if impl_ids
        else []
    )
    observations: list[dict[str, Any]] = []
    obs_uuids_by_impl: dict[int, list[str]] = {}
    for e in evidence_rows:
        obs_uuid = str(uuid.uuid4())
        observations.append(
            {
                "uuid": obs_uuid,
                "title": e.title,
                "description": e.description or e.title,
                "methods": ["EXAMINE"],
                "collected": now,
                "relevant-evidence": [{"href": f"#evidence-{e.id}", "description": e.title}],
            }
        )
        if e.implementation_id is not None:
            obs_uuids_by_impl.setdefault(e.implementation_id, []).append(obs_uuid)

    # Findings: one per AssessmentResult.
    findings: list[dict[str, Any]] = []
    for r in results:
        impl = r.implementation
        control = impl.control if impl else None
        oscal_cid = oscal_cid_by_impl[r.implementation_id]
        control_title = (control.control_name if control else "") or ""
        finding: dict[str, Any] = {
            "uuid": str(uuid.uuid4()),
            "title": f"{oscal_cid}: {control_title}",
            "description": r.rationale or "",
            "target": {
                "type": "statement-id",
                "target-id": f"{oscal_cid}_smt",
                "status": {"state": _OSCAL_FINDING_STATE[r.finding]},
            },
        }
        if r.finding == "not_applicable":
            finding["props"] = [{"name": "applicability", "value": "not-applicable"}]
        related = obs_uuids_by_impl.get(r.implementation_id, [])
        if related:
            finding["related-observations"] = [{"observation-uuid": u} for u in related]
        findings.append(finding)

    # Risks: open POA&Ms for the assessed system (same "open" filter as
    # build_poam_doc's open_only path).
    poams = (
        (
            await session.execute(
                select(POAM)
                .where(
                    POAM.system_id == assessment.system_id,
                    POAM.status.not_in(("closed", "completed")),
                )
                .order_by(POAM.id)
            )
        )
        .scalars()
        .all()
    )
    risks = [
        {
            "uuid": str(uuid.uuid4()),
            "title": p.title,
            "description": p.weakness or p.title or "",
            "status": "open",
            "statement": p.title or "",
        }
        for p in poams
    ]

    result: dict[str, Any] = {
        "uuid": str(uuid.uuid4()),
        "title": assessment.name,
        "description": assessment.summary or assessment.name,
        "start": (assessment.started_on or date.today()).isoformat() + "T00:00:00Z",
        "reviewed-controls": {"control-selections": [{"include-controls": include_controls}]},
    }
    if assessment.finished_on is not None:
        result["end"] = assessment.finished_on.isoformat() + "T00:00:00Z"
    if observations:
        result["observations"] = observations
    if findings:
        result["findings"] = findings
    if risks:
        result["risks"] = risks

    assessor_party_uuid = str(uuid.uuid4())
    metadata: dict[str, Any] = {
        "title": "Security Assessment Report",
        "last-modified": now,
        "version": "0.1.0",
        "oscal-version": "1.1.2",
        "roles": [{"id": "assessor", "title": "Assessor"}],
        "parties": [
            {
                "uuid": assessor_party_uuid,
                "type": "person",
                "name": assessment.assessor or "Assessor",
            }
        ],
        "responsible-parties": [{"role-id": "assessor", "party-uuids": [assessor_party_uuid]}],
        "props": [{"name": "assessment-kind", "value": assessment.kind}],
    }

    return {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": metadata,
            "import-ap": {
                "href": "#no-assessment-plan",
                "remarks": (
                    "No OSCAL assessment plan (SAP) is generated in this release; "
                    "results are reported directly."
                ),
            },
            "results": [result],
        }
    }
