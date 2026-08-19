"""OSCAL Component Definition export (#16).

Emits a minimal OSCAL 1.1 Component Definition describing Concord's view of a
given system: the list of implemented / inherited controls with their
implementation narratives. Not a full OSCAL profile — targets auditor intake.
"""

from __future__ import annotations

import io
import json
import re
import uuid
import zipfile
from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...auth import Principal
from ...boundary.summary import BoundarySummary, system_boundary_summary
from ...catalog.canonical import canonical_to_oscal_id, canonicalize
from ...constants import POAM_UNRESOLVED_STATUSES
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


_TOKEN_DISALLOWED_RE = re.compile(r"[^A-Za-z0-9.\-_]")
_TOKEN_VALID_START_RE = re.compile(r"^[A-Za-z_]")


def _oscal_token(value: str | None) -> str:
    """Coerce ``value`` into a valid OSCAL ``token`` (an NCName-like datatype:
    the first character MUST be a letter or ``_``; the rest may be letters,
    digits, ``.``, ``-``, or ``_``). CMMC identifiers like ``3.1.1`` fail this
    (leading digit), as do free-text statement-part labels like ``Customer
    Responsibility`` (spaces are not a valid token character). Sanitizes
    rather than drops, and preserves case/content wherever already valid —
    e.g. ``AC.L2-3.1.1`` passes through unchanged: whitespace becomes ``-``,
    any other disallowed character is stripped, and ``_`` is prepended only
    when the result would still start with something other than a
    letter/underscore."""
    text = re.sub(r"\s+", "-", (value or "").strip())
    text = _TOKEN_DISALLOWED_RE.sub("", text)
    if not text:
        text = "unspecified"
    if not _TOKEN_VALID_START_RE.match(text):
        text = f"_{text}"
    return text


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
    omitted entirely (never fabricated). The OSCAL information-type object has
    no ``remarks`` property (``additionalProperties: false``), so any free-text
    annotation is carried as a ``props`` entry instead — the one extensible,
    schema-legal place for it."""
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
                node["props"] = [
                    {"name": "adjustment-justification", "value": it.adjustment_justification}
                ]
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
        info_type["props"] = [
            {
                "name": "categorization-gap",
                "value": _placeholder(", ".join(f"fips199.{level}" for level in missing_levels)),
            }
        ]
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
    if not users:
        # OSCAL requires system-implementation.users to be non-empty. When no
        # responsible-role name has been captured in the project's metadata
        # (SSPProject.metadata_json["roles"]), emit one honestly-flagged
        # placeholder user rather than fabricate a name/role.
        users = [{"uuid": str(uuid.uuid4()), "remarks": _placeholder("responsible roles")}]

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

    implemented_reqs: list[dict[str, Any]] = []
    for i in impls:
        # control-id is an OSCAL token — a raw catalog identifier like
        # "AC-2(1)" is not one (parens are illegal); _oscal_control_id already
        # canonicalizes 800-53 ids to their dotted OSCAL form ("ac-2.1") and
        # lowercases anything else (e.g. CMMC ids), and _oscal_token is a
        # defense-in-depth sanitizer for whatever slips through (a control
        # with no catalog row, free text, a leading digit).
        control_id = _oscal_token(
            _oscal_control_id(i.control.identifier if i.control else None)
        )
        # A property's "value" is an OSCAL StringDatatype — non-empty, no
        # leading/trailing whitespace — so an unset "responsibility" must
        # omit the prop entirely rather than emit "" (implementation-status
        # is a non-nullable column with a default, so it is always present).
        props: list[dict[str, str]] = [
            {"name": "implementation-status", "value": i.status},
        ]
        if i.responsibility:
            props.append({"name": "responsibility", "value": i.responsibility})
        implemented_reqs.append(
            {
                "uuid": str(uuid.uuid4()),
                "control-id": control_id,
                # _placeholder() bakes in "...not set in SSP project metadata",
                # which is misleading here — this doc is built from
                # ControlImplementation rows, not an SSP project — so a
                # bespoke marker is used instead (same _PLACEHOLDER prefix).
                "description": i.narrative
                or f"{_PLACEHOLDER} — no implementation narrative on record",
                "props": props,
            }
        )

    now = datetime.now(UTC).isoformat()
    return _component_definition_doc(sys, implemented_reqs, now)


def _component_definition_doc(
    sys: System, implemented_reqs: list[dict[str, Any]], now: str
) -> dict[str, Any]:
    if not implemented_reqs:
        # OSCAL requires control-implementation.implemented-requirements to be
        # non-empty. A system with no ControlImplementation rows yet has
        # genuinely nothing to report — emit one honestly-flagged placeholder
        # requirement rather than fabricate control coverage (mirrors the
        # SSP's empty-implemented-requirements fallback).
        implemented_reqs = [
            {
                "uuid": str(uuid.uuid4()),
                "control-id": "_unspecified",
                "description": f"{_PLACEHOLDER} — no ControlImplementation rows on record",
            }
        ]
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
        # non-conformant ids if we reused the canonical form here. On the CMMC path
        # ``nist`` is often the bare NIST SP 800-171 requirement number (e.g.
        # "3.1.1"), which is not a valid OSCAL token on its own (tokens must start
        # with a letter/underscore) — ``_oscal_token`` sanitizes it (preserving
        # already-valid ids like "AC.L2-3.1.1" verbatim) so control-id and
        # statement-id derive from the SAME sanitized id.
        oscal_cid = canonical_to_oscal_id(e.control_id) if is_80053 else _oscal_token(nist)
        statements = [
            {
                "statement-id": f"{oscal_cid}_smt.{_oscal_token(part.get('label'))}"
                if part.get("label")
                else f"{oscal_cid}_smt",
                "uuid": str(uuid.uuid4()),
                # The OSCAL SSP "statement" object has no "description" property
                # (additionalProperties: false) — the narrative text belongs in
                # "remarks", the one free-text field a statement does allow.
                "remarks": part.get("text") or _placeholder("statement narrative"),
            }
            for part in (e.part_narratives or [])
        ]
        # A property's "value" is an OSCAL StringDatatype — non-empty, no
        # leading/trailing whitespace — so an unset responsible-role/
        # control-origination must omit the prop entirely rather than emit
        # "" (implementation-status always has its "planned" fallback, so it
        # is unconditionally present and this list is never empty).
        props: list[dict[str, str]] = [
            {
                "name": "implementation-status",
                "value": ", ".join(e.implementation_status or []) or "planned",
            }
        ]
        if e.responsible_role:
            props.append({"name": "responsible-role", "value": e.responsible_role})
        origination = ", ".join(e.control_origination or [])
        if origination:
            props.append({"name": "control-origination", "value": origination})
        req: dict[str, Any] = {
            "uuid": str(uuid.uuid4()),
            "control-id": oscal_cid,
            "props": props,
        }
        if statements:
            req["statements"] = statements
        if is_80053:
            set_parameters = [
                {"param-id": pid, "values": [str(v)]}
                for pid, v in (e.odp_values or {}).items()
                if v not in (None, "")
            ]
            if set_parameters:
                req["set-parameters"] = set_parameters
        implemented_reqs.append(req)

    if not implemented_reqs:
        # OSCAL requires control-implementation.implemented-requirements to be
        # non-empty. A project with no SSPControlEntry rows yet (e.g. before
        # seeding) has genuinely nothing to report — emit one honestly-flagged
        # placeholder requirement rather than fabricate control coverage.
        implemented_reqs = [
            {
                "uuid": str(uuid.uuid4()),
                "control-id": "_unspecified",
                "remarks": _placeholder(
                    "control-implementation — no SSP control entries on record"
                ),
            }
        ]

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
        # Positively enumerated: a future status added to the enum then defaults
        # to EXCLUDED here rather than silently becoming "open" in the exported
        # package. Includes risk_accepted deliberately — OSCAL renders it as a
        # first-class "risk-accepted" item state (see _OSCAL_POAM_STATE), which
        # is why this set differs from the dashboards' POAM_ACTIVE_STATUSES.
        stmt = stmt.where(POAM.status.in_(POAM_UNRESOLVED_STATUSES))
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
            # POA&M does not currently cross-reference a specific SSP export
            # (there is no live request context here to build a resolvable
            # URL, and a system may have zero or several SSP projects) — an
            # honest placeholder href, same pattern as build_sar_doc's
            # "import-ap".
            "import-ssp": {
                "href": "#no-ssp",
                "remarks": (
                    "No specific system-security-plan export is referenced by this "
                    "POA&M; see system-id for the system it covers."
                ),
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
                    POAM.status.in_(POAM_UNRESOLVED_STATUSES),
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
            # Project the POA&M's real lifecycle state through the same map the
            # POA&M document uses. Hardcoding "open" meant one ZIP asserted two
            # different things about one record: poam.json rendered
            # `risk-accepted` (or `investigating`) while sar.json said `open`.
            # The OSCAL risk-status field accepts any token, so schema
            # validation could never flag the contradiction.
            "status": _OSCAL_POAM_STATE.get(p.status, p.status),
            "statement": p.title or "",
        }
        for p in poams
    ]

    # "include-controls" has minItems 1 when present — an assessment with no
    # AssessmentResult rows yet has genuinely nothing to list, so the key is
    # omitted (an honest placeholder remark stands in for it) rather than
    # emitting an OSCAL-illegal empty array.
    control_selection: dict[str, Any] = (
        {"include-controls": include_controls}
        if include_controls
        else {"remarks": f"{_PLACEHOLDER} — no AssessmentResult rows on record"}
    )
    result: dict[str, Any] = {
        "uuid": str(uuid.uuid4()),
        "title": assessment.name,
        "description": assessment.summary or assessment.name,
        "start": (assessment.started_on or date.today()).isoformat() + "T00:00:00Z",
        "reviewed-controls": {"control-selections": [control_selection]},
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


@router.get("/package/{system_id}")
async def package_export(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> StreamingResponse:
    """Emit a downloadable authorization-package ZIP (SSP + SAR + POA&M +
    component-definition + README manifest) for a system."""
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    # Scope to the caller's org (global/auth-off principals are unscoped).
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")

    now_iso = datetime.now(UTC).isoformat()
    data = await build_package_zip(session, sys, now_iso=now_iso)
    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/zip",
        headers={
            "content-disposition": f'attachment; filename="authorization-package-{system_id}.zip"'
        },
    )


async def build_package_zip(session: AsyncSession, sys: System, *, now_iso: str) -> bytes:
    """Assemble the in-memory authorization-package ZIP for ``sys``: the most
    recent SSP project's ``ssp.json`` and the most recent assessment's
    ``sar.json`` when present, always ``poam.json`` and
    ``component-definition.json``, plus a ``README.txt`` manifest noting which
    artifacts are present/absent. Never calls ``datetime.now`` itself —
    ``now_iso`` is passed in so the manifest timestamp matches the caller's."""
    proj = (
        await session.execute(
            select(SSPProject)
            .where(SSPProject.system_id == sys.id)
            .order_by(SSPProject.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    assessment = (
        await session.execute(
            select(Assessment)
            .where(Assessment.system_id == sys.id)
            .order_by(Assessment.finished_on.desc().nullslast(), Assessment.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    manifest_lines = [
        "Concord authorization package",
        f"System: {sys.name}",
        f"Generated: {now_iso}",
        "",
    ]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if proj is not None:
            ssp_doc = await build_ssp_doc(session, proj)
            zf.writestr("ssp.json", json.dumps(ssp_doc, indent=2))
            manifest_lines.append("ssp.json: present")
        else:
            manifest_lines.append("ssp.json: ABSENT — no SSP project on record")

        if assessment is not None:
            sar_doc = await build_sar_doc(session, assessment)
            zf.writestr("sar.json", json.dumps(sar_doc, indent=2))
            manifest_lines.append("sar.json: present")
        else:
            manifest_lines.append("sar.json: ABSENT — no assessment on record")

        # OSCAL requires poam-items minItems 1, so an empty POA&M array is an
        # INVALID document. A clean system with no open POA&Ms is a normal, desirable
        # state — represent it by omitting poam.json (and noting it), rather than
        # bundling a non-conformant member into the authorization package.
        poam_doc = await build_poam_doc(session, sys)
        poam_items = poam_doc.get("plan-of-action-and-milestones", {}).get("poam-items", [])
        if poam_items:
            zf.writestr("poam.json", json.dumps(poam_doc, indent=2))
            manifest_lines.append("poam.json: present")
        else:
            manifest_lines.append("poam.json: ABSENT — no open POA&M items for this system")

        component_doc = await build_component_definition_doc(session, sys)
        zf.writestr("component-definition.json", json.dumps(component_doc, indent=2))
        manifest_lines.append("component-definition.json: present")

        manifest_lines.append("")
        manifest_lines.append(
            "This is a machine-readable OSCAL authorization package (SSP + SAR + "
            "POA&M + component-definition)."
        )
        zf.writestr("README.txt", "\n".join(manifest_lines) + "\n")

    return buf.getvalue()
