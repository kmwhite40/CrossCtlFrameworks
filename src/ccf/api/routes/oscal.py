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

from ...assessment.engine.objectives import strip_dedup_suffix
from ...auth import Principal
from ...boundary.summary import BoundarySummary, system_boundary_summary
from ...catalog.canonical import canonical_to_oscal_id, canonicalize
from ...constants import (
    NOT_APPLICABLE,
    NOT_ASSESSED,
    OTHER_THAN_SATISFIED,
    POAM_UNRESOLVED_STATUSES,
    SATISFIED,
    UNKNOWN,
    normalize_finding,
)
from ...models import (
    POAM,
    Assessment,
    AssessmentControlResult,
    AssessmentResult,
    Control,
    ControlImplementation,
    SSPControlEntry,
    SSPProject,
    System,
)
from ...models_evidence import EvidenceObject
from ...oscal import validate_document
from ...ssp.platforms import platform_label
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

# Canonical finding (ccf.constants) -> OSCAL finding target.status.state.
#
# Keyed on the CANONICAL vocabulary, not on any one source's raw spelling, so
# the single map serves both grains the SAR now emits: control-level
# (``AssessmentResult.finding``, a three-value DB enum) and objective-level
# (``AssessmentObjectiveProposal.verdict``, projected into
# ``AssessmentControlResult.objective_findings``, which adds ``not_satisfied``
# and ``insufficient_evidence``). Every raw value goes through
# ``normalize_finding`` first; the DB enum's three values are identity-mapped
# there, so the control-level path is unchanged.
#
# OSCAL 1.1 defines exactly two states for a finding target — "satisfied" and
# "not-satisfied" — so every canonical value that is neither a pass nor a
# plain failure lands on "not-satisfied" and carries a prop saying which one
# it was (see ``_finding_status_props``). That is the pattern
# "not_applicable" has always used here; the alternative, inventing a third
# state token, is not conformant, and the alternative for
# ``insufficient_evidence`` in particular — calling it "satisfied" — would be
# a false claim to an assessor.
_OSCAL_FINDING_STATE = {
    SATISFIED: "satisfied",
    OTHER_THAN_SATISFIED: "not-satisfied",
    NOT_APPLICABLE: "not-satisfied",
    NOT_ASSESSED: "not-satisfied",
    UNKNOWN: "not-satisfied",
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

#: OSCAL assessment method -> the ``Control`` attribute holding the catalog's
#: text for it. These are the workbook's EXAMINE / INTERVIEW / TEST columns,
#: ingested as first-class ``Control`` fields by ``ccf.etl.pipeline`` — each is
#: a ``[SELECT FROM: ...]`` list of the objects to examine, the people to
#: interview, or the mechanisms to test. Ordered EXAMINE -> INTERVIEW -> TEST so
#: a control's planned activities come out in a stable, catalog-like order. The
#: method tokens are OSCAL's own assessment-method vocabulary, the same one
#: ``build_sar_doc`` already emits in ``observation.methods``.
_ASSESSMENT_METHOD_COLUMNS: tuple[tuple[str, str], ...] = (
    ("EXAMINE", "examine"),
    ("INTERVIEW", "interview"),
    ("TEST", "test"),
)

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


def _finding_status_props(raw_finding: str | None) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """An OSCAL finding ``status`` plus the props that keep it honest.

    ``raw_finding`` is whatever the source column holds — a
    ``ccf.finding_status`` enum value, an ``AssessmentControlResult.finding``
    string, or an engine objective verdict — and is normalized ONCE here (see
    ``_OSCAL_FINDING_STATE``) so no caller has to know which vocabulary it is
    holding.

    OSCAL has two finding states, so three canonical determinations collapse
    onto "not-satisfied". A prop is what keeps them distinguishable in the
    delivered document:

    - ``not_applicable`` -> ``applicability: not-applicable`` (unchanged; the
      SAR has always emitted this).
    - ``not_assessed`` / ``unknown`` -> ``determination: <the raw value>``,
      which is how ``insufficient_evidence`` survives the collapse. Without
      it, "the evidence did not settle this objective" and "this objective
      failed" are the same sentence in the artifact an assessor reads.

    A plain ``satisfied`` or ``other_than_satisfied`` gets no prop: the state
    already says everything, and a qualifier on an unqualified determination
    is noise an assessor has to rule out.
    """
    canonical = normalize_finding(raw_finding)
    props: list[dict[str, str]] = []
    if canonical == NOT_APPLICABLE:
        props.append({"name": "applicability", "value": "not-applicable"})
    elif canonical in (NOT_ASSESSED, UNKNOWN):
        # The raw spelling, not the canonical bucket: "insufficient_evidence"
        # and "not_assessed" both normalize to NOT_ASSESSED but mean
        # different things to an assessor ("we could not tell" vs "nobody
        # looked"), and the raw column is the only place that survives.
        raw = (raw_finding or NOT_ASSESSED).strip().lower().replace("_", "-")
        props.append({"name": "determination", "value": _oscal_token(raw)})
    return {"state": _OSCAL_FINDING_STATE[canonical]}, props


def _statement_id(oscal_cid: str, label: str | None) -> str:
    """The OSCAL statement-id for one assessment objective under ``oscal_cid``.

    The same ``<control-id>_smt.<token>`` shape ``build_ssp_doc`` already
    emits for SSP sub-statements, so a SAR finding and the SSP statement it
    speaks to are addressable by the same id.

    ``strip_dedup_suffix`` runs BEFORE ``_oscal_token``, not after: the token
    rules would quietly turn the ETL's ``#row417`` de-dup artifact into
    ``row417``, which reads as part of the catalog item path. A label that is
    nothing BUT the suffix, or empty, degrades to the whole-statement id
    rather than to ``_unspecified`` — targeting the statement is honest about
    the grain; inventing a label is not.
    """
    token = _oscal_token(strip_dedup_suffix(label or ""))
    if not label or not strip_dedup_suffix(label).strip():
        return f"{oscal_cid}_smt"
    return f"{oscal_cid}_smt.{token}"


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
                # The label, never the raw code: "(none)" in a filed OSCAL
                # document reads as a missing value, which is the exact
                # ambiguity 'none' as a platform exists to remove.
                "description": f"CMMC Level 2 enclave for {proj.customer_name} "
                f"({platform_label(proj.platform)}).",
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


@router.get("/sap/{assessment_id}")
async def sap_export(
    assessment_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Emit an OSCAL 1.1 Assessment-Plan (SAP) document for one assessment."""
    assessment = (
        await session.execute(select(Assessment).where(Assessment.id == assessment_id))
    ).scalar_one_or_none()
    if assessment is None:
        raise HTTPException(404, "assessment not found")

    sys = (
        await session.execute(select(System).where(System.id == assessment.system_id))
    ).scalar_one_or_none()
    # Scope to the caller's org via the assessment's system, exactly as
    # ``sar_export`` does (global/auth-off principals are unscoped). A plan
    # enumerates another tenant's control scope just as a report does.
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "assessment not found")

    return await build_sap_doc(session, assessment)


async def _objective_findings_by_control(
    session: AsyncSession, assessment_id: int
) -> dict[str, list[dict[str, Any]]]:
    """Objective-grain findings for one assessment, keyed by OSCAL control id.

    ``AssessmentControlResult.control_id`` is a ``String(32)`` documented as
    keyed to ``scoring_controls`` (CMMC practice ids like ``AC.L2-3.1.1``) —
    but ``ccf.assessment.engine.service`` writes 800-53 canonical ids
    (``AC-2``) into the same column when an assessor accepts a proposal. The
    column carries two vocabularies, and a third spelling on top of that
    (the ingested catalog is inconsistently zero-padded, so ``AC-02`` and
    ``AC-2`` are both real).

    Both sides of this join therefore go through ``_oscal_control_id``, the
    same function the ``AssessmentResult`` side already uses:
    ``canonicalize`` folds the 800-53 forms onto one id (``AC-02`` and
    ``AC-2`` -> ``ac-2``) and returns ``None`` for a CMMC id, which then
    lowercases verbatim (``AC.L2-3.1.1`` -> ``ac.l2-3.1.1``). One
    normalizer, both vocabularies — deliberately not a second one that would
    have to be kept in step with ``canonicalize``'s idea of what an 800-53
    id is.

    A control with no stored objective findings is simply absent from the
    result, which is what makes the control-level fallback the default for
    every assessment predating the engine.
    """
    rows = (
        (
            await session.execute(
                select(AssessmentControlResult)
                .where(AssessmentControlResult.assessment_id == assessment_id)
                .order_by(AssessmentControlResult.sort_order, AssessmentControlResult.id)
            )
        )
        .scalars()
        .all()
    )
    by_cid: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        parts = [p for p in (row.objective_findings or []) if isinstance(p, dict)]
        if not parts:
            continue
        # setdefault + extend, not assignment: two rows CAN fold onto one
        # OSCAL id (the padded and unpadded spellings of one control), and
        # dropping one of them would silently lose objectives from the SAR.
        by_cid.setdefault(_oscal_control_id(row.control_id), []).extend(parts)
    return by_cid


async def _assessed_results(session: AsyncSession, assessment_id: int) -> list[AssessmentResult]:
    """One assessment's ``AssessmentResult`` rows with their control loaded.

    Factored out of ``build_sar_doc`` so the SAP and the SAR read the SAME rows
    in the SAME order. They must: ``build_sar_doc``'s ``import-ap`` resolves to
    a plan only when that plan has a non-empty control selection, and a second
    query that drifted from this one would decide that on a different set of
    controls than the plan is actually built from.
    """
    return list(
        (
            await session.execute(
                select(AssessmentResult)
                .where(AssessmentResult.assessment_id == assessment_id)
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


def _assessed_control_scope(
    results: list[AssessmentResult],
) -> tuple[dict[int, str], list[dict[str, str]], dict[str, Control]]:
    """The distinct controls ``results`` covers, in first-seen order.

    Returns ``(oscal_cid_by_implementation_id, include_controls, control_by_cid)``.
    ``control_by_cid`` keeps the first catalog row seen for each OSCAL control
    id — the SAP reads its EXAMINE/INTERVIEW/TEST columns from it. Controls
    whose implementation carries no catalog row are absent from that mapping
    rather than mapped to a blank stand-in, so "the catalog has no methods for
    this control" stays distinguishable from "there is no control row at all".
    """
    oscal_cid_by_impl: dict[int, str] = {}
    include_controls: list[dict[str, str]] = []
    control_by_cid: dict[str, Control] = {}
    seen_cids: set[str] = set()
    for r in results:
        impl = r.implementation
        control = impl.control if impl else None
        oscal_cid = _oscal_control_id(control.identifier if control else None)
        oscal_cid_by_impl[r.implementation_id] = oscal_cid
        if oscal_cid not in seen_cids:
            seen_cids.add(oscal_cid)
            include_controls.append({"control-id": oscal_cid})
        if control is not None and oscal_cid not in control_by_cid:
            control_by_cid[oscal_cid] = control
    return oscal_cid_by_impl, include_controls, control_by_cid


def _control_selection(
    include_controls: list[dict[str, str]], *, empty_remark: str
) -> dict[str, Any]:
    """One OSCAL ``control-selection``, honest about an empty scope.

    ``include-controls`` carries ``minItems 1`` in BOTH the assessment-results
    and the assessment-plan models, so an empty list is not a "no controls"
    signal — it is an invalid document. The key is omitted and a remark says
    why, rather than emitting ``"include-controls": []``.
    """
    if include_controls:
        return {"include-controls": include_controls}
    return {"remarks": empty_remark}


_NO_ASSESSMENT_RESULTS_REMARK = f"{_PLACEHOLDER} — no AssessmentResult rows on record"


def _assessment_metadata(assessment: Assessment, now: str, *, title: str) -> dict[str, Any]:
    """OSCAL ``metadata`` for a document about ``assessment``.

    The assessor identity the platform actually holds (``assessment.assessor``,
    a free-text name) projected as a ``party`` + ``responsible-parties`` entry,
    plus ``assessment.kind`` as a prop. Shared by the SAR and the SAP so the two
    documents name the same assessor in the same shape — they describe one
    assessment, and a plan crediting a different party than its own results is
    a contradiction no schema would catch.
    """
    assessor_party_uuid = str(uuid.uuid4())
    return {
        "title": title,
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


def _import_ap(assessment_id: int, *, has_reviewed_controls: bool) -> dict[str, Any]:
    """The SAR's ``import-ap``: the real plan when there is one, else the
    honest placeholder this release shipped.

    Concord stores no separately-authored assessment plan, so "a plan exists"
    can only mean "a plan with content can be derived for this assessment".
    The condition is the plan's own scope: ``build_sap_doc`` derives
    ``reviewed-controls`` from the assessment's recorded control coverage, so an
    assessment with no ``AssessmentResult`` rows yields a plan that reviews
    nothing. Pointing ``import-ap`` at that would make the SAR cite a plan
    asserting an assessment scope nobody defined — precisely what the
    placeholder exists to avoid. So the placeholder stays for exactly that case.
    """
    if not has_reviewed_controls:
        return {
            "href": "#no-assessment-plan",
            "remarks": (
                "No OSCAL assessment plan (SAP) is referenced: this assessment has no "
                "recorded control coverage, so a generated plan would review no "
                "controls. Results are reported directly."
            ),
        }
    return {
        "href": f"/api/oscal/sap/{assessment_id}",
        "remarks": (
            "The OSCAL assessment plan (SAP) Concord derives for this assessment. "
            "Its reviewed-controls are derived from the assessment's recorded "
            "control coverage, not from a separately-authored plan scope."
        ),
    }


async def build_sap_doc(session: AsyncSession, assessment: Assessment) -> dict[str, Any]:
    """Build an OSCAL ``assessment-plan`` (SAP) document for ``assessment``.

    Emits only what Concord actually holds:

    * ``import-ssp`` (REQUIRED by the model) — the system's most recent
      ``SSPProject``, selected by the same rule ``build_package_zip`` uses, as a
      resolvable route reference. With no SSP project on record the href is an
      explicit ``#no-system-security-plan`` marker carrying a remark, the same
      pattern ``build_poam_doc``'s ``import-ssp`` already uses: the field cannot
      be omitted, so it is emitted saying plainly that it is not derived.
    * ``reviewed-controls`` — the controls the assessment covers, built by the
      same ``_assessed_control_scope`` the SAR uses, with the same ``minItems 1``
      guard on ``include-controls``. The selection carries a ``description``
      stating that the scope is derived from recorded coverage, because Concord
      has no planned-scope record and a plan that silently presented a
      retrospective scope as a planned one would be asserting something nobody
      entered.
    * ``local-definitions.activities`` — one activity per (control, method) that
      the CATALOG populates, from ``Control.examine`` / ``.interview`` /
      ``.test`` (the workbook's EXAMINE / INTERVIEW / TEST columns, which are
      ``[SELECT FROM: ...]`` assessment-method sources). A control whose catalog
      row is blank for a method contributes no activity for it, and
      ``local-definitions.remarks`` names the reviewed controls that produced no
      activities at all — so a thin plan reads as a thin catalog rather than as
      an assessor having chosen not to test.

    Deliberately NOT emitted: ``terms-and-conditions``, ``assessment-subjects``,
    ``assessment-assets`` and ``tasks``. All four are optional, and Concord holds
    no rules of engagement, no enumerated subject inventory, no assessment
    platform registry and no schedule. Emitting any of them would mean inventing
    an assessment scope or a timetable no record supports.
    """
    results = await _assessed_results(session, assessment.id)
    _impl_map, include_controls, control_by_cid = _assessed_control_scope(results)
    now = datetime.now(UTC).isoformat()

    proj = (
        await session.execute(
            select(SSPProject)
            .where(SSPProject.system_id == assessment.system_id)
            .order_by(SSPProject.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if proj is not None:
        import_ssp: dict[str, Any] = {"href": f"/api/oscal/ssp/{proj.id}"}
    else:
        import_ssp = {
            "href": "#no-system-security-plan",
            "remarks": (
                f"{_PLACEHOLDER} — no SSP project on record for this system, so the "
                "system security plan this assessment covers is not yet derivable."
            ),
        }

    selection = _control_selection(
        include_controls, empty_remark=_NO_ASSESSMENT_RESULTS_REMARK
    )
    selection["description"] = (
        "Controls in scope for this assessment, derived from the control coverage "
        "recorded against it. Concord stores no separately-authored plan scope."
    )

    activities: list[dict[str, Any]] = []
    without_methods: list[str] = []
    for entry in include_controls:
        oscal_cid = entry["control-id"]
        control = control_by_cid.get(oscal_cid)
        found = False
        for method, column in _ASSESSMENT_METHOD_COLUMNS:
            text = (getattr(control, column, None) or "").strip() if control is not None else ""
            if not text:
                continue
            found = True
            activities.append(
                {
                    "uuid": str(uuid.uuid4()),
                    "title": f"{method} — {oscal_cid}",
                    "description": text,
                    "props": [{"name": "method", "value": method}],
                    "related-controls": {
                        "control-selections": [{"include-controls": [{"control-id": oscal_cid}]}]
                    },
                }
            )
        if not found:
            without_methods.append(oscal_cid)

    local_definitions: dict[str, Any] = {}
    if activities:
        local_definitions["activities"] = activities
    if without_methods:
        # Named, not counted, and never silently absent: a reader comparing the
        # plan to its scope must be able to tell WHICH controls have no methods.
        local_definitions["remarks"] = (
            f"{_PLACEHOLDER} — the catalog carries no EXAMINE/INTERVIEW/TEST "
            "assessment methods for these reviewed controls, so no assessment "
            f"activities are planned for them: {', '.join(without_methods)}."
        )

    plan: dict[str, Any] = {
        "uuid": str(uuid.uuid4()),
        "metadata": _assessment_metadata(assessment, now, title="Security Assessment Plan"),
        "import-ssp": import_ssp,
        "reviewed-controls": {"control-selections": [selection]},
    }
    if local_definitions:
        plan["local-definitions"] = local_definitions
    return {"assessment-plan": plan}


async def build_sar_doc(session: AsyncSession, assessment: Assessment) -> dict[str, Any]:
    """Build an OSCAL ``assessment-results`` document for ``assessment``:
    findings from its ``AssessmentResult`` rows, evidence-backed
    observations, and open-POA&M risks. Mirrors ``build_ssp_doc``/
    ``build_poam_doc`` — no OSCAL assessment-plan (SAP) is fabricated; the
    ``import-ap`` is an honest placeholder.

    Findings are emitted at OBJECTIVE grain wherever the assessment has
    objective findings for a control (``AssessmentControlResult
    .objective_findings``, which the assessment engine writes on acceptance
    and the assessor UI maintains), each targeting
    ``<control-id>_smt.<label>`` — the same sub-statement id shape
    ``build_ssp_doc`` emits. A control with no objective findings keeps the
    single whole-statement finding built from its ``AssessmentResult`` row,
    so assessments that predate the engine are unchanged.

    This closes a real divergence rather than adding detail: the docx SAR
    (``ccf.assessment.sar.generate_sar_docx``) has always rendered objective
    grain from that column, so the *machine-readable* artifact — the one an
    assessor ingests — was the coarser of the two SARs Concord ships.
    """
    results = await _assessed_results(session, assessment.id)

    now = datetime.now(UTC).isoformat()

    # Distinct assessed controls, in first-seen order, for reviewed-controls.
    oscal_cid_by_impl, include_controls, _control_by_cid = _assessed_control_scope(results)

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

    # Findings: one per assessment objective where the assessment has them,
    # else one per AssessmentResult (the pre-engine grain).
    objectives_by_cid = await _objective_findings_by_control(session, assessment.id)
    findings: list[dict[str, Any]] = []
    for r in results:
        impl = r.implementation
        control = impl.control if impl else None
        oscal_cid = oscal_cid_by_impl[r.implementation_id]
        control_title = (control.control_name if control else "") or ""
        related = obs_uuids_by_impl.get(r.implementation_id, [])
        parts = objectives_by_cid.get(oscal_cid) or []

        if parts:
            # Objective grain supersedes the control-level finding rather than
            # sitting beside it: emitting both would put two OSCAL findings in
            # one document asserting different things about the same control,
            # and nothing in the schema would flag the contradiction.
            seen_targets: set[str] = set()
            for part in parts:
                label = str(part.get("label") or "")
                target_id = _statement_id(oscal_cid, label)
                # Stripping the ``#rowN`` suffix can collide a de-duplicated
                # label with the one it was de-duplicated FROM. Two findings
                # on one target-id is worse than a suffixed id: it is two
                # determinations about the same objective. Disambiguate on
                # position, which at least does not pretend to be an item
                # path from the catalog.
                if target_id in seen_targets:
                    target_id = f"{target_id}-{len(seen_targets) + 1}"
                seen_targets.add(target_id)

                display = strip_dedup_suffix(label).strip()
                status, props = _finding_status_props(part.get("finding"))
                objective_text = str(part.get("text") or "")
                finding: dict[str, Any] = {
                    "uuid": str(uuid.uuid4()),
                    "title": (
                        f"{oscal_cid} [{display}]: {control_title}"
                        if display
                        else f"{oscal_cid}: {control_title}"
                    ),
                    # The assessor-citable rationale for THIS objective where
                    # the acceptance projection carried one, else the
                    # objective's own text — never an empty description,
                    # which reads as a finding with nothing behind it.
                    "description": str(part.get("rationale") or "") or objective_text,
                    "target": {
                        "type": "statement-id",
                        "target-id": target_id,
                        "status": status,
                    },
                }
                if props:
                    finding["props"] = props
                if related:
                    # Evidence is linked to the implementation, not to an
                    # individual objective, so every objective finding for
                    # this control cites the same observations. Attaching
                    # them to none of the objective findings would drop the
                    # evidence link from the document entirely.
                    finding["related-observations"] = [{"observation-uuid": u} for u in related]
                findings.append(finding)
            continue

        status, props = _finding_status_props(r.finding)
        finding = {
            "uuid": str(uuid.uuid4()),
            "title": f"{oscal_cid}: {control_title}",
            "description": r.rationale or "",
            "target": {
                "type": "statement-id",
                "target-id": f"{oscal_cid}_smt",
                "status": status,
            },
        }
        if props:
            finding["props"] = props
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
    # emitting an OSCAL-illegal empty array. Shared with build_sap_doc, which
    # faces the identical constraint in the assessment-plan model.
    control_selection = _control_selection(
        include_controls, empty_remark=_NO_ASSESSMENT_RESULTS_REMARK
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

    metadata = _assessment_metadata(assessment, now, title="Security Assessment Report")

    return {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": metadata,
            # The seam to the plan. Resolved against the SAME control scope the
            # plan is built from (include_controls), so the SAR can never cite a
            # plan that reviews nothing.
            "import-ap": _import_ap(
                assessment.id, has_reviewed_controls=bool(include_controls)
            ),
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
    recent SSP project's ``ssp.json``, the most recent assessment's ``sap.json``
    and ``sar.json`` when present, always ``poam.json`` and
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
            # Plan before results, the order a reviewer reads them in.
            #
            # The plan is bundled only when it has a scope. `build_sap_doc`
            # returns a schema-valid document either way -- with no
            # `AssessmentResult` rows it omits `include-controls` (minItems 1)
            # and says so in a remark -- so validity is not the test here.
            # `_import_ap` already refuses to cite such a plan from the SAR,
            # for the reason that applies identically to a package: a plan
            # reviewing nothing asserts an assessment scope nobody defined.
            #
            # The condition is read off the BUILT document rather than
            # re-derived from the results, so the file the package ships is the
            # same one the decision was made about.
            sap_doc = await build_sap_doc(session, assessment)
            selections = sap_doc["assessment-plan"]["reviewed-controls"]["control-selections"]
            if any(sel.get("include-controls") for sel in selections):
                zf.writestr("sap.json", json.dumps(sap_doc, indent=2))
                manifest_lines.append("sap.json: present")
            else:
                manifest_lines.append(
                    "sap.json: ABSENT — the assessment on record has no recorded "
                    "control coverage, so a derived plan would review no controls"
                )

            sar_doc = await build_sar_doc(session, assessment)
            zf.writestr("sar.json", json.dumps(sar_doc, indent=2))
            manifest_lines.append("sar.json: present")
        else:
            manifest_lines.append("sap.json: ABSENT — no assessment on record")
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
            "This is a machine-readable OSCAL authorization package (SSP + SAP + "
            "SAR + POA&M + component-definition)."
        )
        zf.writestr("README.txt", "\n".join(manifest_lines) + "\n")

    return buf.getvalue()
