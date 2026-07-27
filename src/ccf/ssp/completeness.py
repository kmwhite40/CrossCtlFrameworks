"""SSP readiness / completeness validation.

An enterprise SSP isn't done when it has narratives — it's done when every
control has a status, responsible role, origination, and a written response, its
organization-defined parameters are filled, and the document's front matter
(system characterization, categorization, roles, boundary) is present. This
scores that and lists exactly what's missing.
"""

from __future__ import annotations

from typing import Any

from .constants import GENERIC_ROLE_FLAG
from .statements import DRAFT_PREFIX

# Front-matter fields an enterprise SSP must carry (dotted paths in metadata_json).
REQUIRED_METADATA = [
    ("system_type", "System type"),
    ("fips199.overall", "FIPS-199 categorization"),
    ("authorization_boundary", "Authorization boundary description"),
    ("roles.system_owner.name", "System Owner"),
    ("roles.isso.name", "ISSO"),
    ("roles.authorizing_official.name", "Authorizing Official"),
]

# Unresolved organization-defined-parameter placeholders left in narrative text:
# NIST-style bracket notation (see ssp/odp.py's _ASSIGNMENT_RE / _SELECTION_RE)
# and the rendered "still blank" token odp.render() substitutes in.
_ODP_PLACEHOLDER_TOKENS = ("[Assignment:", "[Selection", "[ORGANIZATION-DEFINED:")

# implementation_status values (ssp/constants.py IMPLEMENTATION_STATUS_OPTIONS)
# that represent a claim of implementation strong enough to require evidence.
_EVIDENCE_REQUIRED_STATUSES = {"Implemented", "Partially Implemented"}


def _is_draft_or_placeholder(text: str) -> bool:
    return DRAFT_PREFIX in text or any(tok in text for tok in _ODP_PLACEHOLDER_TOKENS)


def _has_linked_evidence(entry: dict[str, Any]) -> bool:
    # Entry-level evidence reference, if the entry carries one directly.
    if str(entry.get("evidence_ref") or "").strip():
        return True
    # Otherwise fall back to evidence on the underlying control implementation.
    implementation = entry.get("control_implementation") or {}
    return bool(implementation.get("evidence"))


def _dig(meta: dict[str, Any], path: str) -> Any:
    cur: Any = meta
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _entry_gaps(entry: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    narratives = entry.get("part_narratives") or []
    texts = [(p.get("text") or "").strip() for p in narratives]
    if not any(texts):
        gaps.append("no implementation narrative")
    elif any(_is_draft_or_placeholder(t) for t in texts):
        # A narrative that's present but still carries the auto-composer's
        # [DRAFT] marker or an unfilled ODP placeholder isn't a real,
        # human-reviewed statement yet.
        gaps.append("draft narrative — needs review")
    role = entry.get("responsible_role")
    if not role:
        gaps.append("no responsible role")
    elif GENERIC_ROLE_FLAG in str(role):
        # ssp/seed.py falls back to a generic "{Domain} Lead / System Owner"
        # label (flagged with GENERIC_ROLE_FLAG) when no named system_owner/
        # ISSO role is on file (FR-13). That bare fallback names a function,
        # not a person — it must not silently satisfy the "named responsible
        # party" gate.
        gaps.append("responsible role is a generic fallback — not a named party")
    statuses = entry.get("implementation_status") or []
    if not statuses:
        gaps.append("no implementation status")
    elif any(s in _EVIDENCE_REQUIRED_STATUSES for s in statuses) and not _has_linked_evidence(
        entry
    ):
        # Claiming a control is (partially) implemented without any evidence
        # linked — at the entry or the control implementation — is a gap.
        gaps.append("implemented without evidence")
    if not entry.get("control_origination"):
        gaps.append("no control origination")
    # Any ODP slot the control defines but the entry hasn't filled.
    defined = {d.get("key") for d in entry.get("odp_definitions") or []}
    # A value of 0 / 0.0 is a legitimately-filled parameter — only None/blank count
    # as unfilled.
    filled = {
        k for k, v in (entry.get("odp_values") or {}).items() if v is not None and str(v).strip()
    }
    missing_odp = defined - filled
    if missing_odp:
        gaps.append(f"{len(missing_odp)} unfilled parameter(s)")
    return gaps


def _odp_totals(entries: list[dict[str, Any]]) -> tuple[int, int]:
    """Return ``(total_odps, unset_odps)`` across all entries' ``odp_values``.

    ``odp_values`` is a dict ``{param_id: value_or_None}``; the 800-53r5 seed
    scaffolds these with all-``None`` values. A value is "unset" if it's
    ``None`` or an empty/whitespace-only string.
    """
    total = 0
    unset = 0
    for e in entries:
        odp_values = e.get("odp_values") or {}
        for v in odp_values.values():
            total += 1
            if v is None or (isinstance(v, str) and not v.strip()):
                unset += 1
    return total, unset


def _boundary_gaps_and_pct(boundary: dict[str, Any]) -> tuple[list[str], float]:
    """Score the four boundary checks and list human-readable gap messages for
    the ones that fail. Returns ``(gaps, boundary_pct)`` where ``boundary_pct``
    is the fraction of the four checks that passed (each weighted equally)."""
    gaps: list[str] = []
    passed = 0
    checks = 4

    if (boundary.get("components") or 0) >= 1:
        passed += 1
    else:
        gaps.append("No boundary components defined")

    if (boundary.get("info_types") or 0) >= 1:
        passed += 1
    else:
        gaps.append("No information types categorized")

    if boundary.get("categorization_reconciles"):
        passed += 1
    else:
        gaps.append("System categorization does not reconcile with information types")

    with_agreements, ic_total = boundary.get("interconnections_with_agreements") or (0, 0)
    if ic_total in (0, with_agreements):
        passed += 1
    else:
        lacking = ic_total - with_agreements
        gaps.append(f"{lacking} of {ic_total} interconnections lack an agreement")

    return gaps, passed / checks


def assess(
    project_metadata: dict[str, Any],
    entries: list[dict[str, Any]],
    boundary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a completeness report: score, per-area gaps, and control detail.

    ``boundary``, when given, is a small summary dict describing the linked
    system's boundary inventory::

        {
            "components": int,                        # SystemComponent count
            "info_types": int,                        # InformationType count
            "categorization_reconciles": bool,        # reconcile_categorization(...) == []
            "interconnections_with_agreements": (k, n),  # k of n have an agreement
        }

    Scoring blend: the overall score stays ``100 * (0.8 * control_pct +
    0.2 * section_pct)`` — control completeness remains the dominant 80%
    weight. ``section_pct`` is the front-matter completion ratio
    (``REQUIRED_METADATA`` present / total) when ``boundary`` is ``None``
    (unchanged, fully backward compatible). When ``boundary`` is provided,
    ``section_pct`` becomes the **average** of that front-matter ratio and a
    boundary sub-score — the fraction of four equally-weighted checks that
    pass (>=1 component, >=1 information type, categorization reconciles,
    every interconnection has an agreement) — folding the boundary section
    into the existing 20% non-control dimension rather than adding a third
    weighted term. Any failing boundary check is appended to the report's
    ``missing_sections`` list.

    ODPs (organization-defined parameters, from each entry's ``odp_values``)
    are folded in the same way: when any entries carry scaffolded ODPs
    (``total_odps > 0``), an ODP fill ratio (filled / total) joins the
    average that makes up ``section_pct``, and an unset-ODP gap is appended
    to ``missing_sections``. When no entries carry any ``odp_values`` at all
    (``total_odps == 0`` — the case for every project seeded before this
    dimension existed, including CMMC projects), the ODP dimension is
    entirely inert: no gap, no score change, byte-identical to before this
    dimension existed. The report always carries an ``odp_summary``
    ``{"total": int, "unset": int}`` field regardless.
    """
    meta = project_metadata or {}
    missing_sections = [label for path, label in REQUIRED_METADATA if not _dig(meta, path)]

    control_gaps: list[dict[str, Any]] = []
    complete = 0
    for e in entries:
        gaps = _entry_gaps(e)
        if gaps:
            control_gaps.append({"control_id": e.get("control_id"), "gaps": gaps})
        else:
            complete += 1

    total = len(entries)
    # Weight: 80% controls complete, 20% front matter (+ boundary, when given) present.
    control_pct = (complete / total) if total else 0.0
    section_pct = (
        1.0
        if not REQUIRED_METADATA
        else (len(REQUIRED_METADATA) - len(missing_sections)) / len(REQUIRED_METADATA)
    )

    if boundary is not None:
        boundary_gaps, boundary_pct = _boundary_gaps_and_pct(boundary)
        section_pct = (section_pct + boundary_pct) / 2.0
        missing_sections = [*missing_sections, *boundary_gaps]

    total_odps, unset_odps = _odp_totals(entries)
    if total_odps > 0:
        odp_pct = (total_odps - unset_odps) / total_odps
        section_pct = (section_pct + odp_pct) / 2.0
        if unset_odps > 0:
            missing_sections = [
                *missing_sections,
                f"{unset_odps} of {total_odps} organization-defined parameters (ODPs) unset",
            ]

    score = round(100 * (0.8 * control_pct + 0.2 * section_pct), 1)
    # "Ready" means genuinely done: every control complete (the 80/20 blend must
    # not let a high score mask empty controls), all required front matter present,
    # and at least one control in the SSP.
    ready = bool(total) and complete == total and not missing_sections
    return {
        "score": score,
        "ready": ready,
        "controls_total": total,
        "controls_complete": complete,
        "missing_sections": missing_sections,
        "control_gaps": control_gaps[:200],
        "odp_summary": {"total": total_odps, "unset": unset_odps},
    }
