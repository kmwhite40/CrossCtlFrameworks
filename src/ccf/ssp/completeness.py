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


def assess(project_metadata: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Return a completeness report: score, per-area gaps, and control detail."""
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
    # Weight: 80% controls complete, 20% front matter present.
    control_pct = (complete / total) if total else 0.0
    section_pct = (
        1.0
        if not REQUIRED_METADATA
        else (len(REQUIRED_METADATA) - len(missing_sections)) / len(REQUIRED_METADATA)
    )
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
    }
