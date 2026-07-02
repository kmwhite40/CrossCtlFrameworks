"""SSP readiness / completeness validation.

An enterprise SSP isn't done when it has narratives — it's done when every
control has a status, responsible role, origination, and a written response, its
organization-defined parameters are filled, and the document's front matter
(system characterization, categorization, roles, boundary) is present. This
scores that and lists exactly what's missing.
"""

from __future__ import annotations

from typing import Any

# Front-matter fields an enterprise SSP must carry (dotted paths in metadata_json).
REQUIRED_METADATA = [
    ("system_type", "System type"),
    ("fips199.overall", "FIPS-199 categorization"),
    ("authorization_boundary", "Authorization boundary description"),
    ("roles.system_owner.name", "System Owner"),
    ("roles.isso.name", "ISSO"),
    ("roles.authorizing_official.name", "Authorizing Official"),
]


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
    if not any((p.get("text") or "").strip() for p in narratives):
        gaps.append("no implementation narrative")
    if not entry.get("responsible_role"):
        gaps.append("no responsible role")
    if not entry.get("implementation_status"):
        gaps.append("no implementation status")
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
