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

# The detection token, derived from DRAFT_PREFIX rather than a second literal
# "[DRAFT]" -- two spellings of one marker drifting apart is the defect shape
# this project has hit repeatedly. DRAFT_PREFIX ("[DRAFT] ", WITH a trailing
# space) is correct for *construction* (DRAFT_PREFIX + text must keep
# producing "[DRAFT] text") but wrong for *detection*: testing the full,
# space-including prefix as a substring misses a marker a human typed without
# a following space ("[DRAFT]" with nothing after it, or "Done. [DRAFT]" at
# the end of a sentence) -- no producer in this codebase ever omits the
# space, so this hole is only reachable through hand-typed narrative text.
# Stripping the trailing space still matches every producer-written instance
# (the stripped token is a substring of the space-including one) while also
# catching the space-less human-typed shape.
_DRAFT_TOKEN = DRAFT_PREFIX.rstrip()


def is_draft_or_placeholder(text: str) -> bool:
    """True if ``text`` is scaffolding rather than a written statement.

    Either the auto-composer's ``[DRAFT]`` marker (``ssp/nist80053.py`` writes
    it into every part narrative of every new 800-53 project) or an unresolved
    organization-defined-parameter placeholder (``ssp/statements.py``,
    ``ssp/platforms.py``, ``ssp/odp.py``).

    Matches the marker whether or not it is followed by a space -- a human
    typing ``[DRAFT]`` with nothing after it (or at the end of a sentence,
    e.g. ``"Done. [DRAFT]"``) means the same thing as the producer-written
    ``"[DRAFT] "`` and must not slip through this gate. See :data:`_DRAFT_TOKEN`.

    Public because :mod:`ccf.cr26.sdr` must drop exactly this text rather than
    render it into a FedRAMP deliverable as the provider's implementation
    description -- and a second copy of the rule is how the CR26 status enum
    went wrong twice. This module already calls the same text "draft narrative
    -- needs review"; one predicate, one answer.
    """
    return _DRAFT_TOKEN in text or any(tok in text for tok in _ODP_PLACEHOLDER_TOKENS)


#: Retained for this module's existing call site; :func:`is_draft_or_placeholder`
#: is the name to use.
_is_draft_or_placeholder = is_draft_or_placeholder


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


#: POA&M severities that must not be open when an SSP is declared ready. A high
#: or critical weakness the organization has not closed is the thing an
#: authorizing official most needs to have seen before signing, so a package
#: that reports itself ready while one stands would be actively misleading.
BLOCKING_POAM_SEVERITIES = ("critical", "high")


def _readiness_blockers(machine_evidence: dict[str, Any]) -> list[str]:
    """Hard gates on declaring the SSP ready, from what the platform observed.

    Separate from the score on purpose. The score is a completeness ratio and
    every dimension in it is a fraction; these are not fractions, they are
    conditions. Folding an open critical POA&M into a percentage would let it be
    averaged away by a well-filled document, which is exactly backwards -- the
    more complete the package, the more the unclosed finding matters.

    ``machine_evidence`` is the same optional shape ``boundary`` and the ODP
    dimension use: absent means the dimension is entirely inert, so every caller
    written before this existed is byte-identical.

    Also gates on missing provider shared-responsibility template coverage once
    the DB query supplies it. That is a hard condition: if Concord cannot say
    whether the provider, customer, or both own a control, the SSP must not be
    declared ready as though origination were settled.
    """
    blockers: list[str] = []
    unassessed = int(machine_evidence.get("controls_not_machine_verified") or 0)
    if unassessed:
        blockers.append(
            f"{unassessed} control(s) could not be assessed automatically "
            "(manual_review_required) and rest on manual evidence"
        )
    findings = int(machine_evidence.get("controls_with_open_findings") or 0)
    if findings:
        blockers.append(
            f"{findings} control(s) have an open finding from automated testing"
        )
    by_severity = machine_evidence.get("open_poams_by_severity") or {}
    for severity in BLOCKING_POAM_SEVERITIES:
        count = int(by_severity.get(severity) or 0)
        if count:
            blockers.append(f"{count} open {severity}-severity POA&M(s)")
    missing_templates = machine_evidence.get("missing_responsibility_templates") or []
    if missing_templates:
        blockers.append(
            f"{len(missing_templates)} control(s) lack provider shared-responsibility "
            "template coverage"
        )
    return blockers


def assess(
    project_metadata: dict[str, Any],
    entries: list[dict[str, Any]],
    boundary: dict[str, Any] | None = None,
    machine_evidence: dict[str, Any] | None = None,
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
    # Only fold ODPs into the score when some are UNSET (an actual gap). When every
    # ODP is filled (unset == 0), leave the score untouched — this keeps existing
    # CMMC projects (which carry only filled odp_values) byte-identical rather than
    # nudging their score upward, while still penalizing a scaffolded 800-53 SSP
    # whose ODPs haven't been filled in.
    if unset_odps > 0:
        odp_pct = (total_odps - unset_odps) / total_odps
        section_pct = (section_pct + odp_pct) / 2.0
        missing_sections = [
            *missing_sections,
            f"{unset_odps} of {total_odps} organization-defined parameters (ODPs) unset",
        ]

    score = round(100 * (0.8 * control_pct + 0.2 * section_pct), 1)
    # Hard gates, kept out of the score -- see `_readiness_blockers`. When no
    # machine evidence is supplied the list is empty and `ready` is decided
    # exactly as it was before this dimension existed.
    # `None` means the machine dimension could not be evaluated at all -- a
    # project with no linked system has nothing scanned and no POA&Ms to reach.
    # An empty blocker list would then read as "conditions cleared", which is the
    # same misreading `framework_posture`'s bare zeros produced: the absence of a
    # measurement is not a clean result, and the report has to say which it is.
    measured = machine_evidence is not None
    blockers = _readiness_blockers(machine_evidence or {}) if measured else []
    # "Ready" means genuinely done: every control complete (the 80/20 blend must
    # not let a high score mask empty controls), all required front matter present,
    # at least one control in the SSP, and nothing the platform observed standing
    # in the way.
    ready = bool(total) and complete == total and not missing_sections and not blockers
    return {
        "score": score,
        "ready": ready,
        "controls_total": total,
        "controls_complete": complete,
        "missing_sections": missing_sections,
        "control_gaps": control_gaps[:200],
        "odp_summary": {"total": total_odps, "unset": unset_odps},
        "readiness_blockers": blockers,
        # False when nothing could be observed, so an empty `readiness_blockers`
        # is never mistaken for a cleared gate.
        "readiness_measured": measured,
        # Named so a reader is not left to assume every condition the programme
        # intends is enforced here. A silent omission reads as a cleared gate.
        "not_yet_gated": (
            [] if measured else ["automated findings and POA&Ms (no system linked to this project)"]
        ),
    }
