"""Organization-defined parameters (ODPs) for CMMC / NIST 800-171 practices.

An ODP is a "fill-in-the-blank" in a control: the requirement is complete only
once the organization supplies a value (a period, a frequency, a condition, a
selection). This module:

  * parses standard NIST ODP notation — ``[Assignment: organization-defined X]``
    and ``[Selection (one or more): a; b; c]`` — out of requirement/objective
    text (works for 800-171 Rev 3 and 800-53 style text), and
  * overlays a curated set of well-known 800-171 ODPs keyed by NIST id, because
    Rev 2 requirement text embeds most parameters implicitly rather than in
    bracket notation.

The merged result drives the SSP builder's fill-in fields; :func:`render`
substitutes the customer's values into a canned statement template, leaving a
clearly-marked placeholder for any blank the customer still owes.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

# [Assignment: organization-defined frequency]  /  [Assignment: frequency]
_ASSIGNMENT_RE = re.compile(
    r"\[Assignment:\s*(?:organization-defined\s+)?([^\]]+?)\]", re.IGNORECASE
)
# [Selection (one or more): a; b; c]  /  [Selection: a; b]
_SELECTION_RE = re.compile(
    r"\[Selection(?:\s*\([^)]*\))?:\s*([^\]]+?)\]", re.IGNORECASE
)


@dataclass
class ODP:
    """One fill-in-the-blank slot within a control."""

    key: str
    label: str
    kind: str = "assignment"  # "assignment" | "selection"
    choices: list[str] = field(default_factory=list)
    guidance: str | None = None
    suggested: str | None = None  # a tailorable example, NOT a mandate
    source: str = "NIST SP 800-171"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _slug(text: str, seq: int) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    base = "_".join(base.split("_")[:6]) or "param"
    return f"{base}_{seq}"


def extract_odps(text: str | None) -> list[ODP]:
    """Parse ``[Assignment: …]`` / ``[Selection: …]`` markers from control text."""
    if not text:
        return []
    out: list[ODP] = []
    for i, m in enumerate(_ASSIGNMENT_RE.finditer(text)):
        label = m.group(1).strip()
        out.append(ODP(key=_slug(label, i), label=label, kind="assignment"))
    for j, m in enumerate(_SELECTION_RE.finditer(text)):
        raw = m.group(1).strip()
        choices = [c.strip() for c in re.split(r";|,| or ", raw) if c.strip()]
        out.append(
            ODP(
                key=_slug("selection_" + raw, 100 + j),
                label=f"selection: {raw}",
                kind="selection",
                choices=choices,
            )
        )
    return out


# Curated, well-known 800-171 ODPs keyed by NIST id (e.g. "3.1.10"). Values are
# tailorable examples an organization confirms/overrides — not fixed mandates.
CURATED_ODP_171: dict[str, list[ODP]] = {
    "3.1.10": [
        ODP(
            key="inactivity_period",
            label="period of inactivity before session/device lock",
            guidance="Common baseline is 15 minutes; set per your risk posture.",
            suggested="15 minutes",
        )
    ],
    "3.1.11": [
        ODP(
            key="session_termination_condition",
            label="condition that triggers session termination",
            suggested="a defined period of inactivity or user logoff",
        )
    ],
    "3.3.1": [
        ODP(
            key="audit_retention_period",
            label="audit record retention period",
            guidance="DoD/DFARS practice commonly retains at least 90 days online.",
            suggested="at least 90 days",
        )
    ],
    "3.5.8": [
        ODP(
            key="password_generations_prohibited",
            label="number of password generations prohibited from reuse",
            suggested="24 generations",
        )
    ],
    "3.6.2": [
        ODP(
            key="incident_report_timeframe",
            label="timeframe to report incidents",
            guidance="DFARS 252.204-7012 requires reporting to DoD within 72 hours.",
            suggested="within 72 hours",
        )
    ],
    "3.7.5": [
        ODP(
            key="nonlocal_maintenance_mfa",
            label="multifactor requirement for nonlocal maintenance sessions",
            suggested="MFA for all nonlocal maintenance sessions",
        )
    ],
    "3.11.1": [
        ODP(
            key="risk_assessment_frequency",
            label="frequency of risk assessments",
            suggested="annually and upon significant change",
        )
    ],
    "3.14.1": [
        ODP(
            key="flaw_remediation_timeframe",
            label="timeframe to remediate flaws by severity",
            suggested="critical within 15 days, high within 30 days",
        )
    ],
}


def odps_for(nist_id: str | None, *texts: str | None) -> list[dict[str, Any]]:
    """Merge curated + text-extracted ODPs for a control, de-duped by key."""
    merged: dict[str, ODP] = {}
    for odp in CURATED_ODP_171.get((nist_id or "").strip(), []):
        merged[odp.key] = odp
    for text in texts:
        for odp in extract_odps(text):
            merged.setdefault(odp.key, odp)
    return [o.to_dict() for o in merged.values()]


_PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-z0-9_]+)\s*\}\}", re.IGNORECASE)


def render(
    body: str,
    odp_values: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    """Substitute ``{{key}}`` placeholders; return ``(text, still_blank_keys)``.

    A key resolves from ``odp_values`` first, then ``context`` (platform, env,
    services…). An unresolved key is left as ``[ORGANIZATION-DEFINED: key]`` and
    reported, so the UI can flag exactly what the customer still owes.
    """
    values = {**(context or {}), **(odp_values or {})}
    missing: list[str] = []

    def _sub(m: re.Match[str]) -> str:
        key = m.group(1)
        val = values.get(key)
        if val is None or (isinstance(val, str) and not val.strip()):
            missing.append(key)
            return f"[ORGANIZATION-DEFINED: {key}]"
        return str(val)

    return _PLACEHOLDER_RE.sub(_sub, body), missing
