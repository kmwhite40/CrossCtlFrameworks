"""Build default per-control SSP entries for a NIST 800-53r5 project.

Given a loaded :class:`~ccf.catalog.oscal.OscalCatalog` and a FIPS-199
baseline level (``low`` | ``moderate`` | ``high``), :func:`build_80053_entries`
selects the authoritative 800-53B control set for that baseline and produces
one draft SSP entry per control (statement, ODP scaffolding, responsible
role, status, origination) — a tailorable starting point, not a claim of
implementation. Pure function over the catalog; no DB access, so it's
unit-testable without a database (see ``ssp/seed.py`` for the CMMC/800-171
equivalent that upserts these into ``SSPControlEntry`` rows).
"""

from __future__ import annotations

from typing import Any

from ..catalog.canonical import canonicalize
from ..catalog.oscal import OscalCatalog
from . import constants


def family_of(canonical_id: str) -> str:
    """The family code of a canonical 800-53 control id (``"AC-2(1)"`` -> ``"AC"``)."""
    return canonical_id.split("-", 1)[0].upper()


def build_80053_entries(
    catalog: OscalCatalog,
    baseline_level: str,
    *,
    named_roles: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """Draft SSP entries + ODP definitions for every control in a baseline.

    Returns ``(entries, odp_defs_by_control)`` where each entry dict has keys
    matching the ``SSPControlEntry`` columns, and ``odp_defs_by_control[cid]``
    is a list of ``{"id", "label", "guidance", "choices"}`` dicts (one per
    catalog param) for rendering ODP fill prompts — the entry's own
    ``odp_values`` holds only ``id -> value`` (scaffolded ``None``).
    """
    roles = named_roles or {}
    ids = [
        cid
        for cid in catalog.baselines.get(baseline_level, set())
        if (oc := catalog.get(cid)) is not None and not oc.withdrawn
    ]

    def _sort_key(cid: str) -> tuple[str, int, tuple[int, ...]]:
        parsed = canonicalize(cid)
        if parsed is None:
            return (family_of(cid), 0, ())
        return (parsed.family, parsed.number, parsed.enhancements)

    ids.sort(key=_sort_key)

    entries: list[dict[str, Any]] = []
    odp_defs_by_control: dict[str, list[dict[str, Any]]] = {}
    for order, cid in enumerate(ids):
        oc = catalog.get(cid)
        assert oc is not None  # filtered above
        domain = family_of(cid)
        role = constants.responsible_role_for(domain, named_role=roles.get(domain))
        entries.append(
            {
                "control_id": cid,
                "nist_id": cid,
                "domain": domain,
                "title": oc.title,
                "requirement": oc.statement,
                "responsible_role": role,
                "odp_values": {p.id: None for p in oc.params},
                "implementation_status": ["planned"],
                "control_origination": ["system-specific"],
                "part_narratives": [
                    {
                        "label": "",
                        "text": (
                            f"[DRAFT] {domain} control {cid} is the responsibility of "
                            f"{role}. Describe the implementation."
                        ),
                        "draft": True,
                    }
                ],
                "sort_order": order,
            }
        )
        odp_defs_by_control[cid] = [
            {"id": p.id, "label": p.label, "guidance": p.guidance, "choices": p.choices}
            for p in oc.params
        ]

    return entries, odp_defs_by_control
