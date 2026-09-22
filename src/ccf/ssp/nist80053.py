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
from ..catalog.oscal import OscalCatalog, OscalControl
from . import constants
from .odp import ODP

#: ``ODP.source`` for a parameter that came out of the 800-53r5 catalog, so a
#: rendered definition says which document defined the blank. The CMMC/800-171
#: producer (``ssp/odp.py``) stamps its own.
ODP_SOURCE_80053 = "NIST SP 800-53r5"


def family_of(canonical_id: str) -> str:
    """The family code of a canonical 800-53 control id (``"AC-2(1)"`` -> ``"AC"``)."""
    return canonical_id.split("-", 1)[0].upper()


def odp_definitions_for(oc: OscalControl) -> list[dict[str, Any]]:
    """The ODP fill-prompt definitions for one catalog control.

    Built through :class:`ccf.ssp.odp.ODP` -- the single dataclass that defines
    this shape -- rather than as an ad-hoc dict. This module used to emit
    ``{"id", "label", "guidance", "choices"}`` while every consumer reads
    ``key`` (``ssp/completeness.py``'s unfilled-parameter gate, and
    ``_ssp_entry.html``'s ``odp::{{ odp.key }}`` field names). One shape, one
    spelling, produced in one place, so the two cannot drift apart again.

    ``key`` is the OSCAL parameter id because that is exactly what
    :func:`build_80053_entries` scaffolds into the entry's ``odp_values`` and
    what the editor posts back -- the prompt and the stored value must share a
    key or the value can never be read back or counted as filled.

    Nothing is invented: a parameter with no guidelines gets ``guidance=None``
    and a parameter with no ``select.choice[]`` gets ``choices=[]`` and stays
    an assignment. ``suggested`` is always ``None`` -- the 800-53 catalog
    offers no example value, and fabricating one would put an unreviewed
    number in front of a human as if NIST had proposed it.
    """
    out: list[dict[str, Any]] = []
    for p in oc.params:
        choices = list(p.choices)
        label = (p.label or "").strip()
        out.append(
            ODP(
                # Two catalog params carry no label at all (SC-36, SI-7(1));
                # fall back to the identifier rather than render a blank prompt.
                key=p.id,
                label=label or p.id,
                kind="selection" if choices else "assignment",
                choices=choices,
                guidance=(p.guidance or "").strip() or None,
                source=ODP_SOURCE_80053,
            ).to_dict()
        )
    return out


def build_80053_entries(
    catalog: OscalCatalog,
    baseline_level: str,
    *,
    named_roles: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """Draft SSP entries + ODP definitions for every control in a baseline.

    Returns ``(entries, odp_defs_by_control)`` where each entry dict has keys
    matching the ``SSPControlEntry`` columns, and ``odp_defs_by_control[cid]``
    is the list :func:`odp_definitions_for` produces (one ``ccf.ssp.odp.ODP``
    dict per catalog param) for rendering ODP fill prompts — the entry's own
    ``odp_values`` holds only ``key -> value`` (scaffolded ``None``).

    The second element is reference data derived from the catalog, not entry
    content: nothing persists it. ``ssp/odp_defs.py`` resolves it again at read
    time for the API, the editor and the completeness gate, so the catalog
    stays the single authority for what a parameter means.
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
                # Canonical vocabulary (ssp.constants). This seeder used to emit
                # a lowercase/hyphenated set — ["planned"], ["system-specific"] —
                # that appears nowhere in constants.py, giving one column two
                # disjoint vocabularies depending on which framework seeded it.
                # Consumers assume the canonical spelling and compare
                # case-sensitively: ssp/completeness.py's evidence gate, the
                # editor's checkbox filter in api/routes/ui.py, and the docx
                # renderer. An 800-53 project therefore rendered with no status
                # selected, and the first HTML save silently rewrote the value.
                "implementation_status": [constants.PLANNED],
                "control_origination": [constants.ORG_SYSTEM_SPECIFIC],
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
        odp_defs_by_control[cid] = odp_definitions_for(oc)

    return entries, odp_defs_by_control
