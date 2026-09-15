"""Map a DISA reference index onto the OSCAL catalog.

Pure: reference string plus the catalog's id sets in, a resolution out. No
database, no file access, no catalog object -- so the caller decides which
catalog a reference is resolved against, and the rule below is testable on its
own.

**The rule that is easy to get wrong.** A leading parenthesized integer is a
control *enhancement*, not a statement item: ``AC-2 (1)`` is ``ac-2.1``, not
``ac-2_smt.1``. Leading ``(n)`` tokens are absorbed into the control id while
the enhanced control actually exists in the catalog; whatever remains is the
item path. Reading them as items mis-maps 1,860 of the list's 3,849 Rev. 5
references.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..catalog.canonical import canonical_to_oscal_id, canonicalize
from ..catalog.oscal import OscalCatalog

_ENH_TOKEN = re.compile(r"^\(\s*(\d{1,3})\s*\)$")


@dataclass(frozen=True)
class ResolvedReference:
    canonical_control: str | None
    oscal_control_id: str | None
    oscal_part_id: str | None


NOTHING = ResolvedReference(None, None, None)


def catalog_index(catalog: OscalCatalog) -> tuple[frozenset[str], frozenset[str]]:
    """The catalog's control ids and statement part ids, as OSCAL spells them."""
    controls: set[str] = set()
    parts: set[str] = set()
    for canonical, control in catalog.controls.items():
        controls.add(canonical_to_oscal_id(canonical))
        parts.update(control.statement_parts)
    return frozenset(controls), frozenset(parts)


def resolve_reference(
    raw_index: str,
    *,
    control_ids: frozenset[str],
    part_ids: frozenset[str],
) -> ResolvedReference:
    tokens = raw_index.split()
    if not tokens:
        return NOTHING
    base = canonicalize(tokens[0])
    if base is None:
        return NOTHING
    canonical = base.value
    oscal_id = canonical_to_oscal_id(canonical)
    if oscal_id not in control_ids:
        return NOTHING

    i = 1
    while i < len(tokens):
        m = _ENH_TOKEN.match(tokens[i])
        if not m:
            break
        candidate_canonical = f"{canonical}({int(m.group(1))})"
        candidate_oscal = canonical_to_oscal_id(candidate_canonical)
        if candidate_oscal not in control_ids:
            break
        canonical, oscal_id = candidate_canonical, candidate_oscal
        i += 1

    segments = [t.strip("()").lower() for t in tokens[i:]]
    part_id = f"{oscal_id}_smt" + ("." + ".".join(segments) if segments else "")
    return ResolvedReference(
        canonical_control=canonical,
        oscal_control_id=oscal_id,
        oscal_part_id=part_id if part_id in part_ids else None,
    )
