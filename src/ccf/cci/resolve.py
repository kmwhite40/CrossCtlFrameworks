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

**The catalog problem.** The platform holds exactly one OSCAL catalog -- Rev.
5 -- so ``control_ids``/``part_ids`` are always Rev. 5's, regardless of which
revision the raw reference actually names. For a Rev. 5 reference that is the
correct catalog and the result is verified. For any other revision (Rev. 4,
v3, 800-53A) it is the *only* catalog available, so the same membership test
becomes a best-effort cross-revision estimate: a control that kept the same
id across revisions still resolves correctly (Rev. 4's ``AC-12(1)`` really is
Rev. 5's ``ac-12.1``), but a control that was renumbered, merged, or withdrawn
since the cited revision does not -- and a reference naming an enhancement in
a format this parser does not recognise (800-53A glues the enhancement to the
item, e.g. ``AC-2 (1).1``) silently stops absorbing and reports the base
control instead. Both failure shapes previously looked identical to a
trustworthy result: same fields, same types, no signal. ``status`` on
:class:`ResolvedReference` is that signal -- see :class:`ResolutionStatus`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from ..catalog.canonical import canonical_to_oscal_id, canonicalize
from ..catalog.oscal import OscalCatalog

_ENH_TOKEN = re.compile(r"^\(\s*(\d{1,3})\s*\)$")

#: A token that LOOKS like an unabsorbed enhancement marker -- starts with
#: "(" followed by a digit -- whether because it is exactly the shape
#: ``_ENH_TOKEN`` expects but failed the catalog membership check (the
#: enhancement doesn't exist in the held Rev. 5 catalog), or because it is a
#: shape ``_ENH_TOKEN`` never matches at all (800-53A's glued ``(1).1``).
#: Used only to flag :attr:`ResolutionStatus.BASE_CONTROL_FALLBACK`; it never
#: changes what gets absorbed.
_ENH_LIKE = re.compile(r"^\(\s*\d")


class ResolutionStatus(StrEnum):
    """How much to trust a :class:`ResolvedReference`.

    Four states, mutually exclusive and exhaustive:

    - ``RESOLVED`` -- the base token (and every leading enhancement token in
      the space-separated ``(n)`` shape) matched an id in the held catalog,
      and nothing after the last absorbed token still looks like an
      enhancement marker. For a Rev. 5 reference this is a verified result.
      For any other revision it is a best-effort cross-revision match (the
      held catalog belongs to Rev. 5, not the cited revision) that happens
      to agree -- often right, never independently checked.
    - ``BASE_CONTROL_FALLBACK`` -- ``canonical_control`` is populated but
      only to the base control (or an earlier enhancement level than the
      reference names): the next token still looks like an enhancement
      marker but could not be absorbed, either because it doesn't fit the
      space-separated ``(n)`` shape (800-53A's ``(1).1``) or because the
      candidate enhancement isn't in the held Rev. 5 catalog. The base
      control is real; the reference may have named something more specific.
    - ``WITHDRAWN`` -- the base token parsed as a syntactically valid
      control id but is not present in the held Rev. 5 catalog.
      ``canonical_control`` is null. Most likely cause: the control was
      withdrawn, merged, or renumbered since the cited revision.
    - ``UNPARSEABLE`` -- the raw index's first token is not a recognisable
      800-53 control id at all. ``canonical_control`` is null.
    """

    RESOLVED = "resolved"
    BASE_CONTROL_FALLBACK = "base_control_fallback"
    WITHDRAWN = "withdrawn"
    UNPARSEABLE = "unparseable"


@dataclass(frozen=True)
class ResolvedReference:
    canonical_control: str | None
    oscal_control_id: str | None
    oscal_part_id: str | None
    status: ResolutionStatus


def _nothing(status: ResolutionStatus) -> ResolvedReference:
    return ResolvedReference(None, None, None, status)


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
        return _nothing(ResolutionStatus.UNPARSEABLE)
    base = canonicalize(tokens[0])
    if base is None:
        return _nothing(ResolutionStatus.UNPARSEABLE)
    canonical = base.value
    oscal_id = canonical_to_oscal_id(canonical)
    if oscal_id not in control_ids:
        return _nothing(ResolutionStatus.WITHDRAWN)

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

    # A leftover token that still looks like an enhancement marker means the
    # loop above stopped short of the reference's real target -- the base
    # control is real, but it isn't necessarily the whole answer.
    status = (
        ResolutionStatus.BASE_CONTROL_FALLBACK
        if i < len(tokens) and _ENH_LIKE.match(tokens[i])
        else ResolutionStatus.RESOLVED
    )

    segments = [t.strip("()").lower() for t in tokens[i:]]
    part_id = f"{oscal_id}_smt" + ("." + ".".join(segments) if segments else "")
    return ResolvedReference(
        canonical_control=canonical,
        oscal_control_id=oscal_id,
        oscal_part_id=part_id if part_id in part_ids else None,
        status=status,
    )
