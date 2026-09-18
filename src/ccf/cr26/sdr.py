"""Seed a FedRAMP Security Decision Record from what the platform holds.

Unlike the CPO -- which is mostly facts about the business that live nowhere
here -- the SDR genuinely IS a second profile over content this platform
already produces. Ten of its eleven mapped fields have real sources.

The eleventh, ``ksiImplementation``, is the provider's narrative of how the
offering meets each indicator, and it exists nowhere per-system.
``KSI.description`` is the catalog's org-agnostic description of the
*requirement*, so rendering it there would describe the obligation while
claiming to describe the implementation.

That gap is more dangerous than the CPO's, because every required
``keySecurityIndicators`` field is an array of free text: ``[]`` satisfies the
schema. A seeder could emit a complete-looking indicator saying nothing at all,
and unlike the CPO the document would still validate. So an indicator with no
authored narrative is **omitted entirely** and named in the result.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import SSPControlEntry, SSPProject


def _parameter_values(odp_values: dict[str, Any] | None) -> list[dict[str, str]]:
    """Answered organization-defined parameters, as CR26 wants them.

    Unanswered parameters are DROPPED, not stringified. ``ssp/nist80053.py``
    scaffolds ``odp_values`` as ``{param.id: None}`` for every parameter in the
    control, and ``parameterValue`` is ``type: string`` -- so ``str(None)``
    would emit ``"None"`` as the provider's chosen value, a document that
    validates and is wrong.
    """
    return [
        {"parameterId": str(key), "parameterValue": str(value)}
        for key, value in (odp_values or {}).items()
        if value is not None
    ]


def render_controls(entries: Sequence[SSPControlEntry]) -> list[dict[str, Any]]:
    """The SSP's control content in the SDR's shape.

    The joins match ``ssp/nist80053_docx.py`` lines 170 and 173, which render
    these same two fields into the Word SSP. Two profiles over one body of
    content must not disagree about what a control says.
    """
    return [
        {
            "controlId": entry.control_id,
            "controlImplementationStatus": ", ".join(entry.implementation_status or []),
            "controlImplementationDescription": " ".join(
                str(part.get("text") or "") for part in (entry.part_narratives or [])
            ),
            "parameterValues": _parameter_values(entry.odp_values),
        }
        for entry in entries
    ]


async def latest_project_id(session: AsyncSession, system_id: int) -> int | None:
    """The SSP project this system's SDR renders from, or ``None``.

    ``SSPProject.system_id`` is nullable with no unique constraint, so a system
    may have several. Two precedents disagree -- ``api/routes/oscal.py`` orders
    by ``id.desc()``, ``api/routes/reports.py`` by ``updated_at.desc()``. This
    follows ``reports.py``: it is the closer analogue (rendering a document
    rather than assembling a package), and "most recently worked on" is the
    better answer to "which SSP describes this system today".

    The choice is reported in :class:`SdrSeedResult` rather than left implicit,
    because the ambiguity is real and an operator should never have to guess
    which SSP their SDR came from.
    """
    return (
        await session.execute(
            select(SSPProject.id)
            .where(SSPProject.system_id == system_id)
            .order_by(SSPProject.updated_at.desc())
            .limit(1)
        )
    ).scalars().first()


#: The five ``keySecurityIndicators`` fields the platform derives. Refreshed on
#: every seed, because each is a fact about the system that changes as scans
#: and reviews run. ``ksiImplementation`` is deliberately absent: it is the one
#: field only a human can supply.
DERIVED_INDICATOR_FIELDS: tuple[str, ...] = (
    "ksiImplementationStatus",
    "ksiValidation",
    "ksiAssessment",
    "ksiTests",
    "ksiEvidence",
)

#: Of the five, these four are ``required`` and ``type: array`` in the schema,
#: so ``[]`` is the correct default when there is nothing to fall back to.
#: ``ksiImplementationStatus`` is deliberately excluded: it is ``optional``
#: and ``enum``-constrained (``Implemented`` / ``Not Implemented`` /
#: ``Partially Implemented``), so inventing a placeholder value for it -- even
#: ``""`` -- produces a string outside the enum and the document fails
#: validation. Omitting the key entirely is the correct reflection of
#: "optional", the same way ``[]`` is the correct reflection of "required,
#: type: array".
_REQUIRED_ARRAY_FIELDS: tuple[str, ...] = tuple(
    field for field in DERIVED_INDICATOR_FIELDS if field != "ksiImplementationStatus"
)


def _has_narrative(value: Any) -> bool:
    """True if ``value`` is a non-empty list of non-blank strings.

    ``ksiImplementation`` is ``type: array``, so three shapes must all count
    as "no narrative": not a list at all (a bare string would satisfy naive
    truthiness while violating the schema), an empty list, and a list of only
    blank strings (schema-valid, but says nothing about the implementation --
    the same invisible gap the omission rule exists to prevent, one level
    down).
    """
    return isinstance(value, list) and any(
        isinstance(item, str) and item.strip() for item in value
    )


def _copied(value: Any) -> Any:
    """A defensive copy of a derived or carried-forward field value.

    Every field this function assigns without deriving it from scratch is
    either a scalar or a list, and ``ksiEvidence``'s list elements are
    further dicts -- exactly the shape Task 3 is most likely to
    post-process. A shallow ``list(...)`` copy only breaks aliasing at the
    top level, so list-of-dict elements are copied one level deeper too.
    Without this, a merged entry can share list (or nested dict) identity
    with either the caller's ``authored`` input or its ``derived`` mapping,
    and mutating the returned document would mutate the caller's data
    underneath it.
    """
    if isinstance(value, list):
        return [dict(item) if isinstance(item, dict) else item for item in value]
    return value


#: Mirrors the vendored schema's ``ksiImplementationStatus`` enum exactly
#: (``schemas/fedramp-security-decision-record-schema-*.json``). Used to
#: drop a carried-forward status that is not a member -- most notably the
#: ``""`` this module's own earlier version wrote into the fallback branch,
#: which would otherwise round-trip forever: ``seed_sdr`` (Task 3) feeds a
#: previously-seeded document's own ``keySecurityIndicators`` back in as
#: ``authored``.
_VALID_IMPLEMENTATION_STATUSES: frozenset[str] = frozenset(
    {"Implemented", "Not Implemented", "Partially Implemented"}
)


def merge_indicators(
    authored: Sequence[dict[str, Any]],
    derived: Mapping[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Merge authored narrative with derived facts, keyed by ``ksiId``.

    Returns the merged entries and the ids omitted for want of a narrative.

    Rules, each load-bearing:

    * **An indicator with no authored ``ksiImplementation`` is omitted.**
      Emitting it with an empty array would satisfy the schema while saying
      nothing about how the offering meets the indicator -- and unlike the
      CPO's gaps, the document would still validate, so the omission would be
      invisible. See :func:`_has_narrative` for what counts as "no narrative".
    * **The five derived fields are overwritten**, because they are facts
      about the system rather than anything a human authored here. Every list
      value this function assigns -- derived, or carried forward from the
      authored side -- is copied rather than aliased, including the dicts
      inside ``ksiEvidence`` one level deeper (see :func:`_copied`), so
      mutating the merged document can reach back into neither the caller's
      ``derived`` mapping nor its ``authored`` list.
    * **An authored entry the platform no longer recognises is KEPT**, with
      whatever derived fields it last carried. A narrative is human work; a
      KSI catalog revision must not silently delete it -- and must not blank
      the fields it can no longer refresh. The four required array fields
      default to ``[]`` when there is nothing to carry forward; the optional,
      enum-constrained ``ksiImplementationStatus`` is left absent when there
      is nothing to carry forward, and DROPPED if the carried-forward value is
      not one of the schema's enum members. That makes this function
      self-healing against documents an earlier version of it wrote: this
      same fallback once defaulted the status to ``""``, and ``seed_sdr``
      (Task 3) feeds a previously-seeded document's own
      ``keySecurityIndicators`` back in as ``authored`` -- so without this
      check, that ``""`` would round-trip through every future seed and the
      document would never validate again.
    * ``keySecurityIndicators`` has no ``uniqueItems`` constraint, so
      **duplicate authored ``ksiId``s are legal input**. A later duplicate
      with no narrative must not evict an earlier real one -- that would both
      destroy human work and misreport it as never having existed (the id
      would land in ``omitted``). When the guard fires, the later duplicate is
      discarded WHOLE, not merged field-by-field, so any fresher derived
      fields it happened to carry are lost along with its empty narrative --
      a deliberate choice (narrative preservation is the stated priority),
      not an oversight.
    """
    by_id: dict[str, dict[str, Any]] = {}
    for authored_entry in authored:
        ksi_id = authored_entry.get("ksiId")
        if not (isinstance(ksi_id, str) and ksi_id):
            continue
        prior = by_id.get(ksi_id)
        if (
            prior is not None
            and _has_narrative(prior.get("ksiImplementation"))
            and not _has_narrative(authored_entry.get("ksiImplementation"))
        ):
            continue
        by_id[ksi_id] = dict(authored_entry)

    merged: list[dict[str, Any]] = []
    omitted: list[str] = []
    for ksi_id in sorted(set(by_id) | set(derived)):
        entry = by_id.get(ksi_id)
        narrative = (entry or {}).get("ksiImplementation")
        if not _has_narrative(narrative):
            omitted.append(ksi_id)
            continue
        assert isinstance(narrative, list)  # _has_narrative just confirmed this
        out = dict(entry or {})
        out["ksiId"] = ksi_id
        out["ksiImplementation"] = _copied(narrative)
        if ksi_id in derived:
            derived_facts = derived[ksi_id]
            for field in DERIVED_INDICATOR_FIELDS:
                if field not in derived_facts:
                    raise KeyError(
                        f"derived facts for {ksi_id!r} are missing required "
                        f"field {field!r}"
                    )
                if derived_facts[field] is None:
                    raise KeyError(
                        f"derived facts for {ksi_id!r} has a None value for "
                        f"required field {field!r}"
                    )
                out[field] = _copied(derived_facts[field])
        else:
            for field in _REQUIRED_ARRAY_FIELDS:
                out[field] = _copied(out.get(field, []))
            if out.get("ksiImplementationStatus") not in _VALID_IMPLEMENTATION_STATUSES:
                out.pop("ksiImplementationStatus", None)
        merged.append(out)
    return merged, omitted
