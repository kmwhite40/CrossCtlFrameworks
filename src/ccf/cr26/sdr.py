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

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    KSI,
    KSIAssessorReview,
    KSIState,
    KSIValidationResult,
    SSPControlEntry,
    SSPProject,
    System,
)
from ..models_cr26 import Cr26Document
from ..ssp.completeness import is_draft_or_placeholder
from .store import put_document
from .validation import schema_path


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


#: Where the vendored SDR schema states its implementation-status enum. BOTH
#: places, because this module constrains both fields and a copy that tracked
#: only one would go stale in silence if FedRAMP widened the other.
_STATUS_ENUM_PATHS: tuple[tuple[str, ...], ...] = (
    (
        "properties", "securityControls", "items", "properties",
        "controlImplementationStatus", "enum",
    ),
    (
        "properties", "keySecurityIndicators", "items", "properties",
        "ksiImplementationStatus", "enum",
    ),
)


@lru_cache(maxsize=1)
def _implementation_status_enum() -> frozenset[str]:
    """``{"Implemented", "Not Implemented", "Partially Implemented"}`` -- READ
    out of the vendored schema, not hand-copied from it.

    Both fields this module constrains --
    ``securityControls[].controlImplementationStatus`` (spec 1.2.1) and
    ``keySecurityIndicators[].ksiImplementationStatus`` (spec 1.3) -- carry
    the same three members, so one derived constant serves both. A hand-typed
    mirror would be a third place for this spec's recurring
    claim-versus-rendering defect to hide: a schema bump that WIDENED the enum
    would leave the copy silently narrow, and the seeder would start omitting
    a status FedRAMP had just begun to accept.

    The platform's own vocabulary is
    :data:`ccf.ssp.constants.IMPLEMENTATION_STATUS_OPTIONS` --
    ``Implemented``, ``Partially Implemented``, ``Planned``,
    ``Alternative Implementation``, ``Not Applicable`` -- whose first two
    members are exact matches here and whose other three have no FedRAMP
    equivalent. Those three are OMITTED rather than translated: "Not
    Implemented" is a harsher claim to a regulator than "Planned" is, and
    inventing the harsher one is the same defect facing the other way.

    Read on demand and cached rather than at import, following
    :mod:`ccf.cr26.validation`, which keeps file I/O out of module import
    deliberately. Raises rather than guessing if the vendored file is missing
    or if the two locations ever stop agreeing -- both are packaging or
    upstream-drift failures that must be loud, and a split enum needs two
    constants and two decisions, not one silently applied to both.
    """
    path = schema_path("sdr")
    if path is None:
        raise RuntimeError(
            "CR26 schema packaging error: the vendored SDR schema is missing, "
            "so the implementation-status enum cannot be read"
        )
    schema: Any = json.loads(path.read_text(encoding="utf-8"))
    found: dict[str, frozenset[str]] = {}
    for keys in _STATUS_ENUM_PATHS:
        node: Any = schema
        for key in keys:
            node = node[key]
        found[keys[-2]] = frozenset(node)
    distinct = set(found.values())
    if len(distinct) != 1:
        raise RuntimeError(
            "CR26 schema drift: the SDR's two implementation-status enums no "
            "longer agree -- "
            f"{ {name: sorted(members) for name, members in sorted(found.items())} }. "
            "They shared three members when this module was written; splitting "
            "them needs two constants and two decisions, not one."
        )
    return distinct.pop()


def _control_implementation_status(statuses: Sequence[str] | None) -> str | None:
    """The one schema-valid status this entry claims, or ``None`` to claim none.

    ``implementation_status`` is JSONB ``list[str]`` and the SDR field is a
    single enum-constrained string, so a ``", ".join(...)`` of two values can
    **never** be an enum member -- ``"planned, partial"`` is not a status, it
    is a sentence. ``ssp/nist80053_docx.py`` joins them because it writes into
    a Word table cell where any string is fine; the SDR has an enum, and that
    difference is the whole of spec 1.2.1.

    So: exactly one status, and that status a member of the enum, or the key
    is omitted. Every field of ``securityControls.items`` is optional, so
    omission validates -- and a control whose status the platform cannot state
    in FedRAMP's vocabulary should say nothing rather than guess.
    """
    values = list(statuses or [])
    if len(values) != 1:
        return None
    value = values[0]
    return value if value in _implementation_status_enum() else None


def _implementation_description(
    part_narratives: Sequence[Any] | None,
) -> tuple[str | None, bool]:
    """The written parts of this control's narrative, and whether any were dropped.

    **Scaffolding is dropped, never rendered.** ``ssp/nist80053.py`` writes
    ``"[DRAFT] AC control AC-2 is the responsibility of System Owner. Describe
    the implementation."`` -- with ``"draft": True`` -- into every part
    narrative of every new 800-53 project, and ``ssp/statements.py`` /
    ``ssp/platforms.py`` leave ``[ORGANIZATION-DEFINED: ...]``,
    ``[Assignment: ...]`` and ``[Selection ...]`` in narrative text. A
    scaffolded-but-unwritten SSP is the state of every new project, and the
    state an operator is most likely to press "seed" in -- so without this,
    the deliverable tells FedRAMP that the provider's implementation
    description is an instruction to write one.

    ``ssp/completeness.py`` already owns this judgement and calls the same text
    "draft narrative -- needs review", so its predicate is imported rather than
    restated: a second copy of a rule is how this module's status enum went
    wrong twice.

    The join itself still matches ``ssp/nist80053_docx.py`` line 170 -- two
    profiles over one body of content must not disagree about what a control
    says.

    Returns ``None``, not ``""``, when nothing survives. ``required`` is absent
    from ``securityControls.items``, so every property there is optional, and
    ``""`` would assert that the provider's description IS blank -- the same
    claim-versus-rendering defect this module refuses for
    ``ksiImplementationStatus`` and ``controlImplementationStatus``. Absence
    says "not stated"; ``""`` says "stated, and empty". Blank parts are
    stripped and skipped BEFORE the join, so ``" "`` cannot come back as the
    truthy ghost of that same empty string -- ``_has_narrative`` applies
    exactly this rule to KSI narratives one level down, and
    ``ssp/completeness.py`` strips too.

    Returns ``(description, dropped_something)``. **Dropping content silently
    is its own defect**: ``ssp/statements.py`` appends
    ``" Frequency: [ORGANIZATION-DEFINED: frequency]."`` to otherwise-complete
    composed paragraphs, so a fully written statement can lose a whole part
    over one trailing token. The caller reports the affected control rather
    than keeping the placeholder -- the surviving text is defensible content
    and the operator can see and fix the gap, which is what
    :class:`SdrSeedResult` is for.
    """
    written: list[str] = []
    dropped = False
    for part in part_narratives or []:
        if not isinstance(part, dict):
            if _is_blank(part):
                # A legacy bare blank string lost nothing; saying otherwise
                # sends an operator hunting for content that never existed.
                continue
            # Any other legacy bare value is content this cannot read, and
            # rendering ``str(part)`` would put a repr in a federal document.
            dropped = True
            continue
        value = part.get("text")
        if not isinstance(value, str):
            if value is None:
                continue  # nothing written here at all
            # Same standard one level down: ``{"text": ["a", "b"]}`` must not
            # render as ``"['a', 'b']"``.
            dropped = True
            continue
        text = value.strip()
        if not text:
            # Nothing was written here; nothing is lost by leaving it out, so
            # this is NOT a drop the operator needs to hear about -- claiming
            # otherwise would put a false statement in the one channel that
            # exists to be truthful. ``api/routes/ui.py`` re-saves a cleared
            # textarea as ``""``.
            continue
        # Both gates matter, in both directions: ``draft`` is the flag
        # ``ssp/nist80053.py`` sets, and the predicate catches marker or
        # placeholder text from producers that set no flag at all
        # (``ssp/statements.py``, ``ssp/platforms.py``). A future scaffolder
        # writing the flag without the marker is exactly what the flag gate is
        # for -- and ``api/routes/ui.py``'s ``ssp_save_entry`` rebuilds every
        # part as ``{"label", "text"}``, dropping ``draft``, so for any control
        # ever touched in that editor the predicate is the ONLY gate left.
        #
        # The predicate is given the RAW text, never the stripped copy:
        # ``constants.DRAFT_PREFIX`` is ``"[DRAFT] "`` WITH its trailing space,
        # and ``is_draft_or_placeholder`` tests it as a plain substring -- so
        # stripping first destroys the token whenever the marker ends the
        # string, and ``"[DRAFT] "`` would ship as ``"[DRAFT]"``. The strip is
        # for the blank test and the join only.
        if part.get("draft") or is_draft_or_placeholder(value):
            dropped = True
            continue
        written.append(text)

    description = " ".join(written) or None
    if description is not None and is_draft_or_placeholder(description):
        # **The join can manufacture the token the per-part check rejected.**
        # ``DRAFT_PREFIX`` is ``"[DRAFT] "`` with a trailing space, so a bare
        # ``"[DRAFT]"`` part slips the per-part predicate -- and then the
        # ``" "`` separator supplies the missing space, putting a literal
        # ``"[DRAFT] "`` into the SHIPPED description. It would read as
        # complete, keep its status, and appear in neither gap list.
        #
        # Re-running the SAME predicate on the composed string closes that
        # without touching ``is_draft_or_placeholder`` itself: the existing
        # membership test already returns True on the join's output. A control
        # that trips here is treated exactly like one whose parts were all
        # scaffolding -- no description, named in both lists.
        return None, True
    return description, dropped


def _is_blank(value: Any) -> bool:
    """True for a value that says nothing -- ``None``, or whitespace-only text."""
    return value is None or (isinstance(value, str) and not value.strip())


def _rendered_controls(
    entries: Sequence[SSPControlEntry],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """One walk producing the rendered controls AND the two gap lists.

    Deliberately a single pass. ``controls_missing_description`` was once read
    back off the rendered dicts, which made the two structurally impossible to
    desync; splitting the walk moved the rule into two places, and the whole
    history of this branch is that what can drift, drifts. The two thin
    wrappers below exist so each half stays separately testable, but
    :func:`seed_sdr` takes all three from here in one pass.

    The two gap lists answer different questions and **deliberately overlap**,
    so an operator reading either one gets a complete answer to it:

    * *missing_description* -- this control reached the document with no
      ``controlImplementationDescription`` at all, because nothing was written
      or because everything there was scaffolding.
    * *dropped_parts* -- at least one narrative part was dropped as
      scaffolding, **whether or not** anything survived. A control that keeps a
      truncated description appears here and nowhere else, and that is the case
      most easily missed: it still carries a status, still reads complete, and
      is the one this list exists for. A part that was simply blank does NOT
      count -- nothing was lost, and saying otherwise would send an operator
      hunting for content that never existed.
    """
    rendered: list[dict[str, Any]] = []
    missing: list[str] = []
    dropped_parts: list[str] = []
    for entry in entries:
        control: dict[str, Any] = {
            "controlId": entry.control_id,
            "parameterValues": _parameter_values(entry.odp_values),
        }
        description, dropped = _implementation_description(entry.part_narratives)
        if description is not None:
            control["controlImplementationDescription"] = description
        else:
            missing.append(str(entry.control_id))
        if dropped:
            dropped_parts.append(str(entry.control_id))
        status = _control_implementation_status(entry.implementation_status)
        if status is not None:
            control["controlImplementationStatus"] = status
        rendered.append(control)
    return rendered, missing, dropped_parts


def render_controls(entries: Sequence[SSPControlEntry]) -> list[dict[str, Any]]:
    """The SSP's control content in the SDR's shape.

    Neither enum-constrained nor free-text fields follow the docx renderer
    blindly -- see :func:`_control_implementation_status` for the status and
    :func:`_implementation_description` for the narrative. ``parameterValues``
    is always present, including as ``[]``: an empty list of *answered*
    parameters is a true statement, unlike an empty description.
    """
    return _rendered_controls(entries)[0]


def _control_gaps(entries: Sequence[SSPControlEntry]) -> tuple[list[str], list[str]]:
    """``(missing_description, dropped_parts)`` -- see :func:`_rendered_controls`."""
    _controls, missing, dropped_parts = _rendered_controls(entries)
    return missing, dropped_parts


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
            # id.desc() breaks a tie: updated_at alone leaves the answer to
            # whatever order Postgres happens to return, and this id is the
            # one value SdrSeedResult exists to make VISIBLE. An operator must
            # not be told a different project on two identical seeds.
            .order_by(SSPProject.updated_at.desc(), SSPProject.id.desc())
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
#:
#: These four are also exactly what a ``derived`` mapping MUST supply.
#: ``ksiImplementationStatus`` is optional there too, because only two of the
#: six validation verdicts map to a defensible implementation status (spec
#: 1.3) -- so :func:`_implementation_status` returns ``None`` for the other
#: four and the producer leaves the key out.
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
      about the system rather than anything a human authored here. The four
      required array fields MUST be present and non-``None`` in
      ``derived[ksi_id]`` or this raises, naming the indicator.
      **``ksiImplementationStatus`` is the one derived field a producer may
      omit**, and the reason is spec 1.3: it is optional and enum-constrained
      in the schema, and only two of the six validation verdicts (``pass``,
      ``fail``) map to a defensible implementation status, so
      :func:`_implementation_status` returns ``None`` for the other four and
      the producer leaves the key out rather than inventing a claim. When it
      is absent, a status the authored entry carried from an earlier seed is
      DROPPED rather than left standing as a stale claim -- the derived half
      is refreshed wholesale, not patched. Every list
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
            for field in _REQUIRED_ARRAY_FIELDS:
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
            # The optional fifth. Absent (or None) means the producer had no
            # defensible claim to make, so any status the authored entry
            # carried from an earlier seed is DROPPED rather than left to
            # assert something the platform no longer stands behind -- the
            # derived half is refreshed wholesale, not patched.
            status = derived_facts.get("ksiImplementationStatus")
            if status is None:
                out.pop("ksiImplementationStatus", None)
            else:
                out["ksiImplementationStatus"] = status
        else:
            for field in _REQUIRED_ARRAY_FIELDS:
                carried = out.get(field)
                # Type-checked, not merely defaulted. These four are
                # ``required`` and ``type: array``, and ``seed_sdr`` feeds a
                # previously-stored document's own entries back in here -- so
                # an authored ``ksiValidation: null`` on a ksiId the catalog
                # no longer knows would round-trip forever and the document
                # could never validate again. Exactly the round-trip the enum
                # self-heal below already guards; the array fields had the
                # default but not the check.
                out[field] = _copied(carried) if isinstance(carried, list) else []
            if out.get("ksiImplementationStatus") not in _implementation_status_enum():
                out.pop("ksiImplementationStatus", None)
        merged.append(out)
    return merged, omitted


# ---------------------------------------------------------------------------
# The five derived KSI fields.
#
# Each is a small named helper so a wrong one is obvious and separately
# testable. Two of the five are *claims* rather than renderings -- see spec
# 1.3 -- and are written to say less than the platform could, not more.
#
# None of them may fall back to ``KSI.description``: that is the catalog's
# org-agnostic description of the *requirement*, so putting it in a field that
# describes the provider's implementation, validation or assessment would
# describe the obligation while claiming to describe the answer.
# ---------------------------------------------------------------------------

#: The only two validation verdicts that map to an implementation status.
#:
#: ``ksi_states.status`` holds a *validation verdict* (``pass``, ``warn``,
#: ``fail``, ``not_tested``, ``manual_review_required``, ``not_applicable`` --
#: see :data:`ccf.fedramp20x.VALIDATION_STATUSES`, assigned straight from a
#: ``Verdict`` in ``fedramp20x/validation.py``). The schema's
#: ``ksiImplementationStatus`` wants an *implementation status*
#: (``Implemented`` / ``Not Implemented`` / ``Partially Implemented``). Those
#: are different assertions: "this automated check passed" is not "the
#: provider has implemented this indicator", and ``not_tested`` is emphatically
#: not "Not Implemented".
#:
#: Mapping the whole vocabulary would have Concord tell FedRAMP "Not
#: Implemented" about something nobody has yet examined -- a document that
#: validates and is wrong. So only the two unambiguous verdicts are mapped and
#: the other four yield no claim at all; the field is optional in the schema,
#: so omitting it validates, and the genuinely ambiguous cases are left to the
#: human already authoring ``ksiImplementation``.
_IMPLEMENTATION_STATUS_BY_VERDICT: dict[str, str] = {
    "pass": "Implemented",
    "fail": "Not Implemented",
}


def _implementation_status(verdict: str | None) -> str | None:
    """``Implemented``/``Not Implemented``, or ``None`` to make no claim.

    The mapping's two target values are checked against
    :func:`_implementation_status_enum` rather than trusted, for the same
    reason the control side stopped hand-typing them: a schema bump that
    NARROWED the enum would leave this producer emitting a value FedRAMP no
    longer accepts, and the seeded document would be invalid with nothing
    saying why. Loud, like the drift guard in the enum reader itself.
    """
    claimed = _IMPLEMENTATION_STATUS_BY_VERDICT.get(verdict or "")
    if claimed is not None and claimed not in _implementation_status_enum():
        raise RuntimeError(
            f"CR26 schema drift: validation verdict {verdict!r} maps to "
            f"{claimed!r}, which the vendored schema's implementation-status "
            f"enum no longer accepts ({sorted(_implementation_status_enum())})"
        )
    return claimed


def _validation_statements(result: KSIValidationResult | None) -> list[str]:
    """How the CSP validated this indicator, from its latest validation run.

    The latest run only: ``ksi_validation_results`` is an append-only trail,
    and the SDR states what is true now. The history is the ongoing
    certification report's job, not this document's.
    """
    if result is None:
        return []
    statement = f"{result.status} at {result.validated_at.isoformat()}"
    if result.source:
        statement = f"{statement} (source: {result.source})"
    return [statement]


def _assessment_statements(review: KSIAssessorReview | None) -> list[str]:
    """What the independent assessor recorded, from their latest review."""
    if review is None:
        return []
    statement = review.status
    if review.assessor:
        statement = f"{statement} by {review.assessor}"
    if review.finding:
        statement = f"{statement}: {review.finding}"
    return [statement]


def _tests(ksi: KSI) -> list[str]:
    """The test used to validate this indicator: method plus rule kind.

    ``KSI.rule`` is the machine-readable validation spec the 20x engine
    evaluates; its ``kind`` is the only part of it that names a test rather
    than restating the requirement.
    """
    method = (ksi.validation_method or "").strip()
    kind = str((ksi.rule or {}).get("kind") or "").strip()
    if method and kind:
        return [f"{method} validation (rule kind: {kind})"]
    if method:
        return [f"{method} validation"]
    if kind:
        return [f"rule kind: {kind}"]
    return []


def _evidence(result: KSIValidationResult | None) -> list[dict[str, str]]:
    """One evidence object per reference the latest validation run recorded.

    ``evidenceType`` is deliberately OMITTED. The schema constrains it to
    ``Log | Report | Screenshot | Configuration | Policy | Procedure | Audit
    Record`` -- a classification this platform does not hold, since
    ``evidence_refs`` are bare strings such as ``"AC-2:implemented"``.
    Inferring a type from a ref's shape would present Concord's guess to a
    regulator as the provider's assertion. Every ``evidence`` property is
    optional, so an object of description plus date validates.

    ``lastUpdated`` is ``format: date``, not ``date-time``, so the run's
    timestamp is narrowed to its calendar date.
    """
    if result is None:
        return []
    last_updated = result.validated_at.date().isoformat()
    return [
        {"evidenceDescription": str(ref), "lastUpdated": last_updated}
        for ref in (result.evidence_refs or [])
    ]


async def _derived_indicators(
    session: AsyncSession, system_id: int
) -> dict[str, dict[str, Any]]:
    """Every catalog indicator's derived facts for this system, by ``ksiId``.

    Keyed on :attr:`KSI.identifier` because that is what the document's
    ``ksiId`` carries. Every catalog KSI appears, including ones this system
    has never validated: an indicator with nothing recorded still belongs on
    the deliverable's to-do list, which is what :func:`merge_indicators`
    turns the unauthored ones into.

    Joined on ``ksi_id`` rather than on the denormalised
    ``ksi_validation_results.ksi_identifier``, since the foreign key is the
    column the database actually guarantees.
    """
    ksis = (await session.execute(select(KSI))).scalars().all()
    if not ksis:
        return {}

    states = {
        state.ksi_id: state
        for state in (
            await session.execute(select(KSIState).where(KSIState.system_id == system_id))
        ).scalars().all()
    }
    # Ascending, folded into a dict, so the LAST row per indicator wins: the
    # most recent run, with the row id breaking a timestamp tie.
    results = {
        result.ksi_id: result
        for result in (
            await session.execute(
                select(KSIValidationResult)
                .where(KSIValidationResult.system_id == system_id)
                .order_by(
                    KSIValidationResult.validated_at.asc(), KSIValidationResult.id.asc()
                )
            )
        ).scalars().all()
    }
    reviews = {
        review.ksi_id: review
        for review in (
            await session.execute(
                select(KSIAssessorReview)
                .where(KSIAssessorReview.system_id == system_id)
                .order_by(KSIAssessorReview.reviewed_at.asc(), KSIAssessorReview.id.asc())
            )
        ).scalars().all()
    }

    derived: dict[str, dict[str, Any]] = {}
    for ksi in ksis:
        result = results.get(ksi.id)
        facts: dict[str, Any] = {
            "ksiValidation": _validation_statements(result),
            "ksiAssessment": _assessment_statements(reviews.get(ksi.id)),
            "ksiTests": _tests(ksi),
            "ksiEvidence": _evidence(result),
        }
        state = states.get(ksi.id)
        status = _implementation_status(state.status if state is not None else None)
        if status is not None:
            facts["ksiImplementationStatus"] = status
        derived[ksi.identifier] = facts
    return derived


@dataclass(frozen=True)
class SdrSeedResult:
    """What one seed produced, and the two things the document cannot say.

    ``seed_sdr`` returns this rather than a bare :class:`Cr26Document` like
    ``seed_cpo`` does, because it has something to report that the CPO does
    not: which indicators were left out for want of a narrative, and which of
    a system's several SSP projects it rendered from. The omitted list is the
    deliverable's own to-do list and is worth more to an operator than the
    document it accompanies.
    """

    document: Cr26Document
    omitted_ksi_ids: list[str]
    ssp_project_id: int | None
    #: Controls that reached the document with NO
    #: ``controlImplementationDescription`` -- either because the SSP entry has
    #: no narrative at all, or because everything it had was ``[DRAFT]``
    #: scaffolding or an unresolved ODP placeholder and was dropped (see
    #: :func:`_implementation_description`). Without this the control gap is
    #: silent: ``controlImplementationStatus`` is omitted for the scaffolded
    #: ``Planned``, so nothing in the document itself says the control is
    #: still unwritten. ``omitted_ksi_ids`` does this job for indicators; this
    #: is its equivalent for controls.
    controls_missing_description: list[str]
    #: Controls that kept a description but lost at least one narrative part to
    #: the scaffolding filter. Distinct from the list above and more easily
    #: missed: such a control still carries a description and a status, and
    #: reads complete. ``ssp/statements.py`` appends
    #: ``" Frequency: [ORGANIZATION-DEFINED: frequency]."`` to composed
    #: paragraphs, so a fully written statement can lose a whole part over one
    #: trailing token. Controls that lost everything appear in BOTH lists.
    controls_with_dropped_parts: list[str]
    #: How many controls were rendered at all. ``0`` alongside a non-``None``
    #: ``ssp_project_id`` is the case ``ssp_project_id`` cannot signal by
    #: itself: an empty but recently-updated SSP project wins the
    #: most-recently-updated selection and blanks a populated
    #: ``securityControls``.
    rendered_control_count: int


async def _current(session: AsyncSession, system_id: int) -> dict[str, Any] | None:
    """This system's stored SDR body, or ``None``.

    The ``kind`` filter is load-bearing, not decorative: a system with both a
    CPO and an SDR is the normal case, and without it this returns whichever
    row the database hands back first -- so ``seed_sdr`` would build the SDR
    on top of the CPO's body, carrying ``serviceIdentification`` into a
    document that has no such field.
    """
    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id, Cr26Document.kind == "sdr"
            )
        )
    ).scalars().first()
    return dict(row.document) if row is not None else None


async def seed_sdr(session: AsyncSession, *, system_id: int) -> SdrSeedResult:
    """Render this system's SDR from what the platform holds, preserving narrative.

    ``securityControls`` is regenerated wholesale -- every field of it is
    derived, so there is nothing to preserve. ``keySecurityIndicators`` is
    merged: the five derived fields refresh on every seed, and the authored
    ``ksiImplementation`` survives, because it is the one field the platform
    cannot derive.

    **"Wholesale" includes the empty case**, and it is the one place this
    seeder destroys stored content without naming what was lost: a system
    with no SSP project has its ``securityControls`` replaced with ``[]``,
    however many controls the previous seed wrote there. That follows from
    the field being wholly derived -- unlike ``ksiImplementation``, no part of
    it is human work -- but it is worth saying out loud rather than leaving to
    be discovered. ``ssp_project_id: None`` in the result is the signal: it
    says the seeder found no SSP to render from, which is exactly when an
    empty ``securityControls`` means "nothing to say" rather than "no
    controls".

    Two fields are deliberately left unfilled:

    * ``fedRampRequirements`` is ``[]`` unless already authored. FedRAMP
      publishes no machine-readable ruleset -- the rule ids exist only in
      README prose -- so there is nothing to populate it from, and the array
      has no ``minItems``, so empty validates.
    * ``certificationPackageOverviewUri`` is carried forward if authored and
      otherwise ABSENT. It is required at the root, so **a seeded SDR is
      invalid until someone publishes the CPO and supplies its URI**. That is
      correct rather than unfortunate -- something is genuinely still owed --
      and it is the same honest-failure posture as the CPO seeder's.
    """
    system = await session.get(System, system_id)
    # A soft-deleted system is not a writable system -- see ccf.cr26.store.
    if system is None or system.deleted_at is not None:
        raise ValueError(f"unknown system: {system_id!r}")

    existing = await _current(session, system_id)
    document: dict[str, Any] = existing if existing is not None else {}

    project_id = await latest_project_id(session, system_id)
    entries: Sequence[SSPControlEntry] = ()
    if project_id is not None:
        entries = (
            await session.execute(
                select(SSPControlEntry)
                .where(SSPControlEntry.project_id == project_id)
                # sort_order defaults to 0 for every entry, so control_id is
                # what actually makes the rendered order stable and a re-seed
                # diff-free.
                .order_by(SSPControlEntry.sort_order, SSPControlEntry.control_id)
            )
        ).scalars().all()
    controls, missing_description, dropped_parts = _rendered_controls(entries)
    document["securityControls"] = controls

    authored = document.get("keySecurityIndicators")
    merged, omitted = merge_indicators(
        [entry for entry in authored if isinstance(entry, dict)]
        if isinstance(authored, list)
        else [],
        await _derived_indicators(session, system_id),
    )
    document["keySecurityIndicators"] = merged
    document.setdefault("fedRampRequirements", [])

    row = await put_document(session, system_id=system_id, kind="sdr", document=document)
    return SdrSeedResult(
        document=row,
        omitted_ksi_ids=omitted,
        ssp_project_id=project_id,
        controls_missing_description=missing_description,
        controls_with_dropped_parts=dropped_parts,
        rendered_control_count=len(controls),
    )
