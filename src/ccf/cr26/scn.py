"""Seed a FedRAMP Significant Change Notification from continuity, not from
platform data.

See docs/superpowers/specs/2026-09-19-cr26-scn-design.md. Concord holds no
record of a provider's significant changes, so this deliverable takes the
OCR/Incident shape (spec §2): seed the scaffold, carry what was authored,
omit what was not, and let the document stay invalid until it is true.

**The SCN has no identity field at all (spec §1).** Root ``required`` is
``certificationPackageOverviewUri``, ``changeType``, ``changeDescription`` --
no tracking id, no change id, no date. Unlike the Incident Report, where
``document_key`` is DERIVED from ``providerTrackingId``, the SCN's
``document_key`` is simply the caller's own ``change_ref``, used verbatim.
There is no second component to compose and therefore no separator and no
``/`` rule -- :func:`_validate_change_ref` checks only what
:func:`ccf.cr26.incident._validate_tracking_id` checks minus that rule: non-
blank after stripping, bounded by
:data:`ccf.models_cr26.DOCUMENT_KEY_MAX_LENGTH` (imported, never restated).

**No cross-key continuity.** The Incident Report's three reports of ONE
incident share a tracking id and carry facts forward across
Initial -> Ongoing -> Final. An SCN has no such lifecycle: each
``change_ref`` is one provider-filed notification of one change, standing
alone. So there is no ``_prior_report`` walk here and no
``carried_from``/``carried_fields`` in the result -- "carried" here means
only "read back from THIS exact key's own previously stored content", the
same as re-seeding the same ``(providerTrackingId, reportType)`` amends an
Incident Report in place.

**``impactedControls`` is checked, named, and never refused (spec §2.1).**
This is the first field in this programme the platform can check against its
own catalog -- ``Control.identifier`` and ``KSI.identifier`` are both held
here. Each entry is resolved in this exact order, because getting it wrong
in either direction is a real trap:

1. Blank after stripping -> ``"identifies nothing"``.
2. :func:`ccf.catalog.canonical.canonicalize` yields a ``CanonicalId`` ->
   look it up in the control catalog. Found -> recognised (nothing added).
   Not found -> ``"no such control"``.
3. Otherwise -> look the RAW value up in the KSI catalog by ``identifier``.
   Found -> recognised. Not found -> ``"not a known control or KSI"``.

``canonicalize`` handles control ids only -- measured,
``canonicalize('KSI-IAM-01')`` returns ``None``, exactly like an unrecognised
string. Resolving through ``canonicalize`` alone would therefore report
EVERY KSI as unrecognised, and the field is documented as holding "KSI OR
control identifiers" -- a list that cries wolf on half its legitimate input
trains an operator to ignore it. Step 3 is what actually catches a genuine
KSI, and also catches anything ``canonicalize`` cannot parse (a framework
Concord has not ingested), which is the same bucket for a reason: Concord
cannot tell a KSI it does not hold from an identifier it has never seen.

Unrecognised is advisory, never a refusal: the document keeps every entry of
``impactedControls`` verbatim regardless of what this module makes of it.
FedRAMP's own identifiers or a framework not yet ingested are legitimate and
simply unknown to Concord -- refusing the filing over that would be wrong.

**``changeDescription`` is required, and a blank one validates (spec §3.2).**
Measured: ``{"changeType": "Adaptive", "changeDescription": ""}`` satisfies
the schema (no ``minLength``). The seeder never writes ``changeDescription``
itself -- a blank-after-stripping or absent stored value is treated as
OMITTED, not written blank, so the document stays invalid and the gap is
named rather than an operator being told a filing is complete when nothing
was actually said.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.canonical import canonicalize
from ..models import KSI, Control
from ..models_cr26 import DOCUMENT_KEY_MAX_LENGTH, Cr26Document
from .store import put_document
from .ver import is_blank

#: Every optional field that is authored in practice and carried forward
#: verbatim from the stored document at this exact key when this seed call
#: does not have fresher content of its own -- in the exact order spec §3.3's
#: table lists them. ``certificationPackageOverviewUri`` and
#: ``changeDescription`` are handled separately (spec §3.1, §3.2): both are
#: distinct from this list because an absent one BLOCKS validity, whereas
#: every field here is merely advisory when absent. ``changeType`` is
#: handled separately too -- it comes only from the caller, never carried.
#:
#: ``planAndTimeline`` needs no special-casing to carry "whole or not at
#: all" (spec §3.3): every field here is copied as a single value, never
#: merged key-by-key, so a half-authored ``planAndTimeline`` on a prior seed
#: is exactly what a later seed call preserves -- never topped up field by
#: field from nowhere, since there is no second source to top it up from.
_AUTHORED_FIELDS: tuple[str, ...] = (
    "assessorName",
    "relatedVulnerability",
    "changeTypeExplanation",
    "reason",
    "customerImpact",
    "planAndTimeline",
    "impactedControls",
    "impactAnalysis",
)


def _validate_change_ref(change_ref: str) -> str:
    """Refuse what cannot identify or safely key an SCN (spec §1).

    Mirrors :func:`ccf.cr26.incident._validate_tracking_id` minus the ``/``
    rule: ``change_ref`` IS ``document_key``, used verbatim, with no second
    component to compose -- so there is no separator whose ambiguity a
    ``/`` could create. Two checks only: non-blank after stripping (an
    unidentifiable notification cannot be filed at all), and bounded by
    :data:`ccf.models_cr26.DOCUMENT_KEY_MAX_LENGTH` -- read from the
    column's own declared type, not a second hardcoded number, for the same
    reason the incident module gives: an off-by-one here would otherwise
    reach Postgres as a raw ``StringDataRightTruncationError``, a 500.

    Leading/trailing whitespace is stripped before either check and before
    the key is used: ``"  CHG-1 "`` and ``"CHG-1"`` must resolve to the SAME
    ``document_key``, or the same change could split across two rows under
    two different keys produced only by whitespace.
    """
    stripped = change_ref.strip()
    if not stripped:
        raise ValueError("change_ref must not be blank")
    if len(stripped) > DOCUMENT_KEY_MAX_LENGTH:
        raise ValueError(
            f"change_ref is too long: {len(stripped)} characters, and "
            f"document_key is limited to {DOCUMENT_KEY_MAX_LENGTH}"
        )
    return stripped


async def _current_document(
    session: AsyncSession, system_id: int, document_key: str
) -> dict[str, Any]:
    """The document already stored at exactly ``(system_id, "scn",
    document_key)``, or ``{}`` if this SCN has never been seeded before.

    There is no "exists but empty" distinction to preserve here the way
    :mod:`ccf.cr26.incident`'s identically-shaped helper needs one: an SCN
    has no lifecycle walk that must tell "the closest prior report was
    filed but sparse" apart from "nothing has been filed yet" -- there is no
    prior report at all, only this exact key's own history.
    """
    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id,
                Cr26Document.kind == "scn",
                Cr26Document.document_key == document_key,
            )
        )
    ).scalars().first()
    if row is None or not row.document:
        return {}
    return dict(row.document)


async def _resolve_impacted_controls(
    session: AsyncSession, entries: Any
) -> list[tuple[str, str]]:
    """Name every ``impactedControls`` entry this catalog does not
    recognise, in the resolution order spec §2.1 fixes exactly (see the
    module docstring for why the order matters). Never refuses: this only
    NAMES what it could not resolve -- the caller is responsible for keeping
    every entry in the stored document verbatim regardless of this
    function's verdict, which :func:`seed_scn` does by building ``document``
    from ``current`` before this function ever runs.

    ``entries`` is untyped ``Any`` rather than ``list[str]`` because it is
    read back from JSONB that the schema constrains but this module does
    not re-validate before reading -- a document written by hand through the
    generic PUT route could hold something other than a list. Anything that
    is not a ``list`` is treated as naming nothing to resolve, matching this
    module's posture everywhere else of never raising over shape the
    vendored schema itself is the authority on.
    """
    if not isinstance(entries, list):
        return []
    unrecognised: list[tuple[str, str]] = []
    for entry in entries:
        if is_blank(entry):
            raw = entry if isinstance(entry, str) else str(entry)
            unrecognised.append((raw, "identifies nothing"))
            continue
        # `is_blank` above already guarantees `entry` is a non-blank `str`
        # at this point (see its own docstring: non-strings are blank).
        canonical = canonicalize(entry)
        if canonical is not None:
            found_control = (
                await session.execute(
                    select(Control.id).where(Control.identifier == canonical.value)
                )
            ).scalar_one_or_none()
            if found_control is None:
                unrecognised.append((entry, "no such control"))
            continue
        found_ksi = (
            await session.execute(select(KSI.id).where(KSI.identifier == entry))
        ).scalar_one_or_none()
        if found_ksi is None:
            unrecognised.append((entry, "not a known control or KSI"))
    return unrecognised


@dataclass(frozen=True)
class ScnSeedResult:
    """What one seed produced and what a human still owes (spec §4).

    ``missing_required`` and ``missing_advisory`` are deliberately separate
    (spec §5): collapsing them would tell an operator that a missing
    ``impactAnalysis`` blocks filing when it does not, or that a missing
    ``changeDescription`` is merely advisory when it is one of the two
    things that make the document invalid. ``missing_required`` pairs a
    field with why it is still owed; ``missing_advisory`` is bare names.

    ``unrecognised_controls`` is a THIRD list, separate from both (spec §4):
    it describes something the operator *did* write -- an
    ``impactedControls`` entry this catalog does not recognise -- rather
    than something they did not write at all. Folding it into
    ``missing_advisory`` would tell an operator a field is missing when its
    content is merely unfamiliar to Concord.
    """

    document: Cr26Document
    document_key: str
    missing_required: list[tuple[str, str]]
    missing_advisory: list[str]
    unrecognised_controls: list[tuple[str, str]]


async def seed_scn(
    session: AsyncSession,
    *,
    system_id: int,
    change_ref: str,
    change_type: str,
) -> ScnSeedResult:
    """Seed (or amend) one Significant Change Notification.

    ``change_type`` is not validated against the schema's ``enum`` here --
    it is written to the document exactly as given and the vendored
    schema's own ``enum`` refuses an unrecognised value (measured:
    ``"adaptive"`` fails), matching this programme's posture everywhere
    else of leaving shape the schema is the authority on to the schema. The
    route narrows this further with its own request model.

    Re-seeding the same ``change_ref`` is how a filed SCN is amended: it
    reads whatever is already stored at that exact key as "authored" and
    keeps every field of it, refreshing only ``changeType`` from this call's
    own argument. There is no content parameter here at all -- every other
    field this function can populate comes from what was already stored at
    this key.
    """
    document_key = _validate_change_ref(change_ref)
    current = await _current_document(session, system_id, document_key)

    document: dict[str, Any] = {"changeType": change_type}

    # certificationPackageOverviewUri (spec §3.1): carried from the stored
    # document at this exact key only, never invented. `is_blank`, not
    # `is not None` -- matching every other CR26 seeder's identical
    # carry-the-URI logic (`ccf.cr26.ocr._carry_uri`, `ccf.cr26.ver._carry_
    # uri`, `ccf.cr26.incident.seed_incident`), because the UI persists a
    # cleared field as `""`, not `null`.
    uri = current.get("certificationPackageOverviewUri")
    if not is_blank(uri):
        document["certificationPackageOverviewUri"] = str(uri).strip()

    # changeDescription (spec §3.2): the seeder never writes it -- see the
    # module docstring. A blank-after-stripping or absent stored value is
    # OMITTED, not written blank, even though a blank string would itself
    # satisfy the schema.
    description = current.get("changeDescription")
    if not is_blank(description):
        document["changeDescription"] = description

    # The eight authored-in-practice optional fields (spec §3.3): preserved
    # verbatim when stored at this key already; otherwise absent and named
    # as advisory. No continuity source to fall back to -- see the module
    # docstring on why there is no cross-key carry here.
    missing_advisory: list[str] = []
    for field_name in _AUTHORED_FIELDS:
        if field_name in current:
            document[field_name] = current[field_name]
        else:
            missing_advisory.append(field_name)

    missing_required: list[tuple[str, str]] = []
    if "certificationPackageOverviewUri" not in document:
        missing_required.append(
            (
                "certificationPackageOverviewUri",
                "no authored certificationPackageOverviewUri on this document "
                "-- never invented",
            )
        )
    if "changeDescription" not in document:
        missing_required.append(
            (
                "changeDescription",
                "no authored changeDescription -- required, and the seeder "
                "never invents or writes one",
            )
        )

    unrecognised_controls = await _resolve_impacted_controls(
        session, document.get("impactedControls")
    )

    row = await put_document(
        session,
        system_id=system_id,
        kind="scn",
        document=document,
        document_key=document_key,
    )
    return ScnSeedResult(
        document=row,
        document_key=document_key,
        missing_required=missing_required,
        missing_advisory=missing_advisory,
        unrecognised_controls=unrecognised_controls,
    )
