"""What moving a system to a higher baseline would require.

The question a customer asks before an uplift -- *"we are Moderate; what would
High require?"* -- had no answer anywhere in the product. ``ssp/seed.py`` seeds
from the system's **own** ``System.baseline``; ``catalog/diff.py`` diffs two
catalog **revisions**; ``packs/service.py`` ``coverage`` compares a system
against a control set the tenant has already **installed**. None of them can
compare a system against a baseline it has *not* adopted.

This module does exactly that and nothing more. It is a read service in the
shape of :mod:`ccf.ssp.completeness_query`: the queries live here, the rule
that turns rows into an answer is a pure function beside them, and no route
grows its own copy of either.

Three things it deliberately does not re-derive (the platform already carries
nine distinct notions of "gap"; this adds a tenth *question*, not a tenth
*vocabulary*):

* identifier normalisation is :func:`ccf.catalog.canonical.canonicalize`;
* "does this system satisfy a control" is
  :data:`ccf.capability.rollup.SATISFIED` -- the same ``{implemented,
  inherited}`` set ``packs/service.py`` uses;
* baseline membership is ``framework_mappings`` rows, not a new table.

It also deliberately does **not** join ``automation.coverage``, which is scoped
to the ~110 CMMC practices of ``profile.derivation`` and answers a different
question over a different universe. Joining the two would give one number two
meanings.

The unit is a canonical control, not a catalog row
--------------------------------------------------
``controls`` holds assessment objectives and ODP placeholders, not only
controls. Measured against the shipped workbook (and reproduced exactly on the
dev catalog)::

    FedRAMP Low       rows=1525   distinct canonical controls=157
    FedRAMP Moderate  rows=2312   distinct canonical controls=323
    FedRAMP High      rows=2673   distinct canonical controls=409

The raw High-minus-Moderate row difference includes ``AU-06(07)#row906`` (a
literal row marker minted by ``etl/pipeline.py``'s duplicate rule),
``SA-11(02)_ODP[03]`` (a parameter placeholder) and ``PS-03b.[01]`` (an
objective decomposition). Counting rows reports a **387**-control uplift where
the truth is **87**. In front of a customer planning an uplift that is not a
near miss; it is a confidently wrong number.

The target does not superset the current baseline
-------------------------------------------------
``CM-2(2)`` is in Moderate and **not** in High, so the result carries
``removed`` as well as ``added``. A ``removed`` entry is an observation about
what the catalog says -- never advice to stop implementing a control.

A system with no baseline is refused
------------------------------------
8 of the dev database's 14 systems have ``baseline = NULL``. A delta from an
unknown current state is not computable, and defaulting to Low would invent a
current state and report an uplift the customer does not owe. Unlike
``ssp/seed.py``, this module does **not** fall back to the FIPS-199 high-water
mark: the per-objective 800-53B columns are a separate, larger question (which
source wins when the two disagree), and answering it inside a first
implementation is exactly the wrong place.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..capability.rollup import SATISFIED
from ..models import Control, ControlImplementation, FrameworkMapping, System
from .canonical import canonicalize

#: ``System.baseline`` level -> the ``framework_mappings.column_key`` that
#: carries its membership marks. The enum on ``System.baseline`` is the source
#: of the three keys; there is no fourth baseline to add here without one.
BASELINE_COLUMN_KEYS: dict[str, str] = {
    "low": "FedRAMP Low",
    "moderate": "FedRAMP Moderate",
    "high": "FedRAMP High",
}

#: ``framework_mappings.value`` for a row that is *in* the baseline. The value
#: is a membership marker and nothing else is encoded in it.
MEMBERSHIP_VALUE = "X"


class BaselineNotSetError(ValueError):
    """Raised when a system has no ``baseline`` to compute a delta from."""


class UnknownBaselineError(ValueError):
    """Raised for a baseline level outside :data:`BASELINE_COLUMN_KEYS`."""


@dataclass(frozen=True)
class BaselineDelta:
    """What the target baseline would require of this system.

    ``already_satisfied + outstanding == added`` is asserted in
    :func:`_assemble` -- the invariant that stops the two lists drifting, in
    the same spirit as ``poam_aging``'s documented
    ``on_track + overdue + no_due_date == open_total``.
    """

    system_id: int
    current: str
    target: str
    added: list[str]
    removed: list[str]
    already_satisfied: list[str]
    outstanding: list[str]
    unmapped: list[str]


def _membership(rows: Iterable[tuple[str, str | None]]) -> tuple[set[str], list[str]]:
    """``(identifier, sequence_control)`` rows -> canonical members + unmapped.

    Pure, so the pinned catalog numbers can be asserted against the shipped
    workbook without a database, and so the DB query and that assertion cannot
    drift apart.

    **Membership** is ``canonicalize(identifier)``. That and only that: a row
    whose identifier canonicalizes is the control it names, and a row whose
    identifier does not is not a control at all.

    **Unmapped** is narrower than "did not canonicalize", and the difference
    matters. 2264 of FedRAMP High's 2673 marked rows do not canonicalize,
    because they are that baseline's own objectives and ODP placeholders --
    ``CM-02(02)[01]``, ``AC-01_ODP[03]``, ``AU-06(07)#row906``. Listing all
    2264 as rows "the platform could not place" would be false: all but nine of
    them decompose a control the platform placed perfectly well, and the count
    would bury the handful that are genuinely unresolved.

    So a non-canonicalizing row is unmapped only when it cannot be attached to
    a member either. The attachment uses ``controls.sequence_control`` -- the
    column the catalog already supplies for this, populated by the ETL from the
    workbook's own ``Sequence Control`` -- run through the *same*
    ``canonicalize``. No second normaliser: where ``sequence_control`` is null
    or is itself not a control id (``AC-06(01).b``), the row stays unmapped and
    is reported, which is the honest answer rather than a guess.

    Measured, this reports 0 unmapped rows for Low, 2 for Moderate and 9 for
    High, and the nine are real signal: ``CM-02(02)``'s four objectives and its
    ODP row are marked in the High column while ``CM-02(02)`` itself is not --
    which is the evidence behind §4's anomaly, and precisely what an operator
    planning an uplift needs to see rather than have silently averaged away.
    """
    materialized = list(rows)
    members: set[str] = set()
    rest: list[tuple[str, str | None]] = []
    for identifier, sequence_control in materialized:
        canonical = canonicalize(identifier)
        if canonical is None:
            rest.append((identifier, sequence_control))
        else:
            members.add(canonical.value)

    unmapped: list[str] = []
    for identifier, sequence_control in rest:
        parent = canonicalize(sequence_control)
        if parent is None or parent.value not in members:
            unmapped.append(identifier)
    return members, sorted(set(unmapped))


def _column_key(level: str) -> str:
    try:
        return BASELINE_COLUMN_KEYS[level]
    except KeyError:
        known = ", ".join(sorted(BASELINE_COLUMN_KEYS))
        raise UnknownBaselineError(
            f"unknown baseline {level!r} — expected one of: {known}"
        ) from None


async def baseline_rows(session: AsyncSession, level: str) -> Sequence[tuple[str, str | None]]:
    """Every ``controls`` row marked as belonging to ``level``'s baseline."""
    result = await session.execute(
        select(Control.identifier, Control.sequence_control)
        .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
        .where(
            FrameworkMapping.column_key == _column_key(level),
            FrameworkMapping.value == MEMBERSHIP_VALUE,
        )
    )
    return [(str(identifier), sequence) for identifier, sequence in result.all()]


async def baseline_members(session: AsyncSession, level: str) -> set[str]:
    """The distinct canonical controls in ``level``'s baseline."""
    members, _ = _membership(await baseline_rows(session, level))
    return members


def _assemble(
    *,
    system_id: int,
    current: str,
    target: str,
    current_members: set[str],
    target_members: set[str],
    target_unmapped: list[str],
    satisfied: set[str],
) -> BaselineDelta:
    added = sorted(target_members - current_members)
    removed = sorted(current_members - target_members)
    already_satisfied = [c for c in added if c in satisfied]
    outstanding = [c for c in added if c not in satisfied]
    # The invariant, asserted rather than assumed: the two halves of `added`
    # are built by one pass over one list, and this is what keeps a later edit
    # from making them two independent derivations that quietly disagree.
    #
    # An explicit raise, not a bare `assert`: `python -O` strips assert
    # statements, and an invariant that guards a number a customer plans an
    # uplift against must not be one that silently stops holding in the
    # deployment configuration nobody re-checks.
    if sorted(already_satisfied + outstanding) != added:
        raise AssertionError(
            "baseline delta invariant violated: already_satisfied + outstanding != added "
            f"({len(already_satisfied)} + {len(outstanding)} vs {len(added)})"
        )
    return BaselineDelta(
        system_id=system_id,
        current=current,
        target=target,
        added=added,
        removed=removed,
        already_satisfied=already_satisfied,
        outstanding=outstanding,
        unmapped=target_unmapped,
    )


async def _satisfied_controls(session: AsyncSession, system_id: int) -> set[str]:
    """Canonical controls this system implements or inherits.

    Scoped by ``system_id``, which is what confines the answer to one tenant:
    a ``ControlImplementation`` belongs to exactly one ``System`` and a
    ``System`` to exactly one organization, so no row of another tenant's can
    reach this set. The caller is responsible for having established that
    ``system_id`` is in the principal's organization (the route does so via
    ``require_system_in_scope``); this function does no tenancy check of its
    own, the same contract ``ssp/completeness_query.project_completeness``
    documents.
    """
    rows = (
        await session.execute(
            select(Control.identifier, ControlImplementation.status)
            .join(ControlImplementation, ControlImplementation.control_id == Control.id)
            .where(ControlImplementation.system_id == system_id)
        )
    ).all()
    satisfied: set[str] = set()
    for identifier, status in rows:
        if status not in SATISFIED:
            continue
        canonical = canonicalize(str(identifier))
        if canonical is not None:
            satisfied.add(canonical.value)
    return satisfied


async def baseline_delta(session: AsyncSession, *, system_id: int, target: str) -> BaselineDelta:
    """Compare ``system_id``'s current baseline against ``target``.

    Raises :class:`BaselineNotSetError` when the system has no baseline -- see the
    module docstring on why that is refused rather than defaulted, and
    :class:`UnknownBaselineError` for a target outside the three FedRAMP levels.
    """
    system = (
        await session.execute(select(System).where(System.id == system_id))
    ).scalar_one_or_none()
    if system is None:
        raise ValueError(f"system {system_id} not found")
    current = system.baseline
    if not current:
        raise BaselineNotSetError(
            f"system {system_id} has no baseline — a delta from an unknown "
            "current baseline is not computable, and defaulting to Low would "
            "report an uplift the system does not owe"
        )
    _column_key(target)  # reject an unknown target before doing any work

    current_members, _ = _membership(await baseline_rows(session, current))
    target_members, target_unmapped = _membership(await baseline_rows(session, target))
    return _assemble(
        system_id=system_id,
        current=current,
        target=target,
        current_members=current_members,
        target_members=target_members,
        target_unmapped=target_unmapped,
        satisfied=await _satisfied_controls(session, system_id),
    )
