"""Fold stub control rows back onto the catalog control they duplicate.

The catalog pads single-digit control numbers: ``IA-02``, ``SC-08``, ``AU-06``.
A caller that spells the same control ``IA-2`` finds nothing -- ``identifier``
is compared as an exact string -- and any code that creates the control when the
lookup misses ends up adding a second row for a control the catalog already has.

The deployed database carried three of these (``IA-2``, ``SC-8``, ``AU-6``): no
family, no description, no ``source_row``, and three of the four control
implementations pointed at *them* rather than at the catalog. Nothing in the
repository creates such a row today, so this is debt rather than a live bug --
but it is invisible debt. The duplicates satisfy the UNIQUE constraint on
``identifier``, so nothing complains, and coverage reporting counts the stub as
an unmapped control while the real one looks untouched.

This module finds those pairs and merges them: references move to the catalog
row, then the stub is deleted.

Two rules keep it conservative.

*Only a stub may be merged away.* A stub is a row with no ``source_row`` -- it
never came from the workbook. Two rows that both came from the workbook are two
real controls, whatever their identifiers look like.

*Padding is the only difference that folds.* ``AC-02`` and ``AC-2`` are one
control; ``AC-2`` and ``AC-2(1)`` are not. ``prep.screen.normalize_control_identifier``
would fold the enhancement suffix too, which is right for search and wrong here,
so this module keeps its own stricter key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import POAM, Base, Control, ControlImplementation, FrameworkMapping, Risk

#: ``LETTERS-DIGITS`` with anything after it kept intact, so an enhancement
#: suffix stays part of the identity. Deliberately narrower than
#: ``prep.screen._PADDED_FAMILY_PATTERN``, which anchors at the end.
_PAD_RE = re.compile(r"^([A-Za-z]{2,3})-0*(\d+)(.*)$")

#: Tables holding a reference that must be moved before a stub can be deleted.
#: ``(model, attribute, conflicts_with)`` -- the third element names the column
#: that, together with ``control_id``, must stay unique. None means no constraint.
_REFERENCES: tuple[tuple[type[Base], str, str | None], ...] = (
    (ControlImplementation, "control_id", "system_id"),
    (FrameworkMapping, "control_id", None),
    (POAM, "control_id", None),
    (Risk, "control_id", None),
)


def identity_key(identifier: str) -> str:
    """Fold only zero-padding, so ``IA-02`` and ``IA-2`` share a key.

    ``AC-2`` and ``AC-2(1)`` do not, and a CMMC-style ``AC.L2-3.1.1`` does not
    match the pattern at all and is returned upper-cased and otherwise intact.
    """
    text = identifier.strip()
    match = _PAD_RE.match(text)
    if match is None:
        return text.upper()
    family, number, rest = match.groups()
    return f"{family.upper()}-{int(number)}{rest.upper()}"


@dataclass
class Merge:
    """One stub and the catalog control it duplicates."""

    stub_id: int
    stub_identifier: str
    canonical_id: int
    canonical_identifier: str
    #: ``table -> row count`` that would be repointed.
    references: dict[str, int] = field(default_factory=dict)
    #: Why this merge cannot be applied, if it cannot.
    blocked: str | None = None

    @property
    def moves(self) -> int:
        return sum(self.references.values())


@dataclass
class DedupePlan:
    merges: list[Merge] = field(default_factory=list)

    @property
    def applicable(self) -> list[Merge]:
        return [m for m in self.merges if m.blocked is None]

    @property
    def blocked(self) -> list[Merge]:
        return [m for m in self.merges if m.blocked is not None]


async def plan_dedupe(session: AsyncSession) -> DedupePlan:
    """Find stub controls that duplicate a catalog control, and say what blocks each."""
    controls = (await session.execute(select(Control))).scalars().all()

    canonical: dict[str, Control] = {}
    for control in controls:
        if control.source_row is not None:
            canonical.setdefault(identity_key(control.identifier), control)

    plan = DedupePlan()
    for control in controls:
        if control.source_row is not None:
            continue
        target = canonical.get(identity_key(control.identifier))
        if target is None or target.id == control.id:
            continue

        merge = Merge(
            stub_id=control.id,
            stub_identifier=control.identifier,
            canonical_id=target.id,
            canonical_identifier=target.identifier,
        )
        for model, attr, unique_with in _REFERENCES:
            column = getattr(model, attr)
            rows = (
                await session.execute(select(model).where(column == control.id))
            ).scalars().all()
            if rows:
                merge.references[model.__tablename__] = len(rows)
            if unique_with is None:
                continue
            # Moving these would collide with a row the canonical control
            # already has. Merging would mean discarding one of them, which is
            # a judgement call about live data, not a mechanical fix.
            partner = getattr(model, unique_with)
            existing = {
                getattr(r, unique_with)
                for r in (
                    await session.execute(select(model).where(column == target.id))
                ).scalars()
            }
            clashes = sorted(
                {getattr(r, unique_with) for r in rows} & existing
            )
            if clashes:
                merge.blocked = (
                    f"{model.__tablename__} already has a row for "
                    f"{partner.key} {clashes} on the catalog control"
                )
        plan.merges.append(merge)
    return plan


async def apply_dedupe(session: AsyncSession) -> DedupePlan:
    """Repoint references onto the catalog control, then delete the stub.

    Blocked merges are left completely alone. The caller owns the transaction.
    """
    plan = await plan_dedupe(session)
    for merge in plan.applicable:
        for model, attr, _ in _REFERENCES:
            column = getattr(model, attr)
            await session.execute(
                update(model).where(column == merge.stub_id).values(**{attr: merge.canonical_id})
            )
        stub = await session.get(Control, merge.stub_id)
        if stub is not None:
            await session.delete(stub)
    await session.flush()
    return plan
