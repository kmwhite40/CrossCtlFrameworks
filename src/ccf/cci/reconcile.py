"""Compare the workbook's CCI columns against DISA's references.

Advisory only, following :mod:`ccf.catalog.reconcile`. The workbook keeps
loading its CCI columns untouched -- the header classifier is deliberately
generic, and special-casing one column would make ``mapping_history``
snapshots differ for reasons unrelated to the workbook. Disagreement is a
finding *about the workbook*, which is useful on its own.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.canonical import CanonicalId, canonicalize
from ..models import Control, FrameworkMapping
from ..models_cci import CciControlRef, CciItemRow

#: The workbook column carrying Rev. 5 CCIs; '*' means "automatically
#: compliant" and is a workbook annotation, not part of the identifier.
WORKBOOK_COLUMN = 'CCI Rev 5 ("*" are automatically compliant)'
_CCI = re.compile(r"CCI-\d{6}")

#: A control id followed by zero or more NUMERIC enhancement groups --
#: "AC-2", "AC-2(1)", "AC-2(1)(2)". Anchored at the start only: matching stops
#: at the first thing that isn't a numeric "(NN)" group, which is exactly
#: where a statement-item suffix ("a.", "b.01", "(a)", "_ODP[01]") begins.
#: Those suffixes name a *part* of the control, not a different control, and
#: DISA's CciControlRef.canonical_control is recorded per control -- not per
#: part -- so folding them away (rather than rejecting the whole identifier,
#: as bare canonicalize() would) is what lets the fold cover the row instead
#: of skipping it.
_CONTROL_PREFIX = re.compile(r"^\s*([A-Za-z]{2}-\d{1,3}(?:\s*\(\s*\d{1,3}\s*\))*)")


@dataclass(frozen=True)
class Disagreement:
    control_identifier: str
    workbook_only: tuple[str, ...]
    disa_only: tuple[str, ...]


def parse_workbook_cci_value(value: str | None) -> set[str]:
    if not value or not value.strip():
        return set()
    return set(_CCI.findall(value))


def _fold_to_canonical(identifier: str) -> CanonicalId | None:
    """Fold a workbook row identifier down to its control's canonical id.

    A workbook row is keyed per *statement part* or *ODP*, e.g.
    ``"AC-01a.[01]"`` or ``"AC-02(02)_ODP[02]"``, not per control -- but
    DISA's ``CciControlRef.canonical_control`` is recorded per control. The
    naive approach of handing the whole identifier to ``canonicalize()``
    rejects every row that carries a statement-item suffix (``a.``, ``b.01``,
    ``(a)``, ``_ODP[nn]``), since ``canonicalize()`` requires a full match and
    those suffixes aren't part of an 800-53 control id. Measured against the
    real workbook, that naive fold silently ``continue``d on 1,519 of 3,154
    CCI-bearing rows (48.2%) -- the reconciliation surface it reported was
    real but roughly half the true one.

    The fix keeps NUMERIC parenthesised groups (enhancements -- part of the
    control identity) and drops everything from the first non-numeric-group
    character onward (statement items -- part of the control's *text*, not
    its identity). ``AC-2(1)`` and ``AC-2(3)(a)`` are different controls from
    ``AC-2``; ``AC-2a.`` and ``AC-2(3)(a)`` are the same control as ``AC-2``
    and ``AC-2(3)`` respectively. Folding an enhancement away (rather than
    skipping the row) would be the worse failure: it would compare a row
    against the wrong control's CCI set instead of just missing it.

    A handful of DoD identifiers (``DS-IA-13[04]``, etc.) still return
    ``None`` after this fix -- their family prefix is five letters, and
    ``canonicalize()`` is deliberately two-letter-only. That residue (14 of
    3,154 rows, 0.4%) is a correct rejection, not a lossy one: these are not
    800-53 control ids and nothing should ever match them.
    """
    head = identifier.split("_", maxsplit=1)[0]  # drop a trailing "_ODP[nn]" first
    m = _CONTROL_PREFIX.match(head)
    return canonicalize(m.group(1)) if m else None


def compare_cci_sets(
    control_identifier: str, workbook: set[str], disa: set[str]
) -> Disagreement | None:
    """None when they agree, or when the workbook says nothing.

    An empty workbook cell is silence, not contradiction: most rows carry no
    CCI, and reporting each as a conflict would bury the real findings.
    """
    if not workbook:
        return None
    only_wb = tuple(sorted(workbook - disa))
    only_disa = tuple(sorted(disa - workbook))
    if not only_wb and not only_disa:
        return None
    return Disagreement(control_identifier, only_wb, only_disa)


async def reconcile_cci(session: AsyncSession) -> list[Disagreement]:
    """Every control row whose workbook CCI set differs from DISA's."""
    disa: dict[str, set[str]] = {}
    for control, cci in (
        await session.execute(
            select(CciControlRef.canonical_control, CciItemRow.cci)
            .join(CciItemRow, CciControlRef.cci_id == CciItemRow.id)
            .where(CciControlRef.revision == "5", CciControlRef.canonical_control.is_not(None))
        )
    ).all():
        disa.setdefault(str(control), set()).add(cci)

    # No join to Framework: FrameworkMapping.framework_id is nullable
    # (SET NULL on delete), and an INNER JOIN there would silently drop any
    # mapping whose framework row was deleted -- the same class of silent
    # loss as the identifier fold above. column_key alone identifies the
    # workbook's CCI column.
    rows = (
        await session.execute(
            select(Control.identifier, FrameworkMapping.value)
            .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
            .where(FrameworkMapping.column_key == WORKBOOK_COLUMN)
        )
    ).all()

    out: list[Disagreement] = []
    for identifier, value in rows:
        canonical = _fold_to_canonical(str(identifier))
        if canonical is None:
            continue
        d = compare_cci_sets(
            str(identifier),
            parse_workbook_cci_value(value),
            disa.get(canonical.value, set()),
        )
        if d is not None:
            out.append(d)
    return out
