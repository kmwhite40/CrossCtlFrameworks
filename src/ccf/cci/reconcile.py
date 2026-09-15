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

from ..catalog.canonical import canonicalize
from ..models import Control, Framework, FrameworkMapping
from ..models_cci import CciControlRef, CciItemRow

#: The workbook column carrying Rev. 5 CCIs; '*' means "automatically
#: compliant" and is a workbook annotation, not part of the identifier.
WORKBOOK_COLUMN = 'CCI Rev 5 ("*" are automatically compliant)'
_CCI = re.compile(r"CCI-\d{6}")


@dataclass(frozen=True)
class Disagreement:
    control_identifier: str
    workbook_only: tuple[str, ...]
    disa_only: tuple[str, ...]


def parse_workbook_cci_value(value: str | None) -> set[str]:
    if not value or not value.strip():
        return set()
    return set(_CCI.findall(value))


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

    rows = (
        await session.execute(
            select(Control.identifier, FrameworkMapping.value)
            .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
            .join(Framework, FrameworkMapping.framework_id == Framework.id)
            .where(FrameworkMapping.column_key == WORKBOOK_COLUMN)
        )
    ).all()

    out: list[Disagreement] = []
    for identifier, value in rows:
        canonical = canonicalize(str(identifier).split("_")[0].rstrip("."))
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
