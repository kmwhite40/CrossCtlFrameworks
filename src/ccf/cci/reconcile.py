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
class RowFinding:
    """One workbook row's CCIs that DISA does not map to its control at all.

    Necessarily per row: a workbook row is keyed per statement-item or ODP
    (``AC-02a.[01]``, ``AC-02(02)_ODP[02]``), so only the row itself can
    assert a CCI DISA has no record of for that control. What a *sibling*
    row of the same control claims is irrelevant here -- that's the
    ``disa_only`` half of :class:`Disagreement`, computed once per control.
    """

    row_identifier: str
    workbook_only: tuple[str, ...]


@dataclass(frozen=True)
class Disagreement:
    """One control's reconciliation result against DISA's Rev. 5 mapping.

    ``disa_only`` is computed ONCE PER CONTROL, against the union of every
    workbook row belonging to that control -- not per row -- because a
    workbook row only carries its own slice of the control's CCIs
    (``AC-02a.[01]`` vs ``AC-02b.``). Comparing one row's slice against the
    whole control's DISA set makes almost every ``disa_only`` entry a
    counting artifact: measured against the real workbook, 95.3% of the
    entries the naive per-row comparison produced were CCIs some *other* row
    of the same control did claim. A CCI is genuinely ``disa_only`` only
    when NO row of the control claims it.

    ``rows`` lists the (possibly empty) set of rows that claim a CCI DISA
    does not map to this control at all -- a genuine per-row finding, since
    silence from a sibling row proves nothing about what THIS row asserts.
    A control with no disagreement at all (empty ``disa_only`` and no rows)
    is never constructed -- see :func:`reconcile_cci`.
    """

    control_identifier: str
    disa_only: tuple[str, ...]
    rows: tuple[RowFinding, ...]


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
    row_identifier: str, workbook: set[str], disa: set[str]
) -> RowFinding | None:
    """A row's own CCIs that DISA does not map to its control -- per row.

    ``disa`` here is the *control's* full DISA set (every rev-5 CCI DISA
    maps to the control this row belongs to), so ``workbook - disa`` is
    exactly the set of CCIs this row asserts that DISA has no record of for
    the control at all -- a real finding regardless of what sibling rows of
    the same control claim.

    This deliberately does NOT compute ``disa - workbook``: a single row is
    only a slice of its control's CCIs, so what DISA has that "this row"
    lacks is meaningless in isolation -- see :func:`reconcile_cci`, which
    computes that half once per control, against the union of all its rows.

    An empty workbook cell is silence, not contradiction: most rows carry no
    CCI, and reporting each as a conflict would bury the real findings.
    """
    if not workbook:
        return None
    only_wb = tuple(sorted(workbook - disa))
    if not only_wb:
        return None
    return RowFinding(row_identifier, only_wb)


async def reconcile_cci(session: AsyncSession) -> list[Disagreement]:
    """Every control whose workbook rows and DISA's Rev. 5 mapping disagree."""
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

    # Group every workbook row under its folded, canonical CONTROL -- not the
    # row's own per-statement-item identifier -- since that's the unit DISA's
    # CciControlRef.canonical_control is recorded against. A row with an
    # empty cell contributes nothing to the union: an empty cell is silence,
    # not an assertion of "no CCIs", so it must neither add to nor subtract
    # from the control's claimed set.
    by_control: dict[str, list[tuple[str, set[str]]]] = {}
    for identifier, value in rows:
        canonical = _fold_to_canonical(str(identifier))
        if canonical is None:
            continue
        workbook = parse_workbook_cci_value(value)
        if not workbook:
            continue
        by_control.setdefault(canonical.value, []).append((str(identifier), workbook))

    # Iterate the UNION of every control the workbook mentions and every
    # control DISA maps -- not `by_control` alone. A control DISA maps that
    # the workbook never mentions at all (no row, or every row's cell empty)
    # never gets a `by_control` key, since that dict is only populated from
    # rows with a non-empty CCI cell; iterating it alone made such a control
    # invisible to the whole report, not merely silent for lack of a
    # contradicting row. `row_values` defaults to `()` for a control with no
    # workbook rows, which keeps the per-row silence rule intact: no row
    # means no RowFinding, only the control-level `disa_only` comparison.
    out: list[Disagreement] = []
    for control in set(by_control) | set(disa):
        row_values = by_control.get(control, [])
        disa_set = disa.get(control, set())
        union_workbook: set[str] = set().union(*(wb for _, wb in row_values))
        disa_only = tuple(sorted(disa_set - union_workbook))
        row_findings = tuple(
            f
            for f in (compare_cci_sets(ident, wb, disa_set) for ident, wb in row_values)
            if f is not None
        )
        if disa_only or row_findings:
            out.append(Disagreement(control, disa_only, row_findings))
    out.sort(key=lambda d: d.control_identifier)
    return out
