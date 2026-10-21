"""The compliance obligations register, and the catalog check its controls pass.

An obligation is something the organization must do, with where the duty
comes from (``source``), the citation, an owner and a due date. The controls
that satisfy it are catalog identifiers, and an identifier is accepted only
if the catalog has it: a mapping to a control that does not exist reads as
coverage nobody has. Identifiers are matched case-insensitively and stored
in the catalog's own spelling.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Control

SOURCES: tuple[str, ...] = ("statute", "regulation", "contract", "framework", "policy")
STATUSES: tuple[str, ...] = ("open", "met", "not_met", "not_applicable")
#: Statuses that still owe something; only these can be overdue.
OPEN_STATUSES: tuple[str, ...] = ("open", "not_met")

_SPLIT = re.compile(r"[\s,;]+")
MAX_CONTROL_IDS = 50


def parse_control_ids(raw: str | None) -> list[str]:
    """Comma-, semicolon- or whitespace-separated identifiers, de-duplicated
    in order of first appearance (case-insensitively)."""
    out: list[str] = []
    seen: set[str] = set()
    for raw_tok in _SPLIT.split(raw or ""):
        tok = raw_tok.strip()
        if tok and tok.upper() not in seen:
            seen.add(tok.upper())
            out.append(tok)
    return out


async def resolve_control_ids(session: AsyncSession, ids: list[str]) -> tuple[list[str], list[str]]:
    """``(canonical identifiers, unknown identifiers)`` for ``ids``.

    The catalog is global reference data, so there is no tenant predicate
    here; the caller refuses the write when ``unknown`` is not empty."""
    if not ids:
        return [], []
    rows = (
        (
            await session.execute(
                select(Control.identifier).where(
                    func.upper(Control.identifier).in_([i.upper() for i in ids])
                )
            )
        )
        .scalars()
        .all()
    )
    by_upper: dict[str, str] = {}
    for ident in rows:
        by_upper.setdefault(ident.upper(), ident)
    known = [by_upper[i.upper()] for i in ids if i.upper() in by_upper]
    unknown = [i for i in ids if i.upper() not in by_upper]
    return known, unknown


async def resolve_control_id(session: AsyncSession, raw: str | None) -> tuple[str | None, bool]:
    """One identifier: ``(canonical or None, ok)``. Empty input is ``(None, True)``."""
    ids = parse_control_ids(raw)
    if not ids:
        return None, True
    if len(ids) > 1:
        return None, False
    known, _ = await resolve_control_ids(session, ids)
    return (known[0], True) if known else (None, False)


def summarize(rows: list[Any], today: Any) -> dict[str, int]:
    """Counts for the register's header. ``overdue`` is an open obligation
    past its due date; every row is in exactly one status bucket."""
    out = {s: 0 for s in STATUSES}
    overdue = 0
    for r in rows:
        out[r.status] = out.get(r.status, 0) + 1
        if r.status in OPEN_STATUSES and r.due_on is not None and r.due_on < today:
            overdue += 1
    out["overdue"] = overdue
    out["total"] = len(rows)
    return out
