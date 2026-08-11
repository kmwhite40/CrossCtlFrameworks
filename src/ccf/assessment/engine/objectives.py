"""Read a control's assessment objectives from the catalog Concord already ingests.

The 800-53A objectives are not a separate dataset. They are sub-clause rows in
``ccf.controls``: ``control_name IS NULL``, ``assessment_objective`` carrying the
objective text, grouped by ``sequence_control``. They are the same rows the
preparation pipeline's screen stage deliberately excludes, because they are not
controls anyone can cite -- which is exactly what makes them objectives.

Nothing is materialised. A proposal stores a label and a SHA-256 of the objective
text, so a catalog re-ingest that rewords an objective makes a stored verdict
detectable as stale rather than silently wrong.
"""

from __future__ import annotations

import hashlib
import string
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import get_settings
from ...models import Control
from ...prep.screen import normalize_control_identifier


class ObjectiveExtractionError(RuntimeError):
    """The catalog rows for a control are not a plausible objective set."""


@dataclass(slots=True)
class Objective:
    """One assessment objective, as read from the catalog."""

    label: str
    text: str
    text_sha256: str
    sort_order: int


def objective_sha256(text: str) -> str:
    """Hash an objective's text so a later reword is detectable."""
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


def _ordinal_label(control_identifier: str, index: int) -> str:
    """Derive ``AC-02a``-style labels when ``ap_acronym`` is absent.

    ``ap_acronym`` is populated on the first sub-clause row and sparse thereafter
    in the real workbook, so most objectives need a derived label. Past 26 the
    suffix doubles (``aa``, ``ab``) rather than wrapping, so labels stay unique.
    """
    letters = string.ascii_lowercase
    if index < len(letters):
        suffix = letters[index]
    else:
        suffix = letters[index // len(letters) - 1] + letters[index % len(letters)]
    return f"{control_identifier}{suffix}"


async def objectives_for(session: AsyncSession, control_identifier: str) -> list[Objective]:
    """Return a control's assessment objectives in catalog order."""
    canonical = normalize_control_identifier(control_identifier)
    rows = (
        await session.execute(
            select(Control)
            .where(
                Control.control_name.is_(None),
                Control.assessment_objective.is_not(None),
            )
            .order_by(Control.source_row, Control.id)
        )
    ).scalars().all()

    # sequence_control is folded and compared in Python, not SQL, because the
    # catalog's stored forms are inconsistent (AC-02 vs CP-9 vs AC.L2-3.1.1) and
    # no SQL predicate folds them the way normalize_control_identifier does. Do
    # not hand-roll this folding in SQL -- that would drift from screen.py.
    matching = [
        r for r in rows if normalize_control_identifier(r.sequence_control or "") == canonical
    ]

    limit = get_settings().assessment_engine_max_objectives_per_control
    if len(matching) > limit:
        raise ObjectiveExtractionError(
            f"control {control_identifier} yielded {len(matching)} objectives, "
            f"above the {limit} guard -- extraction almost certainly grouped wrongly"
        )

    objectives: list[Objective] = []
    for index, row in enumerate(matching):
        text = (row.assessment_objective or "").strip()
        if not text:
            continue
        label = row.ap_acronym or _ordinal_label(control_identifier, index)
        objectives.append(
            Objective(
                label=label,
                text=text,
                text_sha256=objective_sha256(text),
                sort_order=index,
            )
        )
    return objectives
