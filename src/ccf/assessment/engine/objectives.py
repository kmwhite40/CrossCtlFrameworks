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


def _ordinal_label(sequence_control: str, index: int) -> str:
    """Derive ``AC-02a``-style labels when ``ap_acronym`` is absent.

    ``ap_acronym`` is populated on the first sub-clause row and sparse thereafter
    in the real workbook, so most objectives need a derived label. Past 26 the
    suffix doubles (``aa``, ``ab``) rather than wrapping, so labels stay unique.

    ``sequence_control`` must be the matched row's own stored value, not the
    caller's query spelling and not the ``normalize_control_identifier``-folded
    form. It is identical for every row in a group regardless of how the caller
    spelled the query (``AC-02`` vs ``AC-2``), and it is the same source
    ``ap_acronym`` is drawn from -- so a derived label and a catalog-supplied
    ``ap_acronym`` in the same group always agree on their prefix. Building the
    suffix from the caller's argument instead produced mixed sets silently: the
    same control queried as ``AC-2`` (the canonical form
    ``AssessmentControlProposal.control_identifier`` documents) would derive
    ``AC-2b`` next to a catalog-supplied ``AC-02a``.
    """
    letters = string.ascii_lowercase
    if index < len(letters):
        suffix = letters[index]
    else:
        suffix = letters[index // len(letters) - 1] + letters[index % len(letters)]
    return f"{sequence_control}{suffix}"


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
            f"above the {limit}-objective guard configured via "
            "assessment_engine_max_objectives_per_control. This is not necessarily a "
            "grouping bug -- the real catalog's largest control has 98 sub-clause "
            "objectives on its own -- but it is far enough outside the observed range "
            "to confirm before evaluating. Raise the setting if this control is "
            "legitimately this large."
        )

    objectives: list[Objective] = []
    seen_labels: set[str] = set()
    for index, row in enumerate(matching):
        text = (row.assessment_objective or "").strip()
        if not text:
            continue
        label = row.ap_acronym or _ordinal_label(row.sequence_control or canonical, index)
        if label in seen_labels:
            # ap_acronym is sparse and inconsistently unique -- confirmed live
            # on AC-1, which carries two sub-clause rows both stamped
            # "AC-01a". Silently keeping the duplicate would violate
            # uq_objective_proposal_label the moment both rows are persisted
            # as AssessmentObjectiveProposal for the same control proposal,
            # which previously aborted the whole control (see
            # ccf.assessment.engine.service's per-objective savepoint --
            # protects against a raise, not against two rows racing for the
            # same unique key in the first place). Fall back to this row's
            # own ordinal derivation, which is unique by construction (it
            # encodes `index`), rather than the catalog-supplied label the
            # earlier row already claimed.
            label = _ordinal_label(row.sequence_control or canonical, index)
        if label in seen_labels:
            # Exceptionally rare: the ordinal fallback itself coincides with
            # a label already used (e.g. a catalog ap_acronym of "AC-01c"
            # sitting at the same position an ordinal derivation would also
            # produce "AC-01c" for). Not observed in the real catalog, but
            # labels must stay unique regardless.
            label = f"{label}-dup{index}"
        seen_labels.add(label)
        objectives.append(
            Objective(
                label=label,
                text=text,
                text_sha256=objective_sha256(text),
                sort_order=index,
            )
        )
    return objectives
