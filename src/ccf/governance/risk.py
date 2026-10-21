"""Quantitative risk scoring on a five-point scale, and risk appetite.

Likelihood and impact are recorded 1-5 (``Risk.likelihood_score`` /
``Risk.impact_score``, migration 0099) and multiplied for a 1-25 inherent
exposure, then discounted by the chosen treatment to get a residual score.

The three-level enums (``Risk.likelihood`` / ``Risk.impact``) predate the
scores and are kept in step for every reader that still uses them: 1-2 is
``low``, 3 ``moderate``, 4-5 ``high``. When only a level is known it stands
for 1, 3 or 5 -- the values this module has always scored them as, and the
values migration 0099 backfilled -- so no existing score moved.

Risk appetite (``RiskAppetite``) is the most residual exposure the
organization will carry, per category, with a NULL-category default. A
**breach** is an active risk whose residual score is above the appetite that
applies to it. A risk with no residual score, or with no appetite to apply,
is reported as such and never counted as within appetite.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.posture import risk_in_scope as risk_in_scope  # noqa: PLC0414 - re-export
from ..models import Risk
from ..models_program import RiskAppetite

#: The five points, low to high.
SCALE: tuple[int, ...] = (1, 2, 3, 4, 5)
LIKELIHOOD_LABELS: dict[int, str] = {
    1: "Rare",
    2: "Unlikely",
    3: "Possible",
    4: "Likely",
    5: "Almost certain",
}
IMPACT_LABELS: dict[int, str] = {
    1: "Negligible",
    2: "Minor",
    3: "Moderate",
    4: "Major",
    5: "Severe",
}

#: A level given without a score stands for this score.
LEVEL_TO_SCORE: dict[str, int] = {"low": 1, "moderate": 3, "high": 5}
# Treatment effectiveness -- fraction of inherent exposure that remains.
_RESIDUAL_FACTOR = {"mitigate": 0.4, "transfer": 0.5, "avoid": 0.1, "accept": 1.0}

#: Risks that still carry exposure: the heat map's and the dashboard's
#: "active" risks. Accepted and closed risks are decisions already taken.
ACTIVE_STATUSES: tuple[str, ...] = ("open", "mitigated")


def band(score: int | None) -> str:
    """Bucket a 1-25 exposure score into a qualitative band."""
    if not score:
        return "unknown"
    if score <= 4:
        return "low"
    if score <= 9:
        return "moderate"
    if score <= 15:
        return "high"
    return "critical"


def score_to_level(score: int | None) -> str | None:
    """The three-level enum a 1-5 score corresponds to (1-2 low, 3 moderate, 4-5 high)."""
    if score is None or score not in SCALE:
        return None
    if score <= 2:
        return "low"
    if score == 3:
        return "moderate"
    return "high"


def to_score(value: int | str | None) -> int | None:
    """A 1-5 score from a score or a level name; ``None`` for anything else.

    ``bool`` is refused although it is an ``int``: ``True`` is not a likelihood.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value in SCALE else None
    return LEVEL_TO_SCORE.get(value.strip().lower())


def effective_scores(
    likelihood_score: int | None,
    likelihood: str | None,
    impact_score: int | None,
    impact: str | None,
) -> tuple[int | None, int | None]:
    """The scores a risk is placed by: the recorded score, else its level's."""
    return (
        to_score(likelihood_score) or to_score(likelihood),
        to_score(impact_score) or to_score(impact),
    )


def compute_scores(
    likelihood: int | str | None, impact: int | str | None, treatment: str | None
) -> tuple[int | None, int | None]:
    """Return ``(inherent_score, residual_score)`` on a 1-25 scale.

    ``likelihood`` and ``impact`` are each a 1-5 score or a level name
    (``low``/``moderate``/``high``, scored 1/3/5)."""
    lk = to_score(likelihood)
    im = to_score(impact)
    if lk is None or im is None:
        return None, None
    inherent = lk * im
    factor = _RESIDUAL_FACTOR.get((treatment or "").lower(), 1.0)
    residual = max(1, round(inherent * factor))
    return inherent, residual


class AxisConflict(ValueError):  # noqa: N818 -- names the condition, as the 422 does
    """A level and a score were both given and say different things."""


def resolve_axis(
    *,
    axis: str,
    score: int | None,
    level: str | None,
    current_score: int | None = None,
) -> tuple[int | None, str | None]:
    """The ``(score, level)`` to store for one axis, kept in step.

    * A score wins and sets the level.
    * A score and a level that disagree are refused, never silently resolved.
    * A level alone keeps ``current_score`` when that score already lies in
      the level (a whole-form re-save of ``high`` must not move a 4 to a 5);
      otherwise it stands for 1, 3 or 5.
    * Neither keeps the current score.
    """
    if score is not None:
        if isinstance(score, bool) or score not in SCALE:
            raise AxisConflict(f"{axis}_score must be 1-5, not {score!r}")
        derived = score_to_level(score)
        if level is not None and level != derived:
            raise AxisConflict(
                f"{axis} {level!r} does not match {axis}_score {score} (which is {derived!r})"
            )
        return score, derived
    if level is not None:
        if level not in LEVEL_TO_SCORE:
            raise AxisConflict(f"{axis} must be low, moderate or high, not {level!r}")
        if current_score is not None and score_to_level(current_score) == level:
            return current_score, level
        return LEVEL_TO_SCORE[level], level
    return current_score, score_to_level(current_score)


def _effective(score_col: Any, level_col: Any) -> Any:
    return func.coalesce(
        score_col,
        case(*((level_col == lv, s) for lv, s in LEVEL_TO_SCORE.items()), else_=None),
    )


def likelihood_expr() -> Any:
    """SQL for a risk's effective likelihood score (score, else the level's)."""
    return _effective(Risk.likelihood_score, Risk.likelihood)


def impact_expr() -> Any:
    """SQL for a risk's effective impact score (score, else the level's)."""
    return _effective(Risk.impact_score, Risk.impact)


# ── Tenant scope ─────────────────────────────────────────────────────────────


# ``risk_in_scope`` lives beside ``org_system_subq`` (analytics.posture) so
# posture itself can use it without an import cycle; imported above.


# ── Risk appetite ────────────────────────────────────────────────────────────


def category_key(category: str | None) -> str | None:
    """Categories are free text; an appetite applies regardless of case or spacing."""
    if category is None:
        return None
    key = " ".join(category.split()).lower()
    return key or None


@dataclass(frozen=True)
class AppetiteRule:
    id: int
    category: str | None
    max_residual_score: int


def appetite_for(category: str | None, rules: Sequence[AppetiteRule]) -> AppetiteRule | None:
    """The category's own statement, else the default (NULL category), else none."""
    key = category_key(category)
    default = None
    for rule in rules:
        if rule.category is None:
            default = rule
        elif key is not None and category_key(rule.category) == key:
            return rule
    return default


@dataclass(frozen=True)
class Placement:
    """Where one risk stands against appetite."""

    risk_id: int
    state: str  # breach | within | unscored | no_appetite
    appetite: AppetiteRule | None
    residual_score: int | None

    @property
    def over_by(self) -> int | None:
        if self.state != "breach" or self.appetite is None or self.residual_score is None:
            return None
        return self.residual_score - self.appetite.max_residual_score


def place(
    risk_id: int, category: str | None, residual: int | None, rules: Sequence[AppetiteRule]
) -> Placement:
    rule = appetite_for(category, rules)
    if rule is None:
        return Placement(risk_id, "no_appetite", None, residual)
    if residual is None:
        return Placement(risk_id, "unscored", rule, None)
    state = "breach" if residual > rule.max_residual_score else "within"
    return Placement(risk_id, state, rule, residual)


async def appetite_rules(session: AsyncSession, org_id: int) -> list[AppetiteRule]:
    rows = (
        await session.execute(
            select(RiskAppetite.id, RiskAppetite.category, RiskAppetite.max_residual_score).where(
                RiskAppetite.organization_id == org_id
            )
        )
    ).all()
    return [AppetiteRule(r.id, r.category, r.max_residual_score) for r in rows]


async def appetite_placements(
    session: AsyncSession, org_id: int, *, risk_ids: Iterable[int] | None = None
) -> dict[int, Placement]:
    """Every active risk of the org (``risk_in_scope``), placed against appetite.

    Keyed by risk id. ``risk_ids`` narrows the set (a register page that has
    already loaded its rows)."""
    rules = await appetite_rules(session, org_id)
    stmt = select(Risk.id, Risk.category, Risk.residual_score).where(
        risk_in_scope(org_id),
        Risk.status.in_(ACTIVE_STATUSES),
    )
    if risk_ids is not None:
        ids = list(risk_ids)
        if not ids:
            return {}
        stmt = stmt.where(Risk.id.in_(ids))
    rows = (await session.execute(stmt)).all()
    return {r.id: place(r.id, r.category, r.residual_score, rules) for r in rows}


async def breach_count(session: AsyncSession, org_id: int) -> int:
    placements = await appetite_placements(session, org_id)
    return sum(1 for p in placements.values() if p.state == "breach")


# ── Assessments and treatment (0100) ─────────────────────────────────────────

ASSESSMENT_METHODS: tuple[str, ...] = ("qualitative", "quantitative", "both")
STRATEGIES: tuple[str, ...] = ("mitigate", "transfer", "accept", "avoid")
PLAN_STATUSES: tuple[str, ...] = ("planned", "in_progress", "done", "cancelled")
ACTION_STATUSES: tuple[str, ...] = ("open", "done")


def ale(sle: float | None, aro: float | None) -> float | None:
    """Annualized loss expectancy = single-loss expectancy x annual rate of
    occurrence. Computed, never entered; ``None`` unless both are recorded."""
    if sle is None or aro is None:
        return None
    return round(sle * aro, 2)


def assessment_method(qualitative: bool, quantitative: bool) -> str | None:
    if qualitative and quantitative:
        return "both"
    if qualitative:
        return "qualitative"
    if quantitative:
        return "quantitative"
    return None


def plan_progress(done: int, total: int) -> int | None:
    """Done actions over actions, as a whole percent; ``None`` over none."""
    if total <= 0:
        return None
    return round(100 * done / total)
