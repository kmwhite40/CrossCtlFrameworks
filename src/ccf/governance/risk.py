"""Quantitative risk scoring — turn qualitative levels into an exposure score.

Maps the low/moderate/high likelihood and impact onto a 1-5 scale and multiplies
for a 1-25 inherent exposure, then discounts by the chosen treatment to get a
residual score. Gives the risk register a heatmap-able number without changing
the existing qualitative vocabulary.
"""

from __future__ import annotations

_LEVEL = {"low": 1, "moderate": 3, "high": 5}
# Treatment effectiveness — fraction of inherent exposure that remains.
_RESIDUAL_FACTOR = {"mitigate": 0.4, "transfer": 0.5, "avoid": 0.1, "accept": 1.0}


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


def compute_scores(
    likelihood: str | None, impact: str | None, treatment: str | None
) -> tuple[int | None, int | None]:
    """Return ``(inherent_score, residual_score)`` on a 1-25 scale."""
    lk = _LEVEL.get((likelihood or "").lower())
    im = _LEVEL.get((impact or "").lower())
    if lk is None or im is None:
        return None, None
    inherent = lk * im
    factor = _RESIDUAL_FACTOR.get((treatment or "").lower(), 1.0)
    residual = max(1, round(inherent * factor))
    return inherent, residual
