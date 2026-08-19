"""Re-apply the header classifier to mappings already in the database.

``ingest_workbook`` classifies each workbook column into a framework as it
loads. When a classification rule is added or corrected, the rows already in
Postgres keep the framework they were given at load time — the rule change has
no effect until the workbook is ingested again.

A full re-ingest is the obvious answer and, for a long time, was the only one.
It stopped being safe once the database held anything but catalog data: the
pipeline deletes and reloads ``controls``, which mints new ids and severs the
rows that reference them (see ``pipeline._reload_controls``). Re-ingesting to
move a mapping from one framework to another is also disproportionate — the
mapping rows themselves are correct, only their *label* is stale.

This module does the narrow thing instead. It re-runs
:func:`ccf.etl.frameworks.classify_header` over the distinct ``column_key``
values present in ``framework_mappings`` and updates ``framework_id`` where the
verdict has changed. Controls are never touched, mapping rows are never deleted,
and the operation is idempotent: running it twice changes nothing the second
time.

Missing framework rows are created first, because a new rule usually names a
framework that has never been seeded.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Framework, FrameworkMapping
from .frameworks import FRAMEWORKS, classify_header

#: Columns the classifier cannot place land here, matching ``_seed_frameworks``.
FALLBACK_CODE = "OTHER"


def _target_code(column_key: str | None) -> str | None:
    """The framework a stored ``column_key`` should carry, or None to leave it.

    ``classify_header`` returns None for a *core* header — a column that is a
    control attribute rather than a crosswalk, such as "control-name". The
    pipeline never creates a mapping row for one, so seeing a core header here
    means the row is anomalous. Relabelling it ``OTHER`` would bury that; this
    leaves it exactly as it is and lets :attr:`ReclassifyPlan.skipped` report it.
    """
    if column_key is None:
        return None
    return classify_header(column_key)


@dataclass
class ReclassifyPlan:
    """What a reclassification would do, expressed before any row is written."""

    #: ``(from_code, to_code) -> row count``
    moves: dict[tuple[str, str], int] = field(default_factory=dict)
    #: Framework codes that must be inserted before the update can run.
    new_frameworks: list[str] = field(default_factory=list)
    #: Rows whose classification is unchanged.
    unchanged: int = 0
    #: ``column_key -> row count`` for rows the classifier declines to place.
    skipped: dict[str, int] = field(default_factory=dict)

    @property
    def changed(self) -> int:
        return sum(self.moves.values())

    @property
    def total(self) -> int:
        return self.changed + self.unchanged

    @property
    def demotions(self) -> dict[tuple[str, str], int]:
        """Moves that take a row *into* the fallback — a classification regression.

        Promoting ``OTHER`` rows to a real framework is the expected outcome. The
        reverse means a rule stopped recognising a header it used to recognise,
        which is worth surfacing rather than applying silently.
        """
        return {k: v for k, v in self.moves.items() if k[1] == FALLBACK_CODE}


async def plan_reclassification(session: AsyncSession) -> ReclassifyPlan:
    """Compute the reclassification without writing anything."""
    rows = (
        await session.execute(
            select(
                Framework.code,
                FrameworkMapping.column_key,
                func.count().label("n"),
            )
            .join(Framework, Framework.id == FrameworkMapping.framework_id)
            .group_by(Framework.code, FrameworkMapping.column_key)
        )
    ).all()

    known = {code for (code,) in (await session.execute(select(Framework.code))).all()}
    plan = ReclassifyPlan()
    wanted: set[str] = set()
    for old_code, column_key, n in rows:
        new_code = _target_code(column_key)
        if new_code is None:
            plan.skipped[column_key] = plan.skipped.get(column_key, 0) + n
            plan.unchanged += n
            continue
        if new_code == old_code:
            plan.unchanged += n
            continue
        plan.moves[(old_code, new_code)] = plan.moves.get((old_code, new_code), 0) + n
        wanted.add(new_code)

    by_code = {spec.code: spec for spec in FRAMEWORKS}
    plan.new_frameworks = sorted(c for c in wanted if c not in known and c in by_code)
    return plan


async def apply_reclassification(session: AsyncSession) -> ReclassifyPlan:
    """Seed any missing frameworks, then move the mappings the plan identified.

    Returns the plan that was applied. The caller owns the transaction, so a
    failure part-way leaves the mappings exactly as they were.
    """
    plan = await plan_reclassification(session)
    if not plan.changed:
        return plan

    by_code = {spec.code: spec for spec in FRAMEWORKS}
    for code in plan.new_frameworks:
        spec = by_code[code]
        session.add(
            Framework(
                code=spec.code,
                name=spec.name,
                family=spec.family,
                description=spec.description,
            )
        )
    await session.flush()

    ids = {
        code: fid
        for code, fid in (await session.execute(select(Framework.code, Framework.id))).all()
    }

    # One UPDATE per destination framework, keyed on the column_keys that resolve
    # to it. Grouping this way keeps the statement count at one per framework
    # rather than one per column.
    targets: dict[str, list[str]] = {}
    for column_key, in (
        await session.execute(select(FrameworkMapping.column_key).distinct())
    ).all():
        target_code = _target_code(column_key)
        if target_code is None or column_key is None:
            continue
        targets.setdefault(target_code, []).append(column_key)

    for code, column_keys in targets.items():
        target_id = ids.get(code)
        if target_id is None:  # pragma: no cover - guarded by plan.new_frameworks
            raise RuntimeError(f"framework {code!r} is not seeded; cannot reclassify")
        await session.execute(
            update(FrameworkMapping)
            .where(
                FrameworkMapping.column_key.in_(column_keys),
                FrameworkMapping.framework_id != target_id,
            )
            .values(framework_id=target_id)
        )
    return plan
