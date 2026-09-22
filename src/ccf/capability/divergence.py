"""Read-only surface for capability-derived control status.

``derive.py`` writes ``ControlImplementation.derived_status``, ``derived_at``
and ``derived_from``; until this module, nothing read them. The ontology
exists to expose exactly one signal -- a control whose **authored** status
disagrees with what the organization's capabilities actually support -- and a
signal computed into a column nobody queries is a signal that was discarded.

Three properties this module must keep:

* **It never writes.** Every function here is a ``SELECT``. The derived value
  annotates an authored claim; it never becomes one, and nothing here may
  make ``status`` agree with ``derived_status``.
* **``None`` is not ``not_implemented``.** ``rollup.roll_up`` returns ``None``
  for "no capability says anything about this control", deliberately distinct
  from a capability that says not-implemented. That distinction has to survive
  all the way to the page: :data:`NO_COVERAGE` is a separate state, never a
  status value, and :func:`divergence_count` never counts it. Collapsing the
  two would report every uncovered control as a divergence and, worse, print
  "derived: not_implemented" for a control no capability has ever been mapped
  to.
* **It names the source.** ``derived_from`` carries capability *keys*, and
  capabilities have no UI of their own -- there is no page to link to -- so
  naming them in place is the only thing that makes a divergence actionable.
  Titles are resolved live where the capability still exists; the key is the
  fallback, because ``derived_from`` is a snapshot and a capability may have
  been renamed or deleted since the derivation ran.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ControlImplementation, System
from ..models_capability import Capability

#: The rendered state for ``derived_status is None``. A sentinel string, not a
#: member of ``impl_status``: it must never be mistaken for, formatted as, or
#: compared against ``not_implemented``.
NO_COVERAGE = "no_capability_coverage"


@dataclass(frozen=True)
class Contributor:
    """One capability that fed a derivation.

    ``title`` is ``None`` when the capability no longer exists under that key
    (renamed, deleted, or derived under another tenant) -- the key still names
    what the derivation used, which is the point.
    """

    key: str
    status: str | None = None
    title: str | None = None

    @property
    def label(self) -> str:
        """What to print: the title when it resolves, else the bare key."""
        return self.title or self.key


@dataclass(frozen=True)
class Derivation:
    """One system's implementation of one control, with its derived annotation."""

    system_id: int
    system_name: str
    authored_status: str
    derived_status: str | None
    derived_at: datetime | None = None
    contributors: list[Contributor] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        """Whether any capability said anything at all about this control."""
        return self.derived_status is not None

    @property
    def divergent(self) -> bool:
        """Authored and derived disagree.

        Uncovered is never divergent: "no capability says anything" does not
        contradict an authored claim, it is simply silent about it.
        """
        return self.covered and self.derived_status != self.authored_status

    @property
    def state(self) -> str:
        """``NO_COVERAGE`` | ``"agrees"`` | ``"diverges"`` -- for the template."""
        if not self.covered:
            return NO_COVERAGE
        return "diverges" if self.divergent else "agrees"


def _org_systems(org_id: int | None) -> Any:
    """The system ids in scope, mirroring ``governance.insights._org_systems``.

    ``org_id is None`` means unscoped (auth disabled or a global principal),
    the same convention every caller in ``ui.py`` and ``insights.py`` uses.
    """
    q = select(System.id)
    return q if org_id is None else q.where(System.organization_id == org_id)


async def divergence_count(session: AsyncSession, *, org_id: int | None = None) -> int:
    """How many control implementations disagree with their capabilities.

    The ``is_not(None)`` clause is **documentation, not a guard**: SQL's
    three-valued logic already drops those rows, since ``NULL != 'planned'``
    is UNKNOWN rather than TRUE, so deleting the clause changes no result and
    fails no test. It is written out because the rule it states -- "no
    coverage is not a divergence" -- is the one a reader is most likely to
    break here, and the way to break it is to *add* something (a
    ``coalesce(derived_status, 'not_implemented')``), which
    ``test_no_contributors_is_neither_a_divergence_nor_not_implemented``
    does catch.
    """
    stmt = (
        select(func.count(ControlImplementation.id))
        .where(ControlImplementation.system_id.in_(_org_systems(org_id)))
        .where(ControlImplementation.derived_status.is_not(None))
        .where(ControlImplementation.derived_status != ControlImplementation.status)
    )
    return int((await session.execute(stmt)).scalar_one() or 0)


def _contributors(derived_from: dict[str, Any] | None) -> list[Contributor]:
    """Parse ``derived_from`` into keys and per-contributor statuses.

    ``derive.py`` writes ``{"capabilities": [key, ...], "detail":
    ["key=status", ...]}``. ``capabilities`` is the authority on *which*; the
    statuses come from ``detail``, which is what explains a conservative
    rollup ("one planned capability among implemented ones derives partial").
    Anything malformed degrades to the key alone rather than raising -- this
    column is a JSONB snapshot, and a render is not the place to fail.
    """
    if not derived_from:
        return []
    keys = [k for k in derived_from.get("capabilities") or [] if isinstance(k, str)]
    statuses: dict[str, str] = {}
    for entry in derived_from.get("detail") or []:
        if isinstance(entry, str) and "=" in entry:
            k, _, v = entry.partition("=")
            statuses[k] = v
    return [Contributor(key=k, status=statuses.get(k)) for k in keys]


async def _resolve_titles(
    session: AsyncSession, contributors: list[Contributor], *, org_id: int | None
) -> list[Contributor]:
    """Attach the capability's current title to each contributor.

    Scoped to ``org_id``: ``Capability.key`` is unique only *within* an
    organization (``uq_capability_org_key``), so an unscoped lookup could
    print another tenant's title beside this tenant's key.
    """
    keys = {c.key for c in contributors}
    if not keys or org_id is None:
        return contributors
    titles = {
        key: title
        for key, title in (
            await session.execute(
                select(Capability.key, Capability.title).where(
                    Capability.organization_id == org_id, Capability.key.in_(keys)
                )
            )
        ).all()
    }
    return [
        Contributor(key=c.key, status=c.status, title=titles.get(c.key)) for c in contributors
    ]


async def derivations_for_control(
    session: AsyncSession, *, control_id: int, org_id: int | None = None
) -> list[Derivation]:
    """Every in-scope implementation of one control, annotated.

    Returns uncovered rows too: the page has to be able to say "no capability
    covers this" in a way that is visibly not "your capabilities say
    not-implemented".
    """
    rows = (
        await session.execute(
            select(ControlImplementation, System.name)
            .join(System, System.id == ControlImplementation.system_id)
            .where(ControlImplementation.control_id == control_id)
            .where(ControlImplementation.system_id.in_(_org_systems(org_id)))
            .order_by(System.name, ControlImplementation.system_id)
        )
    ).all()
    out: list[Derivation] = []
    for impl, system_name in rows:
        contributors = _contributors(impl.derived_from)
        out.append(
            Derivation(
                system_id=impl.system_id,
                system_name=system_name,
                authored_status=impl.status,
                derived_status=impl.derived_status,
                derived_at=impl.derived_at,
                contributors=await _resolve_titles(session, contributors, org_id=org_id),
            )
        )
    return out


__all__ = [
    "NO_COVERAGE",
    "Contributor",
    "Derivation",
    "derivations_for_control",
    "divergence_count",
]
