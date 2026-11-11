"""One read model over the four places Concord records an accepted risk.

A POA&M in ``risk_accepted`` (expiry: ``due_on``), a Risk ``accepted`` (expiry:
``next_review_on``), an approved check/control ``Waiver`` (``expires_on``) and
an accepted ``KSIException`` (``expires_on``) are each the same decision -- a
known weakness the organization chose to carry until a date. Each has its own
gate and lifecycle and stays the record of truth; this module only lists them
together so an authorization decision can see all of them, and so an expired
one cannot hide in a register nobody opened.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import KSI, POAM, KSIException, Risk
from ..models_waivers import Waiver

KIND_LABELS = {
    "poam": "POA&M risk acceptance",
    "risk": "Accepted risk",
    "waiver": "Waiver",
    "ksi_exception": "KSI exception",
}


@dataclass(frozen=True)
class Acceptance:
    kind: str
    id: int
    system_id: int
    title: str
    expires_on: date | None
    approved_by: str | None

    def expired(self, today: date) -> bool:
        return self.expires_on is not None and self.expires_on < today

    @property
    def indefinite(self) -> bool:
        return self.expires_on is None

    @property
    def label(self) -> str:
        return KIND_LABELS[self.kind]


async def for_systems(session: AsyncSession, system_ids: Iterable[int]) -> list[Acceptance]:
    """Every standing acceptance on the given systems, soonest expiry first."""
    ids = list(system_ids)
    if not ids:
        return []
    out: list[Acceptance] = []
    for p in (
        await session.execute(
            select(POAM).where(POAM.system_id.in_(ids), POAM.status == "risk_accepted")
        )
    ).scalars():
        out.append(Acceptance("poam", p.id, p.system_id, p.title, p.due_on, None))
    for r in (
        await session.execute(
            select(Risk).where(Risk.system_id.in_(ids), Risk.status == "accepted")
        )
    ).scalars():
        assert r.system_id is not None  # filtered by system_id IN (...)
        out.append(Acceptance("risk", r.id, r.system_id, r.title, r.next_review_on, None))
    for w in (
        await session.execute(
            select(Waiver).where(Waiver.system_id.in_(ids), Waiver.status == "approved")
        )
    ).scalars():
        target = w.check_key or w.control_id or "finding"
        out.append(
            Acceptance("waiver", w.id, w.system_id, f"Waiver: {target}", w.expires_on,
                       w.approved_by)
        )
    for e, ksi_id in (
        await session.execute(
            select(KSIException, KSI.identifier)
            .join(KSI, KSI.id == KSIException.ksi_id)
            .where(KSIException.system_id.in_(ids), KSIException.status == "accepted")
        )
    ).all():
        out.append(
            Acceptance("ksi_exception", e.id, e.system_id, f"KSI exception: {ksi_id}",
                       e.expires_on, None)
        )
    out.sort(key=lambda a: (a.expires_on is None, a.expires_on or date.max, a.kind, a.id))
    return out


async def for_system(session: AsyncSession, system_id: int) -> list[Acceptance]:
    return await for_systems(session, [system_id])
