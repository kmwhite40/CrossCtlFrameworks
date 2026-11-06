"""The consumer registry and scope resolution for the outbox.

A :class:`Consumer` says which events it wants (``matches``), what unit of work
they collapse to (``scope`` -> ``"system:N"`` / ``"org:N"`` / ``None``), and how
to do it (``run``). ``enqueue`` reads the registry; the worker runs it.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Event, Organization, System
from ..models_outbox import OutboxJob


@dataclass(frozen=True)
class Consumer:
    name: str
    matches: Callable[[str, str], bool]  # (entity_type, verb)
    scope: Callable[[Event], str | None]  # "system:N" | "org:N" | None
    run: Callable[[AsyncSession, str, OutboxJob], Awaitable[dict[str, Any]]]
    settle_seconds: int = 15
    max_attempts: int = 5


REGISTRY: dict[str, Consumer] = {}


def register(c: Consumer) -> Consumer:
    if c.name in REGISTRY:
        raise ValueError(f"event consumer {c.name!r} is already registered")
    REGISTRY[c.name] = c
    return c


def _parse(scope_key: str) -> tuple[str, int]:
    kind, sep, raw = scope_key.partition(":")
    if not sep or not raw.isascii() or not raw.isdigit():
        raise ValueError(f"malformed scope key {scope_key!r}")
    return kind, int(raw)


async def scope_org(session: AsyncSession, scope_key: str) -> int | Literal["gone"] | None:
    """The organization a scope belongs to.

    ``"gone"`` when the system or organization is missing or soft-deleted;
    ``None`` for a scope kind this function does not own (``event:N`` jobs carry
    their own organization); ``ValueError`` for a malformed key. Run on an
    unscoped session: the worker resolves the tenant before it sets one.
    """
    kind, ident = _parse(scope_key)
    if kind == "system":
        row = (
            await session.execute(
                select(System.organization_id).where(
                    System.id == ident, System.deleted_at.is_(None)
                )
            )
        ).first()
        return "gone" if row is None else row[0]
    if kind == "org":
        found = (
            await session.execute(
                select(Organization.id).where(
                    Organization.id == ident, Organization.deleted_at.is_(None)
                )
            )
        ).first()
        return "gone" if found is None else ident
    return None
