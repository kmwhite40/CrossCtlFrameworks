"""The event bus's durable work queue (transactional outbox).

``emit`` inserts one ``outbox_jobs`` row per matching consumer in the same
transaction as the change, so nothing leaves the database before commit. A
worker claims rows through :func:`ccf.queue.claim_jobs`. ``organization_id`` is
NULL only for platform-only jobs; every other job runs under its tenant.

See docs/superpowers/specs/2026-11-06-event-bus-outbox-design.md.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class OutboxJob(Base):
    """One unit of derived work for one consumer and scope."""

    __tablename__ = "outbox_jobs"
    __table_args__ = (
        Index("ix_outbox_jobs_status_next", "status", "next_attempt_at"),
        Index("ix_outbox_jobs_consumer_scope_status", "consumer", "scope_key", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE")
    )
    consumer: Mapped[str] = mapped_column(String(48))
    scope_key: Mapped[str] = mapped_column(String(96))
    #: NULL only for a job no event triggered: a notification's outbound post.
    trigger_event_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ccf.events.id", ondelete="CASCADE")
    )
    #: Pending jobs this one absorbed when it was claimed (coalescing).
    absorbed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    #: pending | claimed | done | merged | failed
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, server_default="5")

    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    last_error: Mapped[str | None] = mapped_column(Text)
    merged_into: Mapped[int | None] = mapped_column(BigInteger)
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
