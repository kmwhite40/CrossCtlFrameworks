"""Concord-on-Concord self-assurance run record.

Concord dogfoods itself: a "Concord Platform" system whose controls map to
Concord's own reliability checks (RLS, audit hash-chain, migrations, supply chain,
AI guardrails). Each :class:`SelfAssuranceRun` records a point-in-time
self-assessment (readiness + per-check results). Tenant-isolated like everything
else, though in practice it runs under the seeded self-assurance organization.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Integer, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class SelfAssuranceRun(Base):
    """A point-in-time self-assessment of the Concord platform."""

    __tablename__ = "self_assurance_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.systems.id", ondelete="CASCADE"))
    readiness_pct: Mapped[float] = mapped_column(Float, default=0.0)
    checks_total: Mapped[int] = mapped_column(Integer, default=0)
    checks_passed: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
