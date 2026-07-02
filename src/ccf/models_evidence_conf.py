"""Evidence confidence + reproducibility models.

Scores every evidence object on how much assurance weight it carries (source type,
freshness, digest integrity, review/lock status, replayability, …), tracks whether
connector/scan-backed evidence can be reproduced, and records replay runs. Kept in
a dedicated module (imported by the evidence-confidence routes) so the layer is
easy to review; all tables are tenant-isolated by ``organization_id``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class EvidenceConfidenceScore(Base):
    """The current confidence score (0-100) + factor breakdown for one object."""

    __tablename__ = "evidence_confidence_scores"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    evidence_object_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.evidence_objects.id", ondelete="CASCADE"), index=True
    )
    version_id: Mapped[int | None] = mapped_column(BigInteger)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    band: Mapped[str] = mapped_column(String(16), default="low")  # low|moderate|high|strong
    source_type: Mapped[str] = mapped_column(String(32), default="manual_upload")
    reproducible: Mapped[bool] = mapped_column(Boolean, default=False)
    factors: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("evidence_object_id", name="uq_evidence_confidence_object"),
    )


class EvidenceReproducibilityCheck(Base):
    """Whether an object's evidence can be reproduced (digest/connector replay)."""

    __tablename__ = "evidence_reproducibility_checks"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    evidence_object_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.evidence_objects.id", ondelete="CASCADE"), index=True
    )
    reproducible: Mapped[bool] = mapped_column(Boolean, default=False)
    method: Mapped[str] = mapped_column(String(24), default="none")  # connector|digest|none
    detail: Mapped[str | None] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EvidenceSourceTrustPolicy(Base):
    """Per-org trust override for an evidence source type (weights + max age)."""

    __tablename__ = "evidence_source_trust_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    source_type: Mapped[str] = mapped_column(String(32))
    base_trust: Mapped[float] = mapped_column(Float, default=0.5)  # 0..1
    max_age_days: Mapped[int | None] = mapped_column(Integer)
    require_review: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("organization_id", "source_type", name="uq_evidence_trust_policy"),
    )


class EvidenceReplayRun(Base):
    """A replay attempt to reproduce an object's evidence from its source."""

    __tablename__ = "evidence_replay_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    evidence_object_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.evidence_objects.id", ondelete="CASCADE"), index=True
    )
    # reproduced|drifted|missing|error|not_replayable
    status: Mapped[str] = mapped_column(String(16), default="error")
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
