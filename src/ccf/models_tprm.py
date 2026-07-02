"""Third-party risk models — vendor security questionnaires (CAIQ/SIG).

Extends the basic Vendor record into a real vendor-risk workflow: a
:class:`QuestionnaireTemplate` defines weighted questions; a
:class:`VendorQuestionnaire` is one assessment of a vendor whose
:class:`QuestionnaireResponse` rows are scored into a 0-100 posture score and a
risk rating (see :mod:`ccf.governance.tprm`). Kept in a dedicated module
(imported by the questionnaire routes) so this net-new layer is easy to review.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .models import Base


class QuestionnaireTemplate(Base):
    """A reusable questionnaire definition (built-ins are seeded on demand)."""

    __tablename__ = "questionnaire_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    key: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255))
    framework: Mapped[str | None] = mapped_column(String(32))  # CAIQ|SIG|custom
    version: Mapped[str] = mapped_column(String(16), default="1.0")
    # [{id, domain, text, weight}]
    questions: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class VendorQuestionnaire(Base):
    """One security assessment of a vendor, instantiated from a template."""

    __tablename__ = "vendor_questionnaires"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    vendor_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.vendors.id", ondelete="CASCADE"), index=True
    )
    template_key: Mapped[str | None] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(255))
    # draft|sent|in_progress|submitted|reviewed
    status: Mapped[str] = mapped_column(String(16), default="draft")
    sent_on: Mapped[date | None] = mapped_column(Date)
    due_on: Mapped[date | None] = mapped_column(Date)
    submitted_on: Mapped[date | None] = mapped_column(Date)
    reviewed_on: Mapped[date | None] = mapped_column(Date)
    reviewer: Mapped[str | None] = mapped_column(String(255))
    score: Mapped[float | None] = mapped_column(Float)
    risk_rating: Mapped[str | None] = mapped_column(String(16))  # low|moderate|high|critical
    summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    responses: Mapped[list[QuestionnaireResponse]] = relationship(
        back_populates="questionnaire",
        cascade="all, delete-orphan",
        order_by="QuestionnaireResponse.sort_order",
    )


class QuestionnaireResponse(Base):
    """One question + answer within a :class:`VendorQuestionnaire`."""

    __tablename__ = "questionnaire_responses"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    questionnaire_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.vendor_questionnaires.id", ondelete="CASCADE"), index=True
    )
    question_id: Mapped[str] = mapped_column(String(32))
    domain: Mapped[str | None] = mapped_column(String(64))
    question_text: Mapped[str] = mapped_column(Text)
    weight: Mapped[int] = mapped_column(Integer, default=1)
    answer: Mapped[str] = mapped_column(String(16), default="unanswered")  # yes|no|partial|na
    detail: Mapped[str | None] = mapped_column(Text)
    evidence_ref: Mapped[str | None] = mapped_column(String(1024))
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    questionnaire: Mapped[VendorQuestionnaire] = relationship(back_populates="responses")
