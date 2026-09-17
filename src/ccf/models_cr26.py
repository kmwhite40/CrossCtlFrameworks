"""FedRAMP CR26 deliverable documents.

Stored as documents rather than decomposed into columns. The shape belongs to
FedRAMP, who version each schema independently (the CPO is at 0.1.4 while
``assessor-information`` is at 1.0.1), so a decomposed copy would drift from
the published schema and need a migration every time a field is added. The
vendored schema under ``ccf/cr26/schemas/`` is the constraint, and
``ccf.cr26.store`` is what enforces it.

One row per ``(system_id, kind)``: the documents are self-versioning -- the
CPO's ``CPO-CSO-MTD`` metadata block carries version, last-updated and
update-source -- so a history table here would be a second record of one fact.
Change history is :mod:`ccf.api.audit`'s job.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class Cr26Document(Base):
    """One CR26 deliverable for one system."""

    __tablename__ = "cr26_documents"
    __table_args__ = (
        UniqueConstraint("system_id", "kind", name="uq_cr26_document_system_kind"),
        {"schema": "ccf"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    #: Nullable and CASCADE, following 0075_remediation_plans, which is this
    #: table's shape almost exactly. Nullable for consistency with that
    #: precedent only: no current writer can produce a NULL, because
    #: :func:`ccf.cr26.store.put_document` always sets it from
    #: ``System.organization_id``, which is itself ``NOT NULL``.
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: One of ``ccf.cr26.validation.CR26_KINDS``. Deliberately a plain string
    #: rather than a database enum: the vocabulary is FedRAMP's and grows when
    #: they publish a schema, and a new kind should not require a migration.
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    #: What it was judged against. Both, because FedRAMP versions the ruleset
    #: (the date in every filename) and each schema (semver) independently.
    ruleset_version: Mapped[str] = mapped_column(String(32), nullable=False)
    schema_version: Mapped[str | None] = mapped_column(String(32))

    is_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    validation_errors: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)

    updated_by: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    notes: Mapped[str | None] = mapped_column(Text)
