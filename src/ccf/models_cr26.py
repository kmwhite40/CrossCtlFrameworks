"""FedRAMP CR26 deliverable documents.

Stored as documents rather than decomposed into columns. The shape belongs to
FedRAMP, who version each schema independently (the CPO is at 0.1.4 while
``assessor-information`` is at 1.0.1), so a decomposed copy would drift from
the published schema and need a migration every time a field is added. The
vendored schema under ``ccf/cr26/schemas/`` is the constraint, and
``ccf.cr26.store`` is what enforces it.

One row per ``(system_id, kind, document_key)``: the documents are
self-versioning -- the CPO's ``CPO-CSO-MTD`` metadata block carries version,
last-updated and update-source -- so a history table here would be a second
record of one fact. Change history is :mod:`ccf.api.audit`'s job.

``document_key`` (0081) exists for deliverables that are per-instance rather
than per-system: an Incident Report's ``providerTrackingId`` must stay
consistent across its Initial/Ongoing/Final filings, and one system has many
incidents concurrently, so one row per ``(system_id, "incident")`` would let
filing a report for one incident overwrite another's. The six deliverables
shipped as of 0081 (``cpo``, ``sdr``, ``ocr``, ``vdr``, ``avi``,
``ver_history``) are current-state or overwrite-on-purpose snapshots, so all
six always use a NULL key -- see 0081's docstring for why the unique
constraint below is ``NULLS NOT DISTINCT`` rather than a plain unique, which
is what keeps "NULL key" meaning "the one row for this system and kind"
instead of silently admitting a second one.
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
        # NULLS NOT DISTINCT is load-bearing, not decoration: Postgres treats
        # NULLs as distinct from one another by default, so a plain UNIQUE
        # here would silently accept a second NULL-keyed row per
        # (system_id, kind) -- exactly the row every shipped deliverable's
        # one-row invariant depends on not existing. See 0081's docstring for
        # the measured proof.
        UniqueConstraint(
            "system_id",
            "kind",
            "document_key",
            name="uq_cr26_document_system_kind_key",
            postgresql_nulls_not_distinct=True,
        ),
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

    #: Distinguishes multiple documents of the same ``kind`` for the same
    #: system. NULL for all six deliverables shipped as of 0081 -- see the
    #: module docstring. Reserved for a per-instance deliverable (e.g. an
    #: incident's ``providerTrackingId``) that no shipped code writes yet.
    document_key: Mapped[str | None] = mapped_column(String(128))

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


#: ``document_key``'s own column width, read from the column's declared type
#: rather than duplicated as a hand-copied literal anywhere that needs to
#: bound an input against it (review round 2: two separate call sites --
#: ``ccf.cr26.incident``'s tracking-id check and ``ccf.api.routes.cr26``'s
#: generic-route check -- had each hardcoded ``128``, which is exactly the
#: "one rule expressed in two places" shape this programme keeps getting
#: bitten by; an unbounded ``document_key`` reaches Postgres as a raw
#: ``StringDataRightTruncationError`` -- a 500 -- rather than a 422 either
#: caller controls, so both must bound against the SAME number, not a copy
#: of it). ``String(128)``'s ``.length`` is genuinely optional on
#: SQLAlchemy's own type (a dialect-native string type could have none), so
#: this asserts it is set rather than silently typing this constant
#: ``int | None`` for every caller to re-check.
_document_key_type = Cr26Document.__table__.c.document_key.type
assert isinstance(_document_key_type, String), "Cr26Document.document_key must be a String"
assert _document_key_type.length is not None, "Cr26Document.document_key must declare a length"
DOCUMENT_KEY_MAX_LENGTH: int = _document_key_type.length
