# CR26 Document Store Implementation Plan (P9a-ii, part 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store FedRAMP CR26 deliverable documents, validated on every write against the schemas the spine vendors — giving that validator its first production consumer, and giving the Certification Package Overview somewhere to live.

**Architecture:** One tenant-scoped table, `cr26_documents`, keyed by the closed `CR26_KINDS` vocabulary. Each row holds the JSON document plus the verdict, ruleset revision and schema version it was judged against. A service layer validates on write and never refuses. A seeder fills the three CPO fields the platform actually knows and leaves the rest — deliberately producing an invalid document.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, Alembic, pytest. **No new dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-17-cr26-document-store-design.md`

## Global Constraints

- **This is not a generator.** The CPO has ten required fields; the platform can supply **three** — `providerName` (`Organization.name`), `serviceName` (`System.name`), `serviceDescription` (`System.description`). The other seven are facts about the business that live nowhere here. Do not invent values for them, do not derive them, and do not add columns to hold them.
- **`certificationType` is authored, never derived.** It enumerates `20x` and `Rev5`. Inferring it from `certification_class` is the same class of mistake as deriving Class from `baseline`, which `0078` and `tests/test_certification_class_is_independent.py` exist to prevent.
- **Never refuse a write for being invalid.** A draft is necessarily incomplete. Validate, record the verdict, store it anyway. The guarantee is that **no document is ever stored without a recorded verdict** — no path may write `document` and leave `is_valid` stale or null.
- **Never hand-edit a vendored schema** under `src/ccf/cr26/schemas/`. A sha256 manifest and a test pin every one.
- **Tenancy follows `0075_remediation_plans` exactly** (read it first — it is this table's shape almost exactly): `organization_id` nullable with `ondelete="CASCADE"`, `system_id` `NOT NULL`, and the direct predicate
  `(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())`
  applied `FOR ALL` as both `USING` and `WITH CHECK`, with `ENABLE` **and** `FORCE ROW LEVEL SECURITY`.
- **Two RLS guards, and they are opposites.** `EXPECTED_TENANT_ISOLATION_TABLES` (`tests/test_rls_coverage.py`) is a positive-control snapshot with a hardcoded count — currently `== 137` at line 185; add the table name **and** bump to 138. `GLOBAL_TABLES` (`tests/test_rls_registry_no_gap.py`) is for authority-published reference data and **must not** gain this table.
- **Never construct `AuditLog` directly** — use `ccf.api.audit.record_event`, or its `prev_hash`/`row_hash` chain silently breaks. (It has `diff`, not `detail`.)
- Migration chains from `0078_cr26_certification`, carries the `pg_roles`-guarded GRANT used since `0054`, and must leave **exactly one head** — verified with the FULL `alembic heads` output, **never piped through `tail`**, which hid a second head once and errored 1,992 tests.
- **Every new test must be able to fail.** This programme has shipped at least seven that could not, and the schema-spine branch spent three fix rounds on exactly that.
- `ruff check .` and `mypy src` clean. mypy runs with `strict = true`. `ruff format` is **not** enforced here (343 files repo-wide would change; CI runs only `ruff check .`) — do not run it.
- **The suite is hermetic as of `5aa64c3`.** A conftest guard fails any test that opens a connection to :80/:443, recording attempts and failing in teardown. Nothing here should need the network. If you write a test that creates `CatalogSource`/`PackSource` rows, add `pytest.mark.usefixtures("isolate_source_rows")`.
- Test command — the default `pytest` hits the WRONG database (`.env` points at port 5432, another project's container):

```
export CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
.venv/bin/python3 -m pytest -q
```

  Use `.venv/bin/` binaries only — the system `python3` is 3.9 and lacks the project. **Never let a pytest call background:** a Bash call past 120s is auto-backgrounded and its completion notification never arrives. Pass an explicit `timeout` — `600000` focused, `900000` full suite (110–190s). One pytest session at a time. If every test ERRORs with `Can't locate revision`, the shared DB is stamped at another branch's migration; recreate it:

```
.venv/bin/python3 -c "import psycopg; c=psycopg.connect('postgresql://ccf:ccf@localhost:5434/postgres', autocommit=True); c.execute(\"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='ccf_test' AND pid<>pg_backend_pid()\"); c.execute('DROP DATABASE IF EXISTS ccf_test'); c.execute('CREATE DATABASE ccf_test OWNER ccf')"
```

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `src/ccf/models_cr26.py` | the `Cr26Document` model | 1 |
| `migrations/versions/0079_cr26_documents.py` | table, indexes, GRANT, RLS policy | 1 |
| `tests/test_cr26_document_model.py` | persistence, tenancy, uniqueness | 1 |
| `src/ccf/cr26/store.py` | validate-on-write service | 2 |
| `tests/test_cr26_document_store.py` | the verdict guarantee | 2 |
| `src/ccf/cr26/cpo.py` | the CPO seeder | 3 |
| `tests/test_cr26_cpo_seed.py` | seeds three fields, honestly invalid | 3 |
| `tests/test_cr26_certification_type_not_derived.py` | the no-derivation guard | 3 |

A new `models_cr26.py` rather than appending to `models.py`: the repo already splits models by area (`models_grc.py`, `models_packs.py`, `models_patching.py`, `models_cci.py`). **`migrations/env.py` builds metadata from `ccf.models` alone**, so a new model module must be imported at the bottom of `models.py` or anything sorting `Base.metadata` raises `NoReferencedTableError` — check how `models_cci.py` is wired and copy it.

---

### Task 1: The table

**Files:**
- Create: `src/ccf/models_cr26.py`, `migrations/versions/0079_cr26_documents.py`, `tests/test_cr26_document_model.py`
- Modify: `src/ccf/models.py` (import at the bottom), `tests/test_rls_coverage.py` (frozenset + count)

**Interfaces:**
- Produces: `Cr26Document` with `id`, `organization_id`, `system_id`, `kind`, `document`, `ruleset_version`, `schema_version`, `is_valid`, `validation_errors`, `created_at`, `updated_at`, `updated_by`.

- [ ] **Step 1: Read the precedent**

Open `migrations/versions/0075_remediation_plans.py` in full before writing anything. It is this table's shape almost exactly and the migration below is modelled on it line for line — the column style, the index naming (`ix_ccf_<table>_<col>`), the GRANT, and the RLS block.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_cr26_document_model.py
"""CR26 deliverable documents: one row per (system, kind).

FedRAMP publishes eleven CR26 deliverables as JSON schemas. The documents are
stored as documents, validated against those schemas, rather than decomposed
into columns -- FedRAMP versions that shape independently and has already
revised the CPO to 0.1.4, so a decomposed copy would drift and need a migration
every time they add a field.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ccf.cr26.validation import CR26_KINDS
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_cr26 import Cr26Document


async def _system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name}-system")
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


async def test_a_document_round_trips_through_the_database() -> None:
    org_id, system_id = await _system("cr26-doc-roundtrip")
    async with session_scope() as s:
        s.add(
            Cr26Document(
                organization_id=org_id,
                system_id=system_id,
                kind="cpo",
                document={"serviceIdentification": {"serviceName": "Acme"}},
                ruleset_version="2026-06-24",
                schema_version="0.1.4",
                is_valid=False,
                validation_errors=["<root>: 'serviceProperties' is a required property"],
            )
        )

    async with session_scope() as s:
        got = (
            await s.execute(select(Cr26Document).where(Cr26Document.system_id == system_id))
        ).scalar_one()
        # Read back from Postgres, not from the object that was written: the
        # point is that JSONB round-trips, not that Python remembers.
        assert got.document["serviceIdentification"]["serviceName"] == "Acme"
        assert got.is_valid is False
        assert got.validation_errors[0].endswith("is a required property")
        assert got.ruleset_version == "2026-06-24"
        assert got.schema_version == "0.1.4"


async def test_one_current_document_per_system_and_kind() -> None:
    """The documents are self-versioning -- the CPO's own metadata block carries
    version, lastUpdated and updateSource -- so a second row for the same kind
    would be a second record of one fact. History is AuditLog's job."""
    org_id, system_id = await _system("cr26-doc-unique")
    async with session_scope() as s:
        s.add(
            Cr26Document(
                organization_id=org_id, system_id=system_id, kind="cpo",
                document={}, ruleset_version="2026-06-24", is_valid=False,
            )
        )

    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(
                Cr26Document(
                    organization_id=org_id, system_id=system_id, kind="cpo",
                    document={}, ruleset_version="2026-06-24", is_valid=False,
                )
            )


async def test_two_kinds_coexist_for_one_system() -> None:
    """The uniqueness is per KIND -- a system has a CPO and an SDR at once."""
    org_id, system_id = await _system("cr26-doc-two-kinds")
    async with session_scope() as s:
        for kind in ("cpo", "sdr"):
            s.add(
                Cr26Document(
                    organization_id=org_id, system_id=system_id, kind=kind,
                    document={}, ruleset_version="2026-06-24", is_valid=False,
                )
            )

    async with session_scope() as s:
        kinds = (
            await s.execute(
                select(Cr26Document.kind).where(Cr26Document.system_id == system_id)
            )
        ).scalars().all()
        assert sorted(kinds) == ["cpo", "sdr"]


async def test_every_vendored_kind_is_storable() -> None:
    """A kind vocabulary the column rejects is a vocabulary in name only.

    Iterates CR26_KINDS rather than a hand-copied list, so a schema added
    upstream cannot be silently unstorable.
    """
    assert len(CR26_KINDS) == 11
    org_id, system_id = await _system("cr26-doc-all-kinds")
    async with session_scope() as s:
        for kind in CR26_KINDS:
            s.add(
                Cr26Document(
                    organization_id=org_id, system_id=system_id, kind=kind,
                    document={}, ruleset_version="2026-06-24", is_valid=False,
                )
            )
        await s.flush()
```

- [ ] **Step 3: Run to verify it fails**

Run: `.venv/bin/python3 -m pytest tests/test_cr26_document_model.py -q` with `timeout: 600000`
Expected: collection error — `ModuleNotFoundError: No module named 'ccf.models_cr26'`.

- [ ] **Step 4: Write the model**

```python
# src/ccf/models_cr26.py
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
    BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func,
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
    #: Nullable and CASCADE, following 0075_remediation_plans -- an unscoped
    #: principal writes a null-org row that the RLS predicate hides from every
    #: scoped tenant.
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
```

Wire it into metadata. `src/ccf/models.py` ends with a `from . import (models_capability, models_cci, models_enforcement, models_grc, models_patching, models_waivers)` block and a matching list below it — add `models_cr26` to **both**, in alphabetical order. **`migrations/env.py` builds metadata from `ccf.models` alone**, so without this the FK to `ccf.systems` raises `NoReferencedTableError` in anything that sorts `Base.metadata`.

Note `updated_at` uses `onupdate`: `expire_on_commit=False` is set on this project's sessions, but a column with `onupdate` still leaves the object stale after commit, and serializing it then raises `MissingGreenlet`. Refresh explicitly after an update.

- [ ] **Step 5: Write the migration**

Model it on `0075_remediation_plans.py`, which you read in Step 1.

```python
# migrations/versions/0079_cr26_documents.py
"""CR26 deliverable documents, stored as documents and validated on write.

FedRAMP publishes the eleven CR26 deliverables as JSON schemas and versions
each independently, so the shape is theirs, not ours: a decomposed copy would
drift and need a migration for every field they add. One table keyed by the
closed CR26_KINDS vocabulary serves all eleven, rather than eleven near-
identical tables as the SDR, OCR, VDR and SCN arrive.

Tenancy: ``cr26_documents`` carries ``organization_id`` and gets the direct
``organization_id = ccf.current_tenant()`` policy, so it joins
``EXPECTED_TENANT_ISOLATION_TABLES`` (count 137 -> 138) and is NOT added to
``GLOBAL_TABLES``.

Revision ID: 0079_cr26_documents
Revises: 0078_cr26_certification
Create Date: 2026-09-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0079_cr26_documents"
down_revision = "0078_cr26_certification"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    op.create_table(
        "cr26_documents",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column(
            "document",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("ruleset_version", sa.String(length=32), nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=True),
        sa.Column("is_valid", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "validation_errors",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("updated_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.UniqueConstraint("system_id", "kind", name="uq_cr26_document_system_kind"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_cr26_documents_org", "cr26_documents", ["organization_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ccf_cr26_documents_system", "cr26_documents", ["system_id"], schema=_SCHEMA
    )
    op.create_index("ix_ccf_cr26_documents_kind", "cr26_documents", ["kind"], schema=_SCHEMA)

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.execute("ALTER TABLE ccf.cr26_documents ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.cr26_documents FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.cr26_documents "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON ccf.cr26_documents")
    op.drop_table("cr26_documents", schema=_SCHEMA)
```

Copy the GRANT text from `0075` rather than trusting this transcription.

- [ ] **Step 6: Update the RLS guards**

In `tests/test_rls_coverage.py`: add `"cr26_documents"` to `EXPECTED_TENANT_ISOLATION_TABLES` (keep alphabetical order) and change the hardcoded count at line ~185 from `137` to `138`. Do **not** touch `GLOBAL_TABLES` in `tests/test_rls_registry_no_gap.py` — this is tenant data, not authority-published reference data.

- [ ] **Step 7: Migrate and verify exactly one head**

```bash
.venv/bin/alembic upgrade head
.venv/bin/alembic heads          # FULL output. Must print exactly ONE line.
```

Expected: `0079_cr26_documents (head)`. **Never pipe through `tail`.**

Run: `.venv/bin/python3 -m pytest tests/test_cr26_document_model.py tests/test_rls_coverage.py tests/test_rls_registry_no_gap.py -q`

- [ ] **Step 8: Prove the tenancy guard bites**

Temporarily remove `"cr26_documents"` from `EXPECTED_TENANT_ISOLATION_TABLES` (leaving the count at 138), re-run `tests/test_rls_coverage.py`, and confirm it FAILS naming the table. **Restore it.** Paste both outputs. A positive-control snapshot nobody has watched fail is not a control.

- [ ] **Step 9: Commit**

```bash
git add src/ccf/models_cr26.py src/ccf/models.py migrations/versions/0079_cr26_documents.py tests/test_cr26_document_model.py tests/test_rls_coverage.py
git commit -m "feat(cr26): a table for CR26 deliverable documents

FedRAMP publishes the eleven CR26 deliverables as JSON schemas and versions
each independently -- the CPO is at 0.1.4 while assessor-information is at
1.0.1 -- so the shape is theirs, not ours. Storing the document rather than
decomposing it into columns means the vendored schema stays the only
constraint, and a FedRAMP revision needs no migration here.

One table keyed by the closed CR26_KINDS vocabulary serves all eleven kinds,
rather than eleven near-identical tables as the SDR, OCR, VDR and SCN arrive.
VDR and VER are mandatory from 2026-12-07, ahead of the CPO's own date.

One row per (system, kind): the documents are self-versioning, so a history
table would be a second record of one fact.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Validate on write

**Files:**
- Create: `src/ccf/cr26/store.py`, `tests/test_cr26_document_store.py`

**Interfaces:**
- Consumes: `Cr26Document` (Task 1); `ccf.cr26.validation.validate_document`, `CR26_KINDS`, and the manifest's `ruleset_version` / per-file `schema_version`.
- Produces: `async def put_document(session, *, system_id, kind, document, updated_by=None) -> Cr26Document`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cr26_document_store.py
"""Every write records a verdict; no write is refused for being invalid.

A draft is necessarily incomplete -- a CPO cannot carry its assessor before an
assessor exists -- so refusing invalid writes makes authoring impossible.
Refusal belongs at export or submit. What must hold is that no document is
ever stored without a recorded verdict.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ccf.cr26.store import put_document
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_cr26 import Cr26Document

_VALID_SDR = {
    "certificationPackageOverviewUri": "https://example.gov/cpo.json",
    "fedRampRequirements": [{"frrID": "SDR-CSO-FRR", "frrImplementation": ["Implemented."]}],
}


async def _system(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name}-system")
        s.add(sysm)
        await s.flush()
        return sysm.id


async def test_a_valid_document_is_stored_and_marked_valid() -> None:
    system_id = await _system("cr26-store-valid")
    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="sdr", document=_VALID_SDR)
        assert row.is_valid is True
        assert row.validation_errors == []
        assert row.ruleset_version == "2026-06-24"
        assert row.schema_version  # the SDR schema's own $schemaVersion


async def test_an_invalid_document_is_STORED_not_refused() -> None:
    """The whole point. Authoring a CPO means saving it incomplete for a while."""
    system_id = await _system("cr26-store-invalid")
    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="cpo", document={})
        assert row.is_valid is False
        assert row.validation_errors, "an invalid document must say why"

    async with session_scope() as s:
        got = (
            await s.execute(select(Cr26Document).where(Cr26Document.system_id == system_id))
        ).scalar_one()
        assert got.document == {}
        assert got.is_valid is False


async def test_the_tenant_is_taken_from_the_system() -> None:
    system_id = await _system("cr26-store-tenant")
    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="cpo", document={})
        sysm = await s.get(System, system_id)
        assert row.organization_id == sysm.organization_id


async def test_writing_the_same_kind_twice_updates_rather_than_duplicating() -> None:
    """One row per (system, kind) -- a second write is an edit, not a new row."""
    system_id = await _system("cr26-store-upsert")
    async with session_scope() as s:
        await put_document(s, system_id=system_id, kind="sdr", document={})
    async with session_scope() as s:
        await put_document(s, system_id=system_id, kind="sdr", document=_VALID_SDR)

    async with session_scope() as s:
        rows = (
            await s.execute(select(Cr26Document).where(Cr26Document.system_id == system_id))
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].is_valid is True, "the verdict must be refreshed, not left stale"


async def test_the_verdict_is_never_left_stale() -> None:
    """The guarantee that matters: no path writes `document` without re-judging
    it. Going valid -> invalid must flip is_valid back."""
    system_id = await _system("cr26-store-stale")
    async with session_scope() as s:
        await put_document(s, system_id=system_id, kind="sdr", document=_VALID_SDR)
    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="sdr", document={})
        assert row.is_valid is False
        assert row.validation_errors


async def test_an_unknown_kind_is_refused() -> None:
    """Refusing an invalid DOCUMENT would break authoring; refusing an unknown
    KIND is different -- there is no schema to judge it against, so storing it
    would mean storing something that can never be validated."""
    system_id = await _system("cr26-store-badkind")
    async with session_scope() as s:
        with pytest.raises(ValueError, match="kind"):
            await put_document(s, system_id=system_id, kind="not-a-kind", document={})


async def test_an_unknown_system_is_refused() -> None:
    async with session_scope() as s:
        with pytest.raises(ValueError, match="system"):
            await put_document(s, system_id=10**9, kind="cpo", document={})
```

- [ ] **Step 2: Run to verify it fails**

Expected: `ModuleNotFoundError: No module named 'ccf.cr26.store'`.

- [ ] **Step 3: Implement**

```python
# src/ccf/cr26/store.py
"""Persist a CR26 deliverable document, judging it on every write.

The contract is narrow and worth stating: **an invalid document is stored, an
unknown kind is refused.** A draft is necessarily incomplete -- a CPO cannot
carry its assessor before an assessor exists -- so refusing invalid writes
would make authoring impossible, and refusal belongs at export or submit
instead. An unknown *kind* is different: there is no vendored schema to judge
it against, so storing it would mean storing something that can never be
validated at all.

What must hold on every path: no document is stored without a recorded
verdict. There is no way to write ``document`` and leave ``is_valid`` stale.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import System
from ..models_cr26 import Cr26Document
from .validation import CR26_KINDS, schema_path, validate_document


def _manifest() -> dict[str, Any]:
    from pathlib import Path  # noqa: PLC0415

    path = Path(__file__).with_name("schemas") / "MANIFEST.json"
    return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _versions(kind: str) -> tuple[str, str | None]:
    """The ruleset revision and this schema's own semver, from the manifest."""
    manifest = _manifest()
    filename = CR26_KINDS[kind][0]
    entry = manifest["files"].get(filename, {})
    return str(manifest["ruleset_version"]), entry.get("schema_version")


async def put_document(
    session: AsyncSession,
    *,
    system_id: int,
    kind: str,
    document: dict[str, Any],
    updated_by: str | None = None,
) -> Cr26Document:
    """Create or replace this system's document of ``kind``, judged on write."""
    if kind not in CR26_KINDS or schema_path(kind) is None:
        raise ValueError(f"unknown CR26 document kind: {kind!r}")

    system = await session.get(System, system_id)
    if system is None:
        raise ValueError(f"unknown system: {system_id!r}")

    report = validate_document(document, kind)
    ruleset_version, schema_version = _versions(kind)

    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id, Cr26Document.kind == kind
            )
        )
    ).scalars().first()
    if row is None:
        row = Cr26Document(system_id=system_id, kind=kind)
        session.add(row)

    # Tenant comes from the system, never from a caller-supplied value.
    row.organization_id = system.organization_id
    row.document = document
    row.ruleset_version = ruleset_version
    row.schema_version = schema_version
    row.is_valid = report.ok
    row.validation_errors = list(report.errors)
    if updated_by is not None:
        row.updated_by = updated_by
    await session.flush()
    return row
```

- [ ] **Step 4: Run to verify it passes**

Run the focused file, then `ruff check .` and `mypy src`.

- [ ] **Step 5: Prove the verdict guarantee bites**

Temporarily delete the `row.is_valid = report.ok` line, run the focused file, and confirm `test_the_verdict_is_never_left_stale` FAILS. **Restore it.** Paste both outputs — that test is the one carrying this task's central claim, so it must be watched failing.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/cr26/store.py tests/test_cr26_document_store.py
git commit -m "feat(cr26): judge every document on write, and store it either way

An invalid document is stored; an unknown kind is refused. A draft is
necessarily incomplete -- a CPO cannot carry its assessor before an assessor
exists -- so refusing invalid writes would make authoring impossible, and
refusal belongs at export or submit. An unknown kind is different: there is no
vendored schema to judge it against.

The guarantee is that no document is stored without a recorded verdict,
alongside the ruleset revision and schema version it was judged against.

This also gives the schema spine its first production consumer -- both prior
branches' reviews noted the validator had no caller outside its own tests.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: The CPO seeder, and the no-derivation guard

**Files:**
- Create: `src/ccf/cr26/cpo.py`, `tests/test_cr26_cpo_seed.py`, `tests/test_cr26_certification_type_not_derived.py`

**Interfaces:**
- Consumes: `put_document` (Task 2), `Organization`, `System`.
- Produces: `async def seed_cpo(session, *, system_id) -> Cr26Document`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cr26_cpo_seed.py
"""The CPO seeder fills what the platform knows -- three fields of ten.

This is deliberately not a generator. providerName, serviceName and
serviceDescription are the only required CPO fields with a source here;
serviceAcronym, fedRampPackageId, website, logo, certificationType, serviceType
and deploymentModel are facts about the business that live nowhere in the
platform, and inventing them would be worse than leaving them out.
"""

from __future__ import annotations

from ccf.cr26.cpo import SEEDED_FIELDS, seed_cpo
from ccf.db import session_scope
from ccf.models import Organization, System


async def _system(name: str, description: str | None = None) -> int:
    async with session_scope() as s:
        org = Organization(name=f"{name} Provider")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} Service", description=description)
        s.add(sysm)
        await s.flush()
        return sysm.id


async def test_the_seeder_fills_exactly_the_three_fields_it_can() -> None:
    system_id = await _system("Acme", description="An Acme service.")
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        ident = row.document["serviceIdentification"]
        assert ident["providerName"] == "Acme Provider"
        assert ident["serviceName"] == "Acme Service"
        assert ident["serviceDescription"] == "An Acme service."
        assert sorted(ident) == sorted(SEEDED_FIELDS)


async def test_the_seeded_document_is_INVALID_and_that_is_correct() -> None:
    """Seven required fields have no source. A seeder that produced a valid
    document would have invented them."""
    system_id = await _system("Beta")
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        assert row.is_valid is False
        missing = " ".join(row.validation_errors)
        for field in ("serviceAcronym", "fedRampPackageId", "website", "logo"):
            assert field in missing, f"{field} should be reported missing: {row.validation_errors}"


async def test_certification_type_is_not_seeded() -> None:
    """It is a declaration the provider makes, not a fact we can compute --
    see tests/test_cr26_certification_type_not_derived.py."""
    system_id = await _system("Gamma")
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        assert "certificationType" not in row.document["serviceIdentification"]


async def test_seeding_does_not_clobber_an_authored_document() -> None:
    """Re-seeding must not wipe fields a human supplied -- otherwise the first
    accidental re-seed destroys the seven fields only a human can provide."""
    system_id = await _system("Delta")
    async with session_scope() as s:
        row = await seed_cpo(s, system_id=system_id)
        row.document = {
            **row.document,
            "serviceIdentification": {
                **row.document["serviceIdentification"],
                "serviceAcronym": "DELTA",
                "certificationType": "20x",
            },
        }
        await s.flush()

    async with session_scope() as s:
        again = await seed_cpo(s, system_id=system_id)
        ident = again.document["serviceIdentification"]
        assert ident["serviceAcronym"] == "DELTA"
        assert ident["certificationType"] == "20x"
```

```python
# tests/test_cr26_certification_type_not_derived.py
"""Nothing may derive the CPO's certificationType from a Certification Class.

certificationType enumerates 20x and Rev5 -- which deliverable profile a
package is filed under. It is tempting to infer it from whether a system has a
certification_class, and that inference must not be made: through 2026-27 an
offering may hold a Rev5 ATO and pursue a CR26 Certification at once, so the
presence of a Class says nothing definitive about the profile. It is the same
class of mistake as deriving Class from baseline, which
tests/test_certification_class_is_independent.py exists to prevent.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src" / "ccf"
_TYPE = "certificationType"
_CLASS_SOURCES = ("certification_class", "certification_path", "baseline")


def _derivations(tree: ast.AST, label: str) -> list[str]:
    """Any assignment that both mentions certificationType and reads a Class.

    Deliberately blunt: certificationType may be assigned a literal, or a
    variable, or set inside a dict -- what is forbidden is only that its value
    is computed from certification_class, certification_path or baseline. So
    the test is "this statement mentions the field AND its value mentions a
    Class source", which catches the subscript, attribute and dict-literal
    forms without enumerating them.
    """
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        value = ast.dump(node.value)
        if _TYPE in ast.dump(node) and any(src in value for src in _CLASS_SOURCES):
            hits.append(f"{label}:{node.lineno} derives {_TYPE} from a Class or baseline")
    return hits


def test_no_code_derives_certification_type_from_a_class_or_baseline() -> None:
    hits: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits += _derivations(tree, str(path.relative_to(_SRC)))
    assert not hits, hits


def test_the_guard_detects_the_shape_it_forbids() -> None:
    tree = ast.parse(
        'ident["certificationType"] = "20x" if system.certification_class else "Rev5"'
    )
    assert _derivations(tree, "fake.py") == [
        "fake.py:1 derives certificationType from a Class or baseline"
    ]


def test_the_guard_reads_the_real_source_tree() -> None:
    assert len(list(_SRC.rglob("*.py"))) > 50
```

- [ ] **Step 2: Run to verify they fail**

Expected: `ModuleNotFoundError: No module named 'ccf.cr26.cpo'` for the first file; the guard file should already pass (nothing derives it yet) — **that is expected, and Step 5 is what proves it can fail.**

- [ ] **Step 3: Implement**

```python
# src/ccf/cr26/cpo.py
"""Seed a Certification Package Overview with what the platform actually knows.

**This is not a generator, and it must not become one.** The CPO has ten
required fields. Three have a source here:

===========================  ==========================
``providerName``             ``Organization.name``
``serviceName``              ``System.name``
``serviceDescription``       ``System.description``
===========================  ==========================

The rest -- ``serviceAcronym``, ``fedRampPackageId``, ``website``, ``logo``,
``certificationType``, ``serviceType`` and ``deploymentModel``, plus
``contactInformation`` -- are facts about the business that exist nowhere in
this platform. ``Vendor`` is third-party supply chain, and there is no party or
contact table at all. Inventing plausible values would produce a document that
validates and is wrong, which is worse than one that visibly does not validate.

So the seeded document is **invalid by design**, and a test asserts that. The
value this module adds is a starting point and a verdict, not a deliverable.

``certificationType`` is deliberately absent: it is a declaration the provider
makes, not a fact the platform can compute. Inferring it from
``certification_class`` is the same mistake as deriving Class from ``baseline``
-- see :mod:`tests.test_cr26_certification_type_not_derived`.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Organization, System
from ..models_cr26 import Cr26Document
from .store import put_document

#: The only ``serviceIdentification`` fields the platform can fill.
SEEDED_FIELDS: tuple[str, ...] = ("providerName", "serviceName", "serviceDescription")


async def seed_cpo(session: AsyncSession, *, system_id: int) -> Cr26Document:
    """Create or refresh this system's CPO skeleton, preserving authored fields."""
    system = await session.get(System, system_id)
    if system is None:
        raise ValueError(f"unknown system: {system_id!r}")
    org = await session.get(Organization, system.organization_id)

    seeded: dict[str, Any] = {
        "providerName": org.name if org is not None else "",
        "serviceName": system.name,
        "serviceDescription": system.description or "",
    }

    existing = await _current(session, system_id)
    document: dict[str, Any] = dict(existing) if existing else {}
    identification = dict(document.get("serviceIdentification") or {})
    # Seeded values fill gaps; anything a human authored wins. Re-seeding must
    # never destroy the seven fields only a human can supply.
    for field, value in seeded.items():
        identification.setdefault(field, value)
    document["serviceIdentification"] = identification

    return await put_document(session, system_id=system_id, kind="cpo", document=document)


async def _current(session: AsyncSession, system_id: int) -> dict[str, Any] | None:
    from sqlalchemy import select  # noqa: PLC0415

    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id, Cr26Document.kind == "cpo"
            )
        )
    ).scalars().first()
    return dict(row.document) if row is not None else None
```

Note `setdefault`, not assignment: re-seeding preserves authored values. `test_seeding_does_not_clobber_an_authored_document` is what pins that.

- [ ] **Step 4: Run to verify they pass**

Run both focused files, then `ruff check .` and `mypy src`.

- [ ] **Step 5: Prove the no-derivation guard bites**

Temporarily add to `src/ccf/cr26/cpo.py`:

```python
    identification["certificationType"] = "20x" if system.certification_class else "Rev5"
```

Run `tests/test_cr26_certification_type_not_derived.py` — expected: FAIL naming `cr26/cpo.py` and the line. **Revert it**, confirm green, and run `git status` to prove nothing leaked. Paste both outputs.

- [ ] **Step 6: Full verification and commit**

```bash
.venv/bin/python3 -m pytest -q     # timeout: 900000
.venv/bin/ruff check . && .venv/bin/mypy src
.venv/bin/alembic heads            # FULL output, one head
```

```bash
git add src/ccf/cr26/cpo.py tests/test_cr26_cpo_seed.py tests/test_cr26_certification_type_not_derived.py
git commit -m "feat(cr26): seed a CPO with the three fields the platform knows

Not a generator, and the tests pin that it must not become one. The CPO has
ten required fields and three have a source here -- providerName, serviceName,
serviceDescription. Acronym, package id, website, logo, certificationType,
service model, deployment model and contacts are facts about the business that
live nowhere in this platform, and inventing plausible values would produce a
document that validates and is wrong.

So the seeded document is invalid by design, and a test asserts it, naming the
fields still missing. Re-seeding uses setdefault so an authored value always
wins -- otherwise one accidental re-seed destroys the seven fields only a human
can supply.

certificationType is left unset and guarded: inferring it from a Certification
Class is the same mistake as deriving Class from baseline.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Notes for the executor

- **Do not add columns for the seven unsourced CPO fields.** The spec's whole argument is that FedRAMP owns this shape; a column per field re-declares it here and drifts on their next revision.
- **Do not make the seeder produce a valid document.** Its invalidity is the honest signal that seven facts are still owed by a human.
- **Do not refuse an invalid document at write time.** Refusal belongs at submit, which this unit does not ship.
- **Do not add a history table.** The documents carry their own version metadata; history is `AuditLog`'s job, via `record_event`.
- After committing a task, run `git show --stat` and confirm the intended files are in it — and **stage explicit paths, never `git add -A`**, which swept an unrelated file into a commit earlier in this programme.
