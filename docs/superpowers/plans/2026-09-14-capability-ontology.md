# Assurance Capability Ontology (P1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Concord a `Capability` — a thing the organization *does*, authored once and reused across every system, project, and framework — so one MFA decision stops being rewritten into a dozen controls per framework.

**Architecture:** One org-scoped `Capability` object plus four single-edge tables (canonical control, `SystemComponent`, `Risk`, KSI). Cross-framework reach resolves through the *existing* `framework_mappings` crosswalk at query time, never a second mapping table. Control status is *annotated* on `ControlImplementation` via sibling `derived_*` columns — never overwriting `status`, never creating a row.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2 async, Alembic, Typer, pytest + pytest-asyncio, PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-09-14-capability-ontology-design.md`
**Inventory (authoritative on what already exists):** `docs/architecture/forge-capability-inventory.md`

## Global Constraints

- **Integrate, do not duplicate.** `framework_mappings` stays the only crosswalk. `impl_status` stays the only implementation-status vocabulary. `governance/scheduler.py` stays the only scheduler. `ccf.api.audit.record_event` stays the only audit writer.
- **Derivation never writes `ControlImplementation.status`, and never creates a `ControlImplementation` row.** `status` is `NOT NULL DEFAULT 'not_implemented'`, so a created row would assert `not_implemented` for a control that previously had *no row* — and "absent" is not "not_implemented" to the existing coverage and analytics queries. A row-count assertion enforces this.
- **A capability maps to the canonical 800-53 control id only** (`AC-2` form, stored as a string). Mapping capability→each framework would fork the crosswalk.
- **`controls.identifier` is zero-padded (`AC-01`); the canonical form is `AC-1`.** Every join from a capability to `controls` MUST canonicalize. `ccf.catalog.canonical` exists for this.
- **All five new tables are tenant-owned** — each carries `organization_id`, gets `ENABLE` + `FORCE ROW LEVEL SECURITY` and a `tenant_isolation` policy. They MUST NOT be added to `GLOBAL_TABLES` in `tests/test_rls_registry_no_gap.py`.
- **RLS predicate, verbatim from migration 0064:** `(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())`
- Every migration includes the `pg_roles` GRANT guard. Confirm `alembic heads` returns exactly one head.
- **Test database is on port 5434.** Run with `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`. Never run two pytest sessions at once.
- **Tests share one database.** `session_scope` COMMITS and `clean_migrated_db` migrates once per *session*. Never assume an empty DB; use unique values for unique columns (`Organization.name`, `Control.identifier`, `KSI.identifier` are all UNIQUE); clean up rows other modules count.
- `ruff check src tests` and `mypy src` must be clean.

---

### Task 1: Rollup — the pure function

The whole derivation rests on this, and it needs no database, so it comes first.

**Files:**
- Create: `src/ccf/capability/__init__.py`
- Create: `src/ccf/capability/rollup.py`
- Test: `tests/test_capability_rollup.py`

**Interfaces:**
- Produces: `roll_up(statuses: Iterable[str]) -> str | None` — the derived status for one control, or `None` when nothing contributes. Also `SATISFIED: frozenset[str]` and `RANK: tuple[str, ...]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_capability_rollup.py
"""Deterministic rollup of capability statuses into one derived control status."""

from __future__ import annotations

import pytest

from ccf.capability.rollup import roll_up


def test_all_implemented_is_implemented() -> None:
    assert roll_up(["implemented", "implemented"]) == "implemented"


def test_worst_of_wins() -> None:
    """Conservative by design: over-claiming control status is the dangerous direction."""
    assert roll_up(["implemented", "planned"]) == "partial"
    assert roll_up(["implemented", "not_implemented"]) == "partial"
    assert roll_up(["partial", "implemented"]) == "partial"


def test_all_not_implemented_stays_not_implemented() -> None:
    assert roll_up(["not_implemented", "not_implemented"]) == "not_implemented"


def test_inherited_counts_as_satisfied() -> None:
    assert roll_up(["inherited"]) == "inherited"
    assert roll_up(["implemented", "inherited"]) == "implemented"


def test_not_applicable_is_excluded() -> None:
    assert roll_up(["implemented", "not_applicable"]) == "implemented"


def test_no_contributors_yields_none() -> None:
    """None means 'write nothing', not a misleading not_implemented."""
    assert roll_up([]) is None
    assert roll_up(["not_applicable", "not_applicable"]) is None


def test_unknown_status_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown capability status"):
        roll_up(["definitely_not_a_status"])


def test_single_planned_is_planned() -> None:
    assert roll_up(["planned"]) == "planned"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_capability_rollup.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.capability'`

- [ ] **Step 3: Write minimal implementation**

`src/ccf/capability/__init__.py`:

```python
"""Assurance capability ontology — the thing the organization *does*.

A :class:`~ccf.models_capability.Capability` is authored once at the
organization level and reused across every system, project, and framework,
replacing narrative duplicated per control. Its edges point at canonical
controls, system components, risks, and KSIs; cross-framework reach resolves
through Concord's existing ``framework_mappings`` crosswalk rather than a
second mapping table.
"""

from __future__ import annotations

from .rollup import roll_up

__all__ = ["roll_up"]
```

`src/ccf/capability/rollup.py`:

```python
"""Roll capability statuses up into one derived control status.

Pure -- no database, no I/O -- so the rule is unit-testable and cheap to reason
about. The rule is deliberately conservative: a control covered by one
``planned`` capability among ``implemented`` ones derives ``partial``, not
``implemented``. Over-claiming control status in an authorization package is
the dangerous direction; under-claiming is merely cautious, and
``derived_from`` records which capability lowered the result.

Capabilities are treated as *jointly* required for a control, which is the safe
reading when the model cannot yet express "alternative means" (see the spec's
open item 2).
"""

from __future__ import annotations

from collections.abc import Iterable

#: Statuses that mean the capability is in place.
SATISFIED: frozenset[str] = frozenset({"implemented", "inherited"})

#: Worst-to-best. Position is the rank used to pick the winning status.
RANK: tuple[str, ...] = (
    "not_implemented",
    "planned",
    "partial",
    "implemented",
    "inherited",
)

#: Excluded from the rollup entirely rather than ranked.
EXCLUDED: frozenset[str] = frozenset({"not_applicable"})


def roll_up(statuses: Iterable[str]) -> str | None:
    """The derived status for one control, or ``None`` to write nothing.

    ``None`` -- for no contributors, or only ``not_applicable`` ones -- is the
    honest answer and deliberately distinct from ``not_implemented``, which
    would assert something about a control nobody has claimed.
    """
    considered: list[str] = []
    for s in statuses:
        if s in EXCLUDED:
            continue
        if s not in RANK:
            raise ValueError(f"unknown capability status: {s!r}")
        considered.append(s)
    if not considered:
        return None

    worst = min(considered, key=RANK.index)
    # A mix of satisfied and unsatisfied is partial, not the worst member:
    # some of the control *is* in place, which "not_implemented" would deny.
    if worst not in SATISFIED and any(s in SATISFIED for s in considered):
        return "partial"
    return worst
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_capability_rollup.py -v`
Expected: 8 passed

- [ ] **Step 5: Lint and commit**

```bash
ruff check src/ccf/capability tests/test_capability_rollup.py
mypy src/ccf/capability
git add src/ccf/capability tests/test_capability_rollup.py
git commit -m "feat(capability): deterministic, conservative status rollup"
```

---

### Task 2: Models and migration

**Files:**
- Create: `src/ccf/models_capability.py`
- Create: `migrations/versions/0067_capability_ontology.py`
- Modify: `src/ccf/models.py` (add `derived_*` to `ControlImplementation`; `capability_id` to `Evidence`, `implementation_id` nullable)
- Test: `tests/test_capability_models.py`

**Interfaces:**
- Produces: `Capability`, `CapabilityControl`, `CapabilityComponent`, `CapabilityRisk`, `CapabilityKsi` in `ccf.models_capability`; `ControlImplementation.derived_status | derived_at | derived_from`; `Evidence.capability_id`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_capability_models.py
"""Capability schema: constraints, tenancy, and the evidence parent CHECK."""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import Evidence, Organization
from ccf.models_capability import Capability, CapabilityControl

_SEQ = itertools.count()


async def _org(session) -> Organization:
    org = Organization(name=f"CapOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    return org


async def _cap(session, org_id: int, key: str = "mfa") -> Capability:
    cap = Capability(
        organization_id=org_id, key=key, title="MFA everywhere", status="implemented"
    )
    session.add(cap)
    await session.flush()
    return cap


async def test_capability_key_is_unique_per_org() -> None:
    async with session_scope() as session:
        org = await _org(session)
        await _cap(session, org.id, "dup-key")
        await _cap(session, org.id, "dup-key")
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_same_key_allowed_in_different_orgs() -> None:
    async with session_scope() as session:
        a, b = await _org(session), await _org(session)
        await _cap(session, a.id, "shared-key")
        await _cap(session, b.id, "shared-key")
        await session.flush()  # uniqueness is per-org, not global


async def test_control_edge_is_unique() -> None:
    async with session_scope() as session:
        org = await _org(session)
        cap = await _cap(session, org.id, "edge-unique")
        for _ in range(2):
            session.add(
                CapabilityControl(
                    organization_id=org.id, capability_id=cap.id, control_id="AC-2"
                )
            )
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_capability_stores_canonical_control_id() -> None:
    """Canonical form (AC-2), not the zero-padded controls.identifier (AC-01)."""
    async with session_scope() as session:
        org = await _org(session)
        cap = await _cap(session, org.id, "canonical")
        session.add(
            CapabilityControl(organization_id=org.id, capability_id=cap.id, control_id="AC-2")
        )
        await session.flush()
        row = (
            await session.execute(
                select(CapabilityControl).where(CapabilityControl.capability_id == cap.id)
            )
        ).scalars().one()
        assert row.control_id == "AC-2"


async def test_evidence_requires_at_least_one_parent() -> None:
    async with session_scope() as session:
        session.add(Evidence(kind="document", title="orphan", metadata_json={}))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_evidence_may_be_parented_to_a_capability_alone() -> None:
    async with session_scope() as session:
        org = await _org(session)
        cap = await _cap(session, org.id, "ev-parent")
        session.add(
            Evidence(
                capability_id=cap.id, kind="config_export", title="CA policy", metadata_json={}
            )
        )
        await session.flush()  # no implementation_id needed


async def test_all_five_tables_have_rls_policies() -> None:
    """Tenant-owned tables must be policied, not allowlisted as global."""
    expected = {
        "capabilities",
        "capability_controls",
        "capability_components",
        "capability_risks",
        "capability_ksis",
    }
    async with session_scope() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT c.relname FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "JOIN pg_policy p ON p.polrelid = c.oid "
                    "WHERE n.nspname = 'ccf' AND p.polname = 'tenant_isolation' "
                    "AND c.relname = ANY(:names)"
                ).bindparams(names=sorted(expected))
            )
        ).scalars().all()
    assert set(rows) == expected


async def test_derived_columns_default_empty() -> None:
    from ccf.models import ControlImplementation

    async with session_scope() as session:
        cols = (
            await session.execute(
                text(
                    "SELECT column_name, is_nullable FROM information_schema.columns "
                    "WHERE table_schema='ccf' AND table_name='control_implementations' "
                    "AND column_name IN ('derived_status','derived_at','derived_from')"
                )
            )
        ).all()
        assert {c[0] for c in cols} == {"derived_status", "derived_at", "derived_from"}
        assert ControlImplementation.derived_status is not None  # mapped
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_capability_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.models_capability'`

- [ ] **Step 3: Write the models**

`src/ccf/models_capability.py`:

```python
"""Capability ontology models.

A :class:`Capability` is what the organization *does* -- authored once at the
organization level and reused everywhere -- and the four edge tables connect it
to canonical controls, the system components that implement it, the risks it
mitigates, and the FedRAMP 20x KSIs it satisfies.

Every table here is tenant-owned and carries ``organization_id``, because the
RLS policy compares ``ccf.current_tenant()`` against that column. Omitting it
would force these onto the ``GLOBAL_TABLES`` allowlist, which would be a
tenant-isolation hole rather than a shortcut.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
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

#: Reuses the existing implementation-status enum rather than inventing a
#: parallel vocabulary. create_type=False: the type already exists.
_STATUS = Enum(
    "not_implemented",
    "planned",
    "partial",
    "implemented",
    "inherited",
    "not_applicable",
    name="impl_status",
    schema="ccf",
    create_type=False,
)


class Capability(Base):
    """A reusable security capability -- the unit of implementation.

    Authored once per organization and mapped to many controls across many
    frameworks, so a single decision ("Conditional Access enforces MFA") is
    stated once instead of restated in IA-2, IA-2(1), AC-7, MA-4 and every
    other dependent control, per project, per framework.
    """

    __tablename__ = "capabilities"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    #: Stable, addressable slug -- also what a future capability pack installs by.
    key: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    #: The reusable narrative. P4 derives SSP prose from this.
    statement: Mapped[str | None] = mapped_column(Text)
    purpose: Mapped[str | None] = mapped_column(Text)
    responsible_role: Mapped[str | None] = mapped_column(String(128))
    #: Grouping label -- Paramify's "Solution" layer as a facet, not a table.
    solution: Mapped[str | None] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(_STATUS, default="not_implemented")
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "key", name="uq_capability_org_key"),
        {"schema": "ccf"},
    )


class CapabilityControl(Base):
    """Capability -> canonical 800-53 control id.

    ``control_id`` is the **canonical** string (``AC-2``), not a foreign key.
    The workbook-derived ``controls`` table and the OSCAL catalog genuinely
    differ -- ``catalog/reconcile.py`` exists because of it -- so an FK would
    make capabilities un-mappable to catalog controls the workbook lacks.
    Cross-framework reach resolves via ``canonicalize()`` ->
    ``controls.identifier`` -> ``framework_mappings`` at query time.
    """

    __tablename__ = "capability_controls"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    capability_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.capabilities.id", ondelete="CASCADE"), index=True
    )
    control_id: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("capability_id", "control_id", name="uq_capability_control"),
        {"schema": "ccf"},
    )


class CapabilityComponent(Base):
    """Capability -> the system component that implements it.

    Also how a capability binds to a *system*: there is no separate
    capability-to-system table because ``SystemComponent.type`` already
    includes ``policy`` and ``process``, so a policy- or process-backed
    capability binds through a component of that type. That is the OSCAL-native
    answer and it reuses ``boundary/``.
    """

    __tablename__ = "capability_components"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    capability_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.capabilities.id", ondelete="CASCADE"), index=True
    )
    component_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.system_components.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("capability_id", "component_id", name="uq_capability_component"),
        {"schema": "ccf"},
    )


class CapabilityRisk(Base):
    """Capability -> the risk it mitigates.

    This is the edge ``Risk`` has always lacked: before this table, a risk had
    nothing to point at and the register was terminal.
    """

    __tablename__ = "capability_risks"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    capability_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.capabilities.id", ondelete="CASCADE"), index=True
    )
    risk_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.risks.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("capability_id", "risk_id", name="uq_capability_risk"),
        {"schema": "ccf"},
    )


class CapabilityKsi(Base):
    """Capability -> the FedRAMP 20x KSI it satisfies.

    Stores ``KSI.identifier``, not a row id: ``ksis`` is global reference data
    that reseeding can renumber, and the identifier is the stable key. KSIs are
    capability-*shaped requirements*, so they map to capabilities roughly 1:1
    where controls fragment one capability across many.
    """

    __tablename__ = "capability_ksis"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    capability_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.capabilities.id", ondelete="CASCADE"), index=True
    )
    ksi_identifier: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("capability_id", "ksi_identifier", name="uq_capability_ksi"),
        {"schema": "ccf"},
    )
```

- [ ] **Step 4: Alter the two existing models**

In `src/ccf/models.py`, inside `ControlImplementation`, after `narrative`:

```python
    # Capability-derived status, written by ccf.capability.derive. Deliberately
    # a sibling of `status`, not a replacement: UNIQUE (system_id, control_id)
    # forbids two rows, and keeping both means `status` retains its exact
    # meaning for every existing reader while divergence stays visible --
    # "your SSP says planned but your capabilities say implemented" is
    # actionable, and an overwrite would destroy it.
    derived_status: Mapped[str | None] = mapped_column(
        Enum(
            "not_implemented",
            "planned",
            "partial",
            "implemented",
            "inherited",
            "not_applicable",
            name="impl_status",
            schema="ccf",
            create_type=False,
        )
    )
    derived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Which capabilities contributed, so a conservative rollup is explainable.
    derived_from: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
```

In `Evidence`, make the parent optional and add the capability parent:

```python
    # Nullable since 0067: evidence may hang off a capability instead, so
    # "our MFA configuration" is stored once rather than per control. The
    # table CHECK guarantees at least one parent, which is strictly stronger
    # than the NOT NULL it replaces.
    implementation_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.control_implementations.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
    )
    capability_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.capabilities.id", ondelete="CASCADE"), index=True
    )
```

Add to `Evidence.__table_args__` (create it if the class has none):

```python
    __table_args__ = (
        CheckConstraint(
            "implementation_id IS NOT NULL OR capability_id IS NOT NULL",
            name="ck_evidence_has_parent",
        ),
    )
```

Ensure `CheckConstraint` is imported from `sqlalchemy` at the top of
`models.py` (check first — most names are already imported).

- [ ] **Step 5: Write the migration**

```python
# migrations/versions/0067_capability_ontology.py
"""Capability ontology -- the reusable unit of implementation.

Concord was control-first: narrative authored per control, evidence parented to
a (system, control) pair, and a crosswalk that ran control-to-control. One MFA
decision therefore had to be restated in every dependent control, per project,
per framework. `capabilities` is the missing object -- what the organization
*does* -- with edges to canonical controls, system components, risks, and KSIs.

Tenancy: all five tables are tenant-owned and get the standard
`tenant_isolation` policy. They are deliberately NOT added to GLOBAL_TABLES in
tests/test_rls_registry_no_gap.py -- that allowlist is for authority-published
reference data like catalog_sources, and using it here would be an isolation
hole.

`control_implementations` gains derived_status/derived_at/derived_from as
SIBLINGS of `status`, because UNIQUE (system_id, control_id) forbids two rows.
Derivation never writes `status` and never creates a row: `status` is NOT NULL
DEFAULT 'not_implemented', so a created row would assert something about a
control nobody has claimed and could shift reported coverage.

`evidence.implementation_id` becomes nullable so evidence can hang off a
capability instead, guarded by a CHECK that at least one parent is set --
strictly stronger than the NOT NULL it replaces. Every existing row already has
implementation_id, so no data migration is needed.

Revision ID: 0067_capability_ontology
Revises: 0066_catalog_revisions
Create Date: 2026-09-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0067_capability_ontology"
down_revision = "0066_catalog_revisions"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"

TENANT_TABLES: tuple[str, ...] = (
    "capabilities",
    "capability_controls",
    "capability_components",
    "capability_risks",
    "capability_ksis",
)

# Verbatim from migration 0064 -- the repo standard.
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"

_IMPL_STATUS = postgresql.ENUM(
    "not_implemented",
    "planned",
    "partial",
    "implemented",
    "inherited",
    "not_applicable",
    name="impl_status",
    schema=_SCHEMA,
    create_type=False,
)


def _org_fk(name: str = "organization_id") -> sa.Column:
    return sa.Column(
        name,
        sa.Integer,
        sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )


def _edge_table(table: str, extra: list[sa.Column], unique: sa.UniqueConstraint) -> None:
    op.create_table(
        table,
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_fk(),
        sa.Column(
            "capability_id",
            sa.BigInteger,
            sa.ForeignKey("ccf.capabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        *extra,
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        unique,
        schema=_SCHEMA,
    )
    op.create_index(f"ix_ccf_{table}_org", table, ["organization_id"], schema=_SCHEMA)
    op.create_index(f"ix_ccf_{table}_capability", table, ["capability_id"], schema=_SCHEMA)


def upgrade() -> None:
    op.create_table(
        "capabilities",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_fk(),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("statement", sa.Text),
        sa.Column("purpose", sa.Text),
        sa.Column("responsible_role", sa.String(128)),
        sa.Column("solution", sa.String(128)),
        sa.Column("status", _IMPL_STATUS, nullable=False, server_default="not_implemented"),
        sa.Column("notes", sa.Text),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("organization_id", "key", name="uq_capability_org_key"),
        schema=_SCHEMA,
    )
    op.create_index("ix_ccf_capabilities_org", "capabilities", ["organization_id"], schema=_SCHEMA)
    op.create_index("ix_ccf_capabilities_key", "capabilities", ["key"], schema=_SCHEMA)
    op.create_index(
        "ix_ccf_capabilities_solution", "capabilities", ["solution"], schema=_SCHEMA
    )

    _edge_table(
        "capability_controls",
        [sa.Column("control_id", sa.String(64), nullable=False)],
        sa.UniqueConstraint("capability_id", "control_id", name="uq_capability_control"),
    )
    op.create_index(
        "ix_ccf_capability_controls_control", "capability_controls", ["control_id"], schema=_SCHEMA
    )

    _edge_table(
        "capability_components",
        [
            sa.Column(
                "component_id",
                sa.BigInteger,
                sa.ForeignKey("ccf.system_components.id", ondelete="CASCADE"),
                nullable=False,
            )
        ],
        sa.UniqueConstraint("capability_id", "component_id", name="uq_capability_component"),
    )

    _edge_table(
        "capability_risks",
        [
            sa.Column(
                "risk_id",
                sa.Integer,
                sa.ForeignKey("ccf.risks.id", ondelete="CASCADE"),
                nullable=False,
            )
        ],
        sa.UniqueConstraint("capability_id", "risk_id", name="uq_capability_risk"),
    )

    _edge_table(
        "capability_ksis",
        [sa.Column("ksi_identifier", sa.String(32), nullable=False)],
        sa.UniqueConstraint("capability_id", "ksi_identifier", name="uq_capability_ksi"),
    )

    # --- annotate control_implementations (never replace `status`) ----------
    op.add_column(
        "control_implementations",
        sa.Column("derived_status", _IMPL_STATUS, nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        "control_implementations",
        sa.Column("derived_at", sa.DateTime(timezone=True), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        "control_implementations",
        sa.Column(
            "derived_from", postgresql.JSONB, nullable=False, server_default="{}"
        ),
        schema=_SCHEMA,
    )

    # --- evidence may hang off a capability instead -------------------------
    op.add_column(
        "evidence",
        sa.Column(
            "capability_id",
            sa.BigInteger,
            sa.ForeignKey("ccf.capabilities.id", ondelete="CASCADE"),
            nullable=True,
        ),
        schema=_SCHEMA,
    )
    op.create_index("ix_ccf_evidence_capability", "evidence", ["capability_id"], schema=_SCHEMA)
    op.alter_column("evidence", "implementation_id", nullable=True, schema=_SCHEMA)
    op.create_check_constraint(
        "ck_evidence_has_parent",
        "evidence",
        "implementation_id IS NOT NULL OR capability_id IS NOT NULL",
        schema=_SCHEMA,
    )

    # Standard grant guard: no-op where the ccf_app role was never created.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )

    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
        )


def downgrade() -> None:
    op.drop_constraint("ck_evidence_has_parent", "evidence", schema=_SCHEMA, type_="check")
    op.drop_index("ix_ccf_evidence_capability", "evidence", schema=_SCHEMA)
    op.drop_column("evidence", "capability_id", schema=_SCHEMA)
    # Left nullable on downgrade: rows created against 0067 may legitimately
    # have no implementation_id, and restoring NOT NULL would fail on them.
    for col in ("derived_from", "derived_at", "derived_status"):
        op.drop_column("control_implementations", col, schema=_SCHEMA)
    for table in reversed(TENANT_TABLES):
        op.drop_table(table, schema=_SCHEMA)
```

- [ ] **Step 6: Register the models and migrate**

`models_capability.py` must be imported somewhere the metadata sees it. Check
how `models_grc.py` and `models_tprm.py` are registered (likely
`migrations/env.py` or `ccf/models/__init__` re-exports) and follow the same
path:

```bash
grep -rn "models_grc\|models_tprm" migrations/env.py src/ccf/db.py src/ccf/__init__.py
```

Then:

```bash
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
alembic heads          # MUST print exactly one head
alembic upgrade head
pytest tests/test_capability_models.py -v
```
Expected: one head; migration applies; 8 passed.

- [ ] **Step 7: Confirm the RLS guard still passes**

Run: `pytest tests/test_rls_registry_no_gap.py -v`
Expected: PASS **without** adding any capability table to `GLOBAL_TABLES` — the
five tables carry `organization_id` and now have policies, so they satisfy the
tenant-owned branch of the guard.

- [ ] **Step 8: Commit**

```bash
ruff check src/ccf/models_capability.py src/ccf/models.py migrations/versions/0067_capability_ontology.py tests/test_capability_models.py
mypy src/ccf/models_capability.py src/ccf/models.py
git add src/ccf/models_capability.py src/ccf/models.py migrations/versions/0067_capability_ontology.py tests/test_capability_models.py
git commit -m "feat(capability): capability and edge tables with tenant isolation"
```

---

### Task 3: Derivation

**Files:**
- Create: `src/ccf/capability/derive.py`
- Test: `tests/test_capability_derive.py`

**Interfaces:**
- Consumes: `roll_up` (Task 1); `Capability`, `CapabilityControl`, `CapabilityComponent` (Task 2); `ccf.catalog.canonical.canonicalize`
- Produces: `async derive_for_system(session, *, system_id: int) -> int` — number of `ControlImplementation` rows annotated.

- [ ] **Step 1: Confirm `canonicalize`'s exact signature and return type**

```bash
grep -n "def canonicalize" -A 18 src/ccf/catalog/canonical.py
```

It returns an object with a `.value` attribute (or `None`); use that shape, do
not guess.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_capability_derive.py
"""Derivation annotates control status without ever claiming it."""

from __future__ import annotations

import itertools

from sqlalchemy import func, select

from ccf.capability.derive import derive_for_system
from ccf.db import session_scope
from ccf.models import (
    Control,
    ControlImplementation,
    Organization,
    System,
    SystemComponent,
)
from ccf.models_capability import Capability, CapabilityComponent, CapabilityControl

_SEQ = itertools.count()


async def _fixture(session, *, cap_status: str, control_identifier: str):
    """One org + system + component + capability mapped to one control."""
    org = Organization(name=f"DerOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"Sys-{next(_SEQ)}", baseline="moderate")
    session.add(sys_)
    await session.flush()
    comp = SystemComponent(
        organization_id=org.id, system_id=sys_.id, type="service", title="Entra ID"
    )
    session.add(comp)
    ctl = Control(identifier=control_identifier)
    session.add(ctl)
    await session.flush()
    cap = Capability(
        organization_id=org.id, key=f"cap-{next(_SEQ)}", title="MFA", status=cap_status
    )
    session.add(cap)
    await session.flush()
    session.add(
        CapabilityComponent(
            organization_id=org.id, capability_id=cap.id, component_id=comp.id
        )
    )
    session.add(
        CapabilityControl(organization_id=org.id, capability_id=cap.id, control_id="AC-2")
    )
    await session.flush()
    return org, sys_, ctl, cap


async def test_annotates_existing_implementation_row() -> None:
    async with session_scope() as session:
        _, sys_, ctl, cap = await _fixture(
            session, cap_status="implemented", control_identifier="AC-02"
        )
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="planned")
        session.add(impl)
        await session.flush()

        touched = await derive_for_system(session, system_id=sys_.id)
        assert touched == 1
        await session.refresh(impl)
        assert impl.derived_status == "implemented"
        assert impl.derived_at is not None
        assert cap.key in str(impl.derived_from)


async def test_never_mutates_authored_status() -> None:
    """Divergence must be preserved, not silently resolved."""
    async with session_scope() as session:
        _, sys_, ctl, _ = await _fixture(
            session, cap_status="implemented", control_identifier="AC-03"
        )
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="planned")
        session.add(impl)
        await session.flush()

        await derive_for_system(session, system_id=sys_.id)
        await session.refresh(impl)
        assert impl.status == "planned"          # authored value untouched
        assert impl.derived_status == "implemented"  # divergence visible


async def test_never_creates_an_implementation_row() -> None:
    """status is NOT NULL DEFAULT 'not_implemented'; a created row would assert
    something about a control nobody claimed, and could shift coverage math."""
    async with session_scope() as session:
        _, sys_, _, _ = await _fixture(
            session, cap_status="implemented", control_identifier="AC-04"
        )
        before = (
            await session.execute(select(func.count()).select_from(ControlImplementation))
        ).scalar_one()
        touched = await derive_for_system(session, system_id=sys_.id)
        after = (
            await session.execute(select(func.count()).select_from(ControlImplementation))
        ).scalar_one()
        assert after == before
        assert touched == 0


async def test_matches_zero_padded_control_identifier() -> None:
    """Capability stores AC-2; controls.identifier is AC-02. Must still join."""
    async with session_scope() as session:
        _, sys_, ctl, _ = await _fixture(
            session, cap_status="implemented", control_identifier="AC-05"
        )
        # Re-point the capability edge at the padded control this fixture made.
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="planned")
        session.add(impl)
        await session.flush()
        edge = (
            await session.execute(
                select(CapabilityControl).where(CapabilityControl.control_id == "AC-2")
            )
        ).scalars().first()
        assert edge is not None
        edge.control_id = "AC-5"
        await session.flush()

        await derive_for_system(session, system_id=sys_.id)
        await session.refresh(impl)
        assert impl.derived_status == "implemented"


async def test_is_idempotent() -> None:
    async with session_scope() as session:
        _, sys_, ctl, _ = await _fixture(
            session, cap_status="implemented", control_identifier="AC-06"
        )
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="planned")
        session.add(impl)
        await session.flush()
        await derive_for_system(session, system_id=sys_.id)
        await session.refresh(impl)
        first = impl.derived_at
        touched = await derive_for_system(session, system_id=sys_.id)
        await session.refresh(impl)
        assert impl.derived_status == "implemented"
        assert touched == 1
        assert impl.derived_at == first  # unchanged value -> no rewrite


async def test_not_applicable_capability_writes_nothing() -> None:
    async with session_scope() as session:
        _, sys_, ctl, _ = await _fixture(
            session, cap_status="not_applicable", control_identifier="AC-07"
        )
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="planned")
        session.add(impl)
        await session.flush()
        await derive_for_system(session, system_id=sys_.id)
        await session.refresh(impl)
        assert impl.derived_status is None


async def test_system_with_no_capabilities_is_a_noop() -> None:
    async with session_scope() as session:
        org = Organization(name=f"EmptyOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"Empty-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        assert await derive_for_system(session, system_id=sys_.id) == 0
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_capability_derive.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.capability.derive'`

- [ ] **Step 4: Write the implementation**

```python
# src/ccf/capability/derive.py
"""Derive control status from capability coverage.

Annotates, never asserts. For each control a system's capabilities claim, the
rolled-up status is written to ``ControlImplementation.derived_status`` --
alongside the authored ``status``, never over it -- so divergence between what
an SSP says and what the capabilities and evidence show stays visible and
actionable.

Two rules this module must never break:

* **It never writes ``status``.** That column is what every existing reader
  (SSP, scoring, analytics, OSCAL export) consumes.
* **It never creates a ``ControlImplementation`` row.** ``status`` is
  ``NOT NULL DEFAULT 'not_implemented'``, so a created row would assert
  ``not_implemented`` for a control that previously had *no row at all* --
  and "absent" is not "not_implemented" to the coverage and analytics queries.
  Fabricating rows could silently change reported coverage.

Coverage for controls with no implementation row is answered live by the read
API instead, so there are no stale derived rows.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.canonical import canonicalize
from ..logging import get_logger
from ..models import Control, ControlImplementation, SystemComponent
from ..models_capability import Capability, CapabilityComponent, CapabilityControl
from .rollup import roll_up

log = get_logger(__name__)


async def _capabilities_for_system(
    session: AsyncSession, *, system_id: int
) -> list[tuple[Capability, str]]:
    """``(capability, canonical_control_id)`` pairs bound to this system.

    Binding runs capability -> component -> system, which is also how a
    policy- or process-backed capability attaches: ``SystemComponent.type``
    already includes ``policy`` and ``process``.
    """
    rows = (
        await session.execute(
            select(Capability, CapabilityControl.control_id)
            .join(CapabilityComponent, CapabilityComponent.capability_id == Capability.id)
            .join(SystemComponent, SystemComponent.id == CapabilityComponent.component_id)
            .join(CapabilityControl, CapabilityControl.capability_id == Capability.id)
            .where(SystemComponent.system_id == system_id)
        )
    ).all()
    return [(r[0], r[1]) for r in rows]


async def _control_rows_by_canonical(
    session: AsyncSession, canonical_ids: set[str]
) -> dict[str, int]:
    """Map canonical id -> ``controls.id``.

    ``controls.identifier`` is zero-padded (``AC-01``) while the canonical form
    is ``AC-1``, so both sides are canonicalized before comparison rather than
    string-matched.
    """
    if not canonical_ids:
        return {}
    out: dict[str, int] = {}
    for ctl_id, identifier in (
        await session.execute(select(Control.id, Control.identifier))
    ).all():
        c = canonicalize(identifier)
        if c is not None and c.value in canonical_ids:
            out[c.value] = ctl_id
    return out


async def derive_for_system(session: AsyncSession, *, system_id: int) -> int:
    """Annotate this system's control implementations from capability coverage.

    Returns the number of rows whose derived values actually changed, so an
    idempotent re-run reports zero.
    """
    pairs = await _capabilities_for_system(session, system_id=system_id)
    if not pairs:
        return 0

    # canonical control id -> the capabilities claiming it
    grouped: dict[str, list[Capability]] = {}
    for cap, raw_control in pairs:
        c = canonicalize(raw_control)
        if c is None:
            continue
        grouped.setdefault(c.value, []).append(cap)

    control_ids = await _control_rows_by_canonical(session, set(grouped))
    now = datetime.now(UTC)
    touched = 0

    for canonical_id, caps in grouped.items():
        ctl_row_id = control_ids.get(canonical_id)
        if ctl_row_id is None:
            continue  # capability targets a control this deployment lacks
        derived = roll_up([c.status for c in caps])
        if derived is None:
            continue

        impl = (
            await session.execute(
                select(ControlImplementation).where(
                    ControlImplementation.system_id == system_id,
                    ControlImplementation.control_id == ctl_row_id,
                )
            )
        ).scalars().first()
        if impl is None:
            continue  # never create a row -- see the module docstring

        contributors: dict[str, Any] = {
            "capabilities": sorted(c.key for c in caps),
            # Status per contributor, so a conservative rollup is explainable:
            # the reader can see which capability lowered the result.
            "detail": sorted(f"{c.key}={c.status}" for c in caps),
        }
        if impl.derived_status == derived and impl.derived_from == contributors:
            continue  # unchanged -- keep derived_at stable so re-runs are no-ops

        impl.derived_status = derived
        impl.derived_at = now
        impl.derived_from = contributors
        touched += 1

    if touched:
        await session.flush()
        log.info("capability.derived", system_id=system_id, rows=touched)
    return touched
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_capability_derive.py -v`
Expected: 7 passed

- [ ] **Step 6: Commit**

```bash
ruff check src/ccf/capability/derive.py tests/test_capability_derive.py
mypy src/ccf/capability/derive.py
git add src/ccf/capability/derive.py tests/test_capability_derive.py
git commit -m "feat(capability): derive control status without asserting it"
```

---

### Task 4: Cross-framework reach

**Files:**
- Create: `src/ccf/capability/service.py`
- Test: `tests/test_capability_reach.py`

**Interfaces:**
- Produces:
  - `async framework_reach(session, *, capability_id: int) -> dict[str, list[str]]` — framework code → mapped values
  - `async capabilities_for_control(session, *, control_id: str) -> list[Capability]` — canonical id in, capabilities out

- [ ] **Step 1: Write the failing test**

```python
# tests/test_capability_reach.py
"""One capability, many frameworks -- through the existing crosswalk."""

from __future__ import annotations

import itertools

from sqlalchemy import select

from ccf.capability.service import capabilities_for_control, framework_reach
from ccf.db import session_scope
from ccf.models import Control, Framework, FrameworkMapping, Organization
from ccf.models_capability import Capability, CapabilityControl

_SEQ = itertools.count()


async def _framework(session, code: str) -> Framework:
    fw = (
        await session.execute(select(Framework).where(Framework.code == code))
    ).scalars().first()
    if fw is None:
        fw = Framework(code=code, name=code)
        session.add(fw)
        await session.flush()
    return fw


async def test_reaches_other_frameworks_via_the_crosswalk() -> None:
    async with session_scope() as session:
        org = Organization(name=f"ReachOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        cap = Capability(
            organization_id=org.id, key=f"reach-{next(_SEQ)}", title="MFA",
            status="implemented",
        )
        session.add(cap)
        # A control this deployment knows, in the zero-padded form.
        ctl = Control(identifier="IA-02")
        session.add(ctl)
        cmmc = await _framework(session, "CMMC")
        await session.flush()
        session.add(
            FrameworkMapping(
                control_id=ctl.id, framework_id=cmmc.id,
                column_key="CMMC", value="IA.L2-3.5.3",
            )
        )
        # The capability maps to the CANONICAL id, not the padded one.
        session.add(
            CapabilityControl(organization_id=org.id, capability_id=cap.id, control_id="IA-2")
        )
        await session.flush()

        reach = await framework_reach(session, capability_id=cap.id)
        assert "IA.L2-3.5.3" in reach.get("CMMC", [])


async def test_capability_with_no_edges_reaches_nothing() -> None:
    async with session_scope() as session:
        org = Organization(name=f"ReachOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        cap = Capability(
            organization_id=org.id, key=f"bare-{next(_SEQ)}", title="Bare",
            status="planned",
        )
        session.add(cap)
        await session.flush()
        assert await framework_reach(session, capability_id=cap.id) == {}


async def test_control_absent_from_this_deployment_returns_empty() -> None:
    """A capability may target a catalog control the workbook lacks."""
    async with session_scope() as session:
        org = Organization(name=f"ReachOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        cap = Capability(
            organization_id=org.id, key=f"ghost-{next(_SEQ)}", title="Ghost",
            status="implemented",
        )
        session.add(cap)
        await session.flush()
        session.add(
            CapabilityControl(
                organization_id=org.id, capability_id=cap.id, control_id="ZZ-99"
            )
        )
        await session.flush()
        assert await framework_reach(session, capability_id=cap.id) == {}


async def test_capabilities_for_control_is_canonical_insensitive() -> None:
    async with session_scope() as session:
        org = Organization(name=f"ReachOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        cap = Capability(
            organization_id=org.id, key=f"lookup-{next(_SEQ)}", title="Lookup",
            status="implemented",
        )
        session.add(cap)
        await session.flush()
        session.add(
            CapabilityControl(organization_id=org.id, capability_id=cap.id, control_id="AU-2")
        )
        await session.flush()

        # Both spellings must find it.
        for spelling in ("AU-2", "AU-02"):
            found = await capabilities_for_control(session, control_id=spelling)
            assert cap.id in [c.id for c in found], spelling
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_capability_reach.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.capability.service'`

- [ ] **Step 3: Write the implementation**

```python
# src/ccf/capability/service.py
"""Read-side queries over the capability graph.

Cross-framework reach goes *through* Concord's existing ``framework_mappings``
crosswalk rather than a second mapping table: a capability maps only to the
canonical 800-53 control, and every other framework is reached by traversal.
Mapping a capability directly to each framework would fork the crosswalk and
guarantee the two drift apart.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.canonical import canonicalize
from ..models import Control, Framework, FrameworkMapping
from ..models_capability import Capability, CapabilityControl


async def _canonical_edges(session: AsyncSession, capability_id: int) -> set[str]:
    raw = (
        await session.execute(
            select(CapabilityControl.control_id).where(
                CapabilityControl.capability_id == capability_id
            )
        )
    ).scalars().all()
    out: set[str] = set()
    for r in raw:
        c = canonicalize(r)
        if c is not None:
            out.add(c.value)
    return out


async def framework_reach(
    session: AsyncSession, *, capability_id: int
) -> dict[str, list[str]]:
    """``{framework_code: [mapped values]}`` for one capability.

    Empty when the capability has no control edges, or when its controls are
    absent from this deployment's catalog -- a capability may legitimately
    target a control the workbook lacks.
    """
    canonical = await _canonical_edges(session, capability_id)
    if not canonical:
        return {}

    rows = (
        await session.execute(
            select(Control.identifier, Framework.code, FrameworkMapping.value)
            .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
            .join(Framework, Framework.id == FrameworkMapping.framework_id)
        )
    ).all()

    reach: dict[str, list[str]] = {}
    for identifier, code, value in rows:
        c = canonicalize(identifier)
        if c is None or c.value not in canonical or not value:
            continue
        reach.setdefault(code, [])
        if value not in reach[code]:
            reach[code].append(value)
    for code in reach:
        reach[code].sort()
    return reach


async def capabilities_for_control(
    session: AsyncSession, *, control_id: str
) -> list[Capability]:
    """Capabilities claiming ``control_id``, in any spelling of it.

    Accepts the canonical (``AC-2``) or zero-padded (``AC-02``) form, since
    callers hold whichever the surrounding data gave them.
    """
    target = canonicalize(control_id)
    if target is None:
        return []
    rows = (
        await session.execute(
            select(Capability, CapabilityControl.control_id).join(
                CapabilityControl, CapabilityControl.capability_id == Capability.id
            )
        )
    ).all()
    out: list[Capability] = []
    for cap, raw in rows:
        c = canonicalize(raw)
        if c is not None and c.value == target.value:
            out.append(cap)
    return out
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_capability_reach.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
ruff check src/ccf/capability/service.py tests/test_capability_reach.py
mypy src/ccf/capability/service.py
git add src/ccf/capability/service.py tests/test_capability_reach.py
git commit -m "feat(capability): cross-framework reach through the existing crosswalk"
```

---

### Task 5: API

**Files:**
- Create: `src/ccf/api/routes/capabilities.py`
- Modify: `src/ccf/api/routes/__init__.py` (register the router — check how siblings are registered first)
- Test: `tests/test_capability_api.py`

**Interfaces:**
- Consumes: `derive_for_system` (Task 3); `framework_reach`, `capabilities_for_control` (Task 4)
- Produces the endpoints listed in the spec §4.4.

- [ ] **Step 1: Read how an existing tenant-scoped router is registered and gated**

```bash
grep -n "capabilities\|vendors\|risks" src/ccf/api/routes/__init__.py | head
sed -n '1,40p' src/ccf/api/routes/risks.py
```

Follow that file's exact dependency set (`get_session`, `get_principal`,
`require_role` for writes) and its serializer style.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_capability_api.py
"""Capability endpoints: CRUD, edge replacement, reach, and derivation."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


@pytest.mark.asyncio
async def test_openapi_lists_capability_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/capabilities" in paths
        assert "/api/capabilities/{capability_id}" in paths
        assert "/api/capabilities/{capability_id}/controls" in paths
        assert "/api/capabilities/{capability_id}/frameworks" in paths
        assert "/api/controls/{control_id}/capabilities" in paths
        assert "/api/systems/{system_id}/derive-status" in paths


@pytest.mark.asyncio
async def test_create_list_and_fetch_a_capability() -> None:
    async with _client() as client:
        created = await client.post(
            "/api/capabilities",
            json={"key": "api-mfa", "title": "MFA everywhere", "status": "implemented"},
        )
        assert created.status_code == 201, created.text
        cap_id = created.json()["id"]

        listed = await client.get("/api/capabilities")
        assert listed.status_code == 200
        assert any(c["id"] == cap_id for c in listed.json())

        one = await client.get(f"/api/capabilities/{cap_id}")
        assert one.status_code == 200
        assert one.json()["key"] == "api-mfa"


@pytest.mark.asyncio
async def test_replacing_control_edges_is_idempotent() -> None:
    async with _client() as client:
        cap_id = (
            await client.post(
                "/api/capabilities",
                json={"key": "api-edges", "title": "Edges", "status": "planned"},
            )
        ).json()["id"]

        first = await client.put(
            f"/api/capabilities/{cap_id}/controls", json={"control_ids": ["AC-2", "IA-2"]}
        )
        assert first.status_code == 200
        assert sorted(first.json()["control_ids"]) == ["AC-2", "IA-2"]

        again = await client.put(
            f"/api/capabilities/{cap_id}/controls", json={"control_ids": ["AC-2", "IA-2"]}
        )
        assert sorted(again.json()["control_ids"]) == ["AC-2", "IA-2"]

        shrunk = await client.put(
            f"/api/capabilities/{cap_id}/controls", json={"control_ids": ["AC-2"]}
        )
        assert shrunk.json()["control_ids"] == ["AC-2"]


@pytest.mark.asyncio
async def test_unknown_capability_is_404() -> None:
    async with _client() as client:
        assert (await client.get("/api/capabilities/999999")).status_code == 404
        assert (
            await client.get("/api/capabilities/999999/frameworks")
        ).status_code == 404


@pytest.mark.asyncio
async def test_duplicate_key_is_409() -> None:
    async with _client() as client:
        body = {"key": "api-dup", "title": "Dup", "status": "planned"}
        assert (await client.post("/api/capabilities", json=body)).status_code == 201
        assert (await client.post("/api/capabilities", json=body)).status_code == 409


@pytest.mark.asyncio
async def test_key_is_generated_from_the_title_when_omitted() -> None:
    """Spec open item 1: server-generated, client may override."""
    async with _client() as client:
        first = await client.post(
            "/api/capabilities",
            json={"title": "Conditional Access Enforces MFA", "status": "implemented"},
        )
        assert first.status_code == 201
        assert first.json()["key"] == "conditional-access-enforces-mfa"

        # A second capability with the same title must not collide.
        second = await client.post(
            "/api/capabilities",
            json={"title": "Conditional Access Enforces MFA", "status": "planned"},
        )
        assert second.status_code == 201
        assert second.json()["key"] == "conditional-access-enforces-mfa-2"
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_capability_api.py -v`
Expected: FAIL — 404 on the new paths

- [ ] **Step 4: Implement the router**

```python
# src/ccf/api/routes/capabilities.py
"""Capability endpoints — the reusable unit of implementation.

Writes are role-gated and always scoped to the calling principal's
organization; ``organization_id`` is never read from a request body. Edge
collections are replaced with ``PUT`` rather than mutated per item: the client
already holds the whole set, and replace-set is idempotent.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...capability.derive import derive_for_system
from ...capability.service import capabilities_for_control, framework_reach
from ...catalog.canonical import canonicalize
from ...models_capability import (
    Capability,
    CapabilityComponent,
    CapabilityControl,
    CapabilityKsi,
    CapabilityRisk,
)
from ..auth_deps import get_principal, require_role
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["capabilities"])

_STATUSES = (
    "not_implemented",
    "planned",
    "partial",
    "implemented",
    "inherited",
    "not_applicable",
)


class CapabilityIn(BaseModel):
    key: str | None = None
    title: str
    statement: str | None = None
    purpose: str | None = None
    responsible_role: str | None = None
    solution: str | None = None
    status: str = "not_implemented"
    notes: str | None = None


class CapabilityPatch(BaseModel):
    title: str | None = None
    statement: str | None = None
    purpose: str | None = None
    responsible_role: str | None = None
    solution: str | None = None
    status: str | None = None
    notes: str | None = None


class ControlEdgesIn(BaseModel):
    control_ids: list[str]


class ComponentEdgesIn(BaseModel):
    component_ids: list[int]


class RiskEdgesIn(BaseModel):
    risk_ids: list[int]


class KsiEdgesIn(BaseModel):
    ksi_identifiers: list[str]


def _out(c: Capability) -> dict[str, Any]:
    return {
        "id": c.id,
        "organization_id": c.organization_id,
        "key": c.key,
        "title": c.title,
        "statement": c.statement,
        "purpose": c.purpose,
        "responsible_role": c.responsible_role,
        "solution": c.solution,
        "status": c.status,
        "notes": c.notes,
        "created_at": c.created_at,
        "updated_at": c.updated_at,
    }


def _slug(title: str) -> str:
    """A stable, readable key from a title."""
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return (s or "capability")[:56]


async def _unique_key(session: AsyncSession, *, org_id: int, base: str) -> str:
    """``base``, suffixed until unique within the organization.

    The key is server-generated so callers need not invent one, but a supplied
    key is honoured verbatim (and collides loudly with 409 rather than being
    silently renamed).
    """
    taken = set(
        (
            await session.execute(
                select(Capability.key).where(Capability.organization_id == org_id)
            )
        ).scalars().all()
    )
    if base not in taken:
        return base
    for n in range(2, 1000):
        candidate = f"{base}-{n}"
        if candidate not in taken:
            return candidate
    raise HTTPException(status_code=409, detail="Could not allocate a unique capability key")


async def _get_or_404(
    session: AsyncSession, capability_id: int, principal: Principal
) -> Capability:
    cap = await session.get(Capability, capability_id)
    if cap is None:
        raise HTTPException(status_code=404, detail="Unknown capability")
    if principal.org_id is not None and cap.organization_id != principal.org_id:
        # Indistinguishable from absent: never confirm existence across tenants.
        raise HTTPException(status_code=404, detail="Unknown capability")
    return cap


def _require_status(value: str | None) -> None:
    if value is not None and value not in _STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {_STATUSES}")


def _org_of(principal: Principal) -> int:
    if principal.org_id is None:
        raise HTTPException(
            status_code=400, detail="An organization-scoped principal is required"
        )
    return principal.org_id


@router.get("/capabilities")
async def list_capabilities(
    solution: str | None = None,
    status: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Capabilities visible to the caller, newest first."""
    stmt = select(Capability).order_by(Capability.id.desc())
    if principal.org_id is not None:
        stmt = stmt.where(Capability.organization_id == principal.org_id)
    if solution:
        stmt = stmt.where(Capability.solution == solution)
    if status:
        stmt = stmt.where(Capability.status == status)
    return [_out(c) for c in (await session.execute(stmt)).scalars().all()]


@router.post("/capabilities", status_code=201)
async def create_capability(
    body: CapabilityIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "editor")),
) -> dict[str, Any]:
    """Create a capability. A key is generated from the title when omitted."""
    _require_status(body.status)
    org_id = _org_of(principal)
    if body.key:
        clash = (
            await session.execute(
                select(Capability).where(
                    Capability.organization_id == org_id, Capability.key == body.key
                )
            )
        ).scalars().first()
        if clash is not None:
            raise HTTPException(
                status_code=409, detail=f"capability key already in use: {body.key!r}"
            )
        key = body.key
    else:
        key = await _unique_key(session, org_id=org_id, base=_slug(body.title))

    cap = Capability(
        organization_id=org_id,
        key=key,
        title=body.title,
        statement=body.statement,
        purpose=body.purpose,
        responsible_role=body.responsible_role,
        solution=body.solution,
        status=body.status,
        notes=body.notes,
    )
    session.add(cap)
    await session.flush()
    await session.commit()
    return _out(cap)


@router.get("/capabilities/{capability_id}")
async def get_capability(
    capability_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return _out(await _get_or_404(session, capability_id, principal))


@router.patch("/capabilities/{capability_id}")
async def update_capability(
    capability_id: int,
    body: CapabilityPatch,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "editor")),
) -> dict[str, Any]:
    _require_status(body.status)
    cap = await _get_or_404(session, capability_id, principal)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(cap, field, value)
    await session.commit()
    return _out(cap)


@router.delete("/capabilities/{capability_id}", status_code=204)
async def delete_capability(
    capability_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "editor")),
) -> None:
    cap = await _get_or_404(session, capability_id, principal)
    await session.delete(cap)  # edges cascade
    await session.commit()


async def _replace_edges(
    session: AsyncSession,
    *,
    model: type[Any],
    capability_id: int,
    org_id: int,
    column: str,
    values: list[Any],
) -> list[Any]:
    """Replace one edge collection wholesale; idempotent for the same set."""
    await session.execute(delete(model).where(model.capability_id == capability_id))
    unique: list[Any] = []
    for v in values:
        if v not in unique:
            unique.append(v)
    for v in unique:
        session.add(
            model(organization_id=org_id, capability_id=capability_id, **{column: v})
        )
    await session.flush()
    await session.commit()
    return unique


@router.put("/capabilities/{capability_id}/controls")
async def set_controls(
    capability_id: int,
    body: ControlEdgesIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "editor")),
) -> dict[str, Any]:
    """Replace the control edges, storing the canonical form of each id."""
    cap = await _get_or_404(session, capability_id, principal)
    canonical: list[str] = []
    for raw in body.control_ids:
        c = canonicalize(raw)
        if c is None:
            raise HTTPException(
                status_code=422, detail=f"not a recognisable control id: {raw!r}"
            )
        canonical.append(c.value)
    stored = await _replace_edges(
        session,
        model=CapabilityControl,
        capability_id=cap.id,
        org_id=cap.organization_id,
        column="control_id",
        values=canonical,
    )
    return {"capability_id": cap.id, "control_ids": stored}


@router.put("/capabilities/{capability_id}/components")
async def set_components(
    capability_id: int,
    body: ComponentEdgesIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "editor")),
) -> dict[str, Any]:
    cap = await _get_or_404(session, capability_id, principal)
    stored = await _replace_edges(
        session,
        model=CapabilityComponent,
        capability_id=cap.id,
        org_id=cap.organization_id,
        column="component_id",
        values=body.component_ids,
    )
    return {"capability_id": cap.id, "component_ids": stored}


@router.put("/capabilities/{capability_id}/risks")
async def set_risks(
    capability_id: int,
    body: RiskEdgesIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "editor")),
) -> dict[str, Any]:
    cap = await _get_or_404(session, capability_id, principal)
    stored = await _replace_edges(
        session,
        model=CapabilityRisk,
        capability_id=cap.id,
        org_id=cap.organization_id,
        column="risk_id",
        values=body.risk_ids,
    )
    return {"capability_id": cap.id, "risk_ids": stored}


@router.put("/capabilities/{capability_id}/ksis")
async def set_ksis(
    capability_id: int,
    body: KsiEdgesIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "editor")),
) -> dict[str, Any]:
    cap = await _get_or_404(session, capability_id, principal)
    stored = await _replace_edges(
        session,
        model=CapabilityKsi,
        capability_id=cap.id,
        org_id=cap.organization_id,
        column="ksi_identifier",
        values=body.ksi_identifiers,
    )
    return {"capability_id": cap.id, "ksi_identifiers": stored}


@router.get("/capabilities/{capability_id}/frameworks")
async def capability_frameworks(
    capability_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Every framework requirement this capability reaches via the crosswalk."""
    cap = await _get_or_404(session, capability_id, principal)
    return {
        "capability_id": cap.id,
        "frameworks": await framework_reach(session, capability_id=cap.id),
    }


@router.get("/controls/{control_id}/capabilities")
async def control_capabilities(
    control_id: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Which capabilities claim this control, in either spelling of its id."""
    caps = await capabilities_for_control(session, control_id=control_id)
    if principal.org_id is not None:
        caps = [c for c in caps if c.organization_id == principal.org_id]
    return [_out(c) for c in caps]


@router.post("/systems/{system_id}/derive-status")
async def derive_status(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "editor")),
) -> dict[str, Any]:
    """Annotate this system's control implementations from capability coverage.

    Never writes ``status`` and never creates a row — see
    :mod:`ccf.capability.derive`.
    """
    n = await derive_for_system(session, system_id=system_id)
    await session.commit()
    return {"system_id": system_id, "rows_annotated": n}
```

**Check `require_role`'s real role names before using them.** The literals
`"admin", "editor"` above must match what this codebase actually defines:

```bash
grep -rn "require_role(" --include="*.py" src/ccf/api/routes | head -5
grep -n "role" src/ccf/auth.py | head -10
```

Use the roles that appear there; do not invent names.

- [ ] **Step 5: Run tests and commit**

```bash
pytest tests/test_capability_api.py -v
ruff check src/ccf/api/routes/capabilities.py tests/test_capability_api.py
git add src/ccf/api/routes/capabilities.py src/ccf/api/routes/__init__.py tests/test_capability_api.py
git commit -m "feat(api): capability CRUD, edges, framework reach, and derivation"
```

---

### Task 6: CLI, scheduler wiring, and full verification

**Files:**
- Modify: `src/ccf/cli.py`
- Modify: `src/ccf/governance/scheduler.py`
- Test: `tests/test_capability_cli.py`

**Interfaces:**
- Produces: `ccf capability derive --system <id>`; a scheduler step calling `derive_for_system` for every system.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_capability_cli.py
"""The capability CLI group is registered and wired."""

from __future__ import annotations

from typer.testing import CliRunner

from ccf.cli import app

runner = CliRunner()


def test_capability_derive_is_registered() -> None:
    result = runner.invoke(app, ["capability", "derive", "--help"])
    assert result.exit_code == 0
    assert "system" in result.stdout


def test_existing_catalog_group_still_registered() -> None:
    """A new Typer group must not displace the ones already there."""
    assert runner.invoke(app, ["catalog", "revisions", "--help"]).exit_code == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_capability_cli.py -v`
Expected: FAIL — non-zero exit; group not registered

- [ ] **Step 3: Add the CLI group**

In `src/ccf/cli.py`, following the `catalog_app` pattern:

```python
capability_app = typer.Typer(
    help="Assurance capabilities — the reusable unit of implementation.",
    no_args_is_help=True,
)
app.add_typer(capability_app, name="capability")


@capability_app.command("derive")
def capability_derive(
    system: int = typer.Option(..., "--system", help="System id to derive status for."),
) -> None:
    """Annotate a system's control implementations from capability coverage."""
    from .capability.derive import derive_for_system  # noqa: PLC0415

    async def _run() -> Any:
        async with session_scope() as session:
            n = await derive_for_system(session, system_id=system)
            await session.commit()
            return n

    n = asyncio.run(_run())
    console.print(f"Annotated [green]{n}[/green] control implementation(s).")
```

- [ ] **Step 4: Wire the scheduler**

Read the cycle first, so the new step matches its existing error isolation and
tenant scoping exactly:

```bash
sed -n '1,60p' src/ccf/governance/scheduler.py
grep -n "async def \|try:\|except\|log\." src/ccf/governance/scheduler.py | head -40
```

Add the config flag to `src/ccf/config.py`, beside the other job flags:

```python
    # Annotate control implementations from capability coverage on each
    # scheduler cycle. Default on: derivation is non-destructive by
    # construction -- it never writes ControlImplementation.status and never
    # creates a row (see ccf.capability.derive).
    capability_derive_enabled: bool = Field(default=True)
```

Then add this job function to `src/ccf/governance/scheduler.py` and call it
from the cycle in the same place, and with the same `try`/`except` isolation,
that the existing jobs use:

```python
async def derive_capability_status(session: AsyncSession) -> int:
    """Annotate every system's control implementations from capability coverage.

    One system's failure must not abort the sweep, so each is isolated: a bad
    row in one tenant cannot stop the rest of the portfolio being refreshed.
    Returns the total number of implementation rows annotated.
    """
    from ..capability.derive import derive_for_system  # noqa: PLC0415
    from ..models import System  # noqa: PLC0415

    if not get_settings().capability_derive_enabled:
        return 0

    system_ids = (
        await session.execute(
            select(System.id).where(System.deleted_at.is_(None)).order_by(System.id)
        )
    ).scalars().all()

    total = 0
    for sid in system_ids:
        try:
            total += await derive_for_system(session, system_id=sid)
            await session.flush()
        except Exception as exc:  # one system must not abort the sweep
            log.warning("capability.derive_failed", system_id=sid, error=str(exc)[:200])
    if total:
        log.info("capability.derive_cycle", systems=len(system_ids), rows=total)
    return total
```

Check that `select`, `get_settings`, `log`, and `AsyncSession` are already
imported in `scheduler.py` (they almost certainly are — it runs DB jobs
already) and add only what is missing.

- [ ] **Step 5: Run the full suite**

```bash
export CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
pytest -q -p no:randomly
ruff check src tests
mypy src
alembic heads   # exactly one
```

Expected: only the known pre-existing failure
(`test_analytics_residual_and_overdue.py::test_dashboard_overview_sla_excludes_no_due_date_from_on_track`,
which fails on `main` at line 272 — verify it is still the *only* failure);
lint and types clean; one head.

- [ ] **Step 6: Mutation-test the new guards**

Reading is not verification. Delete each guard, confirm a test fails, restore:

1. the `if impl is None: continue` never-create guard in `derive.py`
2. the `if derived is None: continue` no-contributors guard
3. the `s in EXCLUDED` exclusion in `roll_up`
4. the `worst not in SATISFIED and any(...)` partial rule in `roll_up`
5. the `ck_evidence_has_parent` CHECK constraint
6. the `canonicalize` call in `_control_rows_by_canonical` (replace with a raw
   string compare — the `AC-2`/`AC-02` test must fail)
7. the 409 duplicate-key handler in the API

- [ ] **Step 7: Commit**

```bash
git add src/ccf/cli.py src/ccf/governance/scheduler.py src/ccf/config.py tests/test_capability_cli.py
git commit -m "feat(capability): derive on the existing scheduler cycle, plus CLI"
```
