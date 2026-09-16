# Posture Validation Spine (P2a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Concord say *which resources* failed a control test — "47 storage accounts evaluated, 3 allow public access, here are their ids" — instead of only that a test failed.

**Architecture:** Posture checks are declared content that auto-instantiate `ControlTest` rows; scans land in the existing `ControlTestResult` with a new per-resource child table. One result history, one verdict vocabulary, one POA&M path, one recovery loop — all of which already work and none of which are duplicated.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2 async, Alembic, Typer, pytest + pytest-asyncio, PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-09-14-posture-validation-spine-design.md`
**Inventory (authoritative on what already exists):** `docs/architecture/forge-capability-inventory.md`

## Global Constraints

- **Integrate, do not duplicate.** `ControlTest`/`ControlTestResult` stay the only test-and-result spine. `governance.control_tests.record_result` stays the only writer of results — it already owns alerting, POA&M upsert, recovery, and event emission. `connectors.credentials.resolve_credential` stays the only credential path and never falls back to a global value. `governance/scheduler.py` stays the only scheduler.
- **`VALIDATION_STATUSES` (from `ccf.fedramp20x`) is the single verdict vocabulary.** Do not define another. `pass`/`warn`/`fail` remain valid values.
- **`VERDICT_RANK` selection is inverted for posture.** `fedramp20x.validation`'s existing `any_of` use takes the **best** sub-result with `max`; posture rollup takes the **worst**. And `not_applicable`/`not_tested` both rank **0, below `fail` at 1**, so they MUST be **excluded** from the rollup, never ranked — a naive `min` reports "not applicable" for a failing check.
- **Zero resources in scope is `not_applicable`, never `pass`.**
- **Re-scans must not clobber human edits.** An upsert writes only machine-owned fields (`check_key`, `control_id`, `capability_id`, `description`). A human's `name`, `frequency`, and `active` survive — precedent: `test_control_test_recovery.py::test_human_edited_task_and_poam_fields_survive_recovery`.
- **Retiring a check deactivates its test; it never deletes it.** Validation history is the product.
- **`control_test_resource_results` is tenant-scoped by a TWO-HOP parent chain, not by an `organization_id` column** — `control_test_results` has no org column and is policied through `control_tests`; `poam_milestones` chains through `poams → systems`. Do NOT add `organization_id`.
- Add `control_test_resource_results` to `EXPECTED_TENANT_ISOLATION_TABLES` in `tests/test_rls_coverage.py` and bump its hardcoded count **130 → 131**. Do NOT touch `GLOBAL_TABLES` in `tests/test_rls_registry_no_gap.py`.
- Every migration includes the `pg_roles` GRANT guard. Confirm `alembic heads` returns exactly one head.
- **Test database is on port 5434.** `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`. Never run two pytest sessions at once.
- **Tests share one database.** `session_scope` COMMITS and the schema migrates once per *session*. Never assume an empty DB; `Organization.name`, `Control.identifier`, `KSI.identifier`, and `Capability.(organization_id, key)` are all UNIQUE; clean up rows other modules count.
- `ruff check src tests` and `mypy src` must be clean.

---

### Task 1: Verdict rank and the posture rollup

The rule everything else rests on, and it needs no database.

**Files:**
- Modify: `src/ccf/fedramp20x/validation.py` (promote `_VERDICT_RANK`)
- Create: `src/ccf/posture/__init__.py`
- Create: `src/ccf/posture/rollup.py`
- Test: `tests/test_posture_rollup.py`

**Interfaces:**
- Produces: `ccf.fedramp20x.validation.VERDICT_RANK: dict[str, int]` (with `_VERDICT_RANK` retained as an alias); `roll_up_findings(verdicts: Iterable[str]) -> str`; `EXCLUDED_FROM_ROLLUP: frozenset[str]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_posture_rollup.py
"""Rolling per-resource verdicts into one check verdict."""

from __future__ import annotations

import pytest

from ccf.posture.rollup import roll_up_findings


def test_all_pass_is_pass() -> None:
    assert roll_up_findings(["pass", "pass", "pass"]) == "pass"


def test_one_failure_fails_the_check() -> None:
    """3 failing of 47 is a failing check."""
    assert roll_up_findings(["pass"] * 44 + ["fail"] * 3) == "fail"


def test_warn_among_passes_warns() -> None:
    assert roll_up_findings(["pass", "warn", "pass"]) == "warn"


def test_fail_outranks_warn() -> None:
    assert roll_up_findings(["warn", "fail"]) == "fail"


def test_not_applicable_is_excluded_not_ranked() -> None:
    """The trap: not_applicable ranks 0, BELOW fail at 1, because
    VERDICT_RANK exists for any_of's `max`. A naive `min` would report
    not_applicable for a failing check."""
    assert roll_up_findings(["fail", "not_applicable"]) == "fail"
    assert roll_up_findings(["pass", "not_applicable"]) == "pass"
    assert roll_up_findings(["warn", "not_tested"]) == "warn"


def test_no_resources_in_scope_is_not_applicable() -> None:
    """Zero resources is not a passing check."""
    assert roll_up_findings([]) == "not_applicable"
    assert roll_up_findings(["not_applicable", "not_applicable"]) == "not_applicable"
    assert roll_up_findings(["not_tested"]) == "not_applicable"


def test_manual_review_required_is_ranked() -> None:
    assert roll_up_findings(["pass", "manual_review_required"]) == "manual_review_required"
    assert roll_up_findings(["fail", "manual_review_required"]) == "fail"


def test_unknown_verdict_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown verdict"):
        roll_up_findings(["definitely_not_a_verdict"])


def test_rank_is_shared_with_the_20x_engine() -> None:
    """One ranking, not two."""
    from ccf.fedramp20x.validation import VERDICT_RANK, _VERDICT_RANK

    assert VERDICT_RANK is _VERDICT_RANK
    assert VERDICT_RANK["fail"] > VERDICT_RANK["not_applicable"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_posture_rollup.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.posture'`

- [ ] **Step 3: Promote the rank in `fedramp20x/validation.py`**

Replace the private definition with a public one plus a back-compat alias:

```python
# Best-to-worst ranking used to pick the winning verdict of an ``any_of`` rule.
# Public because ccf.posture.rollup shares it -- but note the two uses select
# OPPOSITE ends: ``any_of`` takes the best sub-result with ``max``, where
# posture rollup takes the worst. ``not_applicable`` and ``not_tested`` sit at
# 0, *below* ``fail``, which is correct for "best wins" and actively wrong for
# "worst wins" -- so the posture rollup excludes them rather than ranking them.
VERDICT_RANK = {
    "pass": 4,
    "warn": 3,
    "manual_review_required": 2,
    "fail": 1,
    "not_applicable": 0,
    "not_tested": 0,
}

# Retained for existing references to the private name.
_VERDICT_RANK = VERDICT_RANK
```

- [ ] **Step 4: Write `src/ccf/posture/__init__.py`**

```python
"""Live security posture — what the environment actually reports.

Distinct from :mod:`ccf.api.routes.posture`, which serves *compliance* posture
(internal rollups over POA&Ms and evidence). This package assesses live
provider configuration: a check is declared content, a scan produces
per-resource findings, and the results land in the existing
``ControlTest``/``ControlTestResult`` spine rather than a parallel one.
"""

from __future__ import annotations

from .rollup import EXCLUDED_FROM_ROLLUP, roll_up_findings

__all__ = ["EXCLUDED_FROM_ROLLUP", "roll_up_findings"]
```

- [ ] **Step 5: Write `src/ccf/posture/rollup.py`**

```python
"""Roll per-resource verdicts into one verdict for a check.

Pure -- no database, no I/O. Conservative by design: one failing resource
fails the check, because over-claiming posture in an authorization package is
the dangerous direction.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..fedramp20x import VALIDATION_STATUSES
from ..fedramp20x.validation import VERDICT_RANK

#: Excluded from the rollup entirely rather than ranked. They sit at rank 0,
#: *below* ``fail``, because VERDICT_RANK exists for ``any_of``'s "best wins".
#: Ranking them here would report "not applicable" for a failing check.
EXCLUDED_FROM_ROLLUP: frozenset[str] = frozenset({"not_applicable", "not_tested"})


def roll_up_findings(verdicts: Iterable[str]) -> str:
    """The check-level verdict for a set of per-resource verdicts.

    Returns ``not_applicable`` when nothing was in scope -- zero resources
    evaluated is not a passing check, and saying ``pass`` would assert
    something the scan never observed.
    """
    considered: list[str] = []
    for v in verdicts:
        if v not in VALIDATION_STATUSES:
            raise ValueError(f"unknown verdict: {v!r}")
        if v in EXCLUDED_FROM_ROLLUP:
            continue
        considered.append(v)
    if not considered:
        return "not_applicable"
    # Worst wins: the opposite selection from evaluate_rule's any_of.
    return min(considered, key=lambda v: VERDICT_RANK[v])
```

- [ ] **Step 6: Run tests**

Run: `pytest tests/test_posture_rollup.py tests/test_fedramp20x.py -v`
Expected: all pass — the new rollup tests plus the untouched 20x suite,
proving the alias kept existing callers working.

- [ ] **Step 7: Lint and commit**

```bash
ruff check src/ccf/posture src/ccf/fedramp20x/validation.py tests/test_posture_rollup.py
mypy src/ccf/posture
git add src/ccf/posture src/ccf/fedramp20x/validation.py tests/test_posture_rollup.py
git commit -m "feat(posture): share the verdict rank and roll findings up conservatively"
```

---

### Task 2: Check definitions and the `scan()` contract

**Files:**
- Create: `src/ccf/posture/checks.py`
- Modify: `src/ccf/connectors/base.py`
- Test: `tests/test_posture_contract.py`

**Interfaces:**
- Produces:
  - `PostureCheck(key, title, provider, resource_type, expected, control_ids, capability_key=None)` — frozen dataclass
  - `ResourceFinding(resource_id, resource_type, verdict, observed, detail={})` — frozen dataclass
  - `CheckOutcome(check_key, verdict, expected, findings)` — frozen dataclass with `evaluated` and `failing` properties, plus `from_findings(check, findings)` classmethod
  - `CHECK_REGISTRY: dict[str, tuple[PostureCheck, ...]]` keyed by provider, and `checks_for(provider: str) -> tuple[PostureCheck, ...]`
  - `ConfigConnector.scan() -> list[CheckOutcome]`, defaulting to `[]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_posture_contract.py
"""The scan() contract, and that adding it left capture() alone."""

from __future__ import annotations

import pytest

from ccf.connectors import get_connector, list_connectors
from ccf.connectors.base import ConfigConnector
from ccf.posture.checks import (
    CHECK_REGISTRY,
    CheckOutcome,
    PostureCheck,
    ResourceFinding,
    checks_for,
)


def _check() -> PostureCheck:
    return PostureCheck(
        key="test.demo.check",
        title="Demo",
        provider="demo",
        resource_type="bucket",
        expected="public access blocked",
        control_ids=("AC-3",),
    )


def test_outcome_counts_from_findings() -> None:
    findings = (
        ResourceFinding("a", "bucket", "pass", "blocked"),
        ResourceFinding("b", "bucket", "fail", "open"),
        ResourceFinding("c", "bucket", "not_applicable", "n/a"),
    )
    out = CheckOutcome.from_findings(_check(), findings)
    assert out.check_key == "test.demo.check"
    assert out.evaluated == 3
    assert out.failing == 1
    assert out.verdict == "fail"   # one failure fails the check
    assert out.expected == "public access blocked"


def test_outcome_with_no_findings_is_not_applicable() -> None:
    out = CheckOutcome.from_findings(_check(), ())
    assert out.verdict == "not_applicable"
    assert out.evaluated == 0
    assert out.failing == 0


def test_outcome_rejects_an_unknown_verdict() -> None:
    with pytest.raises(ValueError, match="unknown verdict"):
        CheckOutcome.from_findings(
            _check(), (ResourceFinding("a", "bucket", "nonsense", "x"),)
        )


async def test_base_scan_returns_empty() -> None:
    """Adding scan() must not disturb connectors that do not implement it."""

    class Bare(ConfigConnector):
        key = "bare"
        label = "Bare"

        def is_configured(self) -> bool:
            return False

        async def capture(self) -> list:
            return []

    assert await Bare().scan() == []


async def test_existing_connectors_still_scan_empty() -> None:
    for conn in list_connectors():
        assert await conn.scan() == [], conn.key


async def test_existing_connectors_still_capture_nothing_unconfigured() -> None:
    """capture() behaviour is unchanged."""
    for key in ("msgraph", "aws_govcloud"):
        conn = get_connector(key)
        assert conn is not None
        assert conn.is_configured() is False
        assert await conn.capture() == []


def test_registry_is_keyed_by_provider_and_unique() -> None:
    seen: set[str] = set()
    for provider, checks in CHECK_REGISTRY.items():
        for c in checks:
            assert c.provider == provider, f"{c.key} filed under {provider}"
            assert c.key not in seen, f"duplicate check key {c.key}"
            seen.add(c.key)
            assert c.control_ids, f"{c.key} evidences no control"


def test_checks_for_unknown_provider_is_empty() -> None:
    assert checks_for("no-such-provider") == ()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_posture_contract.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.posture.checks'`

- [ ] **Step 3: Write `src/ccf/posture/checks.py`**

```python
"""Posture check definitions and the shapes a scan returns.

A check is *content*: what to look at, what is expected, and which canonical
controls it evidences. The registry here is deliberately the same shape as
``etl.sources.DEFAULT_SOURCES`` so P2b's move into ``packs/`` relocates
content rather than redesigning it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..fedramp20x import VALIDATION_STATUSES
from .rollup import roll_up_findings


@dataclass(frozen=True)
class PostureCheck:
    """One thing to assess in a provider, and what it evidences.

    ``control_ids`` are **canonical** 800-53 ids (``AC-2``), matching
    ``CapabilityControl.control_id`` and ``SSPControlEntry.control_id`` --
    never the zero-padded ``controls.identifier`` form.
    """

    key: str
    title: str
    provider: str
    resource_type: str
    expected: str
    control_ids: tuple[str, ...]
    #: Resolved to a Capability by (organization_id, key) when one exists.
    #: A missing capability is not an error: checks ship as content, while
    #: capabilities are authored per tenant.
    capability_key: str | None = None


@dataclass(frozen=True)
class ResourceFinding:
    """What one resource actually reported."""

    resource_id: str
    resource_type: str
    verdict: str
    observed: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CheckOutcome:
    """One check's assessment of a fleet."""

    check_key: str
    verdict: str
    expected: str
    findings: tuple[ResourceFinding, ...]

    @property
    def evaluated(self) -> int:
        return len(self.findings)

    @property
    def failing(self) -> int:
        return sum(1 for f in self.findings if f.verdict == "fail")

    @classmethod
    def from_findings(
        cls, check: PostureCheck, findings: tuple[ResourceFinding, ...]
    ) -> CheckOutcome:
        """Build an outcome, rolling the per-resource verdicts up.

        Raises ``ValueError`` on an unrecognised verdict rather than storing
        a value no reader can interpret.
        """
        for f in findings:
            if f.verdict not in VALIDATION_STATUSES:
                raise ValueError(f"unknown verdict: {f.verdict!r}")
        return cls(
            check_key=check.key,
            verdict=roll_up_findings([f.verdict for f in findings]),
            expected=check.expected,
            findings=tuple(findings),
        )


#: Provider key -> its checks. Empty per provider until P3 implements the
#: adapters; the registry exists now so the contract and orchestration are
#: testable and so P2b has something to relocate.
CHECK_REGISTRY: dict[str, tuple[PostureCheck, ...]] = {
    "msgraph": (),
    "aws_govcloud": (),
}


def checks_for(provider: str) -> tuple[PostureCheck, ...]:
    """Checks registered for one provider; empty for an unknown provider."""
    return CHECK_REGISTRY.get(provider, ())
```

- [ ] **Step 4: Add `scan()` to `src/ccf/connectors/base.py`**

Append to `ConfigConnector`, after `verify`:

```python
    async def scan(self) -> list[CheckOutcome]:
        """Assess live configuration against this provider's posture checks.

        Where :meth:`capture` reads a single value to fill an ODP blank, this
        assesses a fleet: each returned :class:`CheckOutcome` carries
        per-resource findings with expected-versus-observed detail.

        Defaults to ``[]`` so a connector that has not implemented posture
        scanning is unaffected -- the same courtesy :meth:`verify` extends by
        returning a not-implemented result. Implementations MUST NOT raise;
        return ``[]`` when unconfigured or on a transient provider error, as
        :meth:`capture` does.
        """
        return []
```

Import under `TYPE_CHECKING` to avoid a cycle (`posture.checks` imports
nothing from `connectors`, but keeping the runtime import out is cheaper and
matches how the module already avoids provider imports):

```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..posture.checks import CheckOutcome
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_posture_contract.py tests/test_connectors.py -v`
(If `tests/test_connectors.py` does not exist, run
`ls tests/ | grep -i connector` and use what is there.)
Expected: all pass.

- [ ] **Step 6: Lint and commit**

```bash
ruff check src/ccf/posture src/ccf/connectors/base.py tests/test_posture_contract.py
mypy src/ccf/posture src/ccf/connectors/base.py
git add src/ccf/posture src/ccf/connectors/base.py tests/test_posture_contract.py
git commit -m "feat(posture): a scan() contract beside capture(), defaulting to empty"
```

---

### Task 3: Models and migration 0068

**Files:**
- Modify: `src/ccf/models_grc.py` (`ControlTest`, `ControlTestResult`, new `ControlTestResourceResult`)
- Create: `migrations/versions/0068_posture_validation_spine.py`
- Modify: `tests/test_rls_coverage.py` (snapshot + count)
- Test: `tests/test_posture_models.py`

**Interfaces:**
- Produces: `ControlTestResourceResult` in `ccf.models_grc`; `ControlTest.source | check_key | capability_id`; `ControlTestResult.evaluated | failing | expected`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_posture_models.py
"""Posture schema: widened vocabulary, provenance, and two-hop tenancy."""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResult, ControlTestResourceResult

_SEQ = itertools.count()


async def _test_row(session, *, check_key: str | None = None, source: str = "authored"):
    org = Organization(name=f"PostOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"PostSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    t = ControlTest(
        organization_id=org.id,
        system_id=sys_.id,
        control_id="AC-3",
        name="demo",
        method="connector",
        source=source,
        check_key=check_key,
    )
    session.add(t)
    await session.flush()
    return org, sys_, t


async def test_status_accepts_the_widened_vocabulary() -> None:
    async with session_scope() as session:
        _, _, t = await _test_row(session)
        r = ControlTestResult(
            control_test_id=t.id, status="manual_review_required", detail="needs a human"
        )
        session.add(r)
        await session.flush()  # varchar(8) would have truncated or failed


async def test_legacy_statuses_still_round_trip() -> None:
    async with session_scope() as session:
        _, _, t = await _test_row(session)
        for status in ("pass", "warn", "fail"):
            session.add(ControlTestResult(control_test_id=t.id, status=status))
        await session.flush()


async def test_source_defaults_to_authored() -> None:
    """Every pre-existing row must read as authored, not generated."""
    async with session_scope() as session:
        org = Organization(name=f"PostOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        t = ControlTest(organization_id=org.id, control_id="AC-3", name="bare")
        session.add(t)
        await session.flush()
        assert t.source == "authored"


async def test_generated_check_key_is_unique_per_system() -> None:
    async with session_scope() as session:
        org, sys_, _ = await _test_row(session, check_key="aws.s3.block", source="generated")
        dup = ControlTest(
            organization_id=org.id,
            system_id=sys_.id,
            control_id="AC-3",
            name="dup",
            source="generated",
            check_key="aws.s3.block",
        )
        session.add(dup)
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_authored_tests_are_not_constrained_by_check_key() -> None:
    """check_key is null for authored tests, and Postgres treats nulls as
    distinct -- so any number may coexist for one system."""
    async with session_scope() as session:
        org, sys_, _ = await _test_row(session)
        for n in range(3):
            session.add(
                ControlTest(
                    organization_id=org.id,
                    system_id=sys_.id,
                    control_id="AC-3",
                    name=f"authored-{n}",
                )
            )
        await session.flush()


async def test_resource_results_attach_to_a_result() -> None:
    async with session_scope() as session:
        _, _, t = await _test_row(session)
        r = ControlTestResult(control_test_id=t.id, status="fail", evaluated=47, failing=3)
        session.add(r)
        await session.flush()
        for i in range(3):
            session.add(
                ControlTestResourceResult(
                    result_id=r.id,
                    resource_id=f"arn:aws:s3:::bucket-{i}",
                    resource_type="s3_bucket",
                    verdict="fail",
                    observed="public access allowed",
                )
            )
        await session.flush()
        rows = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == r.id
                )
            )
        ).scalars().all()
        assert len(rows) == 3
        assert r.evaluated == 47 and r.failing == 3


async def test_resource_results_have_a_two_hop_tenant_policy() -> None:
    """No organization_id column -- scoped through control_tests, like
    control_test_results and poam_milestones."""
    async with session_scope() as session:
        has_org = (
            await session.execute(
                text(
                    "SELECT EXISTS(SELECT 1 FROM information_schema.columns "
                    "WHERE table_schema='ccf' "
                    "AND table_name='control_test_resource_results' "
                    "AND column_name='organization_id')"
                )
            )
        ).scalar()
        assert has_org is False

        policied = (
            await session.execute(
                text(
                    "SELECT EXISTS(SELECT 1 FROM pg_policy p "
                    "JOIN pg_class c ON c.oid = p.polrelid "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname='ccf' AND p.polname='tenant_isolation' "
                    "AND c.relname='control_test_resource_results')"
                )
            )
        ).scalar()
        assert policied is True


async def test_deleting_a_result_cascades_its_resources() -> None:
    async with session_scope() as session:
        _, _, t = await _test_row(session)
        r = ControlTestResult(control_test_id=t.id, status="fail")
        session.add(r)
        await session.flush()
        session.add(
            ControlTestResourceResult(
                result_id=r.id, resource_id="x", resource_type="y", verdict="fail", observed="z"
            )
        )
        await session.flush()
        rid = r.id
        await session.delete(r)
        await session.flush()
        left = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == rid
                )
            )
        ).scalars().all()
        assert left == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_posture_models.py -v`
Expected: FAIL — `ImportError: cannot import name 'ControlTestResourceResult'`

- [ ] **Step 3: Alter the two existing models**

In `src/ccf/models_grc.py`, inside `ControlTest`, after `assertion`:

```python
    # Provenance. 'generated' rows are created by a posture scan from a
    # PostureCheck definition; 'authored' is a human-defined test. Defaults to
    # authored so every pre-existing row is correctly labelled without a data
    # migration, and so a scan can never be mistaken for someone's intent.
    source: Mapped[str] = mapped_column(String(16), default="authored", server_default="authored")
    #: The PostureCheck this test was generated from; null for authored tests.
    check_key: Mapped[str | None] = mapped_column(String(128), index=True)
    #: Optional: this test evidences a capability directly (P1 ontology).
    #: SET NULL on delete -- removing a capability must not destroy validation
    #: history.
    capability_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.capabilities.id", ondelete="SET NULL"), index=True
    )
```

Widen `last_status` in the same class:

```python
    # Widened from String(8) in 0068: the vocabulary is now
    # ccf.fedramp20x.VALIDATION_STATUSES, whose longest member
    # ('manual_review_required') is 22 characters.
    last_status: Mapped[str | None] = mapped_column(String(32))
```

Add to `ControlTest.__table_args__` (create the tuple if absent, preserving
any existing entries):

```python
    __table_args__ = (
        UniqueConstraint("system_id", "check_key", name="uq_control_test_system_check"),
    )
```

In `ControlTestResult`, widen `status` and add the three columns:

```python
    status: Mapped[str] = mapped_column(String(32))  # widened in 0068
    detail: Mapped[str | None] = mapped_column(Text)
    evidence_ref: Mapped[str | None] = mapped_column(String(1024))
    #: Resources considered by this run, and how many failed -- so "47
    #: evaluated, 3 failing" is answerable without counting child rows.
    evaluated: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    failing: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    #: The expectation as evaluated, recorded with the result so a later
    #: change to the check definition cannot rewrite history.
    expected: Mapped[str | None] = mapped_column(Text)
```

- [ ] **Step 4: Add the child model**

After `ControlTestResult` in `src/ccf/models_grc.py`:

```python
class ControlTestResourceResult(Base):
    """One resource's verdict within a control-test run.

    This is what lets the platform say *which* resources failed -- "47 storage
    accounts evaluated, 3 allow public access, here are their ids" -- rather
    than only that a test failed.

    Deliberately carries no ``organization_id``: ``control_test_results`` has
    none either and is policied through ``control_tests``, and
    ``poam_milestones`` chains through ``poams -> systems``. This table follows
    that established parent-chain shape one hop further. Adding an org column
    would denormalize against the convention and create a second source of
    truth for the row's tenant.
    """

    __tablename__ = "control_test_resource_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    result_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.control_test_results.id", ondelete="CASCADE"), index=True
    )
    resource_id: Mapped[str] = mapped_column(String(512))
    resource_type: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    observed: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index(
            "ix_ctrr_type_verdict",
            "resource_type",
            "verdict",
        ),
    )
```

Check the imports at the top of `models_grc.py` and add any of
`BigInteger`, `Index`, `Integer`, `UniqueConstraint`, `ForeignKey`, `func`,
`DateTime`, `JSONB`, `datetime`, `Any` that are missing.

- [ ] **Step 5: Write the migration**

```python
# migrations/versions/0068_posture_validation_spine.py
"""Posture validation spine -- per-resource findings under a control test.

Concord could already define a repeatable control test, run it on a schedule,
record an append-only result, alert, open a POA&M, and resolve on recovery.
What it could not do is say *which* resources failed: status plus a free-text
detail for the whole test, with no resource identity and no
expected-versus-observed.

This adds control_test_resource_results, plus resource counts and the
evaluated expectation on the result, plus provenance and a capability link on
the test.

Vocabulary: control_test_results.status and control_tests.last_status widen
from varchar(8) to varchar(32) so the single vocabulary is
ccf.fedramp20x.VALIDATION_STATUSES -- whose longest member,
'manual_review_required', is 22 characters. ksi_validation_results.status was
already varchar(32) with that vocabulary, so this consolidates two
vocabularies rather than adding a third. Backward-compatible: pass/warn/fail
remain valid.

Tenancy: control_test_resource_results deliberately carries no
organization_id. control_test_results has none either and is policied through
control_tests; poam_milestones chains through poams -> systems. This table
follows that parent-chain shape one hop further. It is therefore NOT added to
GLOBAL_TABLES -- having a policy is what keeps it out of that guard's
unpolicied-table query -- but IS added to EXPECTED_TENANT_ISOLATION_TABLES.

Revision ID: 0068_posture_validation_spine
Revises: 0067_capability_ontology
Create Date: 2026-09-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0068_posture_validation_spine"
down_revision = "0067_capability_ontology"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"

# Two hops: resource result -> result -> test (which carries organization_id).
_PREDICATE = (
    "(ccf.current_tenant() IS NULL OR result_id IN ("
    " SELECT r.id FROM ccf.control_test_results r"
    " JOIN ccf.control_tests t ON t.id = r.control_test_id"
    " WHERE t.organization_id = ccf.current_tenant()))"
)


def upgrade() -> None:
    # --- one verdict vocabulary -------------------------------------------
    op.alter_column(
        "control_test_results",
        "status",
        type_=sa.String(32),
        existing_type=sa.String(8),
        existing_nullable=False,
        schema=_SCHEMA,
    )
    op.alter_column(
        "control_tests",
        "last_status",
        type_=sa.String(32),
        existing_type=sa.String(8),
        existing_nullable=True,
        schema=_SCHEMA,
    )

    # --- provenance + capability link on the test -------------------------
    op.add_column(
        "control_tests",
        sa.Column(
            "source", sa.String(16), nullable=False, server_default="authored"
        ),
        schema=_SCHEMA,
    )
    op.add_column(
        "control_tests", sa.Column("check_key", sa.String(128)), schema=_SCHEMA
    )
    op.add_column(
        "control_tests",
        sa.Column(
            "capability_id",
            sa.BigInteger,
            sa.ForeignKey("ccf.capabilities.id", ondelete="SET NULL"),
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_control_tests_check_key", "control_tests", ["check_key"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ccf_control_tests_capability",
        "control_tests",
        ["capability_id"],
        schema=_SCHEMA,
    )
    # Nulls are distinct in Postgres unique indexes, so authored tests
    # (check_key NULL) are deliberately unconstrained while a generated
    # (system_id, check_key) pair can exist only once -- which is what makes
    # re-scanning idempotent.
    op.create_unique_constraint(
        "uq_control_test_system_check",
        "control_tests",
        ["system_id", "check_key"],
        schema=_SCHEMA,
    )

    # --- resource counts + evaluated expectation on the result ------------
    op.add_column(
        "control_test_results",
        sa.Column("evaluated", sa.Integer, nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.add_column(
        "control_test_results",
        sa.Column("failing", sa.Integer, nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.add_column(
        "control_test_results", sa.Column("expected", sa.Text), schema=_SCHEMA
    )

    # --- the per-resource findings ----------------------------------------
    op.create_table(
        "control_test_resource_results",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "result_id",
            sa.BigInteger,
            sa.ForeignKey("ccf.control_test_results.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("resource_id", sa.String(512), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("verdict", sa.String(32), nullable=False),
        sa.Column("observed", sa.Text),
        sa.Column("detail", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ctrr_result", "control_test_resource_results", ["result_id"], schema=_SCHEMA
    )
    # "every failing resource in this org" is a core query, not a scan.
    op.create_index(
        "ix_ctrr_verdict", "control_test_resource_results", ["verdict"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ctrr_type_verdict",
        "control_test_resource_results",
        ["resource_type", "verdict"],
        schema=_SCHEMA,
    )

    # Standard grant guard: no-op where the ccf_app role was never created.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )

    op.execute("ALTER TABLE ccf.control_test_resource_results ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.control_test_resource_results FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.control_test_resource_results "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.drop_table("control_test_resource_results", schema=_SCHEMA)
    for col in ("expected", "failing", "evaluated"):
        op.drop_column("control_test_results", col, schema=_SCHEMA)
    op.drop_constraint(
        "uq_control_test_system_check", "control_tests", schema=_SCHEMA, type_="unique"
    )
    op.drop_index("ix_ccf_control_tests_capability", "control_tests", schema=_SCHEMA)
    op.drop_index("ix_ccf_control_tests_check_key", "control_tests", schema=_SCHEMA)
    for col in ("capability_id", "check_key", "source"):
        op.drop_column("control_tests", col, schema=_SCHEMA)
    # Statuses are left widened: a value written under 0068 (e.g.
    # 'manual_review_required') would not fit varchar(8), so narrowing would
    # fail on real data.
```

- [ ] **Step 6: Update the RLS snapshot**

In `tests/test_rls_coverage.py`, add `"control_test_resource_results"` to
`EXPECTED_TENANT_ISOLATION_TABLES` (alphabetically, beside
`control_test_results`) with a short comment, and change the hardcoded count
from `130` to `131` in both the module docstring and the assertion.

- [ ] **Step 7: Migrate and test**

```bash
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
alembic heads          # MUST print exactly one head
alembic upgrade head
pytest tests/test_posture_models.py tests/test_rls_coverage.py tests/test_rls_registry_no_gap.py -v
```
Expected: one head; migration applies; all pass with `GLOBAL_TABLES` untouched.

- [ ] **Step 8: Commit**

```bash
ruff check src/ccf/models_grc.py migrations/versions/0068_posture_validation_spine.py tests/test_posture_models.py tests/test_rls_coverage.py
mypy src/ccf/models_grc.py
git add src/ccf/models_grc.py migrations/versions/0068_posture_validation_spine.py tests/test_posture_models.py tests/test_rls_coverage.py
git commit -m "feat(posture): per-resource result rows and one verdict vocabulary"
```

---

### Task 4: Record resource findings through the existing writer

`record_result` already owns alerting, POA&M upsert, recovery, and events. It
must stay the only writer — this task widens it rather than adding a second.

**Files:**
- Modify: `src/ccf/governance/control_tests.py` (`record_result`)
- Test: `tests/test_posture_record.py`

**Interfaces:**
- Consumes: `ResourceFinding` (Task 2), `ControlTestResourceResult` (Task 3)
- Produces: `record_result(session, test, *, status, detail=None, evidence_ref=None, actor="user", evaluated=0, failing=0, expected=None, resources=())` — same return type, `ControlTestResult`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_posture_record.py
"""record_result stays the only writer -- widened, not duplicated."""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResourceResult
from ccf.posture.checks import ResourceFinding

_SEQ = itertools.count()


async def _test_row(session) -> ControlTest:
    org = Organization(name=f"RecOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"RecSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    t = ControlTest(
        organization_id=org.id,
        system_id=sys_.id,
        control_id="AC-3",
        name="demo",
        method="connector",
    )
    session.add(t)
    await session.flush()
    return t


async def test_records_resource_findings() -> None:
    async with session_scope() as session:
        t = await _test_row(session)
        res = await record_result(
            session,
            t,
            status="fail",
            evaluated=3,
            failing=1,
            expected="public access blocked",
            resources=(
                ResourceFinding("b1", "s3_bucket", "pass", "blocked"),
                ResourceFinding("b2", "s3_bucket", "fail", "open"),
                ResourceFinding("b3", "s3_bucket", "pass", "blocked"),
            ),
        )
        assert res.evaluated == 3
        assert res.failing == 1
        assert res.expected == "public access blocked"
        rows = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == res.id
                )
            )
        ).scalars().all()
        assert len(rows) == 3
        assert {r.verdict for r in rows} == {"pass", "fail"}


async def test_accepts_the_widened_vocabulary() -> None:
    async with session_scope() as session:
        t = await _test_row(session)
        res = await record_result(session, t, status="not_applicable", detail="nothing in scope")
        assert res.status == "not_applicable"
        assert t.last_status == "not_applicable"


async def test_rejects_a_verdict_outside_the_vocabulary() -> None:
    async with session_scope() as session:
        t = await _test_row(session)
        with pytest.raises(ValueError, match="status must be one of"):
            await record_result(session, t, status="nonsense")


async def test_legacy_call_without_resources_is_unchanged() -> None:
    """Existing callers pass no resource data and must behave exactly as before."""
    async with session_scope() as session:
        t = await _test_row(session)
        res = await record_result(session, t, status="pass", detail="all good")
        assert res.status == "pass"
        assert res.evaluated == 0
        assert res.failing == 0
        assert res.expected is None
        rows = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == res.id
                )
            )
        ).scalars().all()
        assert rows == []


async def test_recovery_still_fires_on_fail_then_pass() -> None:
    """The existing recovery loop must keep working through the widened writer."""
    async with session_scope() as session:
        t = await _test_row(session)
        await record_result(session, t, status="fail", detail="broken")
        assert t.last_status == "fail"
        await record_result(session, t, status="pass", detail="fixed")
        assert t.last_status == "pass"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_posture_record.py -v`
Expected: FAIL — `TypeError: record_result() got an unexpected keyword argument 'evaluated'`

- [ ] **Step 3: Widen `record_result`**

Replace its signature and the validation/write block:

```python
async def record_result(
    session: AsyncSession,
    test: ControlTest,
    *,
    status: str,
    detail: str | None = None,
    evidence_ref: str | None = None,
    actor: str = "user",
    evaluated: int = 0,
    failing: int = 0,
    expected: str | None = None,
    resources: Sequence[ResourceFinding] = (),
) -> ControlTestResult:
    """Persist one test result, update the test, and alert on fail/warn.

    Shared by the manual UI run action, the scheduler auto-run (run_due
    delegates here), and posture scans -- so the alert + remediation-task +
    recovery behaviour is identical regardless of trigger. This is deliberately
    the only writer of results.

    ``evaluated``/``failing``/``expected``/``resources`` are the posture
    additions and all default to empty, so every pre-existing caller behaves
    exactly as before.
    """
    if status not in VALIDATION_STATUSES:
        raise ValueError(f"status must be one of {VALIDATION_STATUSES}")
    # Must be captured before the reassignment below -- if this instead read
    # test.last_status after the assignment, it would always equal `status` and
    # the fail/warn -> pass transition would be permanently undetectable.
    previous_status = test.last_status
    res = ControlTestResult(
        control_test_id=test.id,
        status=status,
        detail=detail,
        evidence_ref=evidence_ref,
        evaluated=evaluated,
        failing=failing,
        expected=expected,
    )
    session.add(res)
    test.last_status = status
    test.last_tested_at = datetime.now(UTC)
    await session.flush()
    for f in resources:
        session.add(
            ControlTestResourceResult(
                result_id=res.id,
                resource_id=f.resource_id[:512],
                resource_type=f.resource_type[:64],
                verdict=f.verdict,
                observed=f.observed,
                detail=f.detail,
            )
        )
    if resources:
        await session.flush()
    if status in ("fail", "warn"):
        await _alert_on_failure(session, test, status, detail or "")
    elif status == "pass" and previous_status in ("fail", "warn"):
        await _resolve_on_recovery(session, test, result_id=res.id)
    await bus.emit(
        session,
        verb="tested",
        entity_type="control_test",
        entity_id=test.id,
        summary=f"Control test {status}: {test.control_id}",
        org_id=test.organization_id,
        actor=actor,
    )
    return res
```

**The recovery condition is deliberately unchanged.** Only `pass` from
`fail`/`warn` triggers recovery; the widened vocabulary does not make
`not_applicable` or `manual_review_required` a recovery, because neither
asserts the weakness cleared.

Add the imports: `from collections.abc import Sequence`,
`from ..fedramp20x import VALIDATION_STATUSES`,
`from ..models_grc import ControlTestResourceResult` (extend the existing
`models_grc` import), and `from ..posture.checks import ResourceFinding`.

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_posture_record.py tests/test_control_test_recovery.py tests/test_conmon_recovery.py tests/test_control_test_assertions.py -v`
Expected: all pass — the new tests plus every existing recovery and assertion
test, proving the widened writer did not change established behaviour.

- [ ] **Step 5: Commit**

```bash
ruff check src/ccf/governance/control_tests.py tests/test_posture_record.py
mypy src/ccf/governance/control_tests.py
git add src/ccf/governance/control_tests.py tests/test_posture_record.py
git commit -m "feat(posture): record per-resource findings through the existing writer"
```

---

### Task 5: Scan orchestration and verdict precedence

**Files:**
- Create: `src/ccf/posture/scan.py`
- Test: `tests/test_posture_scan.py`

**Interfaces:**
- Consumes: `checks_for`, `CheckOutcome`, `ResourceFinding` (Task 2); `record_result` (Task 4); `resolve_credential`, `get_connector`
- Produces:
  - `async scan_for_system(session, *, system_id: int, connector_key: str, actor: str = "scan") -> dict[str, Any]`
  - `async effective_verdict(session, *, system_id: int, control_id: str) -> dict[str, Any]`
  - `STALE_AFTER_DAYS: int = 30`

- [ ] **Step 1: Confirm how the org for a system is resolved and how credentials load**

```bash
grep -n "async def resolve_credential" -A 12 src/ccf/connectors/credentials.py
grep -n "async def collect_for_org" -A 20 src/ccf/governance/collection.py | head -26
```

Follow `collect_for_org`'s exact credential-resolution and connector-lookup
sequence; do not invent a second one.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_posture_scan.py
"""Scan orchestration: generated tests, idempotence, and human edits."""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResult
from ccf.posture import scan as scan_mod
from ccf.posture.checks import CheckOutcome, PostureCheck, ResourceFinding
from ccf.posture.scan import effective_verdict, scan_for_system

_SEQ = itertools.count()

CHECK = PostureCheck(
    key="demo.bucket.public",
    title="Buckets block public access",
    provider="demo_provider",
    resource_type="bucket",
    expected="public access blocked",
    control_ids=("AC-3",),
)


def _outcome(*verdicts: str) -> CheckOutcome:
    findings = tuple(
        ResourceFinding(f"res-{i}", "bucket", v, "observed") for i, v in enumerate(verdicts)
    )
    return CheckOutcome.from_findings(CHECK, findings)


class _FakeConnector:
    key = "demo_provider"

    def __init__(self, outcomes: list[CheckOutcome]) -> None:
        self._outcomes = outcomes

    def is_configured(self) -> bool:
        return True

    async def scan(self) -> list[CheckOutcome]:
        return self._outcomes


def _patch(monkeypatch: pytest.MonkeyPatch, outcomes: list[CheckOutcome]) -> None:
    """_connector_for_org is async, so the replacement must be too."""

    async def _fake_connector(*a: object, **k: object) -> _FakeConnector:
        return _FakeConnector(outcomes)

    monkeypatch.setattr(scan_mod, "checks_for", lambda provider: (CHECK,))
    monkeypatch.setattr(scan_mod, "_connector_for_org", _fake_connector)


async def _system(session) -> System:
    org = Organization(name=f"ScanOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"ScanSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    return sys_


async def test_scan_creates_a_generated_test_and_a_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, [_outcome("pass", "fail", "pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        assert out["checks_run"] == 1
        assert out["results"][0]["verdict"] == "fail"

        t = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().one()
        assert t.source == "generated"
        assert t.check_key == "demo.bucket.public"
        assert t.control_id == "AC-3"

        r = (
            await session.execute(
                select(ControlTestResult).where(ControlTestResult.control_test_id == t.id)
            )
        ).scalars().one()
        assert r.status == "fail"
        assert r.evaluated == 3
        assert r.failing == 1
        assert r.expected == "public access blocked"


async def test_rescanning_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_outcome("pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        tests = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().all()
        assert len(tests) == 1          # one test
        results = (
            await session.execute(
                select(ControlTestResult).where(
                    ControlTestResult.control_test_id == tests[0].id
                )
            )
        ).scalars().all()
        assert len(results) == 2        # two runs of it -- history is the point


async def test_human_edits_survive_a_rescan(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_outcome("pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        t = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().one()
        t.name = "Renamed by a human"
        t.frequency = "quarterly"
        t.active = False
        await session.flush()

        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        await session.refresh(t)
        assert t.name == "Renamed by a human"
        assert t.frequency == "quarterly"
        assert t.active is False


async def test_empty_fleet_is_not_applicable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_outcome()])
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        assert out["results"][0]["verdict"] == "not_applicable"


async def test_unconfigured_connector_scans_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _no_connector(*a: object, **k: object) -> None:
        return None

    monkeypatch.setattr(scan_mod, "checks_for", lambda provider: (CHECK,))
    monkeypatch.setattr(scan_mod, "_connector_for_org", _no_connector)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        assert out["checks_run"] == 0
        assert out["reason"] == "connector not configured for this organization"


async def test_effective_verdict_prefers_a_fresh_deterministic_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, [_outcome("fail")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")
        assert out["source"] == "deterministic"
        assert out["verdict"] == "fail"


async def test_effective_verdict_is_none_when_nothing_observed() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")
        assert out["source"] is None
        assert out["verdict"] is None


async def test_effective_verdict_treats_a_stale_result_as_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import UTC, datetime, timedelta

    _patch(monkeypatch, [_outcome("fail")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        r = (
            await session.execute(
                select(ControlTestResult).order_by(ControlTestResult.id.desc()).limit(1)
            )
        ).scalars().one()
        r.run_at = datetime.now(UTC) - timedelta(days=scan_mod.STALE_AFTER_DAYS + 5)
        await session.flush()
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")
        assert out["source"] is None
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_posture_scan.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.posture.scan'`

- [ ] **Step 4: Write `src/ccf/posture/scan.py`**

```python
"""Run posture checks against a system and record what they found.

Deliberately thin: it resolves the org's connector, calls ``scan()``, and
hands every outcome to ``governance.control_tests.record_result`` -- the one
writer that already owns alerting, POA&M upsert, recovery, and events. Nothing
here re-implements any of that.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..connectors import get_connector
from ..connectors.base import ConfigConnector
from ..connectors.credentials import resolve_credential
from ..governance.control_tests import record_result
from ..logging import get_logger
from ..models import System
from ..models_capability import Capability
from ..models_grc import ControlTest, ControlTestResult
from .checks import CheckOutcome, checks_for

log = get_logger(__name__)

#: A deterministic result older than this is treated as absent by
#: :func:`effective_verdict`, for a test with no frequency of its own.
STALE_AFTER_DAYS = 30


async def _connector_for_org(
    session: AsyncSession, *, organization_id: int, connector_key: str
) -> ConfigConnector | None:
    """The org's configured connector, or ``None``.

    Credentials come only from ``resolve_credential`` -- per-organization,
    with no global or environment fallback.
    """
    credential = await resolve_credential(
        session, organization_id=organization_id, connector_type=connector_key
    )
    conn = get_connector(connector_key, credential=credential)
    if conn is None or not conn.is_configured():
        return None
    return conn


async def _capability_id_for(
    session: AsyncSession, *, organization_id: int, capability_key: str | None
) -> int | None:
    """Resolve a check's capability by key, if the tenant authored one.

    A missing capability is not an error: checks ship as content, while
    capabilities are authored per tenant.
    """
    if not capability_key:
        return None
    return (
        await session.execute(
            select(Capability.id).where(
                Capability.organization_id == organization_id,
                Capability.key == capability_key,
            )
        )
    ).scalar_one_or_none()


async def _upsert_generated_test(
    session: AsyncSession,
    *,
    organization_id: int,
    system_id: int,
    outcome: CheckOutcome,
    control_id: str,
    title: str,
    capability_id: int | None,
) -> ControlTest:
    """Find or create the generated test for one check on one system.

    Writes **machine-owned fields only**. A human's ``name``, ``frequency``,
    and ``active`` survive a re-scan -- the same discipline
    ``_resolve_on_recovery`` applies to human-edited Task and POA&M fields.
    """
    test = (
        await session.execute(
            select(ControlTest).where(
                ControlTest.system_id == system_id,
                ControlTest.check_key == outcome.check_key,
            )
        )
    ).scalars().first()
    if test is None:
        test = ControlTest(
            organization_id=organization_id,
            system_id=system_id,
            control_id=control_id,
            name=title,
            method="connector",
            source="generated",
            check_key=outcome.check_key,
            capability_id=capability_id,
            description=f"Generated from posture check {outcome.check_key}.",
        )
        session.add(test)
        await session.flush()
        return test

    test.control_id = control_id
    test.capability_id = capability_id
    test.description = f"Generated from posture check {outcome.check_key}."
    return test


async def scan_for_system(
    session: AsyncSession,
    *,
    system_id: int,
    connector_key: str,
    actor: str = "scan",
) -> dict[str, Any]:
    """Scan one system with one connector and record every outcome."""
    system = await session.get(System, system_id)
    if system is None:
        raise ValueError(f"unknown system: {system_id}")

    conn = await _connector_for_org(
        session, organization_id=system.organization_id, connector_key=connector_key
    )
    if conn is None:
        return {
            "system_id": system_id,
            "connector": connector_key,
            "checks_run": 0,
            "results": [],
            "reason": "connector not configured for this organization",
        }

    by_key = {c.key: c for c in checks_for(connector_key)}
    outcomes = await conn.scan()

    recorded: list[dict[str, Any]] = []
    for outcome in outcomes:
        check = by_key.get(outcome.check_key)
        if check is None:
            # A connector returned an outcome for a check this build does not
            # know. Skipped rather than guessed at: without the definition
            # there is no control to attribute it to.
            log.warning(
                "posture.unknown_check", check_key=outcome.check_key, provider=connector_key
            )
            continue
        capability_id = await _capability_id_for(
            session,
            organization_id=system.organization_id,
            capability_key=check.capability_key,
        )
        # A check may evidence several controls; the test carries the first and
        # the others are reachable through the capability graph.
        test = await _upsert_generated_test(
            session,
            organization_id=system.organization_id,
            system_id=system_id,
            outcome=outcome,
            control_id=check.control_ids[0],
            title=check.title,
            capability_id=capability_id,
        )
        detail = (
            f"{outcome.failing} of {outcome.evaluated} {check.resource_type}(s) failing"
            if outcome.evaluated
            else "no resources in scope"
        )
        await record_result(
            session,
            test,
            status=outcome.verdict,
            detail=detail,
            actor=actor,
            evaluated=outcome.evaluated,
            failing=outcome.failing,
            expected=outcome.expected,
            resources=outcome.findings,
        )
        recorded.append(
            {
                "check_key": outcome.check_key,
                "verdict": outcome.verdict,
                "evaluated": outcome.evaluated,
                "failing": outcome.failing,
            }
        )

    return {
        "system_id": system_id,
        "connector": connector_key,
        "checks_run": len(recorded),
        "results": recorded,
    }


async def effective_verdict(
    session: AsyncSession, *, system_id: int, control_id: str
) -> dict[str, Any]:
    """Which verdict should be believed for this control on this system.

    A fresh deterministic result outranks a model verdict: a check that
    actually read the environment is stronger evidence than a model reasoning
    over documents. The model covers what no check reaches.

    This is a read-side helper. It deliberately does not rewire the assessment
    engine, which keeps recording its own verdicts.
    """
    cutoff = datetime.now(UTC) - timedelta(days=STALE_AFTER_DAYS)
    row = (
        await session.execute(
            select(ControlTestResult, ControlTest)
            .join(ControlTest, ControlTest.id == ControlTestResult.control_test_id)
            .where(
                ControlTest.system_id == system_id,
                ControlTest.control_id == control_id,
                ControlTestResult.run_at >= cutoff,
            )
            .order_by(ControlTestResult.run_at.desc())
            .limit(1)
        )
    ).first()
    if row is None:
        return {
            "system_id": system_id,
            "control_id": control_id,
            "source": None,
            "verdict": None,
            "reason": "no fresh deterministic result",
        }
    result, test = row[0], row[1]
    return {
        "system_id": system_id,
        "control_id": control_id,
        "source": "deterministic",
        "verdict": result.status,
        "run_at": result.run_at,
        "evaluated": result.evaluated,
        "failing": result.failing,
        "test_id": test.id,
        "reason": "a deterministic check outranks a model verdict",
    }
```

- [ ] **Step 5: Record why check retirement is not implemented here**

The spec states "retiring a check deactivates its test; it never deletes it."
`CHECK_REGISTRY` ships **empty** in P2a (adapters are P3), so nothing can be
retired yet and a deactivation sweep would be untestable code guarding an
impossible state. Add this note to `scan.py`'s module docstring so the rule
travels with the code rather than living only in the spec:

```python
# Check retirement is not handled here. When a PostureCheck is removed from
# the registry its generated ControlTest must be DEACTIVATED, never deleted --
# validation history is the product. That sweep belongs with P3, which is the
# first pass that can actually remove a check; implementing it now would be
# untestable code guarding a state the empty registry makes unreachable.
```

- [ ] **Step 6: Run tests**

Run: `pytest tests/test_posture_scan.py -v`
Expected: 8 passed

- [ ] **Step 7: Commit**

```bash
ruff check src/ccf/posture/scan.py tests/test_posture_scan.py
mypy src/ccf/posture/scan.py
git add src/ccf/posture/scan.py tests/test_posture_scan.py
git commit -m "feat(posture): scan orchestration and deterministic-check precedence"
```

---

### Task 6: API, CLI, and full verification

**Files:**
- Modify: `src/ccf/api/routes/posture.py`
- Modify: `src/ccf/api/routes/conmon.py`
- Modify: `src/ccf/cli.py`
- Test: `tests/test_posture_api.py`

**Interfaces:**
- Produces: `POST /api/systems/{system_id}/scan`, `GET /api/control-tests/{test_id}/results/{result_id}/resources`, `GET /api/posture/failing-resources`, `GET /api/controls/{control_id}/effective-verdict`; `ccf posture scan --system <id> --connector <key>`

- [ ] **Step 1: Read the two route modules' conventions**

```bash
sed -n '1,40p' src/ccf/api/routes/posture.py
grep -n "@router\|Depends" src/ccf/api/routes/conmon.py | head -20
```

Match their dependency sets and serializer style exactly.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_posture_api.py
"""Posture endpoints, including the org-wide failing-resources query."""

from __future__ import annotations

import itertools

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResult, ControlTestResourceResult

_SEQ = itertools.count()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


@pytest.mark.asyncio
async def test_openapi_lists_posture_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/systems/{system_id}/scan" in paths
        assert "/api/posture/failing-resources" in paths
        assert "/api/controls/{control_id}/effective-verdict" in paths
        assert (
            "/api/control-tests/{test_id}/results/{result_id}/resources" in paths
        )


@pytest.mark.asyncio
async def test_failing_resources_returns_only_failures() -> None:
    async with session_scope() as session:
        org = Organization(name=f"ApiPostOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"ApiPostSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        t = ControlTest(
            organization_id=org.id, system_id=sys_.id, control_id="AC-3", name="demo"
        )
        session.add(t)
        await session.flush()
        r = ControlTestResult(control_test_id=t.id, status="fail", evaluated=2, failing=1)
        session.add(r)
        await session.flush()
        session.add(
            ControlTestResourceResult(
                result_id=r.id, resource_id="bad-bucket", resource_type="s3_bucket",
                verdict="fail", observed="public",
            )
        )
        session.add(
            ControlTestResourceResult(
                result_id=r.id, resource_id="good-bucket", resource_type="s3_bucket",
                verdict="pass", observed="blocked",
            )
        )
        await session.flush()
        result_id, test_id = r.id, t.id

    async with _client() as client:
        failing = await client.get("/api/posture/failing-resources")
        assert failing.status_code == 200
        ids = [row["resource_id"] for row in failing.json()]
        assert "bad-bucket" in ids
        assert "good-bucket" not in ids

        detail = await client.get(
            f"/api/control-tests/{test_id}/results/{result_id}/resources"
        )
        assert detail.status_code == 200
        assert len(detail.json()) == 2   # the per-result view shows all of them


@pytest.mark.asyncio
async def test_failing_resources_filters_by_resource_type() -> None:
    async with _client() as client:
        r = await client.get("/api/posture/failing-resources?resource_type=no_such_type")
        assert r.status_code == 200
        assert r.json() == []


@pytest.mark.asyncio
async def test_scan_on_an_unconfigured_connector_reports_the_reason() -> None:
    async with session_scope() as session:
        org = Organization(name=f"ApiPostOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"ApiPostSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        sid = sys_.id

    async with _client() as client:
        r = await client.post(f"/api/systems/{sid}/scan?connector=aws_govcloud")
        assert r.status_code == 200
        assert r.json()["checks_run"] == 0
        assert "not configured" in r.json()["reason"]


@pytest.mark.asyncio
async def test_scan_on_an_unknown_system_is_404() -> None:
    async with _client() as client:
        r = await client.post("/api/systems/999999/scan?connector=aws_govcloud")
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_effective_verdict_reports_no_source_when_unobserved() -> None:
    async with session_scope() as session:
        org = Organization(name=f"ApiPostOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"ApiPostSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        sid = sys_.id

    async with _client() as client:
        r = await client.get(f"/api/controls/AC-3/effective-verdict?system_id={sid}")
        assert r.status_code == 200
        assert r.json()["source"] is None
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_posture_api.py -v`
Expected: FAIL — 404 on the new paths

- [ ] **Step 4: Add the endpoints**

In `src/ccf/api/routes/posture.py`, extend the module docstring to record that
the prefix now serves both senses:

```python
"""Enterprise compliance posture API — org-wide rollups and analytics, plus
live security-posture reads.

This module deliberately serves both senses of "posture". The original
endpoints roll up internal records (POA&M aging, evidence freshness); the
``failing-resources`` endpoint reports what a live scan observed in the
environment. They share one URL prefix rather than splitting it across two
modules.
"""
```

Then add to `src/ccf/api/routes/posture.py`:

```python
@router.get("/failing-resources")
async def failing_resources(
    resource_type: str | None = None,
    limit: int = 200,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Every resource currently failing a control test, newest first.

    The org-wide question resource granularity exists to answer. Indexed on
    ``verdict`` so this is a lookup rather than a scan.
    """
    stmt = (
        select(
            ControlTestResourceResult,
            ControlTest.control_id,
            ControlTest.system_id,
            ControlTest.id,
        )
        .join(
            ControlTestResult,
            ControlTestResult.id == ControlTestResourceResult.result_id,
        )
        .join(ControlTest, ControlTest.id == ControlTestResult.control_test_id)
        .where(ControlTestResourceResult.verdict == "fail")
        .order_by(ControlTestResourceResult.created_at.desc())
        .limit(min(max(limit, 1), 1000))
    )
    if principal.org_id is not None:
        stmt = stmt.where(ControlTest.organization_id == principal.org_id)
    if resource_type:
        stmt = stmt.where(ControlTestResourceResult.resource_type == resource_type)
    return [
        {
            "resource_id": row[0].resource_id,
            "resource_type": row[0].resource_type,
            "observed": row[0].observed,
            "detail": row[0].detail,
            "result_id": row[0].result_id,
            "created_at": row[0].created_at,
            "control_id": row[1],
            "system_id": row[2],
            "test_id": row[3],
        }
        for row in (await session.execute(stmt)).all()
    ]
```

Add the imports it needs to that module: `select` from `sqlalchemy`,
`AsyncSession`, `Principal`, `Any`, and
`ControlTest, ControlTestResult, ControlTestResourceResult` from
`...models_grc`.

And add to `src/ccf/api/routes/conmon.py`:

```python
@router.post("/systems/{system_id}/scan")
async def scan_system(
    system_id: int,
    connector: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Scan one system with one connector, recording per-resource findings."""
    from ...posture.scan import scan_for_system  # noqa: PLC0415

    try:
        out = await scan_for_system(
            session,
            system_id=system_id,
            connector_key=connector,
            actor=principal.email,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    await session.commit()
    return out


@router.get("/control-tests/{test_id}/results/{result_id}/resources")
async def result_resources(
    test_id: int,
    result_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Every resource row for one result -- passing and failing alike.

    Unlike the org-wide failing-resources view, the per-result view shows
    what was evaluated, not only what broke: "3 of 47" is only meaningful
    alongside the 44.
    """
    owner = (
        await session.execute(
            select(ControlTest)
            .join(ControlTestResult, ControlTestResult.control_test_id == ControlTest.id)
            .where(ControlTest.id == test_id, ControlTestResult.id == result_id)
        )
    ).scalars().first()
    if owner is None:
        raise HTTPException(status_code=404, detail="Unknown result for that test")
    if principal.org_id is not None and owner.organization_id != principal.org_id:
        raise HTTPException(status_code=404, detail="Unknown result for that test")
    rows = (
        await session.execute(
            select(ControlTestResourceResult)
            .where(ControlTestResourceResult.result_id == result_id)
            .order_by(ControlTestResourceResult.verdict, ControlTestResourceResult.resource_id)
        )
    ).scalars().all()
    return [
        {
            "resource_id": r.resource_id,
            "resource_type": r.resource_type,
            "verdict": r.verdict,
            "observed": r.observed,
            "detail": r.detail,
        }
        for r in rows
    ]


@router.get("/controls/{control_id}/effective-verdict")
async def control_effective_verdict(
    control_id: str,
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Which verdict should be believed for this control on this system."""
    from ...posture.scan import effective_verdict  # noqa: PLC0415

    return await effective_verdict(session, system_id=system_id, control_id=control_id)
```

Add `ControlTestResourceResult` to `conmon.py`'s existing `models_grc` import,
and `HTTPException` / `select` / `Principal` / `Any` if the module lacks them.

- [ ] **Step 5: Add the CLI group**

In `src/ccf/cli.py`, following the `capability_app` pattern:

```python
posture_app = typer.Typer(
    help="Live security posture — scan an environment and record findings.",
    no_args_is_help=True,
)
app.add_typer(posture_app, name="posture")


@posture_app.command("scan")
def posture_scan(
    system: int = typer.Option(..., "--system", help="System id to scan."),
    connector: str = typer.Option(..., "--connector", help="Connector key, e.g. aws_govcloud."),
) -> None:
    """Scan one system with one connector and record per-resource findings."""
    from .posture.scan import scan_for_system  # noqa: PLC0415

    async def _run() -> Any:
        async with session_scope() as session:
            out = await scan_for_system(
                session, system_id=system, connector_key=connector, actor="cli"
            )
            await session.commit()
            return out

    out = asyncio.run(_run())
    if not out["checks_run"]:
        console.print(f"[yellow]No checks run:[/yellow] {out.get('reason', 'no checks')}")
        return
    for r in out["results"]:
        colour = "green" if r["verdict"] == "pass" else "red"
        console.print(
            f"  [{colour}]{r['verdict']:<22}[/{colour}] {r['check_key']}"
            f"  ({r['failing']}/{r['evaluated']} failing)"
        )
```

- [ ] **Step 6: Run the full suite**

```bash
export CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
pytest -q -p no:randomly
ruff check src tests
mypy src
alembic heads   # exactly one
```

Expected: the only failure is the known pre-existing
`test_analytics_residual_and_overdue.py::test_dashboard_overview_sla_excludes_no_due_date_from_on_track`
(it fails on `main` at line 272 — confirm it is still the *only* failure);
lint and types clean; one head.

- [ ] **Step 7: Mutation-test the new guards**

Delete each, confirm a test fails, restore:

1. the `EXCLUDED_FROM_ROLLUP` skip in `roll_up_findings`
2. the `if not considered: return "not_applicable"` empty-fleet guard
3. the `v not in VALIDATION_STATUSES` rejection in `roll_up_findings`
4. the `status not in VALIDATION_STATUSES` rejection in `record_result`
5. the machine-owned-fields-only rule in `_upsert_generated_test` (add
   `test.name = title` to the update branch — the human-edits test must fail)
6. the `if conn is None` unconfigured guard in `scan_for_system`
7. the `ControlTestResult.run_at >= cutoff` freshness filter in
   `effective_verdict`
8. the `check is None` unknown-check skip in `scan_for_system`

- [ ] **Step 8: Commit**

```bash
git add src/ccf/api/routes/posture.py src/ccf/api/routes/conmon.py src/ccf/cli.py tests/test_posture_api.py
git commit -m "feat(posture): scan, resource, and precedence endpoints plus a CLI"
```
