# Capability-Derived SSP Narrative (P4a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make editing one capability re-render every control it maps to — the payoff P1 was built for.

**Architecture:** `ssp/statements.compose` gains an optional `capability_statements` sequence that replaces only the *mechanism* clause (`"by configuring {services}"`); every tail `_finish` appends is untouched. Resolution lives in `capability/service.py` so `statements.py` stays pure, and `governance/automation.generate_statements` pre-loads one map before its entry loop.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, pytest + pytest-asyncio. No migration.

**Spec:** `docs/superpowers/specs/2026-09-14-capability-derived-narrative-design.md`
**Depends on:** `docs/superpowers/specs/2026-09-14-capability-ontology-design.md` (P1)

## Global Constraints

- **Additive, provably.** `capability_statements` defaults to `()`. A golden test MUST assert that with no capability statements, `compose` returns output **byte-identical** to calling it without the parameter at all — for every responsibility branch and every value of `STYLES`. This is the property that makes touching the SSP generator safe.
- **Only the mechanism clause changes.** Everything `_finish` appends — ODP parameters, responsible role, review frequency, evidence, CRM, policy reference, `DRAFT_PREFIX` — is untouched in every branch.
- **`needs_review` behaviour MUST NOT change.** It is identical with and without capability text, in every branch. Relaxing a review requirement is a compliance-posture decision outside this sub-project; getting it wrong puts unreviewed text into an authorization package.
- **`ssp/statements.py` stays pure** — no database, no session, no clock. Its module docstring asserts side-effect freedom. Resolution lives in `capability/service.py`.
- **Do not touch the AI path.** `ai.draft_narrative` in `generate_statements` is unchanged.
- **Deterministic ordering.** Statements are sorted by capability key. Non-deterministic prose would be noise now and fatal to P4d's redline later.
- **Three exclusions:** an empty or whitespace-only `Capability.statement`; a capability whose `status == "not_applicable"`; and a project whose `system_id` is `None` (the column is nullable — `models.py:1049`).
- **`not_applicable` controls ignore capability text entirely** — nothing is implemented, so there is nothing to describe.
- **One query, not one per control.** The map loads once before the loop, matching how `generate_statements` already pre-loads `caps_by_nist`, `vendors_by_name`, and `policy_by_control`.
- **Both id spaces must match.** `SSPControlEntry.control_id` may be a CMMC practice (`AC.L2-3.1.1`, which does not canonicalize) while capability edges store canonical 800-53 (`AC-2`); `nist_id` carries the 800-53 form. Try both through `canonicalize`.
- **No schema change and no migration.** P1's tables hold everything this reads.
- **Test database is on port 5434.** `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`. Never run two pytest sessions at once.
- **Tests share one database.** `session_scope` COMMITS and the schema migrates once per session. `Organization.name` and `Capability.(organization_id, key)` are UNIQUE.
- `ruff check src tests` and `mypy src` must be clean.

---

### Task 1: The mechanism clause in `compose`

Pure, no database, and it carries the safety property — so it comes first.

**Files:**
- Modify: `src/ccf/ssp/statements.py`
- Test: `tests/test_statements_capability.py`

**Interfaces:**
- Produces:
  - `compose(..., capability_statements: Sequence[str] = ()) -> tuple[str, bool]`
  - `_capability_clause(capability_statements: Sequence[str], *, residual: bool = False) -> str`
  - `_usable_statements(capability_statements: Sequence[str]) -> list[str]`

- [x] **Step 1: Write the failing test**

```python
# tests/test_statements_capability.py
"""Capability-authored text replaces the mechanism clause, and nothing else."""

from __future__ import annotations

from ccf.ssp.statements import STYLES, compose

CAP = "Entra ID Conditional Access enforces MFA on all interactive sign-ins"


def _c(**kw):
    base = dict(
        control_id="IA-2",
        requirement="uniquely identify and authenticate users",
        responsibility="customer",
        source="platform:m365_gcc_high",
        environment="Microsoft 365 Government (GCC High)",
        services="Entra ID Conditional Access",
    )
    base.update(kw)
    return compose(**base)


# ── The safety property ──────────────────────────────────────────────────────


def test_no_capability_is_byte_identical_to_not_passing_the_parameter() -> None:
    """The property that makes touching the SSP generator safe."""
    for responsibility in ("customer", "shared", "inherited", "not_applicable"):
        for style in STYLES:
            without, nr_without = _c(responsibility=responsibility, style=style)
            with_empty, nr_with = _c(
                responsibility=responsibility, style=style, capability_statements=()
            )
            assert without == with_empty, f"{responsibility}/{style}"
            assert nr_without == nr_with, f"{responsibility}/{style}"


# ── Where the text goes, per branch ──────────────────────────────────────────


def test_customer_branch_uses_the_capability_as_the_mechanism() -> None:
    text, _ = _c(responsibility="customer", capability_statements=(CAP,))
    assert CAP in text
    assert "by configuring Entra ID Conditional Access to" not in text


def test_shared_branch_uses_the_capability_as_the_mechanism() -> None:
    text, _ = _c(responsibility="shared", capability_statements=(CAP,))
    assert CAP in text


def test_inherited_branch_describes_residual_action() -> None:
    """The provider implements it; the capability is the customer's residual part."""
    text, _ = _c(
        responsibility="inherited",
        source="vendor:AWS GovCloud",
        crm_ref="FedRAMP-1234",
        capability_statements=(CAP,),
    )
    assert "inherited from AWS GovCloud" in text
    assert CAP in text


def test_not_applicable_ignores_capability_text() -> None:
    """Nothing is implemented, so there is nothing to describe."""
    text, _ = _c(responsibility="not_applicable", capability_statements=(CAP,))
    assert CAP not in text


# ── Many capabilities, deterministically ─────────────────────────────────────


def test_multiple_capabilities_are_joined() -> None:
    text, _ = _c(capability_statements=("alpha mechanism", "beta mechanism"))
    assert "alpha mechanism" in text
    assert "beta mechanism" in text


def test_ordering_is_stable_regardless_of_input_order() -> None:
    """Regenerating an SSP must produce identical prose."""
    a, _ = _c(capability_statements=("alpha", "beta", "gamma"))
    b, _ = _c(capability_statements=("gamma", "alpha", "beta"))
    assert a == b


# ── Exclusions ───────────────────────────────────────────────────────────────


def test_empty_and_whitespace_statements_are_dropped() -> None:
    """An empty clause would render "...by ." ."""
    baseline, _ = _c()
    text, _ = _c(capability_statements=("", "   ", "\n"))
    assert text == baseline


def test_a_usable_statement_among_empty_ones_still_renders() -> None:
    text, _ = _c(capability_statements=("", CAP, "  "))
    assert CAP in text


# ── needs_review is untouched ────────────────────────────────────────────────


def test_needs_review_is_identical_with_and_without_capabilities() -> None:
    """Relaxing the review posture is out of scope; prove it did not drift."""
    for responsibility in ("customer", "shared", "not_applicable"):
        _, without = _c(responsibility=responsibility)
        _, with_cap = _c(responsibility=responsibility, capability_statements=(CAP,))
        assert without == with_cap, responsibility


def test_inherited_without_crm_still_needs_review_with_a_capability() -> None:
    """FR-11 must survive: a capability statement is not a CRM reference."""
    _, needs_review = _c(
        responsibility="inherited",
        source="vendor:AWS GovCloud",
        crm_ref=None,
        capability_statements=(CAP,),
    )
    assert needs_review is True


# ── The tails still appear ───────────────────────────────────────────────────


def test_tails_survive_a_capability_statement() -> None:
    text, _ = _c(
        capability_statements=(CAP,),
        odp_values={"mfa_enforced": "required"},
        responsible_role="ISSO",
        frequency="annually",
        policy_ref="Access Control Policy",
    )
    assert CAP in text
    assert "mfa enforced: required" in text
    assert "ISSO" in text
    assert "annually" in text
    assert "Access Control Policy" in text
```

- [x] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_statements_capability.py -v`
Expected: FAIL — `TypeError: compose() got an unexpected keyword argument 'capability_statements'`

- [x] **Step 3: Add the helpers to `src/ccf/ssp/statements.py`**

Place them beside the other private clause builders (after `_policy_clause`):

```python
def _usable_statements(capability_statements: Sequence[str]) -> list[str]:
    """Non-empty capability statements, in a stable order.

    Sorted so regenerating an SSP produces identical prose -- reproducibility
    now, and a precondition for narrative redline later. Empty and
    whitespace-only entries are dropped: an empty clause would render
    "...by ." .
    """
    return sorted({s.strip() for s in capability_statements if s and s.strip()})


# _capability_clause is added in Step 4, once the grammar problem there has
# been read -- it replaces the mechanism-splicing approach entirely.
```

Add `from collections.abc import Sequence` to the imports.

- [x] **Step 4: Thread the parameter through `compose`**

Add to the signature, last, after `crm_ref`:

```python
    capability_statements: Sequence[str] = (),
```

Extend the docstring:

```
    ``capability_statements`` are the authored statements of the capabilities
    that cover this control (P1). When present, an implementation sentence
    naming them is appended to the body, so one capability edited once
    re-renders every control it maps to. Empty by default, which makes every
    existing call byte-identical.
```

**A deviation from the spec, forced by grammar — read this before coding.**

The spec says the capability text *replaces* the mechanism clause
(`"by configuring {services}"`). Attempting that does not survive contact with
the two branches, because they need different grammatical forms:

- `customer` reads "…**by configuring** {services} to {obj}" — a gerund
- `shared` reads "…the organization **configures** {services} to {obj}" — a
  finite verb

One mechanism string cannot serve both without rewording the originals, and
rewording them breaks the byte-identical guarantee that makes this change
safe. Worse, capability statements are **whole sentences** ("Entra ID
Conditional Access enforces MFA on all interactive sign-ins"), not fragments,
so splicing one into either slot produces broken English.

**So the capability text is appended as its own sentence rather than spliced
into an existing one.** This is strictly safer — the no-capability path is
byte-identical by construction, because nothing is appended — and it reads
correctly in every branch. The framing sentence stays, and the capability
supplies the specific implementation after it.

Add the helper beside the other clause builders:

```python
def _capability_clause(capability_statements: Sequence[str], *, residual: bool = False) -> str:
    """An implementation sentence naming the capabilities that cover a control.

    Appended rather than spliced into the body sentence. Capability statements
    are whole sentences, and the ``customer`` and ``shared`` branches need
    different grammatical forms ("by configuring X" versus "configures X"), so
    interpolating one string into both would either break the grammar or force
    rewording the existing prose -- and rewording it would break the
    byte-identical guarantee for controls no capability covers.

    ``residual`` frames it for an inherited control, where the provider
    implements the control and the organization's capability covers only what
    is left.
    """
    usable = _usable_statements(capability_statements)
    if not usable:
        return ""
    lead = "The organization's residual implementation" if residual else "Implementation"
    return f" {lead}: {'; '.join(usable)}."
```

Now use it in the three branches that describe an implementation. **The
`not_applicable` branch is left exactly as it is** — nothing is implemented
there, so there is nothing to describe.

`inherited` — appended to the customer-responsibility line, framed as residual:

```python
        customer_line = (
            f" Customer responsibility: {role} monitors {provider}'s continued authorization "
            f"and performs any residual configuration or hybrid actions needed to {obj} that "
            f"{provider} does not fully cover."
        ) + _capability_clause(capability_statements, residual=True)
```

`shared` — the existing sentence is untouched; the clause follows it:

```python
    if responsibility == "shared":
        return _finish(
            f"Control {control_id} is a shared responsibility on {environment}. The platform "
            f"provides the underlying capability, and the organization configures {services} "
            f"to {obj}." + _capability_clause(capability_statements),
            True,
            evidence=_evidence_clause("shared"),
        )
```

`customer` — likewise, both the concise and the standard/detailed forms:

```python
    evidence = _evidence_clause("customer")
    if style == "concise":
        return _finish(
            f"The organization configures {services} on {environment} to {obj}."
            + _capability_clause(capability_statements),
            True,
            evidence=evidence,
        )
    return _finish(
        f"The organization implements Control {control_id} on {environment} by configuring "
        f"{services} to {obj}." + _capability_clause(capability_statements),
        True,
        evidence=evidence,
    )
```

Every existing sentence is preserved character for character. `_mechanism_clause`
from Step 3 is **not needed** — delete it if you already added it, and keep
`_usable_statements`, which `_capability_clause` uses.

- [x] **Step 5: Run the existing statement tests**

Run: `pytest tests/test_statements.py tests/test_ssp_conformance.py tests/test_ssp_vocabulary.py tests/test_ssp_completeness.py -v`
Expected: **all pass, with no test edited.** Because nothing is appended when
no capability covers a control, existing output is unchanged by construction.
If any test fails, an existing sentence was altered — restore it rather than
adjusting the test.

- [x] **Step 6: Update the capability tests for the append form**

Two assertions in Step 1 assumed splicing and must now assert appending:

```python
def test_customer_branch_appends_the_capability_implementation() -> None:
    text, _ = _c(responsibility="customer", capability_statements=(CAP,))
    # The framing sentence survives; the capability follows it.
    assert "by configuring Entra ID Conditional Access" in text
    assert f"Implementation: {CAP}." in text


def test_inherited_branch_frames_the_capability_as_residual() -> None:
    text, _ = _c(
        responsibility="inherited",
        source="vendor:AWS GovCloud",
        crm_ref="FedRAMP-1234",
        capability_statements=(CAP,),
    )
    assert "inherited from AWS GovCloud" in text
    assert f"The organization's residual implementation: {CAP}." in text
```

- [x] **Step 7: Run both suites**

Run: `pytest tests/test_statements_capability.py tests/test_statements.py tests/test_ssp_conformance.py tests/test_ssp_vocabulary.py tests/test_ssp_completeness.py -v`
Expected: all pass, with `tests/test_statements.py` unedited.

- [x] **Step 8: Lint and commit**

```bash
ruff check src/ccf/ssp/statements.py tests/test_statements_capability.py
mypy src/ccf/ssp/statements.py
git add src/ccf/ssp/statements.py tests/test_statements_capability.py
git commit -m "feat(ssp): let a capability supply the implementation mechanism clause"
```

---

### Task 2: Resolution — which capabilities cover this control, for this system

**Files:**
- Modify: `src/ccf/capability/service.py`
- Test: `tests/test_capability_statements_resolution.py`

**Interfaces:**
- Consumes: `Capability`, `CapabilityControl`, `CapabilityComponent` (P1); `canonicalize`
- Produces: `async capability_statements_by_control(session, *, system_id: int) -> dict[str, list[str]]`

- [x] **Step 1: Write the failing test**

```python
# tests/test_capability_statements_resolution.py
"""Capability statements, keyed by canonical control id, scoped to one system."""

from __future__ import annotations

import itertools

from ccf.capability.service import capability_statements_by_control
from ccf.db import session_scope
from ccf.models import Organization, System, SystemComponent
from ccf.models_capability import Capability, CapabilityComponent, CapabilityControl

_SEQ = itertools.count()


async def _bind(
    session,
    *,
    control_id: str,
    statement: str | None,
    status: str = "implemented",
):
    """One org + system + component + capability mapped to one control."""
    org = Organization(name=f"NarrOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"NarrSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    comp = SystemComponent(
        organization_id=org.id, system_id=sys_.id, type="service", title="Entra ID"
    )
    session.add(comp)
    cap = Capability(
        organization_id=org.id,
        key=f"cap-{next(_SEQ)}",
        title="MFA",
        statement=statement,
        status=status,
    )
    session.add(cap)
    await session.flush()
    session.add(
        CapabilityComponent(
            organization_id=org.id, capability_id=cap.id, component_id=comp.id
        )
    )
    session.add(
        CapabilityControl(
            organization_id=org.id, capability_id=cap.id, control_id=control_id
        )
    )
    await session.flush()
    return org, sys_, cap


async def test_returns_statements_keyed_by_canonical_control_id() -> None:
    async with session_scope() as session:
        _, sys_, _ = await _bind(
            session, control_id="IA-2", statement="Conditional Access enforces MFA"
        )
        out = await capability_statements_by_control(session, system_id=sys_.id)
        assert out == {"IA-2": ["Conditional Access enforces MFA"]}


async def test_key_is_canonicalised_from_a_padded_edge() -> None:
    """An edge stored as IA-02 must still be found under IA-2."""
    async with session_scope() as session:
        _, sys_, _ = await _bind(session, control_id="IA-02", statement="padded edge")
        out = await capability_statements_by_control(session, system_id=sys_.id)
        assert out == {"IA-2": ["padded edge"]}


async def test_empty_statement_is_excluded() -> None:
    async with session_scope() as session:
        _, sys_, _ = await _bind(session, control_id="IA-2", statement="")
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}


async def test_null_statement_is_excluded() -> None:
    async with session_scope() as session:
        _, sys_, _ = await _bind(session, control_id="IA-2", statement=None)
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}


async def test_not_applicable_capability_is_excluded() -> None:
    """It does not describe this system's implementation, so it must not claim to."""
    async with session_scope() as session:
        _, sys_, _ = await _bind(
            session,
            control_id="IA-2",
            statement="should not appear",
            status="not_applicable",
        )
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}


async def test_another_systems_capability_does_not_leak() -> None:
    async with session_scope() as session:
        _, sys_a, _ = await _bind(session, control_id="IA-2", statement="system A")
        _, sys_b, _ = await _bind(session, control_id="IA-2", statement="system B")
        out_a = await capability_statements_by_control(session, system_id=sys_a.id)
        assert out_a == {"IA-2": ["system A"]}


async def test_system_with_no_capabilities_is_empty() -> None:
    async with session_scope() as session:
        org = Organization(name=f"NarrOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"Bare-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}


async def test_two_capabilities_on_one_control_are_both_returned() -> None:
    async with session_scope() as session:
        org, sys_, _ = await _bind(session, control_id="IA-2", statement="first")
        comp = SystemComponent(
            organization_id=org.id, system_id=sys_.id, type="process", title="Runbook"
        )
        session.add(comp)
        second = Capability(
            organization_id=org.id,
            key=f"cap-{next(_SEQ)}",
            title="Second",
            statement="second",
            status="implemented",
        )
        session.add(second)
        await session.flush()
        session.add(
            CapabilityComponent(
                organization_id=org.id, capability_id=second.id, component_id=comp.id
            )
        )
        session.add(
            CapabilityControl(
                organization_id=org.id, capability_id=second.id, control_id="IA-2"
            )
        )
        await session.flush()

        out = await capability_statements_by_control(session, system_id=sys_.id)
        assert sorted(out["IA-2"]) == ["first", "second"]


async def test_an_unparseable_edge_is_skipped_not_crashed() -> None:
    async with session_scope() as session:
        _, sys_, _ = await _bind(
            session, control_id="not a control id", statement="orphan"
        )
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}
```

- [x] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_capability_statements_resolution.py -v`
Expected: FAIL — `ImportError: cannot import name 'capability_statements_by_control'`

- [x] **Step 3: Implement**

Append to `src/ccf/capability/service.py`:

```python
async def capability_statements_by_control(
    session: AsyncSession, *, system_id: int
) -> dict[str, list[str]]:
    """Authored capability statements for one system, by canonical control id.

    Loaded as one query so a caller rendering 400 controls does not make 400
    round trips -- ``governance.automation.generate_statements`` pre-loads this
    beside the maps it already builds for captures, vendors, and policies.

    Three exclusions, each deliberate. A capability with no statement has
    nothing to contribute. A ``not_applicable`` capability does not describe
    this system's implementation, so its text must not claim to. And an edge
    whose control id does not canonicalize is skipped rather than keyed under
    a value nothing will look up.

    The map has exactly one key space -- canonical ids. Reconciling the two id
    forms an ``SSPControlEntry`` may carry is the caller's job.
    """
    rows = (
        await session.execute(
            select(CapabilityControl.control_id, Capability.statement)
            .join(Capability, Capability.id == CapabilityControl.capability_id)
            .join(
                CapabilityComponent,
                CapabilityComponent.capability_id == Capability.id,
            )
            .join(
                SystemComponent,
                SystemComponent.id == CapabilityComponent.component_id,
            )
            .where(
                SystemComponent.system_id == system_id,
                Capability.status != "not_applicable",
            )
        )
    ).all()

    out: dict[str, list[str]] = {}
    for raw_control, statement in rows:
        if not statement or not statement.strip():
            continue
        c = canonicalize(raw_control)
        if c is None:
            continue
        bucket = out.setdefault(c.value, [])
        text = statement.strip()
        # A capability bound through two components would otherwise appear
        # twice for the same control.
        if text not in bucket:
            bucket.append(text)
    return out
```

Add `CapabilityComponent` to the `models_capability` import and
`SystemComponent` to the `..models` import.

- [x] **Step 4: Run tests**

Run: `pytest tests/test_capability_statements_resolution.py tests/test_capability_reach.py -v`
Expected: all pass — the new resolution tests plus P1's existing reach tests.

- [x] **Step 5: Lint and commit**

```bash
ruff check src/ccf/capability/service.py tests/test_capability_statements_resolution.py
mypy src/ccf/capability/service.py
git add src/ccf/capability/service.py tests/test_capability_statements_resolution.py
git commit -m "feat(capability): resolve authored statements by control for one system"
```

---

### Task 3: Wire it into `generate_statements`

**Files:**
- Modify: `src/ccf/governance/automation.py`
- Test: `tests/test_ssp_capability_narrative.py`

**Interfaces:**
- Consumes: `compose(..., capability_statements=...)` (Task 1); `capability_statements_by_control` (Task 2)
- Produces: `_cap_key(entry: SSPControlEntry) -> str | None` (module-private)

- [x] **Step 1: Write the failing test**

```python
# tests/test_ssp_capability_narrative.py
"""End to end: edit one capability, and every control it maps to re-renders."""

from __future__ import annotations

import itertools

from sqlalchemy import select

from ccf.db import session_scope
from ccf.governance.automation import generate_statements
from ccf.models import (
    Organization,
    SSPControlEntry,
    SSPProject,
    System,
    SystemComponent,
    SystemProfile,
)
from ccf.models_capability import Capability, CapabilityComponent, CapabilityControl

_SEQ = itertools.count()
CAP_TEXT = "Entra ID Conditional Access enforces MFA on all interactive sign-ins"


async def _project_with_capability(session, *, control_ids: list[str]):
    """A project whose system has one capability covering several controls."""
    org = Organization(name=f"E2EOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"E2ESys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    comp = SystemComponent(
        organization_id=org.id, system_id=sys_.id, type="service", title="Entra ID"
    )
    session.add(comp)
    profile = SystemProfile(system_id=sys_.id, cloud_platform="m365_gcc_high")
    session.add(profile)
    project = SSPProject(
        organization_id=org.id, system_id=sys_.id, customer_name="E2E", platform="m365"
    )
    session.add(project)
    cap = Capability(
        organization_id=org.id,
        key=f"cap-{next(_SEQ)}",
        title="MFA",
        statement=CAP_TEXT,
        status="implemented",
    )
    session.add(cap)
    await session.flush()
    session.add(
        CapabilityComponent(
            organization_id=org.id, capability_id=cap.id, component_id=comp.id
        )
    )
    for cid in control_ids:
        session.add(
            CapabilityControl(
                organization_id=org.id, capability_id=cap.id, control_id=cid
            )
        )
        session.add(
            SSPControlEntry(
                project_id=project.id,
                control_id=cid,
                nist_id=cid,
                requirement="uniquely identify and authenticate users",
            )
        )
    await session.flush()
    return project, profile, cap


async def _narratives(session, project_id: int) -> dict[str, str]:
    rows = (
        await session.execute(
            select(SSPControlEntry).where(SSPControlEntry.project_id == project_id)
        )
    ).scalars().all()
    return {
        r.control_id: " ".join(p.get("text", "") for p in (r.part_narratives or []))
        for r in rows
    }


async def test_capability_text_reaches_every_mapped_control() -> None:
    async with session_scope() as session:
        project, profile, _ = await _project_with_capability(
            session, control_ids=["IA-2", "AC-7"]
        )
        await generate_statements(session, project=project, profile=profile)
        narratives = await _narratives(session, project.id)
        assert CAP_TEXT in narratives["IA-2"]
        assert CAP_TEXT in narratives["AC-7"]


async def test_editing_the_capability_rerenders_both_controls() -> None:
    """The point of the whole sub-project."""
    async with session_scope() as session:
        project, profile, cap = await _project_with_capability(
            session, control_ids=["IA-2", "AC-7"]
        )
        await generate_statements(session, project=project, profile=profile)

        cap.statement = "FIDO2 security keys are required for all privileged roles"
        await session.flush()
        await generate_statements(session, project=project, profile=profile)

        narratives = await _narratives(session, project.id)
        for cid in ("IA-2", "AC-7"):
            assert "FIDO2 security keys" in narratives[cid], cid
            assert CAP_TEXT not in narratives[cid], cid


async def test_a_control_with_no_capability_gets_the_generic_mechanism() -> None:
    async with session_scope() as session:
        project, profile, _ = await _project_with_capability(
            session, control_ids=["IA-2"]
        )
        session.add(
            SSPControlEntry(
                project_id=project.id,
                control_id="AU-2",
                nist_id="AU-2",
                requirement="record auditable events",
            )
        )
        await session.flush()
        await generate_statements(session, project=project, profile=profile)
        narratives = await _narratives(session, project.id)
        assert CAP_TEXT in narratives["IA-2"]
        assert CAP_TEXT not in narratives["AU-2"]
        assert narratives["AU-2"], "the control still gets a composed statement"


async def test_a_cmmc_entry_matches_through_nist_id() -> None:
    """control_id may be a CMMC practice that does not canonicalize; nist_id
    carries the 800-53 form and must still find the capability."""
    async with session_scope() as session:
        project, profile, cap = await _project_with_capability(
            session, control_ids=["IA-2"]
        )
        session.add(
            SSPControlEntry(
                project_id=project.id,
                control_id="IA.L2-3.5.3",
                nist_id="IA-2",
                requirement="use multifactor authentication",
            )
        )
        await session.flush()
        await generate_statements(session, project=project, profile=profile)
        narratives = await _narratives(session, project.id)
        assert CAP_TEXT in narratives["IA.L2-3.5.3"]


async def test_a_project_with_no_system_still_generates() -> None:
    """SSPProject.system_id is nullable; an unbound project composes as before."""
    async with session_scope() as session:
        org = Organization(name=f"E2EOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"E2ESys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        profile = SystemProfile(system_id=sys_.id, cloud_platform="m365_gcc_high")
        session.add(profile)
        project = SSPProject(
            organization_id=org.id, system_id=None, customer_name="Unbound"
        )
        session.add(project)
        await session.flush()
        session.add(
            SSPControlEntry(
                project_id=project.id,
                control_id="IA-2",
                nist_id="IA-2",
                requirement="authenticate users",
            )
        )
        await session.flush()
        out = await generate_statements(session, project=project, profile=profile)
        assert out is not None
        narratives = await _narratives(session, project.id)
        assert narratives["IA-2"], "composed without capability narrative"
```

- [x] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_ssp_capability_narrative.py -v`
Expected: FAIL — the capability text is absent from the rendered narrative.

- [x] **Step 3: Confirm the fields the test relies on**

The fixture guesses at some model fields. Verify each before implementing,
and correct the test to the real names rather than the reverse:

```bash
grep -n "class SystemProfile" -A 16 src/ccf/models.py
grep -n "class SSPControlEntry" -A 14 src/ccf/models.py
grep -n "part_narratives" src/ccf/governance/automation.py | head -4
```

- [x] **Step 4: Add the key helper and the pre-load**

In `src/ccf/governance/automation.py`, beside the other module-level helpers:

```python
def _cap_key(entry: SSPControlEntry) -> str | None:
    """The canonical control id this entry's capabilities would be filed under.

    ``control_id`` may be a CMMC practice (``AC.L2-3.1.1``), which does not
    canonicalize, while ``nist_id`` carries the 800-53 form. Both are tried so
    a CMMC project is not silently left without capability narrative -- the
    same two id spaces this module already bridges for captures via
    ``caps_by_nist.get(e.nist_id)``.
    """
    for candidate in (entry.control_id, entry.nist_id):
        c = canonicalize(candidate or "")
        if c is not None:
            return c.value
    return None
```

Inside `generate_statements`, after the `policy_by_control` pre-load and
before the entry loop:

```python
    # Authored capability statements for this project's system, by canonical
    # control id. One query, like the maps above -- a project can carry 400+
    # entries, and a per-control lookup would be 400 round trips. Empty when
    # the project is not bound to a system (SSPProject.system_id is nullable),
    # in which case every statement composes exactly as it did before P4a.
    caps_by_control: dict[str, list[str]] = {}
    if project.system_id is not None:
        caps_by_control = await capability_statements_by_control(
            session, system_id=project.system_id
        )
```

Add the imports: `from ..capability.service import capability_statements_by_control`
and `from ..catalog.canonical import canonicalize`.

- [x] **Step 5: Pass it into `compose`**

In the entry loop, beside the existing `captured = caps_by_nist.get(...)`:

```python
        cap_key = _cap_key(e)
        cap_statements = caps_by_control.get(cap_key, []) if cap_key else []
```

and add to the `stmt.compose(...)` call:

```python
            capability_statements=cap_statements,
```

- [x] **Step 6: Run tests**

Run: `pytest tests/test_ssp_capability_narrative.py tests/test_automation.py tests/test_statements.py tests/test_statements_capability.py -v`
Expected: all pass, including every existing automation test.

- [x] **Step 7: Lint and commit**

```bash
ruff check src/ccf/governance/automation.py tests/test_ssp_capability_narrative.py
mypy src/ccf/governance/automation.py
git add src/ccf/governance/automation.py tests/test_ssp_capability_narrative.py
git commit -m "feat(ssp): render capability-authored narrative into every mapped control"
```

---

### Task 4: Full verification and mutation testing

- [x] **Step 1: Run the full suite**

```bash
export CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
pytest -q -p no:randomly
ruff check src tests
mypy src
alembic heads   # exactly one; P4a adds no migration
```

Expected: the only failure is the known pre-existing
`test_analytics_residual_and_overdue.py::test_dashboard_overview_sla_excludes_no_due_date_from_on_track`
(it fails on `main` at line 272 — confirm it is still the *only* failure).

- [x] **Step 2: Mutation-test the new guards**

The harness restores on a trap, so a mutation that hangs cannot leave a
mutated file behind. Delete each guard, confirm a test fails, restore:

1. the `if s and s.strip()` filter in `_usable_statements` (the
   empty-statements test must fail)
2. the `sorted(...)` in `_usable_statements` (the stable-ordering test must
   fail)
3. the `if not usable: return ""` guard in `_capability_clause` (replace with
   `if True: return ""` — the capability-text tests must fail)
4. the `Capability.status != "not_applicable"` filter in the query
5. the `if not statement or not statement.strip()` skip in the query
6. the `c is None` skip for an unparseable edge
7. the `if text not in bucket` de-duplication
8. the `SystemComponent.system_id == system_id` scope (the leak test must
   fail)
9. the `entry.nist_id` fallback in `_cap_key` (the CMMC test must fail)
10. the `if project.system_id is not None` guard (the unbound-project test
    must fail)

- [x] **Step 3: Verify each mutation result**

An ESCAPED guard is a test gap, not a pass. Strengthen the test until the
mutation is caught, then re-run that mutation to confirm.

- [x] **Step 4: Demonstrate it end to end**

Write a short throwaway script that creates a system with one capability
mapped to three controls, renders, prints the three narratives, edits the
capability's `statement`, re-renders, and prints them again — showing all
three changed from one edit. Report the before/after; do not commit the
script.

- [x] **Step 5: Commit**

```bash
git add -A
git commit -m "test(ssp): mutation-test the capability-narrative guards"
```

---

## Results

All four tasks complete. Full suite: **1695 passed**, 1 skipped, and the one
pre-existing `test_dashboard_overview_sla_excludes_no_due_date_from_on_track`
failure that also fails on `main`. `ruff check src tests` and `mypy src`
clean. One migration head (`0068_posture_validation_spine`) -- P4a adds none.

Commits: `f550c2c` (Task 1), `687815d` (Task 2), `4cb9d4d` (Task 3).

### Deviations from the plan

**Appending, not splicing.** Recorded in Task 1 Step 4 before implementation:
`customer` needs a gerund and `shared` a finite verb, and capability
statements are whole sentences, so no single string can be spliced into the
mechanism slot of both without rewording prose the byte-identical guarantee
depends on.

**A trailing-period normalization that was not in the spec.** The Step 4
demonstration rendered `"...no legacy-auth exclusions.."` on all three
controls: authors write whole sentences, so a statement usually arrives
already punctuated, and `_capability_clause` supplies the sentence-ending
period. `_usable_statements` now strips a trailing period before
de-duplicating, which also makes the same statement with and without its
period one statement rather than two. Four tests cover it.

### Mutation testing

Twelve guards. **Eleven are caught by a test**; one is caught only by the
type gate:

| Guard | Result |
|---|---|
| `if s` None guard in `_usable_statements` | CAUGHT |
| `sorted(...)` ordering | CAUGHT |
| post-strip `if c` empty filter | CAUGHT |
| `.rstrip(".")` normalization | CAUGHT |
| `if not usable: return ""` | CAUGHT |
| `Capability.status != "not_applicable"` | CAUGHT |
| empty/null statement skip in the query | CAUGHT |
| unparseable-edge `c is None` skip | CAUGHT |
| `if text not in bucket` de-duplication | CAUGHT |
| `SystemComponent.system_id == system_id` scope | CAUGHT (9 tests) |
| `entry.nist_id` fallback in `_cap_key` | CAUGHT |
| `if project.system_id is not None` | **mypy only** |

The last one is honest to state plainly: removing it breaks no test, because
SQLAlchemy renders `system_id == None` as `IS NULL`, which matches no
component and returns `{}` -- the same result the guard produces. `mypy src`
does reject it (`Argument "system_id" ... has incompatible type "int | None";
expected "int"`), and mypy is part of the gate, so the guard cannot be
removed silently. No test was contrived to cover it.

**Three guards escaped on the first pass and the tests were strengthened
until they were caught** -- the escapes were the useful part of the exercise:

1. `sorted(...)` -- `test_ordering_is_stable_regardless_of_input_order`
   compares two calls with the same statements in different orders, and set
   iteration order depends on element hashes rather than insertion order, so
   the two agree even unsorted. The assertion could never have failed. Fixed
   by asserting the rendered order itself over eight statements.
2. `if not usable: return ""` -- with the guard gone, `" Implementation: ."`
   is appended to **both** sides of every comparison in the file, so every
   equality assertion still held while the prose was broken. This is the same
   vacuous-assertion shape found in P1 (`derived_status is None`). Fixed with
   an absolute assertion: no rendered statement may contain
   `"Implementation: ."`.
3. The post-strip empty filter -- `"."` passes the incoming filter and then
   strips to nothing.

### A harness bug worth remembering

The first run reported **CAUGHT for all ten guards, with zero `FAILED`
lines** -- `timeout` does not exist on macOS, so every pytest invocation
exited 127 before running. A mutation harness that cannot fail is worse than
none: it certifies whatever it is pointed at. The harness now asserts its
watchdog (`perl -e 'alarm N; exec @ARGV'`) up front, compares the file hash
before and after each mutation so a `str.replace` that matches nothing is
reported `NOT-APPLIED` instead of scored, and reports `SUSPECT` when pytest
exits non-zero without a `FAILED` line.
