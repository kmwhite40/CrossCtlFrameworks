# OSCAL Authoritative Source Spine (P0') Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bridge Concord's existing catalog-currency poller to its sha256-pinned OSCAL loader by adding retained, commit-pinned catalog revisions that a human can diff, assess for impact, and adopt.

**Architecture:** `etl/sources.py` already polls upstream authorities and logs drift to `CatalogCheck`; `catalog/oscal.py` already loads hash-verified files from disk. This adds one object between them — `CatalogRevision` — materialized as a directory with a generated `MANIFEST.json`, so adoption simply changes which directory the loader resolves. Nothing replaces the poller, the poll log, the fetch client, or the loader.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2 async, Alembic, Typer, httpx, pytest + pytest-asyncio, PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-09-14-oscal-source-spine-design.md`

## Global Constraints

- **Integrate, do not duplicate.** `CatalogSource` remains the only source registry; `CatalogCheck` remains the only poll log; `_fetch()` remains the only HTTP client; `load_oscal_catalog` remains the only catalog parser. No parallel versions of any of these.
- **`load_oscal_catalog` stays database-free.** Its signature and purity are preserved. DB-aware resolution lives in a separate async helper. `catalog/report.py` and `ssp/nist80053.py` depend on the no-DB property.
- **`_verify()` is not modified.** Its guard — every required file must be listed in the manifest — is a security property. Generated manifests must satisfy it.
- **No auto-adoption.** No scheduler, poller, or API path may adopt a revision. This preserves the existing `auto_ingest=False` principle.
- **No network I/O outside the fetch/import paths.** Load, diff, impact, and adopt must work air-gapped.
- **`catalog_revisions` is global reference data** — no `organization_id`, no RLS, consistent with `catalog_sources` / `catalog_checks` (`models.py:1751` documents this category). Writes gated by admin RBAC.
- **Test database is on port 5434**, not conftest's 5432 default. Run tests with `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`. Never run two pytest sessions concurrently.
- **Baselines stay keyed `low`/`moderate`/`high`** — these are NIST 800-53B's own baselines, unaffected by CR26. Do not rename or remap them.
- Every migration includes the `pg_roles` GRANT guard. Confirm `alembic heads` returns exactly one head.
- `ruff` and `mypy` must be clean: `make lint` (or `ruff check src tests && mypy src`).

---

### Task 1: Manifest generation

Generated manifests must satisfy the existing `_verify()` contract, so this comes first — every later task depends on producing a directory the loader accepts.

**Files:**
- Modify: `src/ccf/catalog/oscal.py`
- Test: `tests/test_catalog_manifest.py`

**Interfaces:**
- Consumes: `_CATALOG_FILE`, `_BASELINE_FILES`, `OscalManifestError` (existing module constants)
- Produces: `generate_manifest(d: Path, *, oscal_version: str, source_url: str, upstream_commit_sha: str | None, retrieved_at: str) -> dict[str, Any]` — writes `MANIFEST.json` into `d` and returns the manifest dict. Hashes every `*.json` file in `d` except `MANIFEST.json` itself.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_catalog_manifest.py
"""Generated manifests must satisfy the loader's own verification contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ccf.catalog.oscal import OscalManifestError, _verify, generate_manifest


def _write(d: Path, name: str, payload: dict) -> None:
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


def test_generated_manifest_passes_verify(tmp_path: Path) -> None:
    _write(tmp_path, "NIST_SP-800-53_rev5_catalog.json", {"catalog": {"metadata": {}}})
    for name in (
        "NIST_SP-800-53_rev5_LOW-baseline_profile.json",
        "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
        "NIST_SP-800-53_rev5_HIGH-baseline_profile.json",
    ):
        _write(tmp_path, name, {"profile": {"imports": []}})

    manifest = generate_manifest(
        tmp_path,
        oscal_version="5.2.0",
        source_url="https://example.test/catalog.json",
        upstream_commit_sha="a" * 40,
        retrieved_at="2026-09-14",
    )

    assert manifest["oscal_version"] == "5.2.0"
    assert manifest["upstream_commit_sha"] == "a" * 40
    # Round-trips through the real verifier untouched.
    assert _verify(tmp_path)["files"] == manifest["files"]


def test_generated_manifest_rejects_missing_required_file(tmp_path: Path) -> None:
    # Catalog present, baselines absent — _verify's structural guard must fire.
    _write(tmp_path, "NIST_SP-800-53_rev5_catalog.json", {"catalog": {"metadata": {}}})
    generate_manifest(
        tmp_path,
        oscal_version="5.2.0",
        source_url="https://example.test/catalog.json",
        upstream_commit_sha=None,
        retrieved_at="2026-09-14",
    )
    with pytest.raises(OscalManifestError):
        _verify(tmp_path)


def test_manifest_itself_is_not_hashed(tmp_path: Path) -> None:
    _write(tmp_path, "NIST_SP-800-53_rev5_catalog.json", {"catalog": {"metadata": {}}})
    manifest = generate_manifest(
        tmp_path,
        oscal_version="5.2.0",
        source_url="https://example.test/catalog.json",
        upstream_commit_sha=None,
        retrieved_at="2026-09-14",
    )
    assert "MANIFEST.json" not in manifest["files"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_catalog_manifest.py -v`
Expected: FAIL — `ImportError: cannot import name 'generate_manifest'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/ccf/catalog/oscal.py`, after `_verify`:

```python
_MANIFEST_NAME = "MANIFEST.json"


def generate_manifest(
    d: Path,
    *,
    oscal_version: str,
    source_url: str,
    upstream_commit_sha: str | None,
    retrieved_at: str,
) -> dict[str, Any]:
    """Write ``MANIFEST.json`` into ``d`` describing every JSON file beside it.

    The shape is exactly what :func:`_verify` consumes — ``files`` maps filename
    to sha256 — so a materialized revision directory is loadable without any
    hand-editing. ``MANIFEST.json`` is never hashed into itself.
    """
    files = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(d.glob("*.json"))
        if p.name != _MANIFEST_NAME
    }
    manifest: dict[str, Any] = {
        "oscal_version": oscal_version,
        "source_url": source_url,
        "upstream_commit_sha": upstream_commit_sha,
        "retrieved_at": retrieved_at,
        "files": files,
    }
    (d / _MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_catalog_manifest.py -v`
Expected: 3 passed

- [ ] **Step 5: Lint and commit**

```bash
ruff check src/ccf/catalog/oscal.py tests/test_catalog_manifest.py
mypy src/ccf/catalog/oscal.py
git add src/ccf/catalog/oscal.py tests/test_catalog_manifest.py
git commit -m "feat(catalog): generate MANIFEST.json in the loader's own verify shape"
```

---

### Task 2: `CatalogRevision` model and migration

**Files:**
- Modify: `src/ccf/models.py` (after `CatalogCheck`, which ends at line ~1160)
- Create: `migrations/versions/0066_catalog_revisions.py`
- Test: `tests/test_catalog_revisions_model.py`

**Interfaces:**
- Consumes: `CatalogSource` (`models.py:1098`), `Base`
- Produces: `CatalogRevision` ORM class with columns per the spec; `uq_catalog_revision` unique constraint on `(source_id, revision)`; partial unique index `uq_catalog_revision_adopted` on `(source_id) WHERE status = 'adopted'`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_catalog_revisions_model.py
"""The single-adopted-revision invariant is enforced by the database."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import CatalogRevision, CatalogSource


async def _source(session, key: str = "src_a") -> CatalogSource:
    s = CatalogSource(key=key, name=key, url="https://example.test/x.json")
    session.add(s)
    await session.flush()
    return s


async def test_one_adopted_revision_per_source() -> None:
    async with session_scope() as session:
        src = await _source(session)
        session.add(CatalogRevision(source_id=src.id, revision="aaaaaaaaaaaa", status="adopted"))
        await session.flush()
        session.add(CatalogRevision(source_id=src.id, revision="bbbbbbbbbbbb", status="adopted"))
        with pytest.raises(IntegrityError):
            await session.flush()


async def test_many_available_revisions_allowed() -> None:
    async with session_scope() as session:
        src = await _source(session, "src_b")
        for rev in ("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"):
            session.add(CatalogRevision(source_id=src.id, revision=rev, status="available"))
        await session.flush()  # no constraint violation


async def test_revision_unique_per_source() -> None:
    async with session_scope() as session:
        src = await _source(session, "src_c")
        session.add(CatalogRevision(source_id=src.id, revision="dupdupdupdup", status="available"))
        await session.flush()
        session.add(CatalogRevision(source_id=src.id, revision="dupdupdupdup", status="available"))
        with pytest.raises(IntegrityError):
            await session.flush()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_catalog_revisions_model.py -v`
Expected: FAIL — `ImportError: cannot import name 'CatalogRevision'`

- [ ] **Step 3: Add the model**

In `src/ccf/models.py`, immediately after the `CatalogCheck` class:

```python
class CatalogRevision(Base):
    """One retained, content-addressed revision of a :class:`CatalogSource`.

    Bridges the currency poller to the pinned loader. ``etl.sources`` detects
    that upstream content changed; a revision captures *that* content on disk
    with a generated ``MANIFEST.json``, so a human can diff it, read its impact,
    and adopt it — at which point ``catalog.oscal`` resolves this directory.

    Exactly one revision per source may be ``adopted``; that is a partial unique
    index, not application discipline. Global reference data: no
    ``organization_id`` and no RLS, like ``catalog_sources``.
    """

    __tablename__ = "catalog_revisions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.catalog_sources.id", ondelete="CASCADE"), index=True
    )
    # 12-char prefix of the upstream commit sha, or 'bundled' for shipped content.
    revision: Mapped[str] = mapped_column(String(64))
    upstream_commit_sha: Mapped[str | None] = mapped_column(String(64))
    upstream_url: Mapped[str | None] = mapped_column(Text)
    oscal_version: Mapped[str | None] = mapped_column(String(32))
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    # {filename: sha256} — mirrors the generated manifest.
    files: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # {control_id: prose_hash} in parse_oscal_catalog's shape, so
    # etl.sources.diff_content_index works on it directly.
    content_index: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # None => the packaged in-wheel directory (the implicit 'bundled' revision).
    content_dir: Mapped[str | None] = mapped_column(Text)
    # available | adopted | superseded | rejected
    status: Mapped[str] = mapped_column(String(16), default="available", index=True)
    retrieved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    retrieved_by: Mapped[str | None] = mapped_column(String(255))
    adopted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    adopted_by: Mapped[str | None] = mapped_column(String(255))
    # The impact report exactly as reviewed when this revision was adopted.
    adoption_impact: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    notes: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("source_id", "revision", name="uq_catalog_revision"),
        Index(
            "uq_catalog_revision_adopted",
            "source_id",
            unique=True,
            postgresql_where=text("status = 'adopted'"),
        ),
        {"schema": "ccf"},
    )
```

Ensure `Index` and `text` are imported at the top of `models.py` (check first — most are already there).

- [ ] **Step 4: Write the migration**

```python
# migrations/versions/0066_catalog_revisions.py
"""Catalog revisions — retained, commit-pinned OSCAL content per source.

Bridges the currency poller (``catalog_sources`` / ``catalog_checks``) to the
sha256-pinned loader in ``ccf.catalog.oscal``: a revision is upstream content
captured on disk with a generated manifest, which a human adopts deliberately.

``catalog_revisions`` is global reference data — no ``organization_id`` and no
RLS — consistent with ``catalog_sources`` and ``catalog_checks``. Writes are
gated by admin RBAC at the API layer, not by row policy.

Seeds the currently bundled OSCAL content as revision 'bundled', already
adopted, with ``content_dir`` NULL so it resolves to the packaged in-wheel
directory. Nothing moves on disk.

Revision ID: 0066_catalog_revisions
Revises: 0065_user_session_version
Create Date: 2026-09-14
"""

from __future__ import annotations

import json
from pathlib import Path

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0066_catalog_revisions"
down_revision = "0065_user_session_version"
branch_labels = None
depends_on = None

_PACKAGED_MANIFEST = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "ccf"
    / "catalog"
    / "oscal_data"
    / "MANIFEST.json"
)
_SOURCE_KEY = "nist_800_53_r5_catalog"


def upgrade() -> None:
    op.create_table(
        "catalog_revisions",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "source_id",
            sa.Integer,
            sa.ForeignKey("ccf.catalog_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("revision", sa.String(64), nullable=False),
        sa.Column("upstream_commit_sha", sa.String(64)),
        sa.Column("upstream_url", sa.Text),
        sa.Column("oscal_version", sa.String(32)),
        sa.Column("content_sha256", sa.String(64)),
        sa.Column("files", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("content_index", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("content_dir", sa.Text),
        sa.Column("status", sa.String(16), nullable=False, server_default="available"),
        sa.Column(
            "retrieved_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("retrieved_by", sa.String(255)),
        sa.Column("adopted_at", sa.DateTime(timezone=True)),
        sa.Column("adopted_by", sa.String(255)),
        sa.Column("adoption_impact", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("notes", sa.Text),
        sa.UniqueConstraint("source_id", "revision", name="uq_catalog_revision"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_catalog_revisions_source", "catalog_revisions", ["source_id"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_catalog_revisions_status", "catalog_revisions", ["status"], schema="ccf"
    )
    # Exactly one adopted revision per source, enforced by the database.
    op.create_index(
        "uq_catalog_revision_adopted",
        "catalog_revisions",
        ["source_id"],
        unique=True,
        postgresql_where=sa.text("status = 'adopted'"),
        schema="ccf",
    )

    # Standard grant guard: the ccf_app role exists only where RLS was set up.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )

    _seed_bundled_revision()


def _seed_bundled_revision() -> None:
    """Record the shipped OSCAL content as the adopted 'bundled' revision."""
    if not _PACKAGED_MANIFEST.is_file():
        return  # reader/SQLite builds ship no OSCAL data
    manifest = json.loads(_PACKAGED_MANIFEST.read_text(encoding="utf-8"))
    conn = op.get_bind()
    source_id = conn.execute(
        sa.text("SELECT id FROM ccf.catalog_sources WHERE key = :k"), {"k": _SOURCE_KEY}
    ).scalar()
    if source_id is None:
        source_id = conn.execute(
            sa.text(
                "INSERT INTO ccf.catalog_sources (key, name, authority, kind, url, framework_code) "
                "VALUES (:k, :n, 'NIST', 'oscal_catalog', :u, 'NIST_800_53_R5') RETURNING id"
            ),
            {
                "k": _SOURCE_KEY,
                "n": "NIST SP 800-53 Rev. 5 — control catalog (OSCAL)",
                "u": manifest.get("source_url", ""),
            },
        ).scalar()
    conn.execute(
        sa.text(
            "INSERT INTO ccf.catalog_revisions "
            "(source_id, revision, upstream_url, oscal_version, files, status, adopted_at, "
            " adopted_by, notes) "
            "VALUES (:sid, 'bundled', :url, :ver, CAST(:files AS jsonb), 'adopted', now(), "
            " 'migration:0066', :notes)"
        ),
        {
            "sid": source_id,
            "url": manifest.get("source_url"),
            "ver": manifest.get("oscal_version"),
            "files": json.dumps(manifest.get("files", {})),
            "notes": f"Bundled content, retrieved_at={manifest.get('retrieved_at')}",
        },
    )


def downgrade() -> None:
    op.drop_table("catalog_revisions", schema="ccf")
```

- [ ] **Step 5: Run the migration and the test**

```bash
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
alembic heads          # MUST print exactly one head
alembic upgrade head
pytest tests/test_catalog_revisions_model.py -v
```
Expected: one head; migration applies; 3 passed.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/models.py migrations/versions/0066_catalog_revisions.py tests/test_catalog_revisions_model.py
git commit -m "feat(catalog): retained catalog revisions with a single-adopted DB invariant"
```

---

### Task 3: Pure revision diff

**Files:**
- Create: `src/ccf/catalog/diff.py`
- Modify: `src/ccf/etl/sources.py` (rename `_diff_index` -> `diff_content_index`, keep alias)
- Test: `tests/test_catalog_diff.py`

**Interfaces:**
- Consumes: `OscalCatalog`, `OscalControl`, `OscalParam` from `ccf.catalog.oscal`; `diff_content_index` from `ccf.etl.sources`
- Produces:
  - `ControlChange(canonical_id, title_changed, statement_changed, guidance_changed, params_added, params_removed, params_changed)` — frozen dataclass, tuple fields
  - `CatalogDiff(added, removed, newly_withdrawn, un_withdrawn, changed, baseline_entered, baseline_left)` with `is_empty() -> bool` and `to_dict() -> dict[str, Any]`
  - `diff_revisions(old: OscalCatalog, new: OscalCatalog) -> CatalogDiff`
  - `ccf.etl.sources.diff_content_index(old: dict[str, str], new: dict[str, str]) -> dict[str, list[str]]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_catalog_diff.py
"""Revision diffing: control set, prose, parameters, baseline membership."""

from __future__ import annotations

from ccf.catalog.diff import diff_revisions
from ccf.catalog.oscal import OscalCatalog, OscalControl, OscalParam


def _ctl(
    cid: str,
    *,
    title: str = "T",
    statement: str = "S",
    guidance: str = "G",
    withdrawn: bool = False,
    params: tuple[OscalParam, ...] = (),
) -> OscalControl:
    return OscalControl(
        canonical_id=cid,
        title=title,
        statement=statement,
        guidance=guidance,
        withdrawn=withdrawn,
        incorporated_into=[],
        param_ids=[p.id for p in params],
        params=list(params),
    )


def _cat(*controls: OscalControl, baselines: dict[str, set[str]] | None = None) -> OscalCatalog:
    c = OscalCatalog(version="5.2.0")
    for ctl in controls:
        c.controls[ctl.canonical_id] = ctl
    c.baselines = baselines or {"low": set(), "moderate": set(), "high": set()}
    return c


def test_detects_added_and_removed_controls() -> None:
    d = diff_revisions(_cat(_ctl("AC-1")), _cat(_ctl("AC-1"), _ctl("AC-2")))
    assert d.added == ("AC-2",)
    assert d.removed == ()

    d2 = diff_revisions(_cat(_ctl("AC-1"), _ctl("AC-2")), _cat(_ctl("AC-1")))
    assert d2.removed == ("AC-2",)


def test_detects_withdrawal_transitions() -> None:
    d = diff_revisions(_cat(_ctl("AC-1")), _cat(_ctl("AC-1", withdrawn=True)))
    assert d.newly_withdrawn == ("AC-1",)
    assert d.un_withdrawn == ()

    d2 = diff_revisions(_cat(_ctl("AC-1", withdrawn=True)), _cat(_ctl("AC-1")))
    assert d2.un_withdrawn == ("AC-1",)


def test_detects_prose_changes_separately() -> None:
    d = diff_revisions(
        _cat(_ctl("AC-1", title="Old", statement="S", guidance="G")),
        _cat(_ctl("AC-1", title="New", statement="S2", guidance="G")),
    )
    (change,) = d.changed
    assert change.canonical_id == "AC-1"
    assert change.title_changed is True
    assert change.statement_changed is True
    assert change.guidance_changed is False


def test_detects_parameter_changes() -> None:
    p_old = OscalParam(id="ac-1_prm_1", label="frequency", guidance="", choices=[])
    p_new = OscalParam(id="ac-1_prm_1", label="frequency", guidance="", choices=["annually"])
    p_extra = OscalParam(id="ac-1_prm_2", label="role", guidance="", choices=[])

    d = diff_revisions(
        _cat(_ctl("AC-1", params=(p_old,))),
        _cat(_ctl("AC-1", params=(p_new, p_extra))),
    )
    (change,) = d.changed
    assert change.params_added == ("ac-1_prm_2",)
    assert change.params_changed == ("ac-1_prm_1",)
    assert change.params_removed == ()


def test_detects_baseline_membership_shift() -> None:
    old = _cat(_ctl("AC-1"), _ctl("AC-2"), baselines={"low": {"AC-1"}, "moderate": set(), "high": set()})
    new = _cat(_ctl("AC-1"), _ctl("AC-2"), baselines={"low": {"AC-2"}, "moderate": set(), "high": set()})
    d = diff_revisions(old, new)
    assert d.baseline_entered["low"] == ("AC-2",)
    assert d.baseline_left["low"] == ("AC-1",)


def test_identical_catalogs_produce_empty_diff() -> None:
    a = _cat(_ctl("AC-1"), baselines={"low": {"AC-1"}})
    b = _cat(_ctl("AC-1"), baselines={"low": {"AC-1"}})
    d = diff_revisions(a, b)
    assert d.is_empty() is True
    assert d.to_dict()["added"] == []


def test_control_level_result_matches_content_index_diff() -> None:
    """The control-set computation must agree with the poller's own index diff."""
    from ccf.etl.sources import diff_content_index

    d = diff_revisions(_cat(_ctl("AC-1"), _ctl("AC-2")), _cat(_ctl("AC-2"), _ctl("AC-3")))
    idx = diff_content_index({"AC-1": "x", "AC-2": "y"}, {"AC-2": "y", "AC-3": "z"})
    assert list(d.added) == idx["added"]
    assert list(d.removed) == idx["removed"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_catalog_diff.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.catalog.diff'`

- [ ] **Step 3: Promote `_diff_index` to a public name**

In `src/ccf/etl/sources.py`, rename the function and keep the private alias so nothing breaks:

```python
def diff_content_index(old: dict[str, str], new: dict[str, str]) -> dict[str, list[str]]:
    """Added / modified / removed control ids between two content indexes.

    Public because :mod:`ccf.catalog.diff` reuses it for the control-set half of
    a revision diff rather than recomputing the same set arithmetic.
    """
    old_keys, new_keys = set(old), set(new)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    modified = sorted(k for k in old_keys & new_keys if old[k] != new[k])
    return {"added": added, "modified": modified, "removed": removed}


# Retained for existing callers/tests that import the private name.
_diff_index = diff_content_index
```

- [ ] **Step 4: Write `src/ccf/catalog/diff.py`**

```python
"""Diff two loaded OSCAL catalog revisions.

Pure functions over :class:`~ccf.catalog.oscal.OscalCatalog` — no database, no
network — so the whole diff is unit-testable and safe to run air-gapped.

This is a superset of the currency poller's prose-hash changelog: the
control-set half delegates to :func:`ccf.etl.sources.diff_content_index`, and
the new work is per-control parameter changes and baseline membership shifts,
which a title+prose hash cannot see.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..etl.sources import diff_content_index
from .oscal import OscalCatalog, OscalControl, OscalParam


def _param_fingerprint(p: OscalParam) -> tuple[str, str, tuple[str, ...]]:
    return (p.label, p.guidance, tuple(p.choices))


@dataclass(frozen=True)
class ControlChange:
    """What changed within one control that exists in both revisions."""

    canonical_id: str
    title_changed: bool
    statement_changed: bool
    guidance_changed: bool
    params_added: tuple[str, ...]
    params_removed: tuple[str, ...]
    params_changed: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_id": self.canonical_id,
            "title_changed": self.title_changed,
            "statement_changed": self.statement_changed,
            "guidance_changed": self.guidance_changed,
            "params_added": list(self.params_added),
            "params_removed": list(self.params_removed),
            "params_changed": list(self.params_changed),
        }


@dataclass(frozen=True)
class CatalogDiff:
    """Everything that differs between two revisions of one source."""

    added: tuple[str, ...]
    removed: tuple[str, ...]
    newly_withdrawn: tuple[str, ...]
    un_withdrawn: tuple[str, ...]
    changed: tuple[ControlChange, ...]
    baseline_entered: dict[str, tuple[str, ...]]
    baseline_left: dict[str, tuple[str, ...]]

    def is_empty(self) -> bool:
        return not (
            self.added
            or self.removed
            or self.newly_withdrawn
            or self.un_withdrawn
            or self.changed
            or any(self.baseline_entered.values())
            or any(self.baseline_left.values())
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "added": list(self.added),
            "removed": list(self.removed),
            "newly_withdrawn": list(self.newly_withdrawn),
            "un_withdrawn": list(self.un_withdrawn),
            "changed": [c.to_dict() for c in self.changed],
            "baseline_entered": {k: list(v) for k, v in self.baseline_entered.items()},
            "baseline_left": {k: list(v) for k, v in self.baseline_left.items()},
        }


def _diff_one_control(old: OscalControl, new: OscalControl) -> ControlChange | None:
    old_params = {p.id: _param_fingerprint(p) for p in old.params}
    new_params = {p.id: _param_fingerprint(p) for p in new.params}
    added = tuple(sorted(set(new_params) - set(old_params)))
    removed = tuple(sorted(set(old_params) - set(new_params)))
    changed = tuple(
        sorted(k for k in set(old_params) & set(new_params) if old_params[k] != new_params[k])
    )
    change = ControlChange(
        canonical_id=new.canonical_id,
        title_changed=old.title != new.title,
        statement_changed=old.statement != new.statement,
        guidance_changed=old.guidance != new.guidance,
        params_added=added,
        params_removed=removed,
        params_changed=changed,
    )
    touched = (
        change.title_changed
        or change.statement_changed
        or change.guidance_changed
        or added
        or removed
        or changed
    )
    return change if touched else None


def diff_revisions(old: OscalCatalog, new: OscalCatalog) -> CatalogDiff:
    """Compare two loaded catalogs.

    Control membership is computed with the poller's own index diff so the two
    subsystems can never disagree about what "added" means.
    """
    # Identity-only index: membership arithmetic, not content comparison.
    membership = diff_content_index(
        {cid: cid for cid in old.controls}, {cid: cid for cid in new.controls}
    )

    both = sorted(set(old.controls) & set(new.controls))
    newly_withdrawn = tuple(
        cid for cid in both if new.controls[cid].withdrawn and not old.controls[cid].withdrawn
    )
    un_withdrawn = tuple(
        cid for cid in both if old.controls[cid].withdrawn and not new.controls[cid].withdrawn
    )

    changes: list[ControlChange] = []
    for cid in both:
        change = _diff_one_control(old.controls[cid], new.controls[cid])
        if change is not None:
            changes.append(change)

    entered: dict[str, tuple[str, ...]] = {}
    left: dict[str, tuple[str, ...]] = {}
    for level in sorted(set(old.baselines) | set(new.baselines)):
        o = old.baselines.get(level, set())
        n = new.baselines.get(level, set())
        entered[level] = tuple(sorted(n - o))
        left[level] = tuple(sorted(o - n))

    return CatalogDiff(
        added=tuple(membership["added"]),
        removed=tuple(membership["removed"]),
        newly_withdrawn=newly_withdrawn,
        un_withdrawn=un_withdrawn,
        changed=tuple(changes),
        baseline_entered=entered,
        baseline_left=left,
    )
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_catalog_diff.py tests/test_catalog_sources.py -v`
Expected: all pass (including the pre-existing `_diff_index` test, proving the alias works)

- [ ] **Step 6: Lint and commit**

```bash
ruff check src/ccf/catalog/diff.py src/ccf/etl/sources.py tests/test_catalog_diff.py
mypy src/ccf/catalog/diff.py
git add src/ccf/catalog/diff.py src/ccf/etl/sources.py tests/test_catalog_diff.py
git commit -m "feat(catalog): diff two catalog revisions including params and baselines"
```

---

### Task 4: Revision materialization and offline import

**Files:**
- Create: `src/ccf/catalog/revisions.py`
- Test: `tests/test_catalog_materialize.py`

**Interfaces:**
- Consumes: `CatalogRevision`, `CatalogSource` (Task 2); `generate_manifest` (Task 1); `load_oscal_catalog`, `OscalManifestError`; `parse_oscal_catalog` from `ccf.etl.sources`
- Produces:
  - `revision_root(data_root: Path, source_key: str, revision: str) -> Path`
  - `async materialize_revision(session, *, source: CatalogSource, documents: dict[str, bytes], upstream_commit_sha: str | None, data_root: Path, retrieved_by: str | None = None) -> CatalogRevision`
  - `async import_revision(session, *, source_key: str, payload: Path, data_root: Path, retrieved_by: str | None = None, notes: str | None = None) -> CatalogRevision`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_catalog_materialize.py
"""Materializing a revision: parse-check before commit, idempotence, rejection."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select

from ccf.catalog.revisions import materialize_revision, revision_root
from ccf.db import session_scope
from ccf.models import CatalogRevision, CatalogSource

CATALOG = {
    "catalog": {
        "metadata": {"version": "5.2.0"},
        "groups": [
            {
                "id": "ac",
                "title": "Access Control",
                "controls": [
                    {
                        "id": "ac-1",
                        "title": "Policy",
                        "parts": [{"name": "statement", "prose": "Develop policy"}],
                    }
                ],
            }
        ],
    }
}
PROFILE = {"profile": {"imports": [{"include-controls": [{"with-ids": ["ac-1"]}]}]}}


def _documents() -> dict[str, bytes]:
    docs = {"NIST_SP-800-53_rev5_catalog.json": json.dumps(CATALOG).encode()}
    for name in (
        "NIST_SP-800-53_rev5_LOW-baseline_profile.json",
        "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
        "NIST_SP-800-53_rev5_HIGH-baseline_profile.json",
    ):
        docs[name] = json.dumps(PROFILE).encode()
    return docs


async def _source(session, key: str) -> CatalogSource:
    s = CatalogSource(key=key, name=key, url="https://example.test/catalog.json")
    session.add(s)
    await session.flush()
    return s


async def test_materialize_lands_available_and_loadable(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "mat_ok")
        rev = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="a" * 40,
            data_root=tmp_path,
        )
        assert rev.status == "available"
        assert rev.revision == "a" * 12
        assert rev.oscal_version == "5.2.0"
        # content_index is in parse_oscal_catalog's shape.
        assert "ac-1" in rev.content_index
        # And the directory is loadable by the real, unmodified loader.
        d = revision_root(tmp_path, "mat_ok", rev.revision)
        assert (d / "MANIFEST.json").is_file()
        from ccf.catalog.oscal import load_oscal_catalog

        assert load_oscal_catalog(d).exists("AC-1")


async def test_non_parsing_revision_is_rejected_and_leaves_no_directory(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "mat_bad")
        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = b'{"catalog": "not-an-object"}'
        rev = await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="b" * 40, data_root=tmp_path
        )
        assert rev.status == "rejected"
        assert rev.notes
        assert not revision_root(tmp_path, "mat_bad", rev.revision).exists()


async def test_materialize_is_idempotent_on_same_commit(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "mat_idem")
        first = await materialize_revision(
            session, source=src, documents=_documents(), upstream_commit_sha="c" * 40,
            data_root=tmp_path,
        )
        second = await materialize_revision(
            session, source=src, documents=_documents(), upstream_commit_sha="c" * 40,
            data_root=tmp_path,
        )
        assert first.id == second.id
        rows = (
            await session.execute(
                select(CatalogRevision).where(CatalogRevision.source_id == src.id)
            )
        ).scalars().all()
        assert len(rows) == 1


async def test_materialize_never_touches_the_adopted_revision(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "mat_keep")
        adopted = CatalogRevision(source_id=src.id, revision="bundled", status="adopted")
        session.add(adopted)
        await session.flush()
        await materialize_revision(
            session, source=src, documents=_documents(), upstream_commit_sha="d" * 40,
            data_root=tmp_path,
        )
        await session.refresh(adopted)
        assert adopted.status == "adopted"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_catalog_materialize.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.catalog.revisions'`

- [ ] **Step 3: Write `src/ccf/catalog/revisions.py`**

```python
"""Catalog revisions — capture upstream content, then adopt it deliberately.

The currency poller (:mod:`ccf.etl.sources`) detects that an upstream authority
changed. This module captures *that content* as a retained revision: files on
disk with a generated ``MANIFEST.json``, plus a :class:`~ccf.models.CatalogRevision`
row. A human then diffs it, reads its impact, and adopts it — at which point
:mod:`ccf.catalog.oscal` resolves the adopted directory.

Nothing here adopts automatically, preserving the poller's ``auto_ingest=False``
principle: drift is recorded for a person to review.

A revision is parse-checked with the real loader *before* its row is committed,
so a malformed upstream document is recorded as ``rejected`` and never becomes
loadable content.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..etl.sources import parse_oscal_catalog
from ..logging import get_logger
from ..models import CatalogRevision, CatalogSource
from .oscal import OscalManifestError, generate_manifest, load_oscal_catalog

log = get_logger(__name__)

_PRIMARY_CATALOG = "NIST_SP-800-53_rev5_catalog.json"


def revision_root(data_root: Path, source_key: str, revision: str) -> Path:
    """Directory holding one revision's materialized content."""
    return data_root / source_key / revision


def _revision_label(upstream_commit_sha: str | None, content_sha256: str) -> str:
    """12-char commit prefix when pinned, else a content-addressed label."""
    if upstream_commit_sha:
        return upstream_commit_sha[:12]
    return f"sha-{content_sha256[:8]}"


def _primary_document(documents: dict[str, bytes]) -> tuple[str, bytes]:
    """The catalog document, preferred over profiles, for version/index parsing."""
    if _PRIMARY_CATALOG in documents:
        return _PRIMARY_CATALOG, documents[_PRIMARY_CATALOG]
    name = sorted(documents)[0]
    return name, documents[name]


async def _existing(
    session: AsyncSession, *, source_id: int, revision: str
) -> CatalogRevision | None:
    return (
        await session.execute(
            select(CatalogRevision).where(
                CatalogRevision.source_id == source_id,
                CatalogRevision.revision == revision,
            )
        )
    ).scalars().first()


async def materialize_revision(
    session: AsyncSession,
    *,
    source: CatalogSource,
    documents: dict[str, bytes],
    upstream_commit_sha: str | None,
    data_root: Path,
    retrieved_by: str | None = None,
) -> CatalogRevision:
    """Write ``documents`` as a retained revision of ``source``.

    Returns the existing row unchanged when this revision was already captured,
    so repeated polls of an unchanged upstream stay a no-op. Never mutates the
    adopted revision.
    """
    _, primary_body = _primary_document(documents)
    content_sha256 = hashlib.sha256(primary_body).hexdigest()
    revision = _revision_label(upstream_commit_sha, content_sha256)

    prior = await _existing(session, source_id=source.id, revision=revision)
    if prior is not None:
        return prior

    oscal_version, content_index = parse_oscal_catalog(primary_body)
    row = CatalogRevision(
        source_id=source.id,
        revision=revision,
        upstream_commit_sha=upstream_commit_sha,
        upstream_url=source.url,
        oscal_version=oscal_version,
        content_sha256=content_sha256,
        content_index=content_index,
        retrieved_by=retrieved_by,
        status="available",
    )

    d = revision_root(data_root, source.key, revision)
    try:
        d.mkdir(parents=True, exist_ok=True)
        for name, body in documents.items():
            (d / name).write_bytes(body)
        manifest = generate_manifest(
            d,
            oscal_version=oscal_version or "",
            source_url=source.url,
            upstream_commit_sha=upstream_commit_sha,
            retrieved_at=datetime.now(UTC).date().isoformat(),
        )
        # Parse-check with the real loader before this becomes adoptable content.
        load_oscal_catalog(d)
    except (OscalManifestError, KeyError, ValueError, TypeError) as exc:
        shutil.rmtree(d, ignore_errors=True)
        row.status = "rejected"
        row.notes = f"{type(exc).__name__}: {exc}"
        row.files = {}
        row.content_dir = None
        log.warning(
            "catalog revision rejected", source=source.key, revision=revision, error=str(exc)
        )
    else:
        row.files = manifest["files"]
        row.content_dir = str(d)

    session.add(row)
    await session.flush()
    return row


async def import_revision(
    session: AsyncSession,
    *,
    source_key: str,
    payload: Path,
    data_root: Path,
    retrieved_by: str | None = None,
    notes: str | None = None,
) -> CatalogRevision:
    """Offline import for air-gapped environments — no network.

    ``payload`` is a directory or a zip of OSCAL JSON documents. Any bundled
    ``MANIFEST.json`` is ignored in favour of regenerating one from the bytes
    actually present, so the recorded hashes always describe the landed content.
    """
    source = (
        await session.execute(select(CatalogSource).where(CatalogSource.key == source_key))
    ).scalars().first()
    if source is None:
        raise ValueError(f"unknown catalog source: {source_key!r}")

    documents: dict[str, bytes] = {}
    if payload.is_dir():
        for p in sorted(payload.glob("*.json")):
            if p.name != "MANIFEST.json":
                documents[p.name] = p.read_bytes()
    elif zipfile.is_zipfile(payload):
        with zipfile.ZipFile(payload) as zf:
            for info in zf.infolist():
                name = Path(info.filename).name
                if name.endswith(".json") and name != "MANIFEST.json":
                    documents[name] = zf.read(info)
    else:
        raise ValueError(f"payload must be a directory or zip: {payload}")

    if not documents:
        raise ValueError(f"no OSCAL JSON documents found in {payload}")

    row = await materialize_revision(
        session,
        source=source,
        documents=documents,
        upstream_commit_sha=None,
        data_root=data_root,
        retrieved_by=retrieved_by,
    )
    if notes:
        row.notes = notes if not row.notes else f"{row.notes}; {notes}"
    return row
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_catalog_materialize.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
ruff check src/ccf/catalog/revisions.py tests/test_catalog_materialize.py
mypy src/ccf/catalog/revisions.py
git add src/ccf/catalog/revisions.py tests/test_catalog_materialize.py
git commit -m "feat(catalog): materialize retained revisions, parse-checked before commit"
```

---

### Task 5: Commit pinning and poller integration

Spec §6.2 and §6.1's follow-on. Without this the revision machinery exists but nothing feeds it: `check_source` still detects drift and stops, and revisions carry no upstream commit pin.

**Files:**
- Modify: `src/ccf/etl/sources.py`
- Modify: `src/ccf/config.py`
- Test: `tests/test_catalog_poll_revisions.py`

**Interfaces:**
- Consumes: `materialize_revision`, `revision_root` (Task 4)
- Produces:
  - `async resolve_commit_sha(url: str) -> str | None` — resolves a `raw.githubusercontent.com` URL to the commit SHA that last touched that path; `None` on any failure
  - `check_source(session, source, *, data_dir=None, revision_data_root=None)` — gains revision capture when the body is new, the source's `kind == "oscal_catalog"`, and capture is enabled
  - `Settings.catalog_capture_revisions: bool = False`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_catalog_poll_revisions.py
"""Polling captures revisions without changing existing drift behaviour."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select

from ccf.etl.sources import parse_commit_url, resolve_commit_sha
from ccf.models import CatalogRevision


def test_parse_commit_url_extracts_repo_and_path() -> None:
    repo, ref, path = parse_commit_url(
        "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
        "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
    )
    assert repo == "usnistgov/oscal-content"
    assert ref == "main"
    assert path == "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"


def test_parse_commit_url_returns_none_for_non_github() -> None:
    assert parse_commit_url("file:///data/local.xlsx") == (None, None, None)


async def test_resolve_commit_sha_returns_none_on_failure(monkeypatch) -> None:
    """Commit resolution is best-effort: a failure must never break a poll."""

    async def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr("ccf.etl.sources._get_json", boom)
    assert await resolve_commit_sha("https://raw.githubusercontent.com/o/r/main/x.json") is None


async def test_unchanged_poll_captures_no_revision() -> None:
    """A 304 or identical sha256 must not create a revision."""
    from ccf.db import session_scope
    from ccf.etl.sources import check_source
    from ccf.models import CatalogSource

    async with session_scope() as session:
        src = CatalogSource(
            key="poll_304", name="x", url="https://example.test/c.json", last_sha256="deadbeef"
        )
        session.add(src)
        await session.flush()

        async def fake_fetch(url, etag):
            return 304, None, etag

        import ccf.etl.sources as mod

        orig = mod._fetch
        mod._fetch = fake_fetch
        try:
            check = await check_source(session, src)
        finally:
            mod._fetch = orig
        assert check.status == "unchanged"
        rows = (
            await session.execute(
                select(CatalogRevision).where(CatalogRevision.source_id == src.id)
            )
        ).scalars().all()
        assert rows == []


async def test_changed_poll_captures_an_available_revision(tmp_path: Path) -> None:
    from ccf.db import session_scope
    from ccf.etl.sources import check_source
    from ccf.models import CatalogSource

    from tests.test_catalog_materialize import CATALOG

    body = json.dumps(CATALOG).encode()

    async with session_scope() as session:
        src = CatalogSource(
            key="poll_new",
            name="x",
            kind="oscal_catalog",
            url="https://example.test/c.json",
        )
        session.add(src)
        await session.flush()

        async def fake_fetch(url, etag):
            return 200, body, "etag-1"

        import ccf.etl.sources as mod

        orig = mod._fetch
        mod._fetch = fake_fetch
        try:
            await check_source(session, src, revision_data_root=tmp_path)
        finally:
            mod._fetch = orig

        rows = (
            await session.execute(
                select(CatalogRevision).where(CatalogRevision.source_id == src.id)
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].status in {"available", "rejected"}


async def test_capture_is_skipped_when_no_revision_root_given() -> None:
    """Existing callers that pass no root keep today's behaviour exactly."""
    from ccf.db import session_scope
    from ccf.etl.sources import check_source
    from ccf.models import CatalogSource

    from tests.test_catalog_materialize import CATALOG

    body = json.dumps(CATALOG).encode()
    async with session_scope() as session:
        src = CatalogSource(
            key="poll_noroot", name="x", kind="oscal_catalog", url="https://example.test/c.json"
        )
        session.add(src)
        await session.flush()

        async def fake_fetch(url, etag):
            return 200, body, "etag-1"

        import ccf.etl.sources as mod

        orig = mod._fetch
        mod._fetch = fake_fetch
        try:
            await check_source(session, src)
        finally:
            mod._fetch = orig

        rows = (
            await session.execute(
                select(CatalogRevision).where(CatalogRevision.source_id == src.id)
            )
        ).scalars().all()
        assert rows == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_catalog_poll_revisions.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_commit_url'`

- [ ] **Step 3: Add commit resolution to `src/ccf/etl/sources.py`**

```python
_GH_RAW_PREFIX = "https://raw.githubusercontent.com/"
_GH_API = "https://api.github.com"


def parse_commit_url(url: str) -> tuple[str | None, str | None, str | None]:
    """Split a raw.githubusercontent URL into ``(repo, ref, path)``.

    Returns ``(None, None, None)`` for anything that is not a GitHub raw URL —
    ``file://`` sources and other hosts simply have no commit concept.
    """
    if not url.startswith(_GH_RAW_PREFIX):
        return None, None, None
    rest = url[len(_GH_RAW_PREFIX) :]
    parts = rest.split("/")
    if len(parts) < 4:
        return None, None, None
    owner, repo, ref = parts[0], parts[1], parts[2]
    return f"{owner}/{repo}", ref, "/".join(parts[3:])


async def _get_json(url: str) -> Any:
    async with httpx.AsyncClient(timeout=20.0, headers={"User-Agent": _UA}) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()


async def resolve_commit_sha(url: str) -> str | None:
    """The commit that last touched ``url``'s path, for reproducible pinning.

    Best-effort by design: sources poll a moving ref (``main``) because that is
    what detects drift, and the pin is recorded per *revision*, where
    reproducibility actually matters. Any failure returns ``None`` and the
    revision falls back to a content-addressed label rather than failing the
    poll.
    """
    repo, ref, path = parse_commit_url(url)
    if not (repo and ref and path):
        return None
    try:
        payload = await _get_json(
            f"{_GH_API}/repos/{repo}/commits?path={path}&sha={ref}&per_page=1"
        )
        if isinstance(payload, list) and payload:
            sha = payload[0].get("sha")
            return str(sha) if sha else None
    except Exception as exc:  # noqa: BLE001 — pinning must never break a poll
        log.debug("commit resolution failed", url=url, error=str(exc))
    return None
```

- [ ] **Step 4: Wire capture into `check_source`**

Add a keyword-only `revision_data_root: Path | None = None` parameter. After the existing drift-detection logic has established that the body is new (the branch where `source.last_status` becomes `"changed"`), and only when `revision_data_root is not None` and `source.kind == "oscal_catalog"`, call:

```python
        if revision_data_root is not None and source.kind == "oscal_catalog" and body is not None:
            # Capture the changed content as a retained revision. Never adopts —
            # a human does that after reading the impact report.
            from ..catalog.revisions import materialize_revision  # noqa: PLC0415

            await materialize_revision(
                session,
                source=source,
                documents={Path(source.url).name: body},
                upstream_commit_sha=await resolve_commit_sha(source.url),
                data_root=revision_data_root,
                retrieved_by="poller",
            )
```

The import is local to avoid a circular import (`catalog.revisions` imports `etl.sources` for `parse_oscal_catalog`). Default `None` means every existing caller — scheduler, CLI `sources-check`, tests — keeps today's behaviour byte for byte.

- [ ] **Step 5: Add the config flag**

In `src/ccf/config.py`, near the other catalog settings:

```python
    # Capture changed upstream catalog content as a retained CatalogRevision
    # during polling. Off by default: capture writes files under data/oscal and
    # is only useful where that path is a durable volume. Capture never adopts —
    # adoption is always an explicit human action.
    catalog_capture_revisions: bool = Field(default=False)
```

The scheduler passes `revision_data_root` only when this is true.

- [ ] **Step 6: Run tests**

Run: `pytest tests/test_catalog_poll_revisions.py tests/test_catalog_sources.py -v`
Expected: all pass — the new capture tests plus the untouched existing drift tests.

- [ ] **Step 7: Commit**

```bash
ruff check src/ccf/etl/sources.py src/ccf/config.py tests/test_catalog_poll_revisions.py
mypy src/ccf/etl/sources.py
git add src/ccf/etl/sources.py src/ccf/config.py tests/test_catalog_poll_revisions.py
git commit -m "feat(catalog): pin revisions to upstream commits and capture them while polling"
```

---

### Task 6: Adopted-revision resolution, with the loader kept DB-free

**Files:**
- Modify: `src/ccf/catalog/revisions.py`
- Test: `tests/test_catalog_resolution.py`

**Interfaces:**
- Produces: `async resolve_adopted_dir(session, *, source_key: str) -> Path | None` — the adopted revision's directory, or `None` when the adopted revision is the packaged one or its directory is missing (both mean "fall back to packaged").

- [ ] **Step 1: Write the failing test**

```python
# tests/test_catalog_resolution.py
"""Resolution precedence, and the loader's no-database guarantee."""

from __future__ import annotations

import inspect
from pathlib import Path

from ccf.catalog import oscal as oscal_mod
from ccf.catalog.revisions import resolve_adopted_dir
from ccf.db import session_scope
from ccf.models import CatalogRevision, CatalogSource


async def _source_with_adopted(session, key: str, content_dir: str | None) -> CatalogSource:
    s = CatalogSource(key=key, name=key, url="https://example.test/x.json")
    session.add(s)
    await session.flush()
    session.add(
        CatalogRevision(
            source_id=s.id, revision="rev1", status="adopted", content_dir=content_dir
        )
    )
    await session.flush()
    return s


async def test_returns_adopted_directory_when_present(tmp_path: Path) -> None:
    d = tmp_path / "rev1"
    d.mkdir()
    (d / "MANIFEST.json").write_text("{}", encoding="utf-8")
    async with session_scope() as session:
        await _source_with_adopted(session, "res_ok", str(d))
        assert await resolve_adopted_dir(session, source_key="res_ok") == d


async def test_returns_none_for_packaged_bundled_revision() -> None:
    async with session_scope() as session:
        await _source_with_adopted(session, "res_bundled", None)
        assert await resolve_adopted_dir(session, source_key="res_bundled") is None


async def test_returns_none_when_adopted_directory_is_missing(tmp_path: Path) -> None:
    """A container that lost its volume must fall back, not crash."""
    async with session_scope() as session:
        await _source_with_adopted(session, "res_gone", str(tmp_path / "vanished"))
        assert await resolve_adopted_dir(session, source_key="res_gone") is None


async def test_returns_none_for_unknown_source() -> None:
    async with session_scope() as session:
        assert await resolve_adopted_dir(session, source_key="nope") is None


def test_load_oscal_catalog_performs_no_database_access() -> None:
    """catalog/report.py and ssp/nist80053.py depend on this staying DB-free."""
    src = inspect.getsource(oscal_mod)
    for forbidden in ("AsyncSession", "session_scope", "sqlalchemy", "await "):
        assert forbidden not in src, f"{forbidden!r} leaked into the pure catalog loader"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_catalog_resolution.py -v`
Expected: FAIL — `ImportError: cannot import name 'resolve_adopted_dir'`

- [ ] **Step 3: Implement**

Append to `src/ccf/catalog/revisions.py`:

```python
async def resolve_adopted_dir(session: AsyncSession, *, source_key: str) -> Path | None:
    """Directory of ``source_key``'s adopted revision, if it has a usable one.

    Returns ``None`` — meaning "use the packaged content" — when the source is
    unknown, has no adopted revision, its adopted revision is the packaged
    ``bundled`` one (``content_dir`` NULL), or its directory has gone missing.
    That last case keeps a container whose ``data/oscal`` volume disappeared
    serving the in-wheel catalog rather than failing to start.

    Deliberately separate from :func:`ccf.catalog.oscal.load_oscal_catalog`,
    which must stay database-free for the pure/offline callers.
    """
    row = (
        await session.execute(
            select(CatalogRevision)
            .join(CatalogSource, CatalogSource.id == CatalogRevision.source_id)
            .where(CatalogSource.key == source_key, CatalogRevision.status == "adopted")
        )
    ).scalars().first()
    if row is None or not row.content_dir:
        return None
    d = Path(row.content_dir)
    if not (d / "MANIFEST.json").is_file():
        log.warning(
            "adopted catalog revision directory missing; falling back to packaged",
            source=source_key,
            revision=row.revision,
            content_dir=row.content_dir,
        )
        return None
    return d
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_catalog_resolution.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add src/ccf/catalog/revisions.py tests/test_catalog_resolution.py
git commit -m "feat(catalog): resolve the adopted revision without touching the pure loader"
```

---

### Task 7: Adoption impact report

**Files:**
- Create: `src/ccf/catalog/impact.py`
- Test: `tests/test_catalog_impact.py`

**Interfaces:**
- Consumes: `CatalogDiff` (Task 3); `System`, `SSPControlEntry`, `FrameworkMapping`, `KSI` from `ccf.models`
- Produces:
  - `AdoptionImpact` dataclass with `systems_affected`, `orphaned_entries`, `stale_narratives`, `param_drift`, `dangling_mappings`, `ksi_references` (all `list[dict[str, Any]]`), plus `is_empty() -> bool` and `to_dict() -> dict[str, Any]`
  - `async build_adoption_impact(session, *, diff: CatalogDiff) -> AdoptionImpact`

- [ ] **Step 1: Confirm the exact model/column names before writing**

Run these and use the real names in the implementation:

```bash
grep -n "class SSPControlEntry" -A 14 src/ccf/models.py
grep -n "class FrameworkMapping" -A 12 src/ccf/models.py
grep -n "class KSI(" -A 16 src/ccf/models.py
grep -n "nist_refs" src/ccf/models.py
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_catalog_impact.py
"""Adoption impact: what a revision does to my baselines and authored content."""

from __future__ import annotations

from ccf.catalog.diff import CatalogDiff
from ccf.catalog.impact import build_adoption_impact
from ccf.db import session_scope
from ccf.models import Organization, SSPControlEntry, SSPProject, System


def _diff(**kw) -> CatalogDiff:
    base = {
        "added": (),
        "removed": (),
        "newly_withdrawn": (),
        "un_withdrawn": (),
        "changed": (),
        "baseline_entered": {},
        "baseline_left": {},
    }
    base.update(kw)
    return CatalogDiff(**base)


async def _project(session, *, baseline: str = "moderate") -> SSPProject:
    org = Organization(name="Org")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name="Sys", fedramp_baseline=baseline)
    session.add(sys_)
    await session.flush()
    proj = SSPProject(organization_id=org.id, name="P")
    session.add(proj)
    await session.flush()
    return proj


async def test_empty_diff_yields_empty_impact() -> None:
    async with session_scope() as session:
        impact = await build_adoption_impact(session, diff=_diff())
        assert impact.is_empty() is True


async def test_removed_control_orphans_authored_entry() -> None:
    async with session_scope() as session:
        proj = await _project(session)
        session.add(SSPControlEntry(project_id=proj.id, control_id="AC-2", nist_id="AC-2"))
        await session.flush()
        impact = await build_adoption_impact(session, diff=_diff(removed=("AC-2",)))
        assert impact.is_empty() is False
        assert any(e["control_id"] == "AC-2" for e in impact.orphaned_entries)


async def test_withdrawn_control_orphans_authored_entry() -> None:
    async with session_scope() as session:
        proj = await _project(session)
        session.add(SSPControlEntry(project_id=proj.id, control_id="AC-3", nist_id="AC-3"))
        await session.flush()
        impact = await build_adoption_impact(session, diff=_diff(newly_withdrawn=("AC-3",)))
        assert any(e["control_id"] == "AC-3" for e in impact.orphaned_entries)


async def test_statement_change_marks_narrative_stale() -> None:
    from ccf.catalog.diff import ControlChange

    change = ControlChange(
        canonical_id="AC-4",
        title_changed=False,
        statement_changed=True,
        guidance_changed=False,
        params_added=(),
        params_removed=(),
        params_changed=(),
    )
    async with session_scope() as session:
        proj = await _project(session)
        session.add(SSPControlEntry(project_id=proj.id, control_id="AC-4", nist_id="AC-4"))
        await session.flush()
        impact = await build_adoption_impact(session, diff=_diff(changed=(change,)))
        assert any(e["control_id"] == "AC-4" for e in impact.stale_narratives)


async def test_param_change_reports_drift() -> None:
    from ccf.catalog.diff import ControlChange

    change = ControlChange(
        canonical_id="AC-5",
        title_changed=False,
        statement_changed=False,
        guidance_changed=False,
        params_added=(),
        params_removed=(),
        params_changed=("ac-5_prm_1",),
    )
    async with session_scope() as session:
        proj = await _project(session)
        session.add(SSPControlEntry(project_id=proj.id, control_id="AC-5", nist_id="AC-5"))
        await session.flush()
        impact = await build_adoption_impact(session, diff=_diff(changed=(change,)))
        assert any(e["control_id"] == "AC-5" for e in impact.param_drift)


async def test_baseline_shift_reports_affected_systems() -> None:
    async with session_scope() as session:
        await _project(session, baseline="moderate")
        impact = await build_adoption_impact(
            session, diff=_diff(baseline_entered={"moderate": ("AC-9",)})
        )
        assert impact.systems_affected
        assert impact.systems_affected[0]["entering"] == ["AC-9"]


async def test_to_dict_is_json_serialisable() -> None:
    import json

    async with session_scope() as session:
        impact = await build_adoption_impact(session, diff=_diff(removed=("AC-2",)))
        json.dumps(impact.to_dict())  # must not raise
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_catalog_impact.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.catalog.impact'`

- [ ] **Step 4: Implement `src/ccf/catalog/impact.py`**

Write the module with this structure, substituting the real column names confirmed in Step 1:

```python
"""What adopting a catalog revision would do to this deployment's own content.

A :class:`~ccf.catalog.diff.CatalogDiff` says what changed upstream. This says
what that *means here*: which systems' baselines gain or lose controls, which
authored SSP entries are orphaned or now carry stale narrative, which
cross-framework mappings dangle, and which KSIs reference controls that went
away.

Read-only and side-effect free — it is computed for a human to review before
adoption, and the reviewed result is stored on the revision row as the record of
what was actually approved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import SSPControlEntry, SSPProject, System
from .diff import CatalogDiff


@dataclass
class AdoptionImpact:
    """Per-deployment consequences of adopting one revision."""

    systems_affected: list[dict[str, Any]] = field(default_factory=list)
    orphaned_entries: list[dict[str, Any]] = field(default_factory=list)
    stale_narratives: list[dict[str, Any]] = field(default_factory=list)
    param_drift: list[dict[str, Any]] = field(default_factory=list)
    dangling_mappings: list[dict[str, Any]] = field(default_factory=list)
    ksi_references: list[dict[str, Any]] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (
            self.systems_affected
            or self.orphaned_entries
            or self.stale_narratives
            or self.param_drift
            or self.dangling_mappings
            or self.ksi_references
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "systems_affected": self.systems_affected,
            "orphaned_entries": self.orphaned_entries,
            "stale_narratives": self.stale_narratives,
            "param_drift": self.param_drift,
            "dangling_mappings": self.dangling_mappings,
            "ksi_references": self.ksi_references,
            "empty": self.is_empty(),
        }


async def _entries_for(
    session: AsyncSession, control_ids: set[str]
) -> list[tuple[SSPControlEntry, int | None]]:
    """Authored entries touching any of ``control_ids``, with their org id."""
    if not control_ids:
        return []
    rows = (
        await session.execute(
            select(SSPControlEntry, SSPProject.organization_id)
            .join(SSPProject, SSPProject.id == SSPControlEntry.project_id)
            .where(SSPControlEntry.control_id.in_(control_ids))
        )
    ).all()
    return [(r[0], r[1]) for r in rows]


async def build_adoption_impact(
    session: AsyncSession, *, diff: CatalogDiff
) -> AdoptionImpact:
    """Compute what adopting the revision behind ``diff`` would affect."""
    impact = AdoptionImpact()

    # --- systems whose baseline set shifts ---------------------------------
    touched_levels = {
        lvl
        for lvl in set(diff.baseline_entered) | set(diff.baseline_left)
        if diff.baseline_entered.get(lvl) or diff.baseline_left.get(lvl)
    }
    if touched_levels:
        systems = (
            await session.execute(
                select(System).where(System.fedramp_baseline.in_(touched_levels))
            )
        ).scalars().all()
        for s in systems:
            level = s.fedramp_baseline or ""
            impact.systems_affected.append(
                {
                    "system_id": s.id,
                    "organization_id": s.organization_id,
                    "name": s.name,
                    "baseline": level,
                    "entering": list(diff.baseline_entered.get(level, ())),
                    "leaving": list(diff.baseline_left.get(level, ())),
                }
            )

    # --- authored content that loses its control ---------------------------
    gone = set(diff.removed) | set(diff.newly_withdrawn)
    for entry, org_id in await _entries_for(session, gone):
        impact.orphaned_entries.append(
            {
                "entry_id": entry.id,
                "project_id": entry.project_id,
                "organization_id": org_id,
                "control_id": entry.control_id,
                "reason": "removed" if entry.control_id in set(diff.removed) else "withdrawn",
            }
        )

    # --- authored content whose control text or parameters moved -----------
    prose_changed = {c.canonical_id for c in diff.changed if c.statement_changed or c.guidance_changed}
    param_changed = {
        c.canonical_id
        for c in diff.changed
        if c.params_added or c.params_removed or c.params_changed
    }
    for entry, org_id in await _entries_for(session, prose_changed):
        impact.stale_narratives.append(
            {
                "entry_id": entry.id,
                "project_id": entry.project_id,
                "organization_id": org_id,
                "control_id": entry.control_id,
            }
        )
    for entry, org_id in await _entries_for(session, param_changed):
        impact.param_drift.append(
            {
                "entry_id": entry.id,
                "project_id": entry.project_id,
                "organization_id": org_id,
                "control_id": entry.control_id,
            }
        )

    # --- dangling cross-framework mappings and KSI refs --------------------
    impact.dangling_mappings = await _dangling_mappings(session, gone)
    impact.ksi_references = await _ksi_references(session, gone)
    return impact
```

Then add the two helpers using the real column names from Step 1. `_dangling_mappings` selects `FrameworkMapping` rows whose control reference is in `gone`; `_ksi_references` selects `KSI` rows whose `nist_refs` JSONB overlaps `gone`. Both return `list[dict[str, Any]]` and both return `[]` for an empty `gone` set.

**Reuse requirement:** where `catalog/reconcile.py` already computes dangling mappings or unknown/withdrawn ids against a catalog, call it rather than duplicating the query. Inspect it first:

```bash
grep -n "^def \|^async def \|dangling" src/ccf/catalog/reconcile.py
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_catalog_impact.py -v`
Expected: 7 passed

- [ ] **Step 6: Commit**

```bash
ruff check src/ccf/catalog/impact.py tests/test_catalog_impact.py
mypy src/ccf/catalog/impact.py
git add src/ccf/catalog/impact.py tests/test_catalog_impact.py
git commit -m "feat(catalog): report what adopting a revision does to my own content"
```

---

### Task 8: Adoption

**Files:**
- Modify: `src/ccf/catalog/revisions.py`
- Test: `tests/test_catalog_adopt.py`

**Interfaces:**
- Consumes: `build_adoption_impact` (Task 7), `diff_revisions` (Task 3), `load_oscal_catalog`
- Produces:
  - `class AdoptionRefused(RuntimeError)` — carries `.impact: AdoptionImpact`
  - `async adopt_revision(session, *, revision_id: int, actor: str, acknowledge_impact: bool = False) -> CatalogRevision`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_catalog_adopt.py
"""Adoption is human, audited, and refuses an unreviewed non-empty impact."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import select

from ccf.catalog.revisions import AdoptionRefused, adopt_revision, materialize_revision
from ccf.db import session_scope
from ccf.models import AuditLog, CatalogRevision, CatalogSource, Organization, SSPControlEntry, SSPProject

from tests.test_catalog_materialize import _documents


async def _src(session, key: str) -> CatalogSource:
    s = CatalogSource(key=key, name=key, url="https://example.test/catalog.json")
    session.add(s)
    await session.flush()
    return s


async def test_adopts_when_impact_is_empty(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _src(session, "ad_clean")
        rev = await materialize_revision(
            session, source=src, documents=_documents(), upstream_commit_sha="a" * 40,
            data_root=tmp_path,
        )
        adopted = await adopt_revision(session, revision_id=rev.id, actor="kevin")
        assert adopted.status == "adopted"
        assert adopted.adopted_by == "kevin"
        assert adopted.adopted_at is not None


async def test_refuses_non_empty_impact_without_acknowledgement(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _src(session, "ad_impact")
        # Adopt a first revision so the second produces a real diff.
        first = await materialize_revision(
            session, source=src, documents=_documents(), upstream_commit_sha="a" * 40,
            data_root=tmp_path,
        )
        await adopt_revision(session, revision_id=first.id, actor="kevin")

        # A second revision that drops AC-1 entirely, orphaning an authored entry.
        org = Organization(name="O")
        session.add(org)
        await session.flush()
        proj = SSPProject(organization_id=org.id, name="P")
        session.add(proj)
        await session.flush()
        session.add(SSPControlEntry(project_id=proj.id, control_id="AC-1", nist_id="AC-1"))
        await session.flush()

        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = json.dumps(
            {"catalog": {"metadata": {"version": "5.3.0"}, "groups": []}}
        ).encode()
        second = await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="b" * 40, data_root=tmp_path
        )

        with pytest.raises(AdoptionRefused) as exc:
            await adopt_revision(session, revision_id=second.id, actor="kevin")
        assert not exc.value.impact.is_empty()

        # And it adopts once the impact is acknowledged.
        adopted = await adopt_revision(
            session, revision_id=second.id, actor="kevin", acknowledge_impact=True
        )
        assert adopted.status == "adopted"
        assert adopted.adoption_impact["empty"] is False


async def test_previous_revision_is_superseded(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _src(session, "ad_supersede")
        first = await materialize_revision(
            session, source=src, documents=_documents(), upstream_commit_sha="c" * 40,
            data_root=tmp_path,
        )
        await adopt_revision(session, revision_id=first.id, actor="kevin")
        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = json.dumps(
            {
                "catalog": {
                    "metadata": {"version": "5.3.0"},
                    "groups": [
                        {
                            "id": "ac",
                            "controls": [
                                {
                                    "id": "ac-1",
                                    "title": "Policy",
                                    "parts": [{"name": "statement", "prose": "Develop policy"}],
                                }
                            ],
                        }
                    ],
                }
            }
        ).encode()
        second = await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="d" * 40, data_root=tmp_path
        )
        await adopt_revision(session, revision_id=second.id, actor="kevin", acknowledge_impact=True)
        await session.refresh(first)
        assert first.status == "superseded"


async def test_adoption_writes_an_audit_entry(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _src(session, "ad_audit")
        rev = await materialize_revision(
            session, source=src, documents=_documents(), upstream_commit_sha="e" * 40,
            data_root=tmp_path,
        )
        await adopt_revision(session, revision_id=rev.id, actor="kevin")
        rows = (await session.execute(select(AuditLog))).scalars().all()
        entry = next(r for r in rows if r.entity_type == "catalog_revision")
        assert entry.action == "adopt"
        assert entry.diff["revision"] == rev.revision
        # The chain must be intact — record_event populates both hashes.
        assert entry.prev_hash and entry.row_hash


async def test_rejected_revision_cannot_be_adopted(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _src(session, "ad_rejected")
        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = b'{"catalog": "bad"}'
        rev = await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="f" * 40, data_root=tmp_path
        )
        assert rev.status == "rejected"
        with pytest.raises(ValueError, match="rejected"):
            await adopt_revision(session, revision_id=rev.id, actor="kevin")
```

- [ ] **Step 2: Confirm the audit helper's real signature**

```bash
grep -n "def record_audit\|def write_audit\|class AuditLog" -A 12 src/ccf/models.py src/ccf/auth.py
grep -rn "AuditLog(" --include="*.py" src/ccf | grep -v __pycache__ | head -5
```

Use the existing audit-writing helper rather than constructing `AuditLog` directly if one exists.

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_catalog_adopt.py -v`
Expected: FAIL — `ImportError: cannot import name 'AdoptionRefused'`

- [ ] **Step 4: Implement**

Append to `src/ccf/catalog/revisions.py`:

```python
class AdoptionRefused(RuntimeError):
    """Adoption was blocked because its impact had not been acknowledged."""

    def __init__(self, impact: AdoptionImpact) -> None:
        super().__init__(
            "adopting this revision affects existing content; "
            "re-run with acknowledge_impact=True after reviewing the impact report"
        )
        self.impact = impact


async def compute_revision_diff(
    session: AsyncSession, *, revision: CatalogRevision
) -> CatalogDiff:
    """Diff ``revision`` against its source's currently adopted revision."""
    new_dir = Path(revision.content_dir) if revision.content_dir else None
    new_cat = load_oscal_catalog(new_dir)
    adopted = (
        await session.execute(
            select(CatalogRevision).where(
                CatalogRevision.source_id == revision.source_id,
                CatalogRevision.status == "adopted",
            )
        )
    ).scalars().first()
    old_dir = Path(adopted.content_dir) if adopted and adopted.content_dir else None
    old_cat = load_oscal_catalog(old_dir)
    return diff_revisions(old_cat, new_cat)


async def adopt_revision(
    session: AsyncSession,
    *,
    revision_id: int,
    actor: str,
    acknowledge_impact: bool = False,
) -> CatalogRevision:
    """Make ``revision_id`` the revision the platform loads.

    Always a human action: there is no scheduler or API path that adopts
    implicitly. A non-empty impact report blocks adoption until it is explicitly
    acknowledged, and the report as reviewed is stored on the row so the record
    shows what was approved.
    """
    row = await session.get(CatalogRevision, revision_id)
    if row is None:
        raise ValueError(f"unknown catalog revision: {revision_id}")
    if row.status == "rejected":
        raise ValueError(f"revision {row.revision} was rejected and cannot be adopted")
    if row.status == "adopted":
        return row

    diff = await compute_revision_diff(session, revision=row)
    impact = await build_adoption_impact(session, diff=diff)
    if not impact.is_empty() and not acknowledge_impact:
        raise AdoptionRefused(impact)

    prior = (
        await session.execute(
            select(CatalogRevision).where(
                CatalogRevision.source_id == row.source_id,
                CatalogRevision.status == "adopted",
            )
        )
    ).scalars().all()
    for p in prior:
        p.status = "superseded"
    # Flush the supersede before claiming adoption so the partial unique index
    # never sees two adopted rows for one source mid-transaction.
    await session.flush()

    row.status = "adopted"
    row.adopted_by = actor
    row.adopted_at = datetime.now(UTC)
    row.adoption_impact = impact.to_dict()
    # record_event maintains the prev_hash/row_hash chain. Constructing AuditLog
    # directly would append an unchained row and silently break tamper-evidence.
    await record_event(
        session,
        actor=actor,
        action="adopt",
        entity_type="catalog_revision",
        entity_id=str(row.id),
        diff={
            "source_id": row.source_id,
            "revision": row.revision,
            "diff": diff.to_dict(),
            "impact_acknowledged": acknowledge_impact,
        },
    )
    await session.flush()
    log.info("catalog revision adopted", revision=row.revision, actor=actor)
    return row
```

Add the needed imports: `from .diff import CatalogDiff, diff_revisions`, `from .impact import AdoptionImpact, build_adoption_impact`, and `from ..api.audit import record_event`.

**Do not construct `AuditLog` directly.** `AuditLog` has no `detail` column (the JSONB field is `diff`), and it carries a `prev_hash`/`row_hash` chain that `ccf.api.audit.record_event` maintains. A hand-built row would append an unchained entry and silently break tamper-evidence — the property the whole audit log exists for.

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_catalog_adopt.py -v`
Expected: 5 passed

- [ ] **Step 6: Commit**

```bash
ruff check src/ccf/catalog/revisions.py tests/test_catalog_adopt.py
mypy src/ccf/catalog/revisions.py
git add src/ccf/catalog/revisions.py tests/test_catalog_adopt.py
git commit -m "feat(catalog): adopt a revision behind an acknowledged impact report"
```

---

### Task 9: CLI commands

**Files:**
- Modify: `src/ccf/cli.py` (the existing `catalog_app` Typer group, registered at line ~1563)
- Test: `tests/test_catalog_revisions_cli.py`

**Interfaces:**
- Produces CLI commands: `ccf catalog revisions [--source KEY]`, `ccf catalog diff REVISION_ID`, `ccf catalog impact REVISION_ID`, `ccf catalog import SOURCE_KEY PATH`, `ccf catalog adopt REVISION_ID [--acknowledge-impact]`

- [ ] **Step 1: Read the existing group's style**

```bash
sed -n '1555,1610p' src/ccf/cli.py
```

Match it exactly — the same `asyncio.run` / `session_scope` wrapper and the same output conventions as `catalog reconcile` and `catalog show`.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_catalog_revisions_cli.py
"""The revision CLI surfaces listing, diff, impact, import, and adopt."""

from __future__ import annotations

from typer.testing import CliRunner

from ccf.cli import app

runner = CliRunner()


def test_revisions_command_is_registered() -> None:
    result = runner.invoke(app, ["catalog", "revisions", "--help"])
    assert result.exit_code == 0
    assert "source" in result.stdout.lower()


def test_adopt_command_requires_acknowledge_flag_in_help() -> None:
    result = runner.invoke(app, ["catalog", "adopt", "--help"])
    assert result.exit_code == 0
    assert "acknowledge-impact" in result.stdout


def test_import_command_is_registered() -> None:
    result = runner.invoke(app, ["catalog", "import", "--help"])
    assert result.exit_code == 0


def test_diff_and_impact_commands_are_registered() -> None:
    assert runner.invoke(app, ["catalog", "diff", "--help"]).exit_code == 0
    assert runner.invoke(app, ["catalog", "impact", "--help"]).exit_code == 0
```

Note: assert on command registration and options, never on rendered help text layout — a pre-existing test in this repo broke because it asserted on terminal-width-dependent Typer output.

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_catalog_revisions_cli.py -v`
Expected: FAIL — non-zero exit codes, commands not registered

- [ ] **Step 4: Implement the five commands**

Add to the `catalog_app` group in `src/ccf/cli.py`, following the established pattern. `adopt` must catch `AdoptionRefused`, print the impact summary, and exit non-zero so a script cannot mistake refusal for success.

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_catalog_revisions_cli.py -v`
Expected: 4 passed

- [ ] **Step 6: Commit**

```bash
ruff check src/ccf/cli.py tests/test_catalog_revisions_cli.py
git add src/ccf/cli.py tests/test_catalog_revisions_cli.py
git commit -m "feat(cli): catalog revision listing, diff, impact, import, and adopt"
```

---

### Task 10: API endpoints

**Files:**
- Modify: `src/ccf/api/routes/catalog.py`
- Test: `tests/test_catalog_revisions_api.py`

**Interfaces:**
- Produces: `GET /api/catalog/sources/{source_id}/revisions`, `GET /api/catalog/revisions/{id}/diff`, `GET /api/catalog/revisions/{id}/impact`, `POST /api/catalog/revisions/{id}/adopt`

- [ ] **Step 1: Read the existing route style and auth dependency**

```bash
sed -n '1,60p' src/ccf/api/routes/catalog.py
grep -rn "require_role\|require_write\|Depends(get_principal)" src/ccf/api/routes/catalog.py src/ccf/api/auth_deps.py | head -10
```

- [ ] **Step 2: Write the failing test**

Mirror an existing admin-scoped route test in `tests/test_api.py`, asserting:
- listing revisions for a source returns them newest-first
- `POST .../adopt` without acknowledgement on a non-empty impact returns **409** with the impact in the body
- `POST .../adopt` with `{"acknowledge_impact": true}` returns 200 and flips status
- an unauthenticated or non-admin caller is rejected on the POST

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_catalog_revisions_api.py -v`
Expected: FAIL — 404 on the new paths

- [ ] **Step 4: Implement the four endpoints**

Reuse the module's existing `_source_out`-style serializers; add a `_revision_out(r: CatalogRevision) -> dict[str, Any]`. Map `AdoptionRefused` to HTTP 409 with `impact` in the response body. The POST uses the same write-role dependency as other admin mutations in this codebase.

- [ ] **Step 5: Run tests and commit**

```bash
pytest tests/test_catalog_revisions_api.py -v
ruff check src/ccf/api/routes/catalog.py tests/test_catalog_revisions_api.py
git add src/ccf/api/routes/catalog.py tests/test_catalog_revisions_api.py
git commit -m "feat(api): catalog revision endpoints with 409 on unacknowledged impact"
```

---

### Task 11: New sources, reliability check, and full-suite verification

**Files:**
- Modify: `src/ccf/etl/sources.py` (`DEFAULT_SOURCES`)
- Modify: `src/ccf/reliability/checks.py` (the existing catalog check, ~line 767)
- Test: `tests/test_catalog_revision_reliability.py`

**Interfaces:**
- Produces: four new `DEFAULT_SOURCES` entries; an extended reliability check reporting adopted-revision integrity.

- [ ] **Step 1: Confirm the 800-171 Rev 3 OSCAL filename**

Open item 1 in the spec. Verify the real path under
`https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-171/` before pinning it. Do not guess the filename.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_catalog_revision_reliability.py
"""Seeded sources cover every baseline, and the reliability check sees revisions."""

from __future__ import annotations

from ccf.etl.sources import DEFAULT_SOURCES


def test_all_three_80053b_baselines_are_registered_sources() -> None:
    keys = {s["key"] for s in DEFAULT_SOURCES}
    assert {
        "nist_800_53_r5_low_baseline",
        "nist_800_53_r5_moderate_baseline",
        "nist_800_53_r5_high_baseline",
    } <= keys


def test_csf_and_800_171_are_registered_sources() -> None:
    keys = {s["key"] for s in DEFAULT_SOURCES}
    assert "nist_csf_2_0_catalog" in keys
    assert "nist_800_171_r3_catalog" in keys


def test_every_source_declares_a_kind_and_url() -> None:
    for s in DEFAULT_SOURCES:
        assert s["url"]
        assert s.get("kind", "oscal_catalog")
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_catalog_revision_reliability.py -v`
Expected: FAIL — the LOW/MODERATE/CSF/800-171 keys are absent

- [ ] **Step 4: Add the sources and extend the reliability check**

Add the four `DEFAULT_SOURCES` entries following the existing dict shape. Then extend the catalog reliability check to also report: the adopted revision exists, its directory resolves, its files verify against the manifest, the catalog parses, and the DB `files` map matches disk — degrading (not failing) when no revision rows exist yet, so pre-migration deployments stay green.

- [ ] **Step 5: Run the full suite**

```bash
export CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
pytest -q
ruff check src tests
mypy src
alembic heads   # exactly one
```
Expected: full suite green, lint and types clean, one migration head.

- [ ] **Step 6: Mutation-test the new guards**

Per repo practice, reading is not verification. For each guard below, delete it, confirm a test fails, then restore:

1. the `status == "rejected"` check in `adopt_revision`
2. the `not impact.is_empty() and not acknowledge_impact` refusal
3. the `await session.flush()` between supersede and adopt
4. the manifest-missing fallback in `resolve_adopted_dir`
5. the `shutil.rmtree` cleanup on a rejected revision
6. the `MANIFEST.json` exclusion in `generate_manifest`
7. the `revision_data_root is not None` guard in `check_source` (protects every existing caller's behaviour)

- [ ] **Step 7: Commit**

```bash
git add src/ccf/etl/sources.py src/ccf/reliability/checks.py tests/test_catalog_revision_reliability.py
git commit -m "feat(catalog): register remaining NIST sources and check adopted-revision integrity"
```
