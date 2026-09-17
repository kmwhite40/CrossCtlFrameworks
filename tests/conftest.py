"""Shared pytest fixtures."""

from __future__ import annotations

import os
import socket
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import openpyxl
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from ccf import db as ccf_db
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.etl.sources import _read_file
from ccf.models import CatalogSource
from ccf.models_packs import PackSource
from ccf.packs import sync as _pack_sync_mod

# Run against a real Postgres — CI service container; locally, docker compose.
os.environ.setdefault(
    "CCF_DATABASE_URL",
    "postgresql+asyncpg://ccf:ccf@localhost:5432/ccf_test",
)
os.environ.setdefault(
    "CCF_DATABASE_URL_SYNC",
    "postgresql+psycopg://ccf:ccf@localhost:5432/ccf_test",
)
os.environ.setdefault("CCF_ENV", "test")


@pytest.fixture(scope="session", autouse=True)
def clean_migrated_db() -> None:
    """Start every test session from a clean, fully-migrated schema.

    The suite is designed to run against a fresh database (CI uses a throwaway
    Postgres container). Locally the DB persists between runs, so tests that seed
    and assert exact state would fail on a second run. Resetting to ``base`` then
    ``head`` once, up front, makes ``pytest`` deterministic on repeat runs without
    a manual drop — and, crucially, does it BEFORE any test module runs rather than
    mid-session (a mid-session downgrade wipes data other modules depend on)."""
    if not str(get_settings().database_url_sync).startswith("postgresql"):
        return  # SQLite reader build manages its own schema
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


#: Tables whose rows are polled by the scheduler, and which therefore must not
#: survive the test that created them. Both are org-scoped working data, not
#: reference data, so nothing legitimately expects a row to outlive its test.
_POLLED_SOURCE_MODELS = (CatalogSource, PackSource)


async def _source_row_ids() -> dict[object, set[int]]:
    async with session_scope() as session:
        return {
            model: set((await session.execute(select(model.id))).scalars().all())
            for model in _POLLED_SOURCE_MODELS
        }


@pytest.fixture
async def isolate_source_rows() -> AsyncIterator[None]:
    """Delete the ``CatalogSource`` / ``PackSource`` rows this test created.

    ``clean_migrated_db`` resets the schema once per *session*, so a row a test
    leaves behind is visible to every later module. Ten modules leaked 73 such
    rows between them, and they are not inert: ``scheduler.run_cycle()`` polls
    every enabled row of both tables, so a leaked row is extra work at best and
    a live network fetch at worst — ``tests/test_pack_source_models.py`` leaves
    one carrying a real ``raw.githubusercontent.com`` URL, which is why a
    scheduler test that passed in isolation reached the internet in a full
    suite.

    Opt in with ``pytest.mark.usefixtures("isolate_source_rows")`` rather than
    autouse: autouse would force a database round trip for all ~2500 tests,
    including the many that touch no database at all.

    Deletes by *id difference* rather than by a key prefix or a blanket
    ``DELETE``, so a module that legitimately relies on the migration-seeded
    row keeps it, and a future table row added by some other fixture is left
    alone.
    """
    before = await _source_row_ids()
    yield
    after = await _source_row_ids()
    created = {model: after[model] - before[model] for model in _POLLED_SOURCE_MODELS}
    if not any(created.values()):
        return
    async with session_scope() as session:
        for model, ids in created.items():
            if ids:
                await session.execute(delete(model).where(model.id.in_(ids)))


#: Ports that mean "this is a real call to the internet". The test database
#: lives on 5434 and local fixture servers pick ephemeral ports, so neither is
#: caught here.
_NETWORK_PORTS = frozenset({80, 443})


@pytest.fixture(autouse=True)
def no_outbound_network(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Fail any test that opens a real connection to the internet.

    The suite is meant to be hermetic, and on 2026-09-17 it was not: three
    tests made four live HTTPS calls on every run -- two to graph.microsoft.us
    and two to GitHub. That is slow, it makes the suite fail on an
    egress-restricted runner, and it silently made CI depend on third parties
    being up.

    Worse, it let a test pass for the wrong reason. The msgraph
    hostile-endpoint test asserted only that a check came back
    ``manual_review_required`` -- which ``_unrunnable`` returns for *any*
    exception, so a refused connection and a working host check were
    indistinguishable. It would have passed against the vulnerable connector.

    **Blocking alone is not enough**, which is why this records attempts and
    fails in teardown: code under test routinely catches connection errors and
    converts them into an ordinary result, so a test that reaches the network
    could otherwise still go green while the guard "worked".

    A test that genuinely needs the network marks itself ``allows_network``.
    """
    if request.node.get_closest_marker("allows_network"):
        yield
        return

    real_connect = socket.socket.connect
    attempted: list[str] = []

    def guarded(self: socket.socket, address: object, *a: object, **kw: object) -> object:
        if isinstance(address, tuple) and len(address) >= 2 and address[1] in _NETWORK_PORTS:
            attempted.append(f"{address[0]}:{address[1]}")
            raise OSError(
                f"outbound network blocked in tests: {address[0]}:{address[1]} "
                "(stub the transport, or mark the test allows_network)"
            )
        return real_connect(self, address, *a, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(socket.socket, "connect", guarded)
    yield
    monkeypatch.undo()
    if attempted:
        pytest.fail(
            "this test reached the internet: "
            + ", ".join(sorted(set(attempted)))
            + ". Stub the HTTP transport (see test_msgraph_declared_scan.py) or "
            "the calling function, or mark the test `allows_network`."
        )


@pytest.fixture(autouse=True)
async def fresh_engine() -> AsyncIterator[None]:
    """pytest-asyncio uses a per-test event loop; the global asyncpg engine binds
    to whichever loop created it. Dispose + reset it after each test so the next
    test always gets a fresh engine on its own loop — otherwise a module that
    doesn't reset leaks an engine bound to a now-closed loop and the next module's
    first DB test raises ``RuntimeError: Event loop is closed``.

    Autouse so no module can forget it. Disposal happens in the test's own (still
    open) loop; sync/pure tests that never built an engine are a no-op. The app
    factory resolves the engine lazily per request, so module-scoped app fixtures
    keep working across the reset."""
    yield
    if ccf_db._engine is not None:
        await ccf_db._engine.dispose()
    ccf_db._engine = None
    ccf_db._session_factory = None


def pack_source_url(path: Path) -> str:
    """An ``https://`` URL for a pack-source test fixture file.

    ``ccf.packs.sync.validate_pack_source_url`` (PR #17 security review,
    CRITICAL 1) now requires every ``PackSource.url`` to be ``https://`` --
    ``file://`` and bare local paths, which every pack-source test used
    before that fix, are rejected as SSRF/local-file-read vectors. Pair this
    with the :func:`local_pack_source_fetch` fixture, which maps a URL built
    this way back to the real file on disk, so tests keep exercising the
    poll/adopt/divergence flow against a local fixture without a real network
    endpoint while the stored URL still passes validation exactly as
    production requires.
    """
    return f"https://pack-source.test{path}"


@pytest.fixture
def local_pack_source_fetch(monkeypatch: pytest.MonkeyPatch):
    """Patch ``ccf.packs.sync.fetch_conditional`` to read the local file a
    :func:`pack_source_url` URL points at, instead of making a real request.

    Returns the stub so a test can further wrap or replace it (e.g. to
    simulate a 304, a redirect, or a transport failure).
    """

    async def _fetch(
        url: str, etag: str | None, **_kwargs: object
    ) -> tuple[int, bytes | None, str | None]:
        local = Path(url.removeprefix("https://pack-source.test"))
        data = await _read_file(local)
        return 200, data, None

    monkeypatch.setattr(_pack_sync_mod, "fetch_conditional", _fetch)
    return _fetch


@pytest.fixture(scope="session")
def mini_workbook(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A 10-row fixture workbook with the assessment sheet and one generic tab."""
    path = tmp_path_factory.mktemp("wb") / "mini.xlsx"
    wb = openpyxl.Workbook()
    a = wb.active
    a.title = "SP.800-53Ar5_assessment"
    headers = [
        "family",
        "identifier",
        "Sequence Control",
        "sort-as",
        "control-name",
        "Security Control Description",
        "Security Control Discussion",
        "NIST SP 800-53 Rev. 5 related controls",
        "assessment-objective",
        "EXAMINE",
        "INTERVIEW",
        "TEST",
        "FISMA Low",
        "FISMA Mod",
        "FISMA High",
        "ISO 27001 Mapping",
        "CMMC Rev. 2L2",
        "FedRAMP Moderate",
    ]
    a.append(headers)
    rows = [
        [
            "(AC) ACCESS CONTROL",
            "AC-01",
            "AC-01",
            "AC-01-00-00",
            "Policy and Procedures",
            "Develop, document, and disseminate...",
            "Discussion text",
            "AC-02",
            "Determine if:",
            "policy docs",
            "personnel",
            "",
            "X",
            "X",
            "X",
            "A.5.15",
            "AC.L2-3.1.1",
            "AC-1",
        ],
        [
            "(AC) ACCESS CONTROL",
            "AC-02",
            "AC-02",
            "AC-02-00-00",
            "Account Management",
            "Identify and select account types...",
            "Discussion text",
            "AC-03",
            "Determine if:",
            "config",
            "admins",
            "test",
            "",
            "X",
            "X",
            "A.5.16",
            "AC.L2-3.1.2",
            "AC-2",
        ],
        [
            "(AU) AUDIT AND ACCOUNTABILITY",
            "AU-01",
            "AU-01",
            "AU-01-00-00",
            "Policy and Procedures",
            "Develop audit policy...",
            "Discussion text",
            "",
            "Determine if:",
            "policy docs",
            "personnel",
            "",
            "X",
            "X",
            "X",
            "A.5.28",
            "AU.L2-3.3.1",
            "AU-1",
        ],
    ]
    for r in rows:
        a.append(r)

    b = wb.create_sheet("Data Dictionary")
    b.append(["Term", "Definition"])
    b.append(["Identifier", "The unique ID of a control"])

    wb.save(path)
    return path
