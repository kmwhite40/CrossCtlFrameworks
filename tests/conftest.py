"""Shared pytest fixtures."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import openpyxl
import pytest
from alembic import command
from alembic.config import Config

from ccf import db as ccf_db
from ccf.config import get_settings

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
