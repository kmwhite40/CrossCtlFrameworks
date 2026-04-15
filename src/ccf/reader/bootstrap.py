"""SQLite-friendly schema initialization for Concord Reader.

Alembic migration 0001 uses Postgres-only types (JSONB, TSVECTOR, pg_trgm).
Rather than fork migrations, the Reader creates a *subset* of the schema —
exactly what the read-only UI needs — directly via DDL, portable to SQLite.
"""
from __future__ import annotations

from pathlib import Path
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


READER_DDL_SQLITE = [
    # --- Reference layer -----------------------------------------------------
    """CREATE TABLE IF NOT EXISTS frameworks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        family TEXT,
        description TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS control_families (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        category TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS controls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT NOT NULL UNIQUE,
        sequence_control TEXT,
        sort_as TEXT,
        family_id INTEGER REFERENCES control_families(id) ON DELETE SET NULL,
        control_number TEXT,
        control_name TEXT,
        description TEXT,
        discussion TEXT,
        related_controls TEXT,
        assessment_objective TEXT,
        examine TEXT,
        interview TEXT,
        test TEXT,
        ap_acronym TEXT,
        assurance_control TEXT,
        implemented_by TEXT,
        owner TEXT,
        overall_control_type TEXT,
        opd INTEGER,
        fisma_low INTEGER,
        fisma_mod INTEGER,
        fisma_high INTEGER,
        audit_payload TEXT NOT NULL DEFAULT '{}',  -- JSON encoded
        search_vector TEXT,                         -- unused on sqlite
        source_row INTEGER,
        loaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""",
    "CREATE INDEX IF NOT EXISTS idx_controls_sequence ON controls(sequence_control)",
    "CREATE INDEX IF NOT EXISTS idx_controls_family ON controls(family_id)",

    """CREATE TABLE IF NOT EXISTS framework_mappings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
        framework_id INTEGER REFERENCES frameworks(id) ON DELETE SET NULL,
        column_key TEXT NOT NULL,
        value TEXT NOT NULL,
        UNIQUE(control_id, column_key)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_fm_control ON framework_mappings(control_id)",
    "CREATE INDEX IF NOT EXISTS ix_fm_framework ON framework_mappings(framework_id)",
    "CREATE INDEX IF NOT EXISTS ix_fm_value ON framework_mappings(value)",

    """CREATE TABLE IF NOT EXISTS worksheets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        slug TEXT NOT NULL UNIQUE,
        headers TEXT NOT NULL DEFAULT '[]',
        row_count INTEGER NOT NULL DEFAULT 0,
        loaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS worksheet_rows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        worksheet_id INTEGER NOT NULL REFERENCES worksheets(id) ON DELETE CASCADE,
        row_index INTEGER NOT NULL,
        payload TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS ix_wr_worksheet ON worksheet_rows(worksheet_id)",

    """CREATE TABLE IF NOT EXISTS ingestion_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_file TEXT NOT NULL,
        sha256 TEXT,
        workbook_version_id INTEGER,
        started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        finished_at TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        stats TEXT NOT NULL DEFAULT '{}'
    )""",
]


async def init_reader_schema(engine: AsyncEngine) -> None:
    """Create the Reader's SQLite schema if it doesn't exist."""
    async with engine.begin() as conn:
        for stmt in READER_DDL_SQLITE:
            await conn.execute(text(stmt))


def default_data_dir() -> Path:
    """Return %LOCALAPPDATA%/Concord (Windows) or ~/.concord (Unix)."""
    import os
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    root = Path(base) / ("Concord" if os.name == "nt" else ".concord")
    root.mkdir(parents=True, exist_ok=True)
    return root
