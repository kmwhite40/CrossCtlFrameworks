"""pgvector extension availability and prep settings defaults."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from ccf.config import get_settings
from ccf.db import session_scope

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def test_vector_extension_is_installed() -> None:
    async with session_scope() as s:
        row = (
            await s.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'vector'"))
        ).scalar_one_or_none()
        assert row == 1, "pgvector extension missing — is the DB image pgvector/pgvector:pg16?"


async def test_vector_column_round_trips() -> None:
    async with session_scope() as s:
        await s.execute(text("CREATE TEMP TABLE _vt (v vector(3))"))
        await s.execute(text("INSERT INTO _vt (v) VALUES ('[1,2,3]')"))
        got = (await s.execute(text("SELECT v::text FROM _vt"))).scalar_one()
        assert got == "[1,2,3]"


def test_prep_settings_defaults() -> None:
    s = get_settings()
    assert s.prep_enabled is False
    # Derived against the real 800-53A catalog, not a placeholder — see
    # ccf.config's prep_screen_threshold docstring and task-9-report.md.
    assert s.prep_screen_threshold == 0.72
    assert s.prep_expand_window == 4
    assert s.prep_embed_dimensions == 1024
    assert s.prep_worker_batch_size == 10
    assert s.prep_job_stale_after_minutes == 60
