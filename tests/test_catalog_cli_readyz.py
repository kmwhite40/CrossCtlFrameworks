from __future__ import annotations

from pathlib import Path

import pytest

from ccf.catalog.report import run_and_store
from ccf.db import session_scope
from ccf.models import Control
from ccf.reliability.checks import PASS, _check_catalog_integrity

pytestmark = pytest.mark.usefixtures("fresh_engine")
FIX = Path(__file__).parent / "fixtures" / "oscal_mini"


async def test_readyz_check_reports_pass_with_version():
    async with session_scope() as s:
        s.add(
            Control(
                identifier="cli-readyz-row-1",
                control_number="AC-2",
                control_name="Account Management",
            )
        )
        await s.flush()
        await run_and_store(s, oscal_dir=FIX)
        res = await _check_catalog_integrity(s)
        assert res.status == PASS
        assert "5.2.0" in (res.message or "")
