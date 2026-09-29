"""The cross-source finding rollup reaches a page, and covers the machine source.

`analytics/findings.py` exists to reconcile the several vocabularies a control's
determination is recorded in. Two things were wrong with it:

* **Nothing called it.** A module whose entire purpose is a holistic answer, with
  no caller, answers nothing.
* **It omitted `ControlTest.last_status`** — the machine vocabulary, and now the
  source producing most determinations. `normalize_finding` had no aliases for
  it either, so every automated verdict normalised to `unknown`: feeding a
  scanned system through the rollup returned a column of nothing.
"""

from __future__ import annotations

import itertools
import os
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.analytics.findings import canonical_finding_counts, system_finding_rollup
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.constants import normalize_finding
from ccf.db import session_scope
from ccf.fedramp20x import VALIDATION_STATUSES
from ccf.models import Organization, ScoringControl, ScoringStatus, System, User
from ccf.models_grc import ControlTest
from ccf.scoring.seed import seed_scoring_controls

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# The machine vocabulary is understood
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", VALIDATION_STATUSES)
def test_every_machine_verdict_normalizes_to_something_meaningful(status) -> None:
    """`unknown` is the graceful-degradation bucket for dirty data.

    A verdict the platform itself writes on every scan landing there is not
    graceful degradation, it is the rollup not knowing its own biggest source.
    """
    assert normalize_finding(status) != "unknown", status


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("pass", "satisfied"),
        ("fail", "other_than_satisfied"),
        # A warning is a softer observation, not a different determination.
        ("warn", "other_than_satisfied"),
        # Neither of these is a determination about the control, so neither may
        # manufacture a finding out of an absence.
        ("not_tested", "not_assessed"),
        ("manual_review_required", "not_assessed"),
        ("not_applicable", "not_applicable"),
    ],
)
def test_the_machine_verdicts_map_where_they_belong(status, expected) -> None:
    assert normalize_finding(status) == expected


def test_a_genuinely_unrecognised_value_is_still_visible_as_unknown() -> None:
    """Adding the machine vocabulary must not swallow the dirty-data bucket."""
    assert normalize_finding("cromulent") == "unknown"
    counts = canonical_finding_counts(["pass", "cromulent"])
    assert counts["satisfied"] == 1
    assert counts["unknown"] == 1


# ---------------------------------------------------------------------------
# The rollup reads all four sources
# ---------------------------------------------------------------------------


async def _scene() -> tuple[int, int, str]:
    tag = f"{next(_SEQ)}"
    async with session_scope() as s:
        await seed_scoring_controls(s)
        org = Organization(name=f"Rollup Org {tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"r-{tag}@rollup.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        sys_ = System(organization_id=org.id, name=f"Rollup Sys {tag}")
        s.add(sys_)
        await s.flush()
        for i, status in enumerate(["pass", "pass", "fail", "manual_review_required"]):
            s.add(
                ControlTest(
                    organization_id=org.id,
                    system_id=sys_.id,
                    control_id=f"AC-{i + 1}",
                    name=f"check {i}",
                    method="connector",
                    source="generated",
                    check_key=f"roll.{tag}.{i}",
                    last_status=status,
                    last_tested_at=datetime(2026, 9, 29, tzinfo=UTC),
                )
            )
        practice = (
            await s.execute(select(ScoringControl).limit(1))
        ).scalars().one()
        s.add(
            ScoringStatus(
                system_id=sys_.id,
                scoring_control_id=practice.id,
                state="implemented",
                source="assessed",
            )
        )
        await s.flush()
        return org.id, sys_.id, user.api_token


async def _cleanup(org_id: int) -> None:
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id == org_id))


@pytest.mark.asyncio
async def test_the_rollup_counts_the_machine_source() -> None:
    org_id, sys_id, _token = await _scene()
    try:
        async with session_scope() as s:
            r = await system_finding_rollup(s, sys_id)
        assert r["by_source"]["control_tests"]["satisfied"] == 2
        assert r["by_source"]["control_tests"]["other_than_satisfied"] == 1
        assert r["by_source"]["control_tests"]["not_assessed"] == 1
        assert r["canonical"]["unknown"] == 0, (
            "a machine verdict fell into the dirty-data bucket"
        )
        # The SPRS state is counted too, and the two sources combine.
        assert r["by_source"]["scoring_statuses"]["satisfied"] == 1
        assert r["canonical"]["satisfied"] == 3
        assert r["total"] == 5
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_source_with_nothing_still_appears() -> None:
    """"No assessment results" and "this source was not consulted" must differ."""
    org_id, sys_id, _token = await _scene()
    try:
        async with session_scope() as s:
            r = await system_finding_rollup(s, sys_id)
        for key in (
            "control_tests",
            "scoring_statuses",
            "assessment_results",
            "assessment_control_results",
        ):
            assert key in r["by_source"], key
            assert set(r["by_source"][key]) >= {"satisfied", "other_than_satisfied"}
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_another_systems_findings_are_not_counted() -> None:
    org_a, sys_a, _ = await _scene()
    org_b, _sys_b, _ = await _scene()
    try:
        async with session_scope() as s:
            r = await system_finding_rollup(s, sys_a)
        assert r["total"] == 5, "another system's determinations were counted"
    finally:
        await _cleanup(org_a)
        await _cleanup(org_b)


# ---------------------------------------------------------------------------
# It reaches a page
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_system_page_shows_every_source() -> None:
    """The module existed and nothing called it; a rollup nobody reads is not one."""
    org_id, sys_id, token = await _scene()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=create_app()), base_url="http://t"
        ) as c:
            r = await c.get(
                f"/systems/{sys_id}", headers={"Authorization": f"Bearer {token}"}
            )
        assert r.status_code == 200, r.text
        assert "Finding status, all sources" in r.text
        assert "Automated control tests" in r.text
        assert "SPRS implementation states" in r.text
        assert "5 determination(s) reconciled" in r.text
    finally:
        await _cleanup(org_id)
