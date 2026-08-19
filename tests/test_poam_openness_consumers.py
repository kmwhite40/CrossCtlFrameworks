"""The two consumers that had their own idea of POA&M openness.

Both were unblocked by moving the vocabulary into ``constants.py``; this pins
the behaviour so neither can drift back.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from ccf.api.routes.oscal import _OSCAL_POAM_STATE
from ccf.constants import POAM_ACTIVE_STATUSES, POAM_STATUSES, POAM_UNRESOLVED_STATUSES
from ccf.queries import registry

_SRC = Path(__file__).resolve().parents[1] / "src" / "ccf"


# --- F-S10-2: the SAR must project the real status ---------------------------


def test_sar_projects_the_poam_status_instead_of_hardcoding_open() -> None:
    """One ZIP asserted two different things about one record.

    ``build_package_zip`` writes poam.json and sar.json together. poam.json ran
    the status through ``_OSCAL_POAM_STATE`` (so a risk-accepted item rendered
    ``risk-accepted``), while the SAR wrote the literal ``"open"`` for every
    row. The OSCAL risk-status field accepts any token, so schema validation
    could never catch the contradiction.
    """
    src = (_SRC / "api" / "routes" / "oscal.py").read_text(encoding="utf-8")
    assert '"status": "open",' not in src, "SAR still hardcodes a risk status"
    assert '"status": _OSCAL_POAM_STATE.get(' in src


def test_every_status_has_an_oscal_projection() -> None:
    """A status with no mapping would fall through to its raw internal name."""
    missing = [s for s in POAM_STATUSES if s not in _OSCAL_POAM_STATE]
    assert missing == [], f"no OSCAL projection for: {missing}"


def test_risk_accepted_projects_to_its_own_oscal_state() -> None:
    """This is why the export's open set differs from the dashboards'."""
    assert _OSCAL_POAM_STATE["risk_accepted"] == "risk-accepted"
    assert "risk_accepted" in POAM_UNRESOLVED_STATUSES
    assert "risk_accepted" not in POAM_ACTIVE_STATUSES


# --- F-S26-1: the query template must use the canonical overdue rule ---------


async def _capture_sql(monkeypatch) -> str:
    """Run the template with a stubbed executor and return the SQL it built.

    Asserting on the generated SQL rather than on the function's source text:
    the source contains an explanatory comment that quotes the OLD rule, so a
    text match there tests the comment, not the query.
    """
    captured: dict[str, str] = {}

    async def fake_rows(session, sql, params):
        captured["sql"] = sql
        return []

    monkeypatch.setattr(registry, "_rows", fake_rows)
    await registry._overdue_poams(None, {}, None)  # type: ignore[arg-type]
    return captured["sql"]


@pytest.mark.asyncio
async def test_overdue_query_selects_only_the_active_statuses(monkeypatch) -> None:
    """`status <> 'closed'` admitted completed AND risk_accepted."""
    sql = await _capture_sql(monkeypatch)
    assert "po.status <> 'closed'" not in sql
    assert "po.status IN ('open', 'in_progress')" in sql
    # risk_accepted and completed must not be selectable by this template
    for excluded in ("risk_accepted", "completed", "closed"):
        assert f"'{excluded}'" not in sql, f"{excluded} is still selectable as overdue"


@pytest.mark.asyncio
async def test_overdue_query_uses_the_canonical_due_precedence(monkeypatch) -> None:
    """Precedence was inverted and original_due_on was missing entirely."""
    sql = await _capture_sql(monkeypatch)
    canonical = "COALESCE(po.due_on, po.scheduled_completion, po.original_due_on)"
    assert canonical in sql
    assert "COALESCE(po.scheduled_completion, po.due_on)" not in sql
    # the displayed `due` column must be the same expression the filter used
    assert f"{canonical} AS due" in sql


@pytest.mark.asyncio
async def test_overdue_query_still_scopes_by_org(monkeypatch) -> None:
    """Guard the tenant predicate through the rewrite."""
    sql = await _capture_sql(monkeypatch)
    assert "s.organization_id = CAST(:org AS integer)" in sql


def test_template_and_dashboard_agree_on_the_predicate_shape() -> None:
    """Both sides must name the same columns in the same order."""
    tpl = inspect.getsource(registry._overdue_poams)
    posture = (_SRC / "analytics" / "posture.py").read_text(encoding="utf-8")
    assert "func.coalesce(POAM.due_on, POAM.scheduled_completion, POAM.original_due_on)" in posture
    for col in ("due_on", "scheduled_completion", "original_due_on"):
        assert col in tpl, f"template omits {col}"


def test_interpolated_statuses_cannot_carry_injection() -> None:
    """The status list is interpolated, not bound. Assert it stays constant-only."""
    assert all(s.replace("_", "").isalnum() for s in POAM_ACTIVE_STATUSES)
