"""Posture history: snapshots, /trends, /forecast and the command center tab.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md, "A -- history".

What is pinned, each the shape of a defect this platform has shipped before:

* **Tenant isolation is in the query.** Two organizations, each with
  snapshots carrying distinctive numbers; every page and service is driven on
  an RLS-bypass session, so only the code's own org predicate can keep
  Bravo's history off Alpha's page. Each test also asserts Alpha's own data
  *is* there, so an empty page cannot pass.
* **The one write is admin-only, audited, and refuses a caller with no
  organization.**
* **Parts sum to their whole**, and a ratio over nothing is ``None``.
* **A projection refuses thin history** and never runs past its horizon.
"""

from __future__ import annotations

import asyncio
import itertools
import os
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from typer.testing import CliRunner

from ccf import db as ccf_db
from ccf.analytics import posture_history as ph
from ccf.analytics.command_center import command_center
from ccf.api.deps import get_session
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.cli import app as cli_app
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.models import POAM, AuditLog, Organization, Risk, System, Task, User
from ccf.models_program import PostureSnapshot

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


async def _unscoped_session():
    """RLS tenant cleared (bypass): only the page's own org predicate can keep
    Bravo's rows off Alpha's page."""
    factory = get_session_factory()
    async with factory() as session:
        await set_session_tenant(session, None)
        yield session


def _client() -> AsyncClient:
    app = create_app()
    app.dependency_overrides[get_session] = _unscoped_session
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _today() -> date:
    return datetime.now(UTC).date()


def _metrics(poams: int, *, failing: int = 2, risks: int = 1) -> dict[str, object]:
    """A schema-1 metrics document whose parts sum to their wholes."""
    return {
        "schema": 1,
        "systems_live": 1,
        "controls": {
            "passing": 7,
            "failing_open": failing,
            "failing_accepted": 1,
            "manual_review": 0,
            "judged": 8 + failing,
            "not_in_scope": 0,
        },
        "findings": {
            "open": poams,
            "by_severity": {"critical": 0, "high": poams, "moderate": 0, "low": 0},
            "other": 0,
        },
        "risks": {
            "open": risks,
            "by_band": {"critical": 0, "high": 0, "moderate": risks, "low": 0, "unknown": 0},
        },
        "remediation": {"resolved": 3, "remediable": 3 + poams, "risk_accepted": 0},
        "overdue": {"poams": 0, "tasks": 0, "total": 0},
        "frameworks": [
            {
                "label": "NIST SP 800-53 Rev. 5 · FedRAMP Moderate",
                "addressed": 40,
                "failing": 2,
                "total": 50,
                "unit": "control",
                "systems": 1,
            }
        ],
        "sprs": {"average": None, "minimum": None, "systems_scored": 0},
        "evidence": {"current": 0, "expired": 0, "dated": 0, "undated": 0, "total": 0},
        "monitoring": {
            "healthy": 0,
            "due_soon": 0,
            "at_risk": 0,
            "overdue": 0,
            "total": 0,
        },
    }


async def _org(label: str, tag: str, *, roles: tuple[str, ...] = ("admin",)) -> dict:
    """An organization with a live system carrying one open POA&M and one open
    risk, plus a soft-deleted system carrying more, and one user per role."""
    today = _today()
    async with session_scope() as s:
        org = Organization(name=f"{label}-org-{tag}")
        s.add(org)
        await s.flush()
        tokens = {}
        for role in roles:
            u = User(
                email=f"{label.lower()}-{role}-{tag}@hist.test",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            tokens[role] = u.api_token
        live = System(organization_id=org.id, name=f"{label}-system-{tag}", baseline="moderate")
        gone = System(
            organization_id=org.id,
            name=f"{label}-DELETED-{tag}",
            baseline="moderate",
            deleted_at=datetime.now(UTC),
        )
        s.add_all([live, gone])
        await s.flush()
        s.add_all(
            [
                POAM(
                    system_id=live.id,
                    title=f"{label}-poam-{tag}",
                    severity="high",
                    status="open",
                    identified_on=today - timedelta(days=3),
                    due_on=today - timedelta(days=1),
                ),
                POAM(system_id=gone.id, title="gone", severity="critical", status="open"),
                Risk(
                    system_id=live.id,
                    title=f"{label}-risk-{tag}",
                    likelihood="high",
                    impact="moderate",
                    status="open",
                    inherent_score=15,
                    residual_score=6,
                ),
                Risk(
                    system_id=gone.id,
                    title="gone",
                    likelihood="high",
                    impact="high",
                    status="open",
                    residual_score=25,
                ),
                Task(organization_id=org.id, title="t", status="open", due_on=today - timedelta(2)),
            ]
        )
        await s.flush()
        return {"org_id": org.id, "tokens": tokens, "tag": tag}


async def _snapshots(org_id: int, rows: list[tuple[int, int]]) -> None:
    """``rows`` of (days ago, open POA&Ms)."""
    today = _today()
    async with session_scope() as s:
        for ago, poams in rows:
            s.add(
                PostureSnapshot(
                    organization_id=org_id,
                    taken_on=today - timedelta(days=ago),
                    source="scheduler",
                    metrics=_metrics(poams, failing=poams, risks=poams),
                )
            )


# Alpha's history: falling, five snapshots over 28 days. Bravo's carries a
# number that must never appear on Alpha's page.
ALPHA = [(28, 4321), (21, 4300), (14, 4280), (7, 4262), (1, 4240)]
BRAVO = [(30, 98765), (20, 98760), (10, 98755), (3, 98750), (2, 98745), (1, 98740), (0, 98735)]


@pytest.fixture
async def scene() -> tuple[dict, dict]:
    tag = f"hi{next(_SEQ)}h{os.getpid()}{os.urandom(2).hex()}"
    a = await _org("Alpha", tag, roles=("admin", "viewer", "control_owner", "assessor"))
    b = await _org("Bravo", tag)
    await _snapshots(a["org_id"], ALPHA)
    await _snapshots(b["org_id"], BRAVO)
    return a, b


async def _rows(org_id: int) -> list[PostureSnapshot]:
    async with session_scope() as s:
        return list(
            (
                await s.execute(
                    select(PostureSnapshot)
                    .where(PostureSnapshot.organization_id == org_id)
                    .order_by(PostureSnapshot.taken_on)
                )
            )
            .scalars()
            .all()
        )


# ── pure: the fit, the projection, the thinning ─────────────────────────────


def test_linear_fit_recovers_a_known_line() -> None:
    fit = ph.linear_fit([(0, 10), (1, 8), (2, 6), (3, 4)])
    assert fit["slope"] == pytest.approx(-2)
    assert fit["intercept"] == pytest.approx(10)
    assert fit["r2"] == pytest.approx(1)


def test_a_flat_history_has_no_fit_to_report() -> None:
    """No variance means R² is undefined; it is not 0 and not 1."""
    assert ph.linear_fit([(0, 5), (7, 5), (14, 5)])["r2"] is None


def _obs(rows: list[tuple[int, int]]) -> list[tuple[date, int]]:
    start = date(2026, 1, 1)
    return [(start + timedelta(days=d), v) for d, v in rows]


def test_fewer_than_four_snapshots_are_not_projected() -> None:
    out = ph.project(_obs([(0, 10), (10, 8), (20, 6)]))
    assert out["ok"] is False and "at least 4" in out["reason"]


def test_snapshots_spanning_under_fourteen_days_are_not_projected() -> None:
    out = ph.project(_obs([(0, 10), (4, 9), (8, 8), (13, 7)]))
    assert out["ok"] is False and "at least 14" in out["reason"]
    assert ph.project(_obs([(0, 10), (4, 9), (8, 8), (14, 7)]))["ok"] is True


def test_a_falling_backlog_gets_a_zero_date_inside_the_horizon() -> None:
    out = ph.project(_obs([(0, 40), (7, 33), (14, 26), (21, 19)]))  # -1/day
    assert out["ok"] and out["direction"] == "down"
    assert out["slope_per_week"] == pytest.approx(-7)
    assert out["zero_on"] == date(2026, 1, 1) + timedelta(days=40)
    assert out["r2"] == pytest.approx(1)


def test_no_projection_runs_past_ninety_days() -> None:
    out = ph.project(_obs([(0, 400), (7, 399), (14, 398), (21, 397)]))
    last = date(2026, 1, 22)
    assert out["horizon_on"] == last + timedelta(days=90)
    assert max(m["days"] for m in out["marks"]) == 90
    assert all(m["on"] <= out["horizon_on"] for m in out["marks"])
    # Falling, but zero is ~397 days out: not shown.
    assert out["zero_on"] is None and out["zero_note"] == "beyond"


def test_a_rising_or_flat_backlog_never_gets_a_zero_date() -> None:
    assert ph.project(_obs([(0, 1), (7, 2), (14, 3), (21, 4)]))["zero_on"] is None
    flat = ph.project(_obs([(0, 3), (7, 3), (14, 3), (21, 3)]))
    assert flat["zero_on"] is None and flat["direction"] == "flat" and flat["r2"] is None


def test_a_vanishing_slope_does_not_overflow_the_calendar() -> None:
    out = ph.project(_obs([(0, 10**9), (7, 10**9), (14, 10**9), (21, 10**9 - 1)]))
    assert out["ok"] and out["zero_on"] is None


def test_projected_counts_are_floored_at_zero_and_say_so() -> None:
    out = ph.project(_obs([(0, 30), (7, 20), (14, 10), (21, 5)]))
    assert all(m["value"] >= 0 for m in out["marks"])
    assert any(m["floored"] for m in out["marks"])


def test_thinning_keeps_recorded_values_and_the_newest() -> None:
    snaps = [
        SimpleNamespace(taken_on=date(2026, 1, 1) + timedelta(days=i), v=i) for i in range(100)
    ]
    out = ph.thin(snaps, 12)
    assert len(out) <= 12
    assert out[-1] is snaps[-1]
    assert all(s in snaps for s in out)
    assert [s.taken_on for s in out] == sorted(s.taken_on for s in out)
    assert ph.thin(snaps[:5], 12) == snaps[:5]


def test_every_stacked_chart_sums_to_its_whole() -> None:
    snaps = [
        SimpleNamespace(
            taken_on=date(2026, 1, 1) + timedelta(days=i), source="scheduler", metrics=_metrics(i)
        )
        for i in range(3)
    ]
    t = ph.trends(snaps, range_days=90, today=date(2026, 1, 10))
    for chart in [*t["charts"], *t["frameworks"]]:
        for i, whole in enumerate(chart["wholes"]):
            assert sum(s["values"][i] for s in chart["series"]) == whole, chart["title"]


def test_a_ratio_over_nothing_is_none_in_the_snapshot_table() -> None:
    row = ph.snapshot_row(
        SimpleNamespace(taken_on=date(2026, 1, 1), source="manual", metrics=_metrics(0))
    )
    assert row["evidence_pct"] is None and row["monitoring_pct"] is None
    assert row["controls_pct"] == 70  # 7 of 10


# ── the service, on an unscoped session ──────────────────────────────────────


async def test_a_capture_counts_one_organization_and_its_parts_sum(scene) -> None:
    a, _ = scene
    async with session_scope() as s:
        out = await ph.capture_snapshot(s, a["org_id"], today=_today(), source="manual")
    m = next(r for r in await _rows(a["org_id"]) if r.id == out["id"]).metrics
    # One live POA&M and one live risk: Bravo's and the deleted system's are out.
    assert m["findings"]["open"] == 1
    assert m["risks"]["open"] == 1
    assert sum(m["findings"]["by_severity"].values()) + m["findings"]["other"] == 1
    assert sum(m["risks"]["by_band"].values()) == 1
    c = m["controls"]
    parts = c["passing"] + c["failing_open"] + c["failing_accepted"] + c["manual_review"]
    assert parts == c["judged"]
    assert m["overdue"]["poams"] + m["overdue"]["tasks"] == m["overdue"]["total"] == 2
    e = m["evidence"]
    assert e["current"] + e["expired"] == e["dated"]
    assert e["dated"] + e["undated"] == e["total"]
    mon = m["monitoring"]
    assert sum(mon[k] for k in ph.MONITORING_STATES) == mon["total"]


async def test_a_second_capture_the_same_day_replaces_the_first(scene) -> None:
    """Bravo already has a snapshot today; Alpha's first capture must still be
    new -- the existing-row lookup is scoped to the organization."""
    a, b = scene
    today = _today()
    async with session_scope() as s:
        first = await ph.capture_snapshot(s, a["org_id"], today=today, source="manual")
    async with session_scope() as s:
        second = await ph.capture_snapshot(s, a["org_id"], today=today, source="scheduler")
    assert first["replaced"] is False
    assert second["replaced"] is True and second["id"] == first["id"]
    todays = [r for r in await _rows(a["org_id"]) if r.taken_on == today]
    assert len(todays) == 1 and todays[0].source == "scheduler"
    assert len([r for r in await _rows(b["org_id"]) if r.taken_on == today]) == 1


async def test_a_bad_source_is_refused(scene) -> None:
    a, _ = scene
    async with session_scope() as s:
        with pytest.raises(ValueError):
            await ph.capture_snapshot(s, a["org_id"], today=_today(), source="guess")


async def test_capture_all_records_every_live_organization(scene) -> None:
    a, b = scene
    async with session_scope() as s:
        out = await ph.capture_all(s, _today())
    ids = {c["organization_id"] for c in out["captured"]}
    assert {a["org_id"], b["org_id"]} <= ids
    assert not out["failed"]
    by_org = {c["organization_id"]: c for c in out["captured"]}
    assert by_org[b["org_id"]]["replaced"] is True  # Bravo had today's row
    assert by_org[a["org_id"]]["replaced"] is False


async def test_trends_read_only_the_callers_snapshots(scene) -> None:
    a, _ = scene
    async with session_scope() as s:
        t = await ph.trends_for(s, a["org_id"], today=_today(), range_days=0)
    assert t["count"] == len(ALPHA) and t["total_recorded"] == len(ALPHA)
    assert {r["poams_open"] for r in t["rows"]} == {v for _, v in ALPHA}


async def test_the_command_center_tab_reads_only_the_callers_snapshots(scene) -> None:
    a, _ = scene
    async with session_scope() as s:
        cc = await command_center(s, a["org_id"])
    p = cc["trends"]["posture"]
    assert p["count"] == len(ALPHA) and p["total_recorded"] == len(ALPHA)
    assert p["enough"] is True
    assert "SPRS score" not in cc["trends"]["not_recorded"]


async def test_an_organization_without_snapshots_says_nothing_is_recorded(scene) -> None:
    async with session_scope() as s:
        org = Organization(name=f"Empty-{next(_SEQ)}h{os.getpid()}")
        s.add(org)
        await s.flush()
        cc = await command_center(s, org.id)
        f = await ph.forecast_for(s, org.id, today=_today())
    assert cc["trends"]["posture"]["count"] == 0
    assert "SPRS score" in cc["trends"]["not_recorded"]
    assert all(m["ok"] is False for m in f["metrics"])


# ── the pages, through the real auth gate ────────────────────────────────────


@pytest.mark.parametrize("path", ["/trends?days=0", "/forecast", "/dashboard"])
async def test_no_page_shows_another_organizations_history(scene, path: str) -> None:
    a, _ = scene
    async with _client() as c:
        resp = await c.get(path, headers=_auth(a["tokens"]["viewer"]))
    assert resp.status_code == 200, resp.text[:400]
    assert "9876" not in resp.text, f"{path} shows Bravo's history to Alpha"
    assert "4240" in resp.text, f"{path} does not show Alpha's own latest snapshot"


async def test_trends_shows_the_callers_own_history(scene) -> None:
    a, _ = scene
    async with _client() as c:
        body = (await c.get("/trends?days=0", headers=_auth(a["tokens"]["viewer"]))).text
    assert "4321" in body and "4240" in body
    assert f"{len(ALPHA)} snapshots" in body
    assert f"{len(ALPHA)} recorded in all" in body


async def test_forecast_projects_the_callers_own_history(scene) -> None:
    a, _ = scene
    async with _client() as c:
        body = (await c.get("/forecast", headers=_auth(a["tokens"]["viewer"]))).text
    assert "projection from recorded history, not a prediction" in body
    assert "Fitted to 5 snapshots" in body
    assert "4240" in body  # Alpha's latest open POA&Ms


async def test_one_snapshot_is_not_a_trend(scene) -> None:
    tag = f"hi{next(_SEQ)}h{os.getpid()}{os.urandom(2).hex()}"
    lone = await _org("Lone", tag)
    await _snapshots(lone["org_id"], [(2, 5)])
    async with _client() as c:
        trends = (await c.get("/trends", headers=_auth(lone["tokens"]["admin"]))).text
        fc = (await c.get("/forecast", headers=_auth(lone["tokens"]["admin"]))).text
    assert "One snapshot is not a trend" in trends
    assert "a trend needs at least two" in trends
    assert "1 snapshot recorded; a projection needs at least 4." in fc


async def test_a_short_history_is_not_projected(scene) -> None:
    tag = f"hi{next(_SEQ)}h{os.getpid()}{os.urandom(2).hex()}"
    short = await _org("Short", tag)
    await _snapshots(short["org_id"], [(9, 8), (6, 7), (3, 6), (0, 5)])
    async with _client() as c:
        fc = (await c.get("/forecast", headers=_auth(short["tokens"]["admin"]))).text
    assert "The snapshots span 9 days; a projection needs at least 14." in fc


# ── the write: role gate, audit, scope ───────────────────────────────────────


@pytest.mark.parametrize("role", ["viewer", "control_owner", "assessor"])
async def test_only_an_admin_may_record_a_snapshot(scene, role: str) -> None:
    a, _ = scene
    before = len(await _rows(a["org_id"]))
    async with _client() as c:
        resp = await c.post("/trends/capture", headers=_auth(a["tokens"][role]))
    assert resp.status_code == 403
    assert len(await _rows(a["org_id"])) == before


async def test_an_admin_records_todays_snapshot_and_it_is_audited(scene) -> None:
    a, b = scene
    async with _client() as c:
        resp = await c.post("/trends/capture", headers=_auth(a["tokens"]["admin"]))
        page = (await c.get("/trends", headers=_auth(a["tokens"]["admin"]))).text
    assert resp.status_code == 303 and resp.headers["location"] == "/trends?captured=new"
    rows = await _rows(a["org_id"])
    today_row = next(r for r in rows if r.taken_on == _today())
    assert today_row.source == "manual"
    assert len(rows) == len(ALPHA) + 1
    assert len(await _rows(b["org_id"])) == len(BRAVO)  # Bravo untouched
    async with session_scope() as s:
        events = (
            await s.execute(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.action == "posture_snapshot_captured",
                    AuditLog.entity_id == str(today_row.id),
                    AuditLog.organization_id == a["org_id"],
                )
            )
        ).scalar_one()
    assert events == 1
    assert "Record today&#39;s snapshot" in page or "Record today's snapshot" in page


async def test_the_capture_button_is_offered_to_admins_only(scene) -> None:
    a, _ = scene
    async with _client() as c:
        viewer = (await c.get("/trends", headers=_auth(a["tokens"]["viewer"]))).text
    assert 'action="/trends/capture"' not in viewer


async def test_a_caller_with_no_organization_cannot_record_one() -> None:
    """With auth off every request is the global system principal: an admin
    with no organization. A snapshot is one organization's, so it is refused
    rather than written for nobody."""
    os.environ.pop("CCF_AUTH_ENABLED", None)
    get_settings.cache_clear()
    async with session_scope() as s:
        before = (await s.execute(select(func.count()).select_from(PostureSnapshot))).scalar_one()
    async with _client() as c:
        resp = await c.post("/trends/capture")
        page = await c.get("/trends")
    assert resp.status_code == 400
    assert page.status_code == 200 and "No organization in scope" in page.text
    async with session_scope() as s:
        after = (await s.execute(select(func.count()).select_from(PostureSnapshot))).scalar_one()
    assert after == before


async def test_capture_all_skips_a_deleted_organization(scene) -> None:
    tag = f"hi{next(_SEQ)}h{os.getpid()}{os.urandom(2).hex()}"
    gone = await _org("Gone", tag)
    async with session_scope() as s:
        org = await s.get(Organization, gone["org_id"])
        org.deleted_at = datetime.now(UTC)
    async with session_scope() as s:
        out = await ph.capture_all(s, _today())
    assert gone["org_id"] not in {c["organization_id"] for c in out["captured"]}
    assert await _rows(gone["org_id"]) == []


# ── the CLI ──────────────────────────────────────────────────────────────────


async def _invoke_cli(args: list[str]):
    """Run the CLI in a thread with its own event loop and its own engine: the
    global engine is bound to this test's loop and cannot be shared."""
    saved = (ccf_db._engine, ccf_db._session_factory)
    ccf_db._engine, ccf_db._session_factory = None, None
    try:
        return await asyncio.to_thread(CliRunner().invoke, cli_app, args)
    finally:
        ccf_db._engine, ccf_db._session_factory = saved


async def test_the_cli_records_one_organizations_snapshot(scene) -> None:
    a, b = scene
    result = await _invoke_cli(["posture-snapshot", "--org", str(a["org_id"])])
    assert result.exit_code == 0, result.output
    assert "recorded snapshot" in result.output
    assert any(r.taken_on == _today() and r.source == "manual" for r in await _rows(a["org_id"]))
    assert len(await _rows(b["org_id"])) == len(BRAVO)
    async with session_scope() as s:
        audited = (
            await s.execute(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.action == "posture_snapshot_captured",
                    AuditLog.actor == "cli",
                    AuditLog.organization_id == a["org_id"],
                )
            )
        ).scalar_one()
    assert audited == 1


async def test_the_cli_refuses_an_unknown_organization() -> None:
    result = await _invoke_cli(["posture-snapshot", "--org", "2147480000"])
    assert result.exit_code == 1
    assert "No organization with id 2147480000" in result.output
