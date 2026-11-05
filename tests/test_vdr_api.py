"""VDR evaluations and a system's deadlines, through the real API with auth on."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, date, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, AuditLog, Organization, ScanIngestion, System, User
from ccf.models_program import KevEntry
from ccf.models_vdr import VulnerabilityEvaluation

pytestmark = pytest.mark.usefixtures("fresh_engine")

TODAY = datetime.now(UTC).date()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
def _auth_enabled() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


class World:
    def __init__(self) -> None:
        self.ids: dict[str, int] = {}
        self.hdr: dict[str, dict[str, str]] = {}


async def _world(cls: str | None = "C") -> World:
    w = World()
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"vdr-{tag}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"vdr {tag}", certification_class=cls)
        s.add(sysm)
        await s.flush()
        w.ids.update(org=org.id, system=sysm.id)
        for key, role in (("owner", "control_owner"), ("viewer", "viewer"), ("admin", "admin")):
            u = User(
                email=f"{key}-{tag}@vdr.example",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            await s.flush()
            w.hdr[key] = {"Authorization": f"Bearer {u.api_token}"}
    return w


async def _poam(w: World, **kw: object) -> int:
    base: dict[str, object] = {
        "system_id": w.ids["system"],
        "title": "OpenSSL flaw",
        "severity": "high",
        "status": "open",
        "source": "scan",
        "scanner": "nessus",
        "identified_on": TODAY,
        "due_on": TODAY + timedelta(days=30),
        "finding_uid": uuid.uuid4().hex,
    }
    base.update(kw)
    async with session_scope() as s:
        p = POAM(**base)
        s.add(p)
        await s.flush()
        return p.id


async def _get_poam(pid: int) -> POAM:
    async with session_scope() as s:
        return (await s.execute(select(POAM).where(POAM.id == pid))).scalar_one()


BODY = {
    "pain_rating": 5,
    "internet_reachable": True,
    "likely_exploitable": True,
    "rationale": "Unauthenticated RCE on the public load balancer.",
}


@pytest.mark.asyncio
async def test_an_evaluation_is_recorded_and_tightens_the_due_date(_auth_enabled: None) -> None:
    w = await _world("C")
    pid = await _poam(w)
    async with _client() as c:
        r = await c.post(f"/api/poams/{pid}/evaluations", json=BODY, headers=w.hdr["owner"])
        assert r.status_code == 201, r.text
        out = r.json()
        # Class C, N5, LEV + IRV: 2 days from evaluation.
        assert out["status"]["state"] == "within"
        assert out["status"]["mitigation_column"] == "irv_lev"
        assert out["due_on_changed"] is True
        assert out["previous_due_on"] == (TODAY + timedelta(days=30)).isoformat()
        h = await c.get(f"/api/poams/{pid}/evaluations", headers=w.hdr["viewer"])
        assert h.status_code == 200
        assert [e["pain_rating"] for e in h.json()] == [5]
        assert h.json()[0]["evaluated_by"].startswith("owner-")
    poam = await _get_poam(pid)
    assert poam.due_on is not None and poam.due_on <= TODAY + timedelta(days=3)
    assert poam.original_due_on is None  # untouched: tightening is not a rebaseline
    async with session_scope() as s:
        events = (
            (
                await s.execute(
                    select(AuditLog).where(
                        AuditLog.action == "vdr_due_tightened", AuditLog.entity_id == str(pid)
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(events) == 1


@pytest.mark.asyncio
async def test_an_evaluation_never_extends_a_due_date(_auth_enabled: None) -> None:
    w = await _world("A")
    pid = await _poam(w, due_on=TODAY + timedelta(days=5))
    body = {**BODY, "pain_rating": 2, "likely_exploitable": False}  # Class A N2 NLEV: 192 days
    async with _client() as c:
        r = await c.post(f"/api/poams/{pid}/evaluations", json=body, headers=w.hdr["owner"])
    assert r.status_code == 201, r.text
    assert r.json()["due_on_changed"] is False
    assert (await _get_poam(pid)).due_on == TODAY + timedelta(days=5)


@pytest.mark.asyncio
async def test_a_viewer_cannot_record_an_evaluation(_auth_enabled: None) -> None:
    w = await _world()
    pid = await _poam(w)
    async with _client() as c:
        r = await c.post(f"/api/poams/{pid}/evaluations", json=BODY, headers=w.hdr["viewer"])
    assert r.status_code == 403
    async with session_scope() as s:
        n = (
            (
                await s.execute(
                    select(VulnerabilityEvaluation).where(VulnerabilityEvaluation.poam_id == pid)
                )
            )
            .scalars()
            .all()
        )
    assert n == []


@pytest.mark.asyncio
async def test_another_organization_cannot_see_or_evaluate(_auth_enabled: None) -> None:
    mine, theirs = await _world(), await _world()
    pid = await _poam(theirs)
    async with _client() as c:
        r = await c.post(f"/api/poams/{pid}/evaluations", json=BODY, headers=mine.hdr["owner"])
        assert r.status_code == 404
        r = await c.get(f"/api/poams/{pid}/evaluations", headers=mine.hdr["owner"])
        assert r.status_code == 404
        r = await c.get(f"/api/systems/{theirs.ids['system']}/vdr", headers=mine.hdr["owner"])
        assert r.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("change", "poam_kw", "status", "words"),
    [
        ({"false_positive": True}, {}, 422, "false positive"),
        ({"rationale": "   "}, {}, 422, "rationale"),
        ({}, {"source": "assessment"}, 422, "control deficiency"),
        ({}, {"status": "closed", "closed_on": TODAY}, 409, "closed"),
    ],
)
async def test_evaluations_that_cannot_be_recorded_are_refused(
    _auth_enabled: None, change: dict, poam_kw: dict, status: int, words: str
) -> None:
    w = await _world()
    pid = await _poam(w, **poam_kw)
    async with _client() as c:
        r = await c.post(
            f"/api/poams/{pid}/evaluations", json={**BODY, **change}, headers=w.hdr["owner"]
        )
    assert r.status_code == status, r.text
    assert words in r.json()["detail"]


@pytest.mark.asyncio
async def test_a_rating_outside_zero_to_five_is_refused(_auth_enabled: None) -> None:
    w = await _world()
    pid = await _poam(w)
    async with _client() as c:
        r = await c.post(
            f"/api/poams/{pid}/evaluations",
            json={**BODY, "pain_rating": 6},
            headers=w.hdr["owner"],
        )
    assert r.status_code == 422


@pytest.fixture
async def kev_entry() -> AsyncIterator[str]:
    cve = f"CVE-2099-{uuid.uuid4().int % 10_000_000:07d}"
    async with session_scope() as s:
        s.add(
            KevEntry(
                cve_id=cve,
                name="test",
                date_added=TODAY - timedelta(days=30),
                due_date=TODAY + timedelta(days=1),
                catalog_version="test",
                synced_at=datetime.now(UTC),
            )
        )
    yield cve
    async with session_scope() as s:
        await s.execute(delete(KevEntry).where(KevEntry.cve_id == cve))


@pytest.mark.asyncio
async def test_a_kev_due_date_tightens_the_due_date_and_shows_on_the_system(
    _auth_enabled: None, kev_entry: str
) -> None:
    w = await _world("A")
    pid = await _poam(w, weakness=f"Refs: {kev_entry}")
    body = {**BODY, "pain_rating": 2, "likely_exploitable": False}
    async with _client() as c:
        r = await c.post(f"/api/poams/{pid}/evaluations", json=body, headers=w.hdr["owner"])
        assert r.status_code == 201, r.text
        assert r.json()["status"]["kev_due"] == (TODAY + timedelta(days=1)).isoformat()
        v = await c.get(f"/api/systems/{w.ids['system']}/vdr", headers=w.hdr["viewer"])
    assert (await _get_poam(pid)).due_on == TODAY + timedelta(days=1)
    flaw = next(f for f in v.json()["flaws"] if f["poam_id"] == pid)
    assert flaw["kev_due"] == (TODAY + timedelta(days=1)).isoformat()


@pytest.mark.asyncio
async def test_the_system_view_counts_flaws_and_measures_cadence(_auth_enabled: None) -> None:
    w = await _world("C")
    old = await _poam(w, identified_on=TODAY - timedelta(days=30))
    await _poam(w)
    await _poam(w, source="assessment")  # a control deficiency: not counted
    async with session_scope() as s:
        s.add(
            ScanIngestion(
                organization_id=w.ids["org"],
                system_id=w.ids["system"],
                scanner="nessus",
                findings_total=2,
                summary={},
            )
        )
    async with _client() as c:
        r = await c.get(f"/api/systems/{w.ids['system']}/vdr", headers=w.hdr["viewer"])
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["certification_class"] == "C"
    assert out["rules_version"] == "2026.10.13.01"
    assert out["counts"]["overdue"] == 1
    assert out["counts"]["awaiting_evaluation"] == 1
    assert sum(out["counts"].values()) == 2
    late = next(f for f in out["flaws"] if f["poam_id"] == old)
    assert [b["rule"] for b in late["breaches"]] == ["VER-TFR-EVU"]
    assert out["cadence"] == [
        {
            "scanner": "nessus",
            "last_at": out["cadence"][0]["last_at"],
            "age_days": out["cadence"][0]["age_days"],
            "required_days": 3,
            "stale": False,
        }
    ]


@pytest.mark.asyncio
async def test_a_system_without_a_class_gets_no_class_deadlines(_auth_enabled: None) -> None:
    w = await _world(None)
    await _poam(w, identified_on=TODAY - timedelta(days=400))
    async with _client() as c:
        r = await c.get(f"/api/systems/{w.ids['system']}/vdr", headers=w.hdr["viewer"])
    flaw = r.json()["flaws"][0]
    assert flaw["state"] == "awaiting_evaluation"
    assert flaw["evaluation_due"] is None
    assert "class" in flaw["note"]


def test_today_is_a_date() -> None:
    assert isinstance(TODAY, date)


# ── pages ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_pages_render_and_only_writers_see_the_form(_auth_enabled: None) -> None:
    w = await _world("D")
    pid = await _poam(w)
    async with _client() as c:
        idx = await c.get("/vdr", headers=w.hdr["viewer"])
        assert idx.status_code == 200, idx.text
        assert f"/systems/{w.ids['system']}/vdr" in idx.text
        page = await c.get(f"/systems/{w.ids['system']}/vdr", headers=w.hdr["owner"])
        assert page.status_code == 200, page.text
        assert f"/vdr/poams/{pid}/evaluate" in page.text
        assert "Class D" in page.text
        assert "no scan has been ingested" in page.text.lower()
        seen = await c.get(f"/systems/{w.ids['system']}/vdr", headers=w.hdr["viewer"])
        assert f"/vdr/poams/{pid}/evaluate" not in seen.text


@pytest.mark.asyncio
async def test_the_form_records_an_evaluation_and_says_what_moved(_auth_enabled: None) -> None:
    w = await _world("D")
    pid = await _poam(w)
    async with _client() as c:
        r = await c.post(
            f"/systems/{w.ids['system']}/vdr/poams/{pid}/evaluate",
            data={"pain_rating": "4", "likely_exploitable": "on", "rationale": "Admin VPC only."},
            headers=w.hdr["owner"],
        )
        assert r.status_code == 303, r.text
        assert "msg=" in r.headers["location"] and "earlier" in r.headers["location"]
        h = (await c.get(f"/api/poams/{pid}/evaluations", headers=w.hdr["owner"])).json()
    assert [(e["pain_rating"], e["internet_reachable"], e["likely_exploitable"]) for e in h] == [
        (4, False, True)
    ]


@pytest.mark.asyncio
async def test_a_refused_form_evaluation_redirects_with_the_reason(_auth_enabled: None) -> None:
    w = await _world()
    pid = await _poam(w)
    async with _client() as c:
        r = await c.post(
            f"/systems/{w.ids['system']}/vdr/poams/{pid}/evaluate",
            data={"pain_rating": "3", "rationale": "  "},
            headers=w.hdr["owner"],
        )
    assert r.status_code == 303
    assert "error=" in r.headers["location"] and "rationale" in r.headers["location"]


@pytest.mark.asyncio
async def test_the_form_refuses_a_poam_from_another_system(_auth_enabled: None) -> None:
    """Same organization, different system: the org check passes, so only the
    page's own system check can refuse it."""
    w = await _world()
    async with session_scope() as s:
        sibling = System(organization_id=w.ids["org"], name=f"sibling {uuid.uuid4().hex[:6]}")
        s.add(sibling)
        await s.flush()
        sibling_id = sibling.id
    pid = await _poam(w, system_id=sibling_id)
    async with _client() as c:
        r = await c.post(
            f"/systems/{w.ids['system']}/vdr/poams/{pid}/evaluate",
            data={"pain_rating": "3", "rationale": "x"},
            headers=w.hdr["owner"],
        )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_a_viewer_cannot_post_the_form(_auth_enabled: None) -> None:
    w = await _world()
    pid = await _poam(w)
    async with _client() as c:
        r = await c.post(
            f"/systems/{w.ids['system']}/vdr/poams/{pid}/evaluate",
            data={"pain_rating": "3", "rationale": "x"},
            headers=w.hdr["viewer"],
        )
    assert r.status_code == 403


# ── relaxing needs a second person ────────────────────────────────────────


async def _eval(c: AsyncClient, pid: int, hdr: dict[str, str], **kw: object) -> dict:
    r = await c.post(f"/api/poams/{pid}/evaluations", json={**BODY, **kw}, headers=hdr)
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.asyncio
async def test_a_lowered_rating_waits_for_someone_else(_auth_enabled: None) -> None:
    w = await _world("C")
    pid = await _poam(w)
    async with _client() as c:
        first = await _eval(c, pid, w.hdr["owner"], pain_rating=5)
        assert first["pending_confirmation"] is False
        lowered = await _eval(c, pid, w.hdr["owner"], pain_rating=2)
        assert lowered["pending_confirmation"] is True
        # Not in effect: the deadline is still N5's.
        assert lowered["status"]["evaluation"]["pain_rating"] == 5
        eid = lowered["evaluation"]["id"]
        view = (await c.get(f"/api/systems/{w.ids['system']}/vdr", headers=w.hdr["viewer"])).json()
        flaw = next(f for f in view["flaws"] if f["poam_id"] == pid)
        assert flaw["evaluation"]["pain_rating"] == 5
        assert [p["id"] for p in flaw["pending"]] == [eid]

        own = await c.post(f"/api/poams/{pid}/evaluations/{eid}/confirm", headers=w.hdr["owner"])
        assert own.status_code == 403, own.text
        viewer = await c.post(
            f"/api/poams/{pid}/evaluations/{eid}/confirm", headers=w.hdr["viewer"]
        )
        assert viewer.status_code == 403
        ok = await c.post(f"/api/poams/{pid}/evaluations/{eid}/confirm", headers=w.hdr["admin"])
        assert ok.status_code == 200, ok.text
        assert ok.json()["status"]["evaluation"]["pain_rating"] == 2
        assert ok.json()["evaluation"]["confirmed_by"].startswith("admin-")
        again = await c.post(f"/api/poams/{pid}/evaluations/{eid}/confirm", headers=w.hdr["admin"])
        assert again.status_code == 409


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kw",
    [
        {"pain_rating": 1},
        {"pain_rating": 0, "false_positive": True},
    ],
)
async def test_a_first_evaluation_that_removes_every_deadline_waits(
    _auth_enabled: None, kw: dict
) -> None:
    w = await _world("C")
    pid = await _poam(w, identified_on=TODAY - timedelta(days=30))
    async with _client() as c:
        out = await _eval(c, pid, w.hdr["owner"], **kw)
    assert out["pending_confirmation"] is True
    assert out["status"]["state"] == "overdue"  # still late for evaluation (VER-TFR-EVU)


@pytest.mark.asyncio
async def test_a_raised_rating_takes_effect_at_once(_auth_enabled: None) -> None:
    w = await _world("C")
    pid = await _poam(w)
    async with _client() as c:
        await _eval(c, pid, w.hdr["owner"], pain_rating=3)
        out = await _eval(c, pid, w.hdr["owner"], pain_rating=5)
    assert out["pending_confirmation"] is False
    assert out["status"]["evaluation"]["pain_rating"] == 5


@pytest.mark.asyncio
async def test_a_superseded_pending_evaluation_cannot_be_confirmed(_auth_enabled: None) -> None:
    w = await _world("C")
    pid = await _poam(w)
    async with _client() as c:
        await _eval(c, pid, w.hdr["owner"], pain_rating=5)
        held = await _eval(c, pid, w.hdr["owner"], pain_rating=2)
        await _eval(c, pid, w.hdr["owner"], pain_rating=5)
        r = await c.post(
            f"/api/poams/{pid}/evaluations/{held['evaluation']['id']}/confirm",
            headers=w.hdr["admin"],
        )
        view = (await c.get(f"/api/systems/{w.ids['system']}/vdr", headers=w.hdr["viewer"])).json()
    assert r.status_code == 409 and "supersedes" in r.json()["detail"]
    assert next(f for f in view["flaws"] if f["poam_id"] == pid)["pending"] == []


@pytest.mark.asyncio
async def test_an_evaluation_in_effect_needs_no_confirmation(_auth_enabled: None) -> None:
    w = await _world("C")
    pid = await _poam(w)
    async with _client() as c:
        out = await _eval(c, pid, w.hdr["owner"], pain_rating=5)
        r = await c.post(
            f"/api/poams/{pid}/evaluations/{out['evaluation']['id']}/confirm",
            headers=w.hdr["admin"],
        )
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_with_auth_off_there_is_no_second_person_to_wait_for() -> None:
    w = await _world("C")
    pid = await _poam(w)
    async with _client() as c:
        out = await _eval(c, pid, {}, pain_rating=1)
    assert out["pending_confirmation"] is False
    assert out["status"]["state"] == "no_timeframe"


@pytest.mark.asyncio
async def test_the_page_offers_confirmation_to_others_but_not_the_author(
    _auth_enabled: None,
) -> None:
    w = await _world("C")
    pid = await _poam(w)
    async with _client() as c:
        await _eval(c, pid, w.hdr["owner"], pain_rating=5)
        held = await _eval(c, pid, w.hdr["owner"], pain_rating=2)
        eid = held["evaluation"]["id"]
        action = f"/vdr/poams/{pid}/evaluations/{eid}/confirm"
        mine = await c.get(f"/systems/{w.ids['system']}/vdr", headers=w.hdr["owner"])
        assert "Awaiting confirmation" in mine.text and action not in mine.text
        theirs = await c.get(f"/systems/{w.ids['system']}/vdr", headers=w.hdr["admin"])
        assert action in theirs.text
        r = await c.post(f"/systems/{w.ids['system']}{action}", headers=w.hdr["admin"])
        assert r.status_code == 303 and "confirmed" in r.headers["location"]


@pytest.mark.asyncio
async def test_an_evaluation_cannot_be_confirmed_through_another_poam(
    _auth_enabled: None,
) -> None:
    w = await _world("C")
    held_on, other = await _poam(w), await _poam(w)
    async with _client() as c:
        await _eval(c, held_on, w.hdr["owner"], pain_rating=5)
        held = await _eval(c, held_on, w.hdr["owner"], pain_rating=2)
        r = await c.post(
            f"/api/poams/{other}/evaluations/{held['evaluation']['id']}/confirm",
            headers=w.hdr["admin"],
        )
    assert r.status_code == 404
