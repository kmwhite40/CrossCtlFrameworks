"""Server-rendered GRC routes may not be addressed across tenants.

Seven handlers in ``ccf.api.routes.ui_grc`` took an id from the URL (and in
four cases no principal at all) and acted on whatever row it named. They are
the browser twins of JSON routes that already carry the predicate --
``grc.get_engagement``, ``grc.add_request``, ``grc.add_finding``,
``ui_grc.questionnaire_export``, ``ui_grc.connector_detail`` -- reached by
editing a URL rather than by crafting a request.

**Why these tests call the handlers directly.** Every table involved
(``audit_engagements``, ``audit_findings``, ``audit_requests``,
``vendor_questionnaires``, ``questionnaire_responses``, ``regulatory_updates``,
``connector_configs``) carries a ``tenant_isolation`` RLS policy, and
``ccf.api.deps.get_session`` binds the RLS tenant from the principal. An
HTTP-only test therefore cannot tell the new app-layer predicate from RLS
underneath it -- delete the predicate and the request still fails. So each
guard is exercised at its own layer on an unscoped ``session_scope()`` session
(RLS in bypass), with the **owning** org asserted first so the refusal is
provably the org check and not a seeding failure. HTTP tests sit alongside
them for the end-to-end result.
"""

from __future__ import annotations

import itertools
import os
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from starlette.requests import Request

from ccf.api.main import create_app
from ccf.api.routes import ui_grc
from ccf.auth import Principal, hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import Organization, User, Vendor
from ccf.models_grc import (
    AuditEngagement,
    AuditFinding,
    AuditRequest,
    ConnectorConfig,
    RegulatoryUpdate,
)
from ccf.models_tprm import QuestionnaireResponse, VendorQuestionnaire

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


def _tag() -> str:
    return f"{next(_SEQ)}-{os.urandom(3).hex()}"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
async def orgs() -> AsyncIterator[list[int]]:
    """Seeded orgs, deleted with everything that cascades.

    ``clean_migrated_db`` resets the schema once per *session*, so a leaked row
    is visible to every later module.
    """
    created: list[int] = []
    try:
        yield created
    finally:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            for org_id in created:
                await s.execute(delete(Organization).where(Organization.id == org_id))


@pytest.fixture
def auth_enabled() -> Iterator[None]:
    """Auth ON: without it every request is ``SYSTEM_PRINCIPAL``, which is
    global, and an HTTP test would exercise the bypass rather than the guard."""
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


@pytest.fixture
def production_env() -> Iterator[None]:
    """A non-development environment.

    ``tests/conftest.py`` sets ``CCF_ENV=test`` process-wide and ``is_dev_env``
    treats ``test`` as a development environment, so the whole suite runs on the
    permissive side of the ``0eadea4`` gate by default.
    """
    prev = os.environ.get("CCF_ENV")
    os.environ["CCF_ENV"] = "production"
    get_settings.cache_clear()
    yield
    if prev is None:
        os.environ.pop("CCF_ENV", None)
    else:
        os.environ["CCF_ENV"] = prev
    get_settings.cache_clear()


async def _org(created: list[int], name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name, description="ui_grc scoping test")
        s.add(org)
        await s.flush()
        created.append(org.id)
        return org.id


async def _admin(org_id: int, tag: str, side: str) -> str:
    async with session_scope() as s:
        u = User(
            email=f"{side}-{tag}@uigrc.test", organization_id=org_id, role="admin",
            active=True, password_hash=hash_password("pw"), api_token=new_api_token(),
        )
        s.add(u)
        await s.flush()
        return u.api_token


def _principal(org_id: int | None) -> Principal:
    return Principal(user_id=None, email="probe@uigrc.test", org_id=org_id, role="admin")


def _req(org_id: int | None, path: str = "/") -> Request:
    """A Request carrying only what ``_principal_org`` reads off it.

    ``auth_gate_middleware`` is what normally sets ``state.principal``; these
    handlers are being called beneath it on purpose.
    """
    request = Request(
        {
            "type": "http", "http_version": "1.1", "method": "GET", "scheme": "http",
            "path": path, "raw_path": path.encode(), "root_path": "", "query_string": b"",
            "headers": [(b"host", b"t")], "client": ("test", 1), "server": ("t", 80),
        }
    )
    request.state.principal = _principal(org_id)
    return request


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- Audit Workspace --------------------------------------------------------


async def _engagement(org_id: int, name: str) -> int:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        e = AuditEngagement(organization_id=org_id, name=name, framework="fedramp")
        s.add(e)
        await s.flush()
        return e.id


@pytest.mark.asyncio
async def test_audit_engagement_detail_is_scoped(orgs: list[int]) -> None:
    """The page renders the engagement's whole request + finding tree."""
    tag = _tag()
    owner = await _org(orgs, f"UIGRC Audit Owner {tag}")
    outsider = await _org(orgs, f"UIGRC Audit Outsider {tag}")
    eng = await _engagement(owner, f"Owned Audit {tag}")

    async with session_scope() as s:
        await set_session_tenant(s, None)
        # Owning org first: the row IS reachable on this unscoped session.
        page = await ui_grc.audit_engagement_detail(eng, _req(owner), s)
        assert page.status_code == 200

        with pytest.raises(HTTPException) as err:
            await ui_grc.audit_engagement_detail(eng, _req(outsider), s)
        assert err.value.status_code == 404

        # A global principal keeps full access.
        assert (await ui_grc.audit_engagement_detail(eng, _req(None), s)).status_code == 200


@pytest.mark.asyncio
async def test_audit_add_request_is_scoped(orgs: list[int]) -> None:
    """``eng_id`` used to write a PBC item into any tenant's audit: the parent
    engagement was never loaded at all."""
    tag = _tag()
    owner = await _org(orgs, f"UIGRC Req Owner {tag}")
    outsider = await _org(orgs, f"UIGRC Req Outsider {tag}")
    eng = await _engagement(owner, f"Req Audit {tag}")

    async with session_scope() as s:
        await set_session_tenant(s, None)
        ok = await ui_grc.audit_add_request(
            eng, _req(owner), title=f"Owner PBC {tag}", due_on="", session=s
        )
        assert ok.status_code == 303

        with pytest.raises(HTTPException) as err:
            await ui_grc.audit_add_request(
                eng, _req(outsider), title=f"Injected PBC {tag}", due_on="", session=s
            )
        assert err.value.status_code == 404

        glob = await ui_grc.audit_add_request(
            eng, _req(None), title=f"Global PBC {tag}", due_on="", session=s
        )
        assert glob.status_code == 303

    # The refused write left no row -- read unscoped, so RLS cannot stand in
    # for the row never existing.
    async with session_scope() as s:
        await set_session_tenant(s, None)
        titles = (
            await s.execute(select(AuditRequest.title).where(AuditRequest.engagement_id == eng))
        ).scalars().all()
    assert f"Injected PBC {tag}" not in titles
    assert f"Owner PBC {tag}" in titles


@pytest.mark.asyncio
async def test_audit_add_finding_is_scoped_and_mirrors_the_parent_org(
    orgs: list[int],
) -> None:
    """Two defects on one handler.

    The parent was never loaded, so a finding could be raised inside another
    tenant's audit; and ``organization_id`` was left NULL, unlike
    ``grc.add_finding``'s (ISSM-04), so a UI-raised finding fell out of every
    org-scoped filter of the findings table.
    """
    tag = _tag()
    owner = await _org(orgs, f"UIGRC Find Owner {tag}")
    outsider = await _org(orgs, f"UIGRC Find Outsider {tag}")
    eng = await _engagement(owner, f"Find Audit {tag}")

    async with session_scope() as s:
        await set_session_tenant(s, None)
        ok = await ui_grc.audit_add_finding(
            eng, _req(owner), title=f"Owner Finding {tag}", severity="high", session=s
        )
        assert ok.status_code == 303

        with pytest.raises(HTTPException) as err:
            await ui_grc.audit_add_finding(
                eng, _req(outsider), title=f"Injected Finding {tag}",
                severity="high", session=s,
            )
        assert err.value.status_code == 404

        glob = await ui_grc.audit_add_finding(
            eng, _req(None), title=f"Global Finding {tag}", severity="low", session=s
        )
        assert glob.status_code == 303

    async with session_scope() as s:
        await set_session_tenant(s, None)
        rows = (
            await s.execute(
                select(AuditFinding.title, AuditFinding.organization_id).where(
                    AuditFinding.engagement_id == eng
                )
            )
        ).all()
    by_title = dict(rows)
    assert f"Injected Finding {tag}" not in by_title
    # ISSM-04: both the tenant-principal and the global-principal writes mirror
    # the PARENT's org, not the caller's -- a global caller has none to mirror.
    assert by_title[f"Owner Finding {tag}"] == owner, by_title
    assert by_title[f"Global Finding {tag}"] == owner, by_title


@pytest.mark.asyncio
async def test_audit_workspace_routes_over_http(orgs: list[int], auth_enabled: None) -> None:
    tag = _tag()
    owner = await _org(orgs, f"UIGRC HTTP Audit Owner {tag}")
    outsider = await _org(orgs, f"UIGRC HTTP Audit Outsider {tag}")
    eng = await _engagement(owner, f"HTTP Audit {tag}")
    owner_token = await _admin(owner, tag, "aowner")
    outsider_token = await _admin(outsider, tag, "aoutsider")

    async with _client() as c:
        assert (
            await c.get(f"/audit-workspace/{eng}", headers=_auth(owner_token))
        ).status_code == 200
        for path, kwargs in (
            (f"/audit-workspace/{eng}", {}),
            (f"/audit-workspace/{eng}/requests", {"data": {"title": "x"}}),
            (f"/audit-workspace/{eng}/findings", {"data": {"title": "x"}}),
        ):
            method = c.get if not kwargs else c.post
            r = await method(path, headers=_auth(outsider_token), **kwargs)
            assert r.status_code == 404, (path, r.status_code, r.text[:200])


# --- Regulatory Change ------------------------------------------------------


@pytest.mark.asyncio
async def test_regulatory_update_is_scoped(orgs: list[int]) -> None:
    """The handler took no principal at all: any tenant could rewrite another's
    applicability, status and owner by posting to an id.

    A foreign row takes the same silent no-op an unknown id already takes, so
    the write path does not become an existence oracle -- the assertion is on
    the STORED VALUE, not on a status code.
    """
    tag = _tag()
    owner = await _org(orgs, f"UIGRC Reg Owner {tag}")
    outsider = await _org(orgs, f"UIGRC Reg Outsider {tag}")
    async with session_scope() as s:
        await set_session_tenant(s, None)
        u = RegulatoryUpdate(
            organization_id=owner, title=f"Reg {tag}", status="new", applicability="unknown"
        )
        s.add(u)
        await s.flush()
        upd = u.id

    async with session_scope() as s:
        await set_session_tenant(s, None)
        assert (
            await ui_grc.regulatory_update(
                upd, _req(owner), applicability="applicable",
                status="assessing", owner="me", session=s,
            )
        ).status_code == 303

    async with session_scope() as s:
        await set_session_tenant(s, None)
        row = await s.get(RegulatoryUpdate, upd)
        assert row is not None
        assert row.status == "assessing", "the owning org's own write must land"

    async with session_scope() as s:
        await set_session_tenant(s, None)
        await ui_grc.regulatory_update(
            upd, _req(outsider), applicability="not_applicable",
            status="closed", owner="them", session=s,
        )

    async with session_scope() as s:
        await set_session_tenant(s, None)
        row = await s.get(RegulatoryUpdate, upd)
        assert row is not None
        assert row.status == "assessing", "another tenant rewrote this regulatory update"
        assert row.applicability == "applicable"
        assert row.owner == "me"

    # A global principal still writes.
    async with session_scope() as s:
        await set_session_tenant(s, None)
        await ui_grc.regulatory_update(
            upd, _req(None), applicability="", status="closed", owner="", session=s
        )
    async with session_scope() as s:
        await set_session_tenant(s, None)
        row = await s.get(RegulatoryUpdate, upd)
        assert row is not None and row.status == "closed"


# --- Connector registry -----------------------------------------------------


async def _connector(org_id: int, name: str) -> int:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        c = ConnectorConfig(
            organization_id=org_id, name=name, connector_type="aws",
            status="pending", objects_discovered=0,
        )
        s.add(c)
        await s.flush()
        return c.id


@pytest.mark.asyncio
async def test_connectors_sync_is_scoped(orgs: list[int]) -> None:
    """Its sibling ``connector_detail`` is scoped; this one took no principal.

    The mock writes exactly the four columns ``connector_backing_state`` reads,
    so a foreign ``cfg_id`` manufactures an "evidenced by automated capture"
    posture in someone else's tenant.
    """
    tag = _tag()
    owner = await _org(orgs, f"UIGRC Conn Owner {tag}")
    outsider = await _org(orgs, f"UIGRC Conn Outsider {tag}")
    cfg = await _connector(owner, f"Conn {tag}")

    async with session_scope() as s:
        await set_session_tenant(s, None)
        assert (await ui_grc.connectors_sync(cfg, _req(owner), s)).status_code == 303
    async with session_scope() as s:
        await set_session_tenant(s, None)
        row = await s.get(ConnectorConfig, cfg)
        assert row is not None and row.status == "configured"
        # Reset, so the outsider's attempt is measured from a known state.
        row.status = "pending"
        row.last_sync = None
        row.objects_discovered = 0

    async with session_scope() as s:
        await set_session_tenant(s, None)
        assert (await ui_grc.connectors_sync(cfg, _req(outsider), s)).status_code == 303
    async with session_scope() as s:
        await set_session_tenant(s, None)
        row = await s.get(ConnectorConfig, cfg)
        assert row is not None
        assert row.status == "pending", "another tenant ran the capture mock on this connector"
        assert row.last_sync is None
        assert row.objects_discovered == 0

    async with session_scope() as s:
        await set_session_tenant(s, None)
        assert (await ui_grc.connectors_sync(cfg, _req(None), s)).status_code == 303
    async with session_scope() as s:
        await set_session_tenant(s, None)
        row = await s.get(ConnectorConfig, cfg)
        assert row is not None and row.status == "configured", "global principal must still sync"


@pytest.mark.asyncio
async def test_connectors_sync_is_disabled_outside_dev(
    orgs: list[int], production_env: None
) -> None:
    """``0eadea4`` gated ``grc.sync_connector`` and missed this twin, so the
    mock kept writing the capture columns in every environment.

    ``tests/conftest.py`` sets ``CCF_ENV=test``, which ``is_dev_env`` counts as
    a development environment -- so this needs ``production_env`` explicitly, or
    it would pass with no gate present at all.
    """
    tag = _tag()
    owner = await _org(orgs, f"UIGRC Conn Prod {tag}")
    cfg = await _connector(owner, f"Conn Prod {tag}")
    async with session_scope() as s:
        await set_session_tenant(s, None)
        with pytest.raises(HTTPException) as err:
            await ui_grc.connectors_sync(cfg, _req(owner), s)
        assert err.value.status_code == 503
        assert "development-only mock" in str(err.value.detail)
    async with session_scope() as s:
        await set_session_tenant(s, None)
        row = await s.get(ConnectorConfig, cfg)
        assert row is not None and row.status == "pending"


# --- Vendor questionnaires --------------------------------------------------


async def _questionnaire(org_id: int, tag: str) -> tuple[int, int]:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        v = Vendor(organization_id=org_id, name=f"Vendor {tag}")
        s.add(v)
        await s.flush()
        q = VendorQuestionnaire(
            organization_id=org_id, vendor_id=v.id, template_key="default",
            name=f"Questionnaire {tag}", status="sent", sent_on=datetime.now(UTC).date(),
        )
        s.add(q)
        await s.flush()
        r = QuestionnaireResponse(
            questionnaire_id=q.id, question_id="Q1", question_text="MFA everywhere?",
            weight=3, answer="unanswered", sort_order=0,
        )
        s.add(r)
        await s.flush()
        return q.id, r.id


@pytest.mark.asyncio
async def test_questionnaire_detail_is_scoped(orgs: list[int]) -> None:
    """``questionnaire_export`` already carried this predicate on the same row."""
    tag = _tag()
    owner = await _org(orgs, f"UIGRC Q Owner {tag}")
    outsider = await _org(orgs, f"UIGRC Q Outsider {tag}")
    qid, _ = await _questionnaire(owner, tag)

    async with session_scope() as s:
        await set_session_tenant(s, None)
        assert (await ui_grc.questionnaire_detail(qid, _req(owner), s)).status_code == 200
        with pytest.raises(HTTPException) as err:
            await ui_grc.questionnaire_detail(qid, _req(outsider), s)
        assert err.value.status_code == 404
        assert (await ui_grc.questionnaire_detail(qid, _req(None), s)).status_code == 200


@pytest.mark.asyncio
async def test_questionnaire_answer_is_scoped(orgs: list[int]) -> None:
    """No principal at all: another tenant's vendor answers could be rewritten,
    and the questionnaire's score with them."""
    tag = _tag()
    owner = await _org(orgs, f"UIGRC QA Owner {tag}")
    outsider = await _org(orgs, f"UIGRC QA Outsider {tag}")
    qid, rid = await _questionnaire(owner, tag)

    async with session_scope() as s:
        await set_session_tenant(s, None)
        assert (
            await ui_grc.questionnaire_answer(
                qid, rid, _req(owner), answer="yes", detail="owner answer", session=s
            )
        ).status_code == 303
    async with session_scope() as s:
        await set_session_tenant(s, None)
        r = await s.get(QuestionnaireResponse, rid)
        assert r is not None and r.answer == "yes"

    async with session_scope() as s:
        await set_session_tenant(s, None)
        await ui_grc.questionnaire_answer(
            qid, rid, _req(outsider), answer="no", detail="injected", session=s
        )
    async with session_scope() as s:
        await set_session_tenant(s, None)
        r = await s.get(QuestionnaireResponse, rid)
        assert r is not None
        assert r.answer == "yes", "another tenant rewrote this vendor answer"
        assert r.detail == "owner answer"

    async with session_scope() as s:
        await set_session_tenant(s, None)
        await ui_grc.questionnaire_answer(
            qid, rid, _req(None), answer="partial", detail="global", session=s
        )
    async with session_scope() as s:
        await set_session_tenant(s, None)
        r = await s.get(QuestionnaireResponse, rid)
        assert r is not None and r.answer == "partial", "global principal must still answer"


@pytest.mark.asyncio
async def test_questionnaire_review_is_scoped(orgs: list[int]) -> None:
    """Not on the reported list, and the most consequential of the three: it
    writes ``risk_rating`` onto the **vendor** and marks the questionnaire
    reviewed under the caller's name."""
    tag = _tag()
    owner = await _org(orgs, f"UIGRC QR Owner {tag}")
    outsider = await _org(orgs, f"UIGRC QR Outsider {tag}")
    qid, _ = await _questionnaire(owner, tag)

    async with session_scope() as s:
        await set_session_tenant(s, None)
        with pytest.raises(HTTPException) as err:
            await ui_grc.questionnaire_review(qid, _req(outsider), open_tasks="", session=s)
        assert err.value.status_code == 404

    async with session_scope() as s:
        await set_session_tenant(s, None)
        q = await s.get(VendorQuestionnaire, qid)
        assert q is not None and q.status == "sent", "another tenant reviewed this questionnaire"

    async with session_scope() as s:
        await set_session_tenant(s, None)
        assert (
            await ui_grc.questionnaire_review(qid, _req(owner), open_tasks="", session=s)
        ).status_code == 303
    async with session_scope() as s:
        await set_session_tenant(s, None)
        q = await s.get(VendorQuestionnaire, qid)
        assert q is not None and q.status == "reviewed"


@pytest.mark.asyncio
async def test_questionnaire_routes_over_http(orgs: list[int], auth_enabled: None) -> None:
    tag = _tag()
    owner = await _org(orgs, f"UIGRC HTTP Q Owner {tag}")
    outsider = await _org(orgs, f"UIGRC HTTP Q Outsider {tag}")
    qid, rid = await _questionnaire(owner, tag)
    owner_token = await _admin(owner, tag, "qowner")
    outsider_token = await _admin(outsider, tag, "qoutsider")

    async with _client() as c:
        assert (
            await c.get(f"/vendor-questionnaires/{qid}", headers=_auth(owner_token))
        ).status_code == 200
        assert (
            await c.get(f"/vendor-questionnaires/{qid}", headers=_auth(outsider_token))
        ).status_code == 404
        r = await c.post(
            f"/vendor-questionnaires/{qid}/responses/{rid}",
            data={"answer": "no", "detail": "http injected"},
            headers=_auth(outsider_token),
        )
        assert r.status_code in (303, 404), r.text[:200]

    async with session_scope() as s:
        await set_session_tenant(s, None)
        row = await s.get(QuestionnaireResponse, rid)
        assert row is not None and row.answer == "unanswered"
