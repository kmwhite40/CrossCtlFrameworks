"""``generate_statements`` must not silently replace a human-authored narrative.

``ccf.governance.automation.generate_statements`` used to assign
``part_narratives`` for *every* entry of a project, unconditionally. One
``POST /projects/{id}/auto-statements`` therefore replaced a project's worth
of human-written narrative with generated text, reported only a count, and
left nothing to recover from. Locking the route to ``admin`` limited who could
fire it; it did nothing about what it did.

The provenance signal is :func:`ccf.ssp.statements.is_draft_narrative`
(CISO-02): a narrative that still carries ``DRAFT_PREFIX`` has not been cleared
by a human, a narrative without it has. So per entry: nothing there -> generate;
draft-marked -> regenerate; unmarked -> preserve *and name the control* in the
result, the way ``ccf.cr26.sdr`` never drops a part without naming it. An
explicit ``overwrite_authored=True`` replaces authored narratives, and names
every control it did that to, in a separate list.

Two traps this file avoids on purpose. The route tests use a real
role-bearing principal (``tests/test_ssp_api_rbac.py``'s harness), because
``SYSTEM_PRINCIPAL`` is global and ``require_role`` short-circuits for it. And
the "regenerated" assertions check that the fixture text is *gone* rather than
that some expected string is present, so a fixture that happens to contain the
string under assertion cannot make them pass.

Seeded rows are removed in ``finally`` -- the DB is not truncated between
tests, and ``ScoringControl`` is a global catalog every later test sees.
"""

from __future__ import annotations

import inspect
import itertools
import os
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance.automation import generate_ssp, generate_statements
from ccf.models import (
    Organization,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
    User,
)
from ccf.ssp.constants import DRAFT_PREFIX
from ccf.ssp.statements import is_draft_narrative

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()

AUTHORED_A = "Access is provisioned by the ISSO after manager approval."
AUTHORED_B = "Accounts are reviewed quarterly against the HR roster."
#: A human's multi-part narrative: no ``DRAFT_PREFIX`` anywhere, two labelled
#: parts (the generator writes exactly one part labelled "Implementation").
AUTHORED: list[dict[str, str]] = [
    {"label": "Part a", "text": AUTHORED_A},
    {"label": "Part b", "text": AUTHORED_B},
]
DRAFTED_BODY = "machine text awaiting review"
DRAFTED: list[dict[str, str]] = [{"label": "Implementation", "text": DRAFT_PREFIX + DRAFTED_BODY}]

AUTHORED_ID = "AC-2"
DRAFTED_ID = "AC-3"
EMPTY_ID = "AC-6"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _tag() -> str:
    return str(next(_SEQ))


async def _seed(
    entries: dict[str, list[dict[str, str]] | None], *, org_id: int | None = None
) -> tuple[int, int, int]:
    """An org (unless given), a system with an m365 profile, and a project
    carrying one entry per ``entries`` item, stored with exactly that
    ``part_narratives`` value. Returns ``(org_id, system_id, project_id)``."""
    tag = _tag()
    async with session_scope() as s:
        if org_id is None:
            org = Organization(name=f"Preserve Org {tag}")
            s.add(org)
            await s.flush()
            org_id = org.id
        sys_ = System(organization_id=org_id, name=f"Preserve Sys {tag}")
        s.add(sys_)
        await s.flush()
        s.add(SystemProfile(system_id=sys_.id, cloud_platform="m365_gcc_high", derivation={}))
        proj = SSPProject(
            organization_id=org_id, system_id=sys_.id, customer_name="Preserve", platform="m365"
        )
        s.add(proj)
        await s.flush()
        for control_id, narrative in entries.items():
            s.add(
                SSPControlEntry(
                    project_id=proj.id,
                    control_id=control_id,
                    nist_id=control_id,
                    domain="AC",
                    requirement="manage system accounts",
                    part_narratives=narrative,
                )
            )
        await s.flush()
        return org_id, sys_.id, proj.id


async def _cleanup(org_id: int | None, proj_id: int | None) -> None:
    async with session_scope() as s:
        if proj_id is not None:
            await s.execute(delete(SSPProject).where(SSPProject.id == proj_id))
        if org_id is not None:
            await s.execute(delete(Organization).where(Organization.id == org_id))


async def _run(proj_id: int, sys_id: int, **kw: Any) -> dict[str, Any]:
    async with session_scope() as s:
        proj = await s.get(SSPProject, proj_id)
        assert proj is not None
        profile = (
            await s.execute(select(SystemProfile).where(SystemProfile.system_id == sys_id))
        ).scalar_one()
        return await generate_statements(s, project=proj, profile=profile, **kw)


async def _narratives(proj_id: int) -> dict[str, list[dict[str, str]] | None]:
    """What is actually stored, read back in a fresh session."""
    async with session_scope() as s:
        rows = (
            (await s.execute(select(SSPControlEntry).where(SSPControlEntry.project_id == proj_id)))
            .scalars()
            .all()
        )
        return {r.control_id: r.part_narratives for r in rows}


def _text(parts: list[dict[str, str]] | None) -> str:
    return " ".join((p or {}).get("text") or "" for p in parts or [])


# --- the defect, in the failing direction ------------------------------------


async def test_authored_narrative_survives_and_is_named() -> None:
    """A human's unmarked, multi-part narrative comes through byte for byte,
    and its control id is in ``preserved_authored`` so the operator can see
    what the generator declined to touch. Before the fix the narrative was
    replaced by one generated ``[DRAFT]`` part and the result said nothing."""
    org_id = proj_id = None
    try:
        org_id, sys_id, proj_id = await _seed({AUTHORED_ID: AUTHORED, EMPTY_ID: []})
        out = await _run(proj_id, sys_id)
        stored = await _narratives(proj_id)
        assert stored[AUTHORED_ID] == AUTHORED, stored[AUTHORED_ID]
        assert out["preserved_authored"] == [AUTHORED_ID], out
        assert out["replaced_authored"] == [], out
        # The generator did run -- the empty sibling was filled -- so the
        # authored one survived by decision, not because nothing happened.
        assert _text(stored[EMPTY_ID]).strip(), stored[EMPTY_ID]
    finally:
        await _cleanup(org_id, proj_id)


async def test_overwrite_authored_is_keyword_only_and_off_by_default() -> None:
    p = inspect.signature(generate_statements).parameters["overwrite_authored"]
    assert p.kind is inspect.Parameter.KEYWORD_ONLY
    assert p.default is False


# --- the endpoint still does its job ------------------------------------------


async def test_draft_marked_narrative_is_regenerated() -> None:
    """Machine text is exactly what the endpoint exists to regenerate."""
    org_id = proj_id = None
    try:
        org_id, sys_id, proj_id = await _seed({DRAFTED_ID: DRAFTED})
        out = await _run(proj_id, sys_id)
        stored = await _narratives(proj_id)
        assert stored[DRAFTED_ID] != DRAFTED
        assert DRAFTED_BODY not in _text(stored[DRAFTED_ID])
        assert _text(stored[DRAFTED_ID]).strip()
        assert out["preserved_authored"] == [], out
        # Regenerating a draft is not "replacing authored content".
        assert out["replaced_authored"] == [], out
    finally:
        await _cleanup(org_id, proj_id)


@pytest.mark.parametrize(
    "empty",
    [[], None, [{"label": "Implementation", "text": ""}], [{"label": "a", "text": "   "}]],
    ids=["empty-list", "none", "blank-text", "whitespace-only"],
)
async def test_empty_entry_is_populated(empty: list[dict[str, str]] | None) -> None:
    org_id = proj_id = None
    try:
        org_id, sys_id, proj_id = await _seed({EMPTY_ID: empty})
        out = await _run(proj_id, sys_id)
        stored = await _narratives(proj_id)
        assert _text(stored[EMPTY_ID]).strip(), stored[EMPTY_ID]
        assert out["preserved_authored"] == [], out
        assert out["replaced_authored"] == [], out
    finally:
        await _cleanup(org_id, proj_id)


# --- the explicit override, and it is not silent either ----------------------


async def test_overwrite_authored_replaces_and_names_the_control() -> None:
    """``overwrite_authored=True`` replaces the human narrative and names its
    control in ``replaced_authored`` -- only that control: the draft and the
    empty siblings were regenerated/populated, not "replaced authored"."""
    org_id = proj_id = None
    try:
        org_id, sys_id, proj_id = await _seed(
            {AUTHORED_ID: AUTHORED, DRAFTED_ID: DRAFTED, EMPTY_ID: []}
        )
        out = await _run(proj_id, sys_id, overwrite_authored=True)
        stored = await _narratives(proj_id)
        assert stored[AUTHORED_ID] != AUTHORED
        assert AUTHORED_A not in _text(stored[AUTHORED_ID])
        assert AUTHORED_B not in _text(stored[AUTHORED_ID])
        assert out["replaced_authored"] == [AUTHORED_ID], out
        assert out["preserved_authored"] == [], out
    finally:
        await _cleanup(org_id, proj_id)


# --- the sibling: generate_ssp on a project it just created ------------------


async def test_generate_ssp_still_fills_every_entry() -> None:
    """``generate_ssp`` seeds the project, then composes every statement.

    The seeder (``ssp.seed._narratives``) writes sample text into every new
    entry, and ``sample_statement`` writes it WITHOUT ``DRAFT_PREFIX`` -- so a
    control fully inherited on the platform (m365 "Microsoft Coverage", no
    customer lead-in) looks, to ``is_draft_narrative``, exactly like a human
    narrative. A fresh project has no human in it, so ``generate_ssp`` must
    still compose that entry. The PE control here is that case.
    """
    prefix = f"P{_tag()}"
    ac_id, pe_id = f"AC.{prefix}-3.1.1", f"PE.{prefix}-3.10.1"
    org_id = proj_id = None
    try:
        async with session_scope() as s:
            s.add_all(
                [
                    ScoringControl(
                        control_id=ac_id,
                        nist_id=f"AC-{prefix}-1",
                        domain="AC",
                        title="Access Control",
                        point_value="5",
                        requirement="limit system access to authorized users",
                        m365_coverage_status="Customer Responsibility",
                        sort_order=1,
                    ),
                    ScoringControl(
                        control_id=pe_id,
                        nist_id=f"PE-{prefix}-1",
                        domain="PE",
                        title="Physical Access",
                        point_value="1",
                        requirement="limit physical access to organizational systems",
                        m365_coverage_status="Microsoft Coverage",
                        sort_order=2,
                    ),
                ]
            )
            org = Organization(name=f"Preserve SSP Org {prefix}")
            s.add(org)
            await s.flush()
            org_id = org.id
            sys_ = System(organization_id=org.id, name=f"Preserve SSP Sys {prefix}")
            s.add(sys_)
            await s.flush()
            profile = SystemProfile(
                system_id=sys_.id, environment_type="cloud", cloud_platform="m365_gcc_high"
            )
            s.add(profile)
            await s.flush()
            proj_id = await generate_ssp(s, system=sys_, profile=profile)
        stored = await _narratives(proj_id)
        assert ac_id in stored and pe_id in stored
        for control_id, parts in stored.items():
            # The composed form: one "Implementation" part with text. The seed
            # form has objective/"Customer Responsibility" labels instead.
            assert parts is not None and len(parts) == 1, (control_id, parts)
            assert parts[0]["label"] == "Implementation", (control_id, parts)
            assert (parts[0].get("text") or "").strip(), (control_id, parts)
        # Not a fixture artefact: the composed statement for a customer control
        # on an uncaptured tenant is draft-marked, which the seed lead-in also
        # is -- so assert the property that distinguishes them: the seed's
        # unmarked PE sample is gone.
        assert "The organization satisfies this objective" not in _text(stored[pe_id])
        assert is_draft_narrative(stored[ac_id])
    finally:
        async with session_scope() as s:
            await s.execute(
                delete(ScoringControl).where(ScoringControl.control_id.in_([ac_id, pe_id]))
            )
        await _cleanup(org_id, proj_id)


# --- the route: flag and lists cross the HTTP boundary; the gate holds -------


@pytest.fixture
def _auth_enabled() -> Any:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _mk_user(role: str) -> tuple[str, int]:
    """An org + a real, non-global user with ``role``. Returns ``(token, org_id)``."""
    tag = _tag()
    async with session_scope() as s:
        org = Organization(name=f"Preserve Route Org {tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"{role}-{tag}@preserve.test",
            organization_id=org.id,
            role=role,
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token, org.id


@pytest.mark.usefixtures("_auth_enabled")
async def test_route_exposes_the_flag_and_both_lists() -> None:
    """Both lists reach the client, and the query flag reaches the generator.
    Asserted on list *contents*: a route that dropped either field would
    otherwise pass every other test in the suite."""
    org_id = proj_id = None
    try:
        token, org_id = await _mk_user("admin")
        _, _sys_id, proj_id = await _seed(
            {AUTHORED_ID: AUTHORED, DRAFTED_ID: DRAFTED, EMPTY_ID: []}, org_id=org_id
        )
        async with _client() as c:
            resp = await c.post(
                f"/api/ssp/projects/{proj_id}/auto-statements", headers=_auth(token)
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["preserved_authored"] == [AUTHORED_ID], body
            assert body["replaced_authored"] == [], body
            assert (await _narratives(proj_id))[AUTHORED_ID] == AUTHORED

            resp = await c.post(
                f"/api/ssp/projects/{proj_id}/auto-statements",
                params={"overwrite_authored": "true"},
                headers=_auth(token),
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["replaced_authored"] == [AUTHORED_ID], body
            assert body["preserved_authored"] == [], body
            stored = await _narratives(proj_id)
            assert stored[AUTHORED_ID] != AUTHORED
            assert AUTHORED_A not in _text(stored[AUTHORED_ID])
    finally:
        await _cleanup(org_id, proj_id)


@pytest.mark.usefixtures("_auth_enabled")
@pytest.mark.parametrize("role", ["control_owner", "viewer"])
@pytest.mark.parametrize(
    "params", [{}, {"overwrite_authored": "true"}], ids=["default", "overwrite"]
)
async def test_route_stays_admin_only(role: str, params: dict[str, str]) -> None:
    """The gate from ``fix/authz-write-gating`` holds, with and without the
    new flag -- the flag is not a bypass. Asserted on the stored row too."""
    org_id = proj_id = None
    try:
        token, org_id = await _mk_user(role)
        _, _sys_id, proj_id = await _seed({AUTHORED_ID: AUTHORED, EMPTY_ID: []}, org_id=org_id)
        async with _client() as c:
            resp = await c.post(
                f"/api/ssp/projects/{proj_id}/auto-statements", params=params, headers=_auth(token)
            )
            assert resp.status_code == 403, resp.text
        stored = await _narratives(proj_id)
        assert stored[AUTHORED_ID] == AUTHORED
        assert stored[EMPTY_ID] == []
    finally:
        await _cleanup(org_id, proj_id)
