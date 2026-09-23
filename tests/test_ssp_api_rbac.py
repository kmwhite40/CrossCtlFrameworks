"""SSP authoring API under real auth: who may write, who may only read.

Until this file, not one route in ``api/routes/ssp.py`` called
``require_role``. Every one of them -- ``POST /projects``, ``PATCH``,
``DELETE``, ``PUT .../entries/{control_id}``, ``/reseed``,
``/auto-statements`` -- depended only on ``get_principal``, i.e. "authenticated
and in this org". ``_require_project`` scopes by organization, but tenancy is
not authority: a ``viewer`` could delete another person's SSP project outright
and rewrite every control narrative in it. Read authority and write authority
were the same thing across the whole editing surface.

The trap this file exists to avoid: the repo's other SSP tests run with auth
disabled, as ``SYSTEM_PRINCIPAL`` (``org_id=None``, ``is_global=True``), and
``require_role`` returns early for a global principal. A test written that way
passes with or without the gate and proves nothing about it. Every test here
therefore uses a real, non-global, role-bearing principal with its own bearer
token, mirroring ``tests/test_waivers_api_rbac.py`` and
``tests/test_audit_rbac.py`` (module autouse ``_auth_enabled`` fixture,
``_client()``, ``_mk_user``, ``_auth``) -- unique org/email names per test,
since the DB is not truncated between tests.

Both directions are covered on purpose. A gate that refuses everybody is not a
fix, so ``control_owner`` editing a control entry is exercised end to end, and
``viewer``/``assessor`` reads are asserted to still work: locking readers out
of an SSP would be a worse defect than the one being closed.
"""

from __future__ import annotations

import itertools
import os
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, SSPControlEntry, SSPProject, User

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()

CONTROL_ID = "AC.L2-3.1.1"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _tag() -> str:
    return str(next(_SEQ))


async def _mk_user(email: str, org_name: str, role: str) -> tuple[str, int]:
    """An org + a user with the given role. Returns ``(bearer_token, org_id)``."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=email,
            organization_id=org.id,
            role=role,
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token, org.id


async def _project(org_id: int) -> int:
    """A project with one control entry, built directly.

    Not through ``POST /projects`` on purpose: that route is itself one of the
    gated ones, and the seeding it runs depends on catalog reference data this
    test does not load.
    """
    async with session_scope() as s:
        proj = SSPProject(organization_id=org_id, customer_name="RBAC Cust", platform="m365")
        s.add(proj)
        await s.flush()
        s.add(
            SSPControlEntry(
                project_id=proj.id,
                control_id=CONTROL_ID,
                nist_id="3.1.1",
                odp_values={},
                part_narratives=[{"label": "Implementation", "text": "authored by a human"}],
            )
        )
        await s.flush()
        return proj.id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _call(c: AsyncClient, spec: dict[str, Any], proj_id: int, token: str) -> Any:
    path = spec["path"].format(proj=proj_id, control=CONTROL_ID)
    return await c.request(
        spec["method"],
        path,
        json=spec.get("json"),
        params=spec.get("params"),
        headers=_auth(token),
    )


#: Writes any authoring role may perform: ``admin`` and ``control_owner``.
#: Each entry is a real, well-formed request -- the point is that the role gate
#: refuses it, not that the payload is rejected first.
AUTHOR_WRITES: list[dict[str, Any]] = [
    {"id": "create_project", "method": "POST", "path": "/api/ssp/projects",
     "json": {"customer_name": "RBAC New Co"}},
    {"id": "update_project", "method": "PATCH", "path": "/api/ssp/projects/{proj}",
     "json": {"title": "Renamed"}},
    {"id": "set_metadata", "method": "PUT", "path": "/api/ssp/projects/{proj}/metadata",
     "json": {"metadata_json": {"system_type": "Cloud"}, "autofill": False}},
    {"id": "add_revision", "method": "POST", "path": "/api/ssp/projects/{proj}/revisions",
     "json": {"version": "1.1"}},
    {"id": "update_entry", "method": "PUT",
     "path": "/api/ssp/projects/{proj}/entries/{control}",
     "json": {"responsible_role": "System Administrator"}},
    {"id": "apply_template", "method": "POST",
     "path": "/api/ssp/projects/{proj}/entries/{control}/apply-template",
     "json": {"template_key": "any-template", "replace": True}},
    {"id": "autofill", "method": "POST", "path": "/api/ssp/projects/{proj}/autofill",
     "params": {"connector": "msgraph", "apply": "true"}},
    {"id": "verify_connector", "method": "POST", "path": "/api/ssp/connectors/msgraph/verify"},
]

#: Writes reserved to ``admin``: they destroy or wholesale replace content a
#: human authored, rather than editing it.
ADMIN_ONLY_WRITES: list[dict[str, Any]] = [
    {"id": "delete_project", "method": "DELETE", "path": "/api/ssp/projects/{proj}"},
    {"id": "reseed_project", "method": "POST", "path": "/api/ssp/projects/{proj}/reseed"},
    {"id": "auto_statements", "method": "POST",
     "path": "/api/ssp/projects/{proj}/auto-statements"},
]

ALL_WRITES = AUTHOR_WRITES + ADMIN_ONLY_WRITES

_IDS = [w["id"] for w in ALL_WRITES]
_AUTHOR_IDS = [w["id"] for w in AUTHOR_WRITES]
_ADMIN_IDS = [w["id"] for w in ADMIN_ONLY_WRITES]


# --- failing direction: read-only roles are refused every write ---------------


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "assessor"])
@pytest.mark.parametrize("spec", ALL_WRITES, ids=_IDS)
async def test_read_only_roles_cannot_write(role: str, spec: dict[str, Any]) -> None:
    """``viewer`` and ``assessor`` are read-only on SSP -- that is the point of
    both roles. Before the gate, every one of these returned 2xx."""
    tag = _tag()
    token, org_id = await _mk_user(
        f"{role}-{tag}@ssp-rbac.test", f"SSP RBAC {role} Org {tag}", role
    )
    proj_id = await _project(org_id)
    async with _client() as c:
        resp = await _call(c, spec, proj_id, token)
        assert resp.status_code == 403, f"{spec['id']} as {role}: {resp.status_code} {resp.text}"


@pytest.mark.asyncio
@pytest.mark.parametrize("spec", ADMIN_ONLY_WRITES, ids=_ADMIN_IDS)
async def test_control_owner_cannot_destroy_or_replace(spec: dict[str, Any]) -> None:
    """Deleting a project, reseeding it, and recomposing every statement all
    can discard human-authored narrative wholesale -- ``auto_statements`` does
    so on ``overwrite_authored=true``, irreversibly (it preserves and names
    authored narratives by default; see ``tests/test_auto_statements_preserve.py``)
    -- so they sit with delete rather than with ordinary editing."""
    tag = _tag()
    token, org_id = await _mk_user(
        f"co-destroy-{tag}@ssp-rbac.test", f"SSP RBAC CO Destroy Org {tag}", "control_owner"
    )
    proj_id = await _project(org_id)
    async with _client() as c:
        resp = await _call(c, spec, proj_id, token)
        assert resp.status_code == 403, f"{spec['id']}: {resp.status_code} {resp.text}"


@pytest.mark.asyncio
async def test_a_viewer_cannot_delete_a_project_and_it_survives() -> None:
    """The headline case, asserted on the stored row rather than the status
    code alone: before the gate this returned 204 and the project was gone."""
    tag = _tag()
    v_token, org_id = await _mk_user(
        f"vdel-{tag}@ssp-rbac.test", f"SSP RBAC ViewerDelete Org {tag}", "viewer"
    )
    proj_id = await _project(org_id)
    async with _client() as c:
        resp = await c.delete(f"/api/ssp/projects/{proj_id}", headers=_auth(v_token))
        assert resp.status_code == 403, resp.text
        # Still readable by its own org's viewer -- nothing was deleted.
        still = await c.get(f"/api/ssp/projects/{proj_id}", headers=_auth(v_token))
        assert still.status_code == 200, still.text


@pytest.mark.asyncio
async def test_a_viewer_cannot_rewrite_a_control_narrative() -> None:
    """The stored narrative is unchanged, not merely the response refused."""
    tag = _tag()
    token, org_id = await _mk_user(
        f"vedit-{tag}@ssp-rbac.test", f"SSP RBAC ViewerEdit Org {tag}", "viewer"
    )
    proj_id = await _project(org_id)
    async with _client() as c:
        resp = await c.put(
            f"/api/ssp/projects/{proj_id}/entries/{CONTROL_ID}",
            json={"part_narratives": [{"label": "Implementation", "text": "overwritten"}]},
            headers=_auth(token),
        )
        assert resp.status_code == 403, resp.text
        got = await c.get(f"/api/ssp/projects/{proj_id}", headers=_auth(token))
        entry = next(e for e in got.json()["entries"] if e["control_id"] == CONTROL_ID)
        assert entry["part_narratives"] == [
            {"label": "Implementation", "text": "authored by a human"}
        ]


# --- passing direction: the roles that should write still can -----------------


@pytest.mark.asyncio
async def test_control_owner_can_edit_a_control_entry_end_to_end() -> None:
    """The primary authoring workflow, start to finish, as a real
    ``control_owner``: write the narrative, read it back changed."""
    tag = _tag()
    token, org_id = await _mk_user(
        f"co-edit-{tag}@ssp-rbac.test", f"SSP RBAC CO Edit Org {tag}", "control_owner"
    )
    proj_id = await _project(org_id)
    async with _client() as c:
        resp = await c.put(
            f"/api/ssp/projects/{proj_id}/entries/{CONTROL_ID}",
            json={
                "responsible_role": "System Administrator",
                "implementation_status": ["Implemented"],
                "part_narratives": [{"label": "Implementation", "text": "MFA is enforced."}],
            },
            headers=_auth(token),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["responsible_role"] == "System Administrator"

        got = await c.get(f"/api/ssp/projects/{proj_id}", headers=_auth(token))
        entry = next(e for e in got.json()["entries"] if e["control_id"] == CONTROL_ID)
        assert entry["part_narratives"] == [
            {"label": "Implementation", "text": "MFA is enforced."}
        ]
        assert entry["implementation_status"] == ["Implemented"]


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["admin", "control_owner"])
@pytest.mark.parametrize("spec", AUTHOR_WRITES, ids=_AUTHOR_IDS)
async def test_authoring_roles_are_not_locked_out(role: str, spec: dict[str, Any]) -> None:
    """Every authoring write reaches its handler for both allowed roles.

    Asserted as "not 403" plus a 2xx/404 whitelist rather than one exact code:
    ``apply_template`` 404s on a template this fixture does not create, and
    that 404 comes from the handler -- which is exactly the proof wanted here,
    that the gate passed the caller through.
    """
    tag = _tag()
    token, org_id = await _mk_user(
        f"{role}-ok-{tag}@ssp-rbac.test", f"SSP RBAC {role} OK Org {tag}", role
    )
    proj_id = await _project(org_id)
    async with _client() as c:
        resp = await _call(c, spec, proj_id, token)
        assert resp.status_code != 403, f"{spec['id']} as {role}: {resp.text}"
        assert resp.status_code in (200, 201, 404), f"{spec['id']} as {role}: {resp.text}"


@pytest.mark.asyncio
@pytest.mark.parametrize("spec", ADMIN_ONLY_WRITES, ids=_ADMIN_IDS)
async def test_admin_still_holds_the_destructive_writes(spec: dict[str, Any]) -> None:
    """``auto_statements`` 400s for want of a system profile; that refusal is
    the handler's, which is the point -- the gate let the admin through."""
    tag = _tag()
    token, org_id = await _mk_user(
        f"admin-destroy-{tag}@ssp-rbac.test", f"SSP RBAC Admin Destroy Org {tag}", "admin"
    )
    proj_id = await _project(org_id)
    async with _client() as c:
        resp = await _call(c, spec, proj_id, token)
        assert resp.status_code != 403, f"{spec['id']}: {resp.text}"
        assert resp.status_code in (200, 204, 400), f"{spec['id']}: {resp.text}"


@pytest.mark.asyncio
async def test_admin_can_actually_delete() -> None:
    tag = _tag()
    token, org_id = await _mk_user(
        f"admin-del-{tag}@ssp-rbac.test", f"SSP RBAC Admin Delete Org {tag}", "admin"
    )
    proj_id = await _project(org_id)
    async with _client() as c:
        resp = await c.delete(f"/api/ssp/projects/{proj_id}", headers=_auth(token))
        assert resp.status_code == 204, resp.text
        gone = await c.get(f"/api/ssp/projects/{proj_id}", headers=_auth(token))
        assert gone.status_code == 404


# --- reads stay open to everyone in the org -----------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "assessor", "control_owner", "admin"])
async def test_every_role_can_still_read(role: str) -> None:
    """A fix that locked readers out of an SSP would be worse than the defect.

    ``assessor`` in particular exists to read a system's control statements;
    ``viewer`` is the organization's read seat.
    """
    tag = _tag()
    token, org_id = await _mk_user(
        f"{role}-read-{tag}@ssp-rbac.test", f"SSP RBAC {role} Read Org {tag}", role
    )
    proj_id = await _project(org_id)
    async with _client() as c:
        listed = await c.get("/api/ssp/projects", headers=_auth(token))
        assert listed.status_code == 200, listed.text
        assert any(p["id"] == proj_id for p in listed.json())

        got = await c.get(f"/api/ssp/projects/{proj_id}", headers=_auth(token))
        assert got.status_code == 200, got.text
        assert any(e["control_id"] == CONTROL_ID for e in got.json()["entries"])

        assert (await c.get("/api/ssp/options", headers=_auth(token))).status_code == 200
        completeness = await c.get(
            f"/api/ssp/projects/{proj_id}/completeness", headers=_auth(token)
        )
        assert completeness.status_code == 200, completeness.text


# --- 403 vs 404: the gate must not start leaking cross-tenant existence -------


@pytest.mark.asyncio
async def test_another_tenants_project_is_still_404_not_403() -> None:
    """The distinction this repo already draws (``test_waivers_api_rbac.py``'s
    ``test_cross_tenant_waiver_is_not_found``): wrong role on a resource you
    can see is 403; a resource in another tenant is 404, because confirming an
    id exists elsewhere is itself a disclosure. An outsider who *does* hold the
    role must therefore still get 404, not 403."""
    tag = _tag()
    _owner_token, org_a = await _mk_user(
        f"owner-{tag}@ssp-rbac.test", f"SSP RBAC CrossTenant OrgA {tag}", "admin"
    )
    outsider_token, _org_b = await _mk_user(
        f"outsider-{tag}@ssp-rbac.test", f"SSP RBAC CrossTenant OrgB {tag}", "admin"
    )
    proj_id = await _project(org_a)
    async with _client() as c:
        for spec in ALL_WRITES:
            if "{proj}" not in spec["path"]:
                continue  # not addressed by project id (create, connector verify)
            resp = await _call(c, spec, proj_id, outsider_token)
            assert resp.status_code == 404, (
                f"{spec['id']} cross-tenant returned {resp.status_code}: {resp.text}"
            )


@pytest.mark.asyncio
async def test_require_project_org_check_rejects_a_foreign_principal_without_rls() -> None:
    """``_require_project``'s OWN org predicate, exercised at its own layer.

    ``test_another_tenants_project_is_still_404_not_403`` above asserts the
    right end-to-end result, but it cannot fail when only the explicit
    predicate is removed: ``ccf.ssp_projects`` carries a ``tenant_isolation``
    RLS policy and ``ccf.api.deps.get_session`` binds the RLS tenant from the
    principal, so the outsider's request 404s at the query before
    ``_require_project``'s own check is reached (confirmed by mutation --
    deleting the predicate left that test passing).

    RLS is documented in ``ccf.api.deps.get_session`` as a backstop *beneath*
    the app-layer scoping, and the unscoped ``session_scope()`` the CLI and
    scheduler use bypasses it by design, so the predicate is pinned here where
    it is the only defense. The owning org is asserted first, so the 404 is
    provably the org check and not the row being unreachable.
    """
    from fastapi import HTTPException  # noqa: PLC0415

    from ccf.api.routes.ssp import _require_project  # noqa: PLC0415
    from ccf.auth import Principal  # noqa: PLC0415

    tag = _tag()
    _owner_token, org_a = await _mk_user(
        f"owner-layer-{tag}@ssp-rbac.test", f"SSP RBAC Layer OrgA {tag}", "admin"
    )
    _outsider_token, org_b = await _mk_user(
        f"outsider-layer-{tag}@ssp-rbac.test", f"SSP RBAC Layer OrgB {tag}", "admin"
    )
    proj_id = await _project(org_a)

    async with session_scope() as s:  # unscoped: RLS is not filtering here
        owner = Principal(
            user_id=None, email=f"owner-layer-{tag}@ssp-rbac.test", org_id=org_a, role="admin"
        )
        found = await _require_project(s, proj_id, owner)
        assert found.id == proj_id  # the owning org is not locked out

        outsider = Principal(
            user_id=None, email=f"outsider-layer-{tag}@ssp-rbac.test", org_id=org_b, role="admin"
        )
        with pytest.raises(HTTPException) as exc:
            await _require_project(s, proj_id, outsider)
        assert exc.value.status_code == 404  # 404, not 403 -- no id disclosure


@pytest.mark.asyncio
async def test_a_read_only_outsider_learns_nothing_from_the_status_code() -> None:
    """A refused role gets the same 403 for a real foreign project and for an
    id that does not exist at all, so the gate is not an existence oracle in
    the other direction either."""
    tag = _tag()
    _owner_token, org_a = await _mk_user(
        f"owner2-{tag}@ssp-rbac.test", f"SSP RBAC Oracle OrgA {tag}", "admin"
    )
    viewer_token, _org_b = await _mk_user(
        f"viewer-oracle-{tag}@ssp-rbac.test", f"SSP RBAC Oracle OrgB {tag}", "viewer"
    )
    real_id = await _project(org_a)
    async with _client() as c:
        real = await c.delete(f"/api/ssp/projects/{real_id}", headers=_auth(viewer_token))
        fake = await c.delete("/api/ssp/projects/98765432", headers=_auth(viewer_token))
        assert real.status_code == fake.status_code == 403, (real.text, fake.text)


# --- unauthenticated is refused ----------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_write_is_refused() -> None:
    async with _client() as c:
        r = await c.post("/api/ssp/projects", json={"customer_name": "Nobody"})
        assert r.status_code == 401
