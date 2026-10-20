"""Policy documents: the template library, rendering, activation behind an
approval of the exact version, attestation by the signed-in person, tenant
scoping, package facts, and the pages.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.api.routes.policies import require_policy
from ccf.auth import Principal, hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, Policy, System, User
from ccf.packages.service import capture_facts
from ccf.policies.library import BY_KEY, TEMPLATES
from ccf.policies.templates import CONTEXT_TOKENS, KINDS

pytestmark = pytest.mark.usefixtures("fresh_engine")

_PLACEHOLDER = re.compile(r"\{\{\s*([a-z0-9_]+)\s*\}\}")
#: Product names the source asserted as fact for every tenant.
_PRODUCTS = re.compile(
    r"microsoft|azure|entra|intune|sentinel|defender|purview|\bpim\b|gcc[- ]high|\bm365\b|"
    r"office 365|sharepoint|onedrive|\bteams\b",
    re.IGNORECASE,
)
#: Statements that something is already in place -- a template states requirements.
_STATUS_CLAIMS = re.compile(
    r"\bimplemented\b|\bis enforced (via|through|by)\b|\bhas been configured\b", re.IGNORECASE
)


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


# ── the library itself ────────────────────────────────────────────────────


def test_the_library_is_complete_and_its_placeholders_are_declared() -> None:
    assert len(TEMPLATES) >= 30
    assert len(BY_KEY) == len(TEMPLATES), "template keys must be unique"
    for t in TEMPLATES:
        assert t.kind in KINDS, t.key
        assert t.controls, t.key
        declared = {p.key for p in t.parameters}
        used: set[str] = set()
        for s in t.sections:
            used |= set(_PLACEHOLDER.findall(s.body))
        assert used - declared <= set(CONTEXT_TOKENS), (t.key, used - declared)
        assert declared <= used, (t.key, "declared but never used", declared - used)


def test_no_template_asserts_a_product_or_an_implementation() -> None:
    for t in TEMPLATES:
        text = " ".join([t.title, t.summary, *(s.heading + " " + s.body for s in t.sections)])
        assert not _PRODUCTS.search(text), (t.key, _PRODUCTS.search(text))
        assert not _STATUS_CLAIMS.search(text), (t.key, _STATUS_CLAIMS.search(text))


# ── helpers ───────────────────────────────────────────────────────────────


async def _org(name: str) -> tuple[int, dict[str, dict[str, str]], dict[str, int]]:
    hdr: dict[str, dict[str, str]] = {}
    ids: dict[str, int] = {}
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        for key, role in (("author", "control_owner"), ("admin", "admin"),
                          ("admin2", "admin"), ("staff", "control_owner")):
            u = User(email=f"{key}@{name.lower()}.example", organization_id=org.id, role=role,
                     active=True, password_hash=hash_password("pw"), api_token=new_api_token())
            s.add(u)
            await s.flush()
            hdr[key] = {"Authorization": f"Bearer {u.api_token}"}
            ids[key] = u.id
        return org.id, hdr, ids


def _template():
    # The template with the most parameters exercises rendering hardest.
    return max(TEMPLATES, key=lambda t: len(t.parameters))


def _all_values(t) -> dict[str, str]:
    return {p.key: f"value-for-{p.key}" for p in t.parameters}


async def _draft(c: AsyncClient, hdr: dict[str, str], **extra) -> dict:
    t = _template()
    r = await c.post("/api/policies/from-template", json={"template_key": t.key, **extra},
                     headers=hdr)
    assert r.status_code == 201, r.text
    return r.json()


async def _filled(c: AsyncClient, hdr: dict[str, str], pid: int, owner: int | None) -> dict:
    r = await c.put(f"/api/policies/{pid}/parameters",
                    json={"parameters": _all_values(_template())}, headers=hdr)
    assert r.status_code == 200, r.text
    if owner is not None:
        async with session_scope() as s:
            p = await s.get(Policy, pid)
            assert p is not None
            p.owner_user_id = owner
        r = await c.put(f"/api/policies/{pid}/parameters",
                        json={"parameters": _all_values(_template())}, headers=hdr)
    return r.json()["version"]


# ── creating and rendering ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_policy_cannot_be_created_already_in_force() -> None:
    async with _client() as c:
        r = await c.post("/api/policies", json={"name": "Shortcut", "status": "active"})
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_a_draft_shows_every_unset_value_and_cannot_be_put_in_force(
    _auth_enabled: None,
) -> None:
    _org_id, hdr, _ids = await _org("PolDocA")
    async with _client() as c:
        d = await _draft(c, hdr["author"])
        v = d["version"]
        assert d["status"] == "draft" and v["version"] == "1.0"
        assert set(v["unresolved_parameters"]) >= {p.key for p in _template().parameters}
        md = await c.get(f"/api/policies/{d['id']}/versions/{v['id']}/document?fmt=md",
                         headers=hdr["author"])
        assert "[ORGANIZATION-DEFINED:" in md.text
        assert "PolDocA" in md.text  # {{organization}} resolved
        r = await c.post(f"/api/policies/{d['id']}/versions/{v['id']}/activate",
                         headers=hdr["admin"])
        assert r.status_code == 409 and "organization-defined" in r.json()["detail"]


@pytest.mark.asyncio
async def test_filling_values_renders_a_new_version_with_nothing_unset(
    _auth_enabled: None,
) -> None:
    _org_id, hdr, ids = await _org("PolDocB")
    async with _client() as c:
        d = await _draft(c, hdr["author"])
        v = await _filled(c, hdr["author"], d["id"], ids["author"])
        assert v["version"] != "1.0"
        assert v["unresolved_parameters"] == []
        doc = await c.get(f"/api/policies/{d['id']}/versions/{v['id']}/document",
                          headers=hdr["author"])
        assert doc.status_code == 200 and doc.content[:2] == b"PK"


# ── activation behind an approval of the exact version ───────────────────


@pytest.mark.asyncio
async def test_activation_needs_an_independent_approval_of_that_version(
    _auth_enabled: None,
) -> None:
    _org_id, hdr, ids = await _org("PolDocC")
    async with _client() as c:
        d = await _draft(c, hdr["author"])
        v = await _filled(c, hdr["author"], d["id"], ids["author"])
        act = f"/api/policies/{d['id']}/versions/{v['id']}/activate"
        assert (await c.post(act, headers=hdr["admin"])).status_code == 409
        await c.post(f"/api/approvals/policy_version/{v['id']}/submit", headers=hdr["admin"])
        # The submitter cannot approve; a non-admin has no authority.
        r = await c.post(f"/api/approvals/policy_version/{v['id']}/approve", headers=hdr["admin"])
        assert r.status_code == 403
        r = await c.post(f"/api/approvals/policy_version/{v['id']}/approve", headers=hdr["staff"])
        assert r.status_code == 403
        r = await c.post(f"/api/approvals/policy_version/{v['id']}/approve", headers=hdr["admin2"])
        assert r.status_code == 200, r.text
        r = await c.post(act, headers=hdr["author"])
        assert r.status_code == 200, r.text
        body = r.json()
    assert body["status"] == "active" and body["active_version_id"] == v["id"]
    assert body["next_review_on"] is not None


@pytest.mark.asyncio
async def test_activation_is_refused_when_the_spend_finds_nothing(
    _auth_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``approvals.consume`` is the gate: one conditional UPDATE. Reading the
    state first and ignoring the spend's answer let two concurrent requests
    both pass on one approval. Staged here: the version reads as approved,
    but another request has already spent it, so the spend returns False."""
    from ccf.governance import approvals  # noqa: PLC0415

    _org_id, hdr, ids = await _org("PolDocRace")
    async with _client() as c:
        d = await _draft(c, hdr["author"])
        v = await _filled(c, hdr["author"], d["id"], ids["author"])
        await c.post(f"/api/approvals/policy_version/{v['id']}/submit", headers=hdr["admin"])
        r = await c.post(f"/api/approvals/policy_version/{v['id']}/approve", headers=hdr["admin2"])
        assert r.status_code == 200, r.text

        async def already_spent(*_a: object, **_k: object) -> bool:
            return False

        monkeypatch.setattr(approvals, "consume", already_spent)
        r = await c.post(
            f"/api/policies/{d['id']}/versions/{v['id']}/activate", headers=hdr["author"]
        )
    assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_an_approval_covers_only_the_version_reviewed(_auth_enabled: None) -> None:
    _org_id, hdr, ids = await _org("PolDocD")
    async with _client() as c:
        d = await _draft(c, hdr["author"])
        v1 = await _filled(c, hdr["author"], d["id"], ids["author"])
        await c.post(f"/api/approvals/policy_version/{v1['id']}/submit", headers=hdr["author"])
        await c.post(f"/api/approvals/policy_version/{v1['id']}/approve", headers=hdr["admin"])
        values = {**_all_values(_template()), _template().parameters[0].key: "changed later"}
        r = await c.put(f"/api/policies/{d['id']}/parameters", json={"parameters": values},
                        headers=hdr["author"])
        v2 = r.json()["version"]
        assert v2["id"] != v1["id"]
        r = await c.post(f"/api/policies/{d['id']}/versions/{v2['id']}/activate",
                         headers=hdr["author"])
        assert r.status_code == 409, r.text


# ── attestation ───────────────────────────────────────────────────────────


async def _in_force(c: AsyncClient, hdr: dict, ids: dict) -> tuple[int, int]:
    d = await _draft(c, hdr["author"])
    v = await _filled(c, hdr["author"], d["id"], ids["author"])
    await c.post(f"/api/approvals/policy_version/{v['id']}/submit", headers=hdr["author"])
    await c.post(f"/api/approvals/policy_version/{v['id']}/approve", headers=hdr["admin"])
    r = await c.post(f"/api/policies/{d['id']}/versions/{v['id']}/activate",
                     headers=hdr["author"])
    assert r.status_code == 200, r.text
    return d["id"], v["id"]


@pytest.mark.asyncio
async def test_attestation_records_the_signed_in_person_only(_auth_enabled: None) -> None:
    _org_id, hdr, ids = await _org("PolDocE")
    async with _client() as c:
        _pid, vid = await _in_force(c, hdr, ids)
        r = await c.post(f"/api/policies/versions/{vid}/attest",
                         json={"user_id": ids["admin"], "attestor": "someone-else"},
                         headers=hdr["staff"])
        assert r.status_code == 201, r.text
        assert r.json()["attestor"] == "staff@poldoce.example"
        again = await c.post(f"/api/policies/versions/{vid}/attest", json={},
                             headers=hdr["staff"])
        assert again.json()["id"] == r.json()["id"]


@pytest.mark.asyncio
async def test_only_the_version_in_force_can_be_attested(_auth_enabled: None) -> None:
    _org_id, hdr, _ids = await _org("PolDocF")
    async with _client() as c:
        d = await _draft(c, hdr["author"])
        r = await c.post(f"/api/policies/versions/{d['version']['id']}/attest", json={},
                         headers=hdr["staff"])
    assert r.status_code == 409


# ── tenant scoping ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_another_tenants_policy_is_not_found(_auth_enabled: None) -> None:
    _, hdr, _ids = await _org("PolDocG")
    _, other_hdr, _other_ids = await _org("PolDocG2")
    async with _client() as c:
        theirs = await _draft(c, other_hdr["author"])
        r = await c.post(f"/api/policies/{theirs['id']}/versions",
                         json={"version": "9.9", "body": "x"}, headers=hdr["author"])
        assert r.status_code == 404
        r = await c.post(f"/api/policies/versions/{theirs['version']['id']}/attest", json={},
                         headers=hdr["author"])
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_policy_lookup_refuses_another_tenant_without_rls(
    _auth_enabled: None,
) -> None:
    # RLS hides the row from a scoped request, so pin the check itself.
    org, _hdr, ids = await _org("PolDocH")
    _other, other_hdr, _ = await _org("PolDocH2")
    async with _client() as c:
        theirs = await _draft(c, other_hdr["author"])
    me = Principal(ids["author"], "a@x", org, "control_owner")
    async with session_scope() as s:
        with pytest.raises(HTTPException) as exc:
            await require_policy(s, theirs["id"], me)
    assert exc.value.status_code == 404


# ── packages and pages ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_package_captures_the_policies_in_force(_auth_enabled: None) -> None:
    org, hdr, ids = await _org("PolDocI")
    async with session_scope() as s:
        sysm = System(organization_id=org, name="PolDocI sys")
        s.add(sysm)
        await s.flush()
        sys_id = sysm.id
    async with _client() as c:
        _pid, _vid = await _in_force(c, hdr, ids)
        draft_only = await _draft(c, hdr["author"], name="Never in force")
    async with session_scope() as s:
        facts = [f for f in await capture_facts(s, sys_id) if f["fact_type"] == "policy"]
    names = {f["fact_key"] for f in facts}
    assert _template().title in names
    assert draft_only["name"] not in names
    assert all(f["digest"] and len(f["digest"]) == 64 for f in facts)


@pytest.mark.asyncio
async def test_the_pages_render() -> None:
    _org_id, hdr, _ids = await _org("PolDocJ")
    async with _client() as c:
        d = await _draft(c, hdr["author"], name="Pages render draft")
        index = await c.get("/policies")
        assert index.status_code == 200 and "Pages render draft" in index.text
        page = await c.get(f"/policies/{d['id']}")
        assert page.status_code == 200
        assert "Organization-defined values" in page.text


@pytest.mark.asyncio
async def test_single_operator_mode_can_name_the_organization_itself() -> None:
    """With auth off a policy has no organization to read a name from; the
    name is then a value the operator supplies, not a blank stuck forever."""
    async with _client() as c:
        d = await _draft(c, {}, name="Single-operator policy")
        values = {**_all_values(_template()), "organization": "Solo Org",
                  "policy_owner": "Pat Operator"}
        r = await c.put(f"/api/policies/{d['id']}/parameters", json={"parameters": values})
        v = r.json()["version"]
        assert v["unresolved_parameters"] == [], v
        r = await c.post(f"/api/policies/{d['id']}/versions/{v['id']}/activate")
        assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_a_retired_policy_governs_nothing_and_only_an_admin_retires(
    _auth_enabled: None,
) -> None:
    org, hdr, ids = await _org("PolDocK")
    async with session_scope() as s:
        sysm = System(organization_id=org, name="PolDocK sys")
        s.add(sysm)
        await s.flush()
        sys_id = sysm.id
    async with _client() as c:
        pid, _ = await _in_force(c, hdr, ids)
        r = await c.post(f"/api/policies/{pid}/retire", headers=hdr["staff"])
        assert r.status_code == 403
        r = await c.post(f"/api/policies/{pid}/retire", headers=hdr["admin"])
        assert r.status_code == 200 and r.json()["status"] == "retired"
    async with session_scope() as s:
        facts = [f for f in await capture_facts(s, sys_id) if f["fact_type"] == "policy"]
    assert facts == []


@pytest.mark.asyncio
async def test_the_register_counts_acknowledgments_of_the_version_in_force(
    _auth_enabled: None,
) -> None:
    """The register's "current version" is the one in force, not the newest:
    a later draft would otherwise read "0 of N" and hide the acknowledged one."""
    _org_id, hdr, ids = await _org("PolDocReg")
    async with _client() as c:
        pid, vid = await _in_force(c, hdr, ids)
        r = await c.post(f"/api/policies/versions/{vid}/attest", json={}, headers=hdr["staff"])
        assert r.status_code == 201, r.text
        in_force = (await c.get(f"/api/policies/{pid}", headers=hdr["staff"])).json()
        r = await c.put(f"/api/policies/{pid}/parameters",
                        json={"parameters": {**_all_values(_template()),
                                             next(iter(_all_values(_template()))): "revised"}},
                        headers=hdr["author"])
        assert r.status_code == 200, r.text
        newer = r.json()["version"]
        assert newer["id"] != vid
        page = (await c.get("/policies", headers=hdr["staff"])).text
    row = page.split(f'id="policy-{pid}"', 1)[1].split("</tr>", 1)[0]
    in_force_no = next(v["version"] for v in in_force["versions"] if v["id"] == vid)
    assert f"v{in_force_no}" in row and f"v{newer['version']}" not in row, row
    assert "1 of " in row, row
    assert "you" in row, row


async def test_the_author_cannot_approve_a_version_someone_else_submitted(
    _auth_enabled: None,
) -> None:
    _org_id, hdr, _ids = await _org("PolDocL")
    async with _client() as c:
        d = await _draft(c, hdr["admin"])  # an admin renders it -- the author
        r = await c.put(f"/api/policies/{d['id']}/parameters",
                        json={"parameters": _all_values(_template())}, headers=hdr["admin"])
        v = r.json()["version"]
        await c.post(f"/api/approvals/policy_version/{v['id']}/submit", headers=hdr["staff"])
        r = await c.post(f"/api/approvals/policy_version/{v['id']}/approve", headers=hdr["admin"])
        assert r.status_code == 403 and "author" in r.json()["detail"]
        r = await c.post(f"/api/approvals/policy_version/{v['id']}/approve",
                         headers=hdr["admin2"])
        assert r.status_code == 200, r.text
