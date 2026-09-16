"""GET/POST /api/evidence with a capability-parented row (0067).

``EvidenceOut.implementation_id`` was never widened when 0067 made the column
nullable: an unscoped principal listing evidence with a capability-parented row
present used to raise ``ValidationError`` -> 500 on the whole endpoint, and a
scoped principal's inner join on ``implementation_id`` silently dropped such
rows -- evidence the tenant authored was invisible with no error.
``EvidenceCreate.implementation_id`` was also still a required int, so the
capability-parented case 0067 enables could not be exercised through the API
at all.

The scoped-principal cases below call ``list_evidence``/``create_evidence``
directly against a ``session_scope()`` (RLS-bypass) session with a synthetic
``Principal``, rather than through a real authenticated HTTP request. That
isolates exactly the app-layer query/validation logic this fix touches, as a
deliberate choice: the *separate*, RLS-layer gap this docstring used to
describe here -- the ``evidence`` table's ``tenant_isolation`` policy
(migration 0010) predicating solely on ``implementation_id IN (...)``, never
updated for the capability parent 0067 added, and so blocking both ``INSERT``
and ``SELECT`` of a capability-parented row for every real scoped tenant --
has since been fixed in 0067 itself (0067's ``upgrade()`` now recreates the
``evidence`` policy with an added ``capability_id`` branch). See
``tests/test_rls_evidence_capability_parent.py`` for the RLS-enforced,
real-tenant coverage of that fix.
"""

from __future__ import annotations

import itertools

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.api.routes.evidence import EvidenceCreate, create_evidence, list_evidence
from ccf.auth import Principal
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_capability import Capability

_SEQ = itertools.count()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


def _principal(org_id: int | None) -> Principal:
    return Principal(user_id=None, email=f"t{next(_SEQ)}@test", org_id=org_id, role="admin")


@pytest.mark.asyncio
async def test_unscoped_list_does_not_500_on_capability_parented_evidence() -> None:
    async with session_scope() as session:
        org = Organization(name=f"UnscopedEvOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        cap = Capability(organization_id=org.id, key=f"unscoped-ev-{next(_SEQ)}", title="Cap")
        session.add(cap)
        await session.flush()
        cap_id = cap.id

    async with _client() as client:
        created = await client.post(
            "/api/evidence",
            json={"capability_id": cap_id, "kind": "config_export", "title": "CA policy"},
        )
        assert created.status_code == 201, created.text
        assert created.json()["implementation_id"] is None
        assert created.json()["capability_id"] == cap_id

        listed = await client.get("/api/evidence")
        assert listed.status_code == 200, listed.text
        rows = listed.json()
        assert any(r["id"] == created.json()["id"] for r in rows)


@pytest.mark.asyncio
async def test_evidence_requires_a_parent_is_422_not_db_error() -> None:
    async with _client() as client:
        r = await client.post("/api/evidence", json={"kind": "config_export", "title": "orphan"})
        assert r.status_code == 422


@pytest.mark.asyncio
async def test_scoped_principal_sees_own_capability_parented_evidence_only() -> None:
    """The list query's app-layer scoping predicate (outer join / OR), in
    isolation from the separate pre-existing RLS gap described in the module
    docstring: org B's scoped query must not return org A's row, and org A's
    must.
    """
    async with session_scope() as session:
        org_a = Organization(name=f"EvScopeOrgA-{next(_SEQ)}")
        org_b = Organization(name=f"EvScopeOrgB-{next(_SEQ)}")
        session.add_all([org_a, org_b])
        await session.flush()
        cap_a = Capability(organization_id=org_a.id, key=f"scope-cap-a-{next(_SEQ)}", title="Cap A")
        session.add(cap_a)
        await session.flush()

        principal_a = _principal(org_a.id)
        principal_b = _principal(org_b.id)

        created = await create_evidence(
            EvidenceCreate(capability_id=cap_a.id, kind="config_export", title="A's evidence"),
            session=session,
            principal=principal_a,
        )

        own = await list_evidence(session=session, implementation_id=None, principal=principal_a)
        assert any(r.id == created.id for r in own)

        other = await list_evidence(session=session, implementation_id=None, principal=principal_b)
        assert not any(r.id == created.id for r in other), (
            "org B must not see org A's capability-parented evidence"
        )


@pytest.mark.asyncio
async def test_scoped_principal_cannot_parent_evidence_to_anothers_capability() -> None:
    async with session_scope() as session:
        org_a = Organization(name=f"EvCrossOrgA-{next(_SEQ)}")
        org_b = Organization(name=f"EvCrossOrgB-{next(_SEQ)}")
        session.add_all([org_a, org_b])
        await session.flush()
        cap_a = Capability(organization_id=org_a.id, key=f"cross-cap-a-{next(_SEQ)}", title="Cap A")
        session.add(cap_a)
        await session.flush()

        principal_b = _principal(org_b.id)
        with pytest.raises(HTTPException) as exc:
            await create_evidence(
                EvidenceCreate(capability_id=cap_a.id, kind="config_export", title="cross-tenant"),
                session=session,
                principal=principal_b,
            )
        assert exc.value.status_code == 404
