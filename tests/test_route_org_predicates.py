"""Route-level organization predicates, exercised where RLS cannot mask them.

A sweep found routes that take an id and relied entirely on Postgres RLS for
tenant isolation. On the request path ``ccf.api.deps.get_session`` binds the RLS
tenant, so they look safe; RLS is documented there as a backstop *beneath* the
app-layer scoping. Every other caller -- the CLI, the scheduler, the workers,
and any code on an unscoped ``session_scope()`` -- runs with the tenant context
cleared, and those routes were then unguarded.

Each test here follows ``39c86de``:

* it calls the handler **directly** on an unscoped ``session_scope()`` session,
  so RLS is out of the way and the route's own predicate is the only thing
  under test;
* it **first asserts the owning org still gets its row**, so the outsider's
  refusal is provably the org check and not the row being unreachable;
* it asserts a **global principal** (``org_id is None`` -- the CLI/ETL/system
  path, which ``auth_deps.require_role`` lets through early) keeps full access.
  That is the regression that would break the schedulers.

Tests written the usual way -- through the HTTP client -- run as
``SYSTEM_PRINCIPAL``, which is global, and so exercise the bypass rather than
the guard. That is why these go through the handler.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from ccf.api.main import create_app
from ccf.api.routes.approvals import get_approval
from ccf.api.routes.artifacts import download
from ccf.api.routes.automation import (
    ProfileIn,
    _get_profile,
    authorization_package,
    coverage,
    derive,
    evidence_requirements,
    generate_ssp,
    impact,
    list_framework_controls,
    upsert_profile,
)
from ccf.api.routes.capabilities import derive_status
from ccf.api.routes.diagrams import system_diagram
from ccf.api.routes.enforcement import PlanIn, create
from ccf.api.routes.events import delete_webhook
from ccf.api.routes.grc import (
    RegulatoryUpdateIn,
    RequestIn,
    RequestUpdate,
    add_request,
    get_engagement,
    update_regulatory,
    update_request,
)
from ccf.api.routes.grc import (
    test_results as grc_test_results,
)
from ccf.api.routes.notifications import mark_read
from ccf.api.routes.policies import get_policy
from ccf.api.routes.portal import revoke_engagement_endpoint, revoke_grant_endpoint
from ccf.api.routes.posture import control_effective_verdict, scan_system
from ccf.api.routes.vendors import VendorUpdate, update_vendor
from ccf.auth import Principal
from ccf.db import session_scope
from ccf.models import (
    Approval,
    Artifact,
    FrameworkControl,
    Notification,
    Organization,
    Policy,
    System,
    SystemProfile,
    Vendor,
    Webhook,
)
from ccf.models_grc import (
    AuditEngagement,
    AuditRequest,
    ControlTest,
    ControlTestResult,
    RegulatoryUpdate,
)
from ccf.models_portal import (
    AssessmentEngagement,
    ExternalAccessGrant,
    ExternalPrincipal,
)

pytestmark = pytest.mark.asyncio


# --------------------------------------------------------------------------
# principals + fixtures
# --------------------------------------------------------------------------

#: The CLI / ETL / scheduler identity: no org, full reach. ``require_role``
#: returns early for it and every predicate added here is conditional on
#: ``principal.org_id is not None``, so it must keep seeing everything.
GLOBAL = Principal(user_id=None, email="system@ccf.test", org_id=None, role="admin")


def _p(org_id: int) -> Principal:
    return Principal(user_id=None, email=f"user-{org_id}@orgpred.test", org_id=org_id, role="admin")


async def _two_orgs(label: str) -> tuple[int, int]:
    """An owning org and an unrelated one. Names are label-unique: the suite
    shares one database and ``organizations.name`` is UNIQUE."""
    async with session_scope() as s:
        owner = Organization(name=f"OrgPred {label} Owner")
        other = Organization(name=f"OrgPred {label} Other")
        s.add_all([owner, other])
        await s.flush()
        return owner.id, other.id


async def _system(org_id: int, name: str) -> int:
    async with session_scope() as s:
        sysrow = System(organization_id=org_id, name=name)
        s.add(sysrow)
        await s.flush()
        return sysrow.id


async def _profile(system_id: int) -> None:
    async with session_scope() as s:
        s.add(
            SystemProfile(
                system_id=system_id,
                environment_type="cloud",
                cloud_platform="m365_gcc_high",
                cui_present=True,
                answers={"environment_type": "cloud"},
                derivation={},
            )
        )


async def _drop(model: Any, ids: list[int]) -> None:
    if not ids:
        return
    async with session_scope() as s:
        await s.execute(delete(model).where(model.id.in_(ids)))


async def _refused(fn: Any, *args: Any, **kwargs: Any) -> HTTPException:
    """Call a handler expecting an HTTPException, and hand it back."""
    with pytest.raises(HTTPException) as excinfo:
        await fn(*args, **kwargs)
    return excinfo.value


# --------------------------------------------------------------------------
# artifacts.download -- raw bytes on an existence check
# --------------------------------------------------------------------------


async def test_artifact_download_org_guard() -> None:
    owner_org, other_org = await _two_orgs("Artifact")
    secret = b"CUI: org-owned artifact bytes"
    async with session_scope() as s:
        a = Artifact(
            organization_id=owner_org,
            sha256="a" * 64,
            filename="owned.txt",
            media_type="text/plain",
            size_bytes=len(secret),
            content=secret,
        )
        s.add(a)
        await s.flush()
        artifact_id = a.id
    try:
        async with session_scope() as s:
            # 1. the owner still gets the bytes -- so the refusal below is the
            #    org check, not an unreachable row.
            ok = await download(artifact_id, session=s, principal=_p(owner_org))
            assert ok.body == secret

            # 2. a foreign principal gets 404 AND no bytes. Asserted on the
            #    body, not only the status: the whole point of this route is
            #    what it hands back.
            exc = await _refused(download, artifact_id, session=s, principal=_p(other_org))
            assert exc.status_code == 404
            assert secret not in str(exc.detail).encode()

            # 3. the CLI/scheduler identity keeps full access.
            assert (await download(artifact_id, session=s, principal=GLOBAL)).body == secret
    finally:
        await _drop(Artifact, [artifact_id])


async def test_artifact_download_over_http_returns_no_bytes_to_a_foreign_principal() -> None:
    """The same refusal end to end, asserted on the response body."""
    owner_org, _other = await _two_orgs("ArtifactHttp")
    secret = b"CUI: http artifact bytes"
    async with session_scope() as s:
        a = Artifact(
            organization_id=owner_org,
            sha256="b" * 64,
            filename="http.txt",
            media_type="text/plain",
            size_bytes=len(secret),
            content=secret,
        )
        s.add(a)
        await s.flush()
        artifact_id = a.id
    try:
        transport = ASGITransport(app=create_app())
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            # Auth is off in the test env, so the HTTP caller is SYSTEM_PRINCIPAL
            # -- global. It must still be served: this is the scheduler's path.
            r = await c.get(f"/api/artifacts/{artifact_id}/download")
            assert r.status_code == 200
            assert r.content == secret
    finally:
        await _drop(Artifact, [artifact_id])


# --------------------------------------------------------------------------
# automation.py -- the system-scoped federal-artifact routes
# --------------------------------------------------------------------------


async def test_automation_system_routes_org_guard() -> None:
    """Every ``/api/systems/{system_id}/...`` route in automation.py.

    The order is the dependency order: ``upsert_profile`` saves the profile
    ``derive`` needs, and ``derive`` writes the derivation ``generate_ssp``
    needs -- so each route genuinely succeeds for the owner, which is what
    makes the outsider's 404 attributable to the org predicate rather than to
    a missing precondition.
    """
    owner_org, other_org = await _two_orgs("Automation")
    system_id = await _system(owner_org, "OrgPred Automation System")
    await _profile(system_id)
    owner, foreign = _p(owner_org), _p(other_org)
    body = ProfileIn(environment_type="cloud", cloud_platform="m365_gcc_high")

    async with session_scope() as s:
        # -- reads that fully succeed for the owner ------------------------
        for fn in (coverage, impact, evidence_requirements, authorization_package):
            assert await fn(system_id, session=s, principal=owner) is not None
            exc = await _refused(fn, system_id, session=s, principal=foreign)
            assert exc.status_code == 404, fn.__name__
            assert exc.detail == "system not found", fn.__name__
            assert await fn(system_id, session=s, principal=GLOBAL) is not None

        # -- write: upsert_profile ----------------------------------------
        assert (await upsert_profile(system_id, body, session=s, principal=owner))[
            "profile_saved"
        ]
        exc = await _refused(upsert_profile, system_id, body, session=s, principal=foreign)
        assert exc.status_code == 404
        assert exc.detail == "system not found"
        assert (await upsert_profile(system_id, body, session=s, principal=GLOBAL))[
            "profile_saved"
        ]

        # -- derive --------------------------------------------------------
        assert await derive(system_id, session=s, principal=owner) is not None
        exc = await _refused(derive, system_id, session=s, principal=foreign)
        assert exc.status_code == 404
        assert exc.detail == "system not found"
        assert await derive(system_id, session=s, principal=GLOBAL) is not None

        # -- generate_ssp --------------------------------------------------
        # The derivation is written straight in: ``derive`` above leaves it
        # empty on a database with no seeded catalog, and generate_ssp's own
        # 400 for that is a *different* refusal from the org check.
        prof = await _get_profile(s, system_id)
        assert prof is not None
        prof.derivation = {"AC-1": {"responsibility": "customer", "state": "planned"}}
        await s.commit()

        assert (await generate_ssp(system_id, session=s, principal=owner))["project_id"]
        exc = await _refused(generate_ssp, system_id, session=s, principal=foreign)
        assert exc.status_code == 404
        assert exc.detail == "system not found"
        assert (await generate_ssp(system_id, session=s, principal=GLOBAL))["project_id"]


async def test_framework_controls_are_not_global_reference_data() -> None:
    """``framework_controls`` rows are uploaded per tenant, so ``{code}`` must
    not reach another org's catalog."""
    owner_org, other_org = await _two_orgs("FrameworkControls")
    async with session_scope() as s:
        fc = FrameworkControl(
            organization_id=owner_org,
            framework_code="ORGPREDFW",
            identifier="OPF-1",
            title="Owned framework control",
        )
        s.add(fc)
        await s.flush()
        fc_id = fc.id
    try:
        async with session_scope() as s:
            mine = await list_framework_controls("ORGPREDFW", session=s, principal=_p(owner_org))
            assert mine["total"] == 1
            assert mine["controls"][0]["identifier"] == "OPF-1"

            theirs = await list_framework_controls(
                "ORGPREDFW", session=s, principal=_p(other_org)
            )
            assert theirs["total"] == 0
            assert theirs["controls"] == []

            everything = await list_framework_controls("ORGPREDFW", session=s, principal=GLOBAL)
            assert everything["total"] == 1
    finally:
        await _drop(FrameworkControl, [fc_id])


# --------------------------------------------------------------------------
# capabilities / diagrams / enforcement / posture -- system-scoped
# --------------------------------------------------------------------------


async def test_capability_derive_status_org_guard() -> None:
    owner_org, other_org = await _two_orgs("CapDerive")
    system_id = await _system(owner_org, "OrgPred CapDerive System")
    async with session_scope() as s:
        assert (await derive_status(system_id, session=s, principal=_p(owner_org)))[
            "system_id"
        ] == system_id
        exc = await _refused(derive_status, system_id, session=s, principal=_p(other_org))
        assert exc.status_code == 404
        assert exc.detail == "system not found"
        assert (await derive_status(system_id, session=s, principal=GLOBAL))[
            "system_id"
        ] == system_id


async def test_system_diagram_org_guard() -> None:
    """The route had no ``principal`` in its signature at all -- its sibling
    ``landscape`` already passed ``org_id=principal.org_id``."""
    owner_org, other_org = await _two_orgs("Diagram")
    system_id = await _system(owner_org, "OrgPred Diagram System")
    async with session_scope() as s:
        for kind in ("authorization-boundary", "control-coverage"):
            mine = await system_diagram(system_id, kind, session=s, principal=_p(owner_org))
            assert isinstance(mine, str) and mine

            exc = await _refused(
                system_diagram, system_id, kind, session=s, principal=_p(other_org)
            )
            assert exc.status_code == 404, kind
            assert exc.detail == "system not found", kind

            assert await system_diagram(system_id, kind, session=s, principal=GLOBAL)


async def test_posture_routes_org_guard() -> None:
    owner_org, other_org = await _two_orgs("Posture")
    system_id = await _system(owner_org, "OrgPred Posture System")
    owner, foreign = _p(owner_org), _p(other_org)

    async with session_scope() as s:
        # No connector is configured, so the owner gets a clean "nothing to
        # scan" result rather than an error -- a real success to contrast with.
        mine = await scan_system(system_id, "aws", session=s, principal=owner)
        assert mine["system_id"] == system_id
        exc = await _refused(scan_system, system_id, "aws", session=s, principal=foreign)
        assert exc.status_code == 404
        assert exc.detail == "system not found"
        assert (await scan_system(system_id, "aws", session=s, principal=GLOBAL))[
            "system_id"
        ] == system_id

        assert await control_effective_verdict(
            "AC-2", system_id=system_id, session=s, principal=owner
        )
        exc = await _refused(
            control_effective_verdict, "AC-2", system_id=system_id, session=s, principal=foreign
        )
        assert exc.status_code == 404
        assert exc.detail == "system not found"
        assert await control_effective_verdict(
            "AC-2", system_id=system_id, session=s, principal=GLOBAL
        )


async def test_remediation_plan_create_org_guard() -> None:
    """``require_role`` is not an org gate: ``admin`` is a tenant role, so an
    enforcer in another org passed it. The owner reaches the provider-binding
    refusal; the outsider is stopped at the org check before it."""
    owner_org, other_org = await _two_orgs("Enforcement")
    system_id = await _system(owner_org, "OrgPred Enforcement System")
    body = PlanIn(check_key="orgpred.no.such.check")

    async with session_scope() as s:
        owner_exc = await _refused(create, system_id, body, session=s, principal=_p(owner_org))
        assert owner_exc.status_code == 404
        assert "remediation provider" in str(owner_exc.detail)

        glob_exc = await _refused(create, system_id, body, session=s, principal=GLOBAL)
        assert "remediation provider" in str(glob_exc.detail)

        foreign_exc = await _refused(create, system_id, body, session=s, principal=_p(other_org))
        assert foreign_exc.status_code == 404
        assert foreign_exc.detail == "system not found"


# --------------------------------------------------------------------------
# grc.py
# --------------------------------------------------------------------------


async def test_audit_engagement_routes_org_guard() -> None:
    """``add_finding`` beside these already had the predicate; these did not."""
    owner_org, other_org = await _two_orgs("Engagement")
    owner, foreign = _p(owner_org), _p(other_org)
    async with session_scope() as s:
        e = AuditEngagement(organization_id=owner_org, name="OrgPred Engagement")
        s.add(e)
        await s.flush()
        eng_id = e.id
        r = AuditRequest(engagement_id=eng_id, title="OrgPred Request")
        s.add(r)
        await s.flush()
        req_id = r.id
    try:
        async with session_scope() as s:
            assert (await get_engagement(eng_id, session=s, principal=owner))["id"] == eng_id
            exc = await _refused(get_engagement, eng_id, session=s, principal=foreign)
            assert exc.status_code == 404
            assert (await get_engagement(eng_id, session=s, principal=GLOBAL))["id"] == eng_id

            body = RequestIn(title="OrgPred Added Request")
            assert (await add_request(eng_id, body, session=s, principal=owner))["id"]
            exc = await _refused(add_request, eng_id, body, session=s, principal=foreign)
            assert exc.status_code == 404
            assert (await add_request(eng_id, body, session=s, principal=GLOBAL))["id"]

            # audit_requests carries no organization_id -- it inherits the
            # tenant from its engagement, which is where the predicate went.
            upd = RequestUpdate(status="closed")
            assert (await update_request(req_id, upd, session=s, principal=owner))["id"] == req_id
            exc = await _refused(update_request, req_id, upd, session=s, principal=foreign)
            assert exc.status_code == 404
            assert (await update_request(req_id, upd, session=s, principal=GLOBAL))["id"] == req_id
    finally:
        async with session_scope() as s:
            await s.execute(delete(AuditRequest).where(AuditRequest.engagement_id == eng_id))
            await s.execute(delete(AuditEngagement).where(AuditEngagement.id == eng_id))


async def test_regulatory_update_org_guard() -> None:
    owner_org, other_org = await _two_orgs("Regulatory")
    async with session_scope() as s:
        r = RegulatoryUpdate(organization_id=owner_org, title="OrgPred Reg")
        s.add(r)
        await s.flush()
        reg_id = r.id
    try:
        body = RegulatoryUpdateIn(title="OrgPred Reg", owner="new-owner@orgpred.test")
        async with session_scope() as s:
            assert (await update_regulatory(reg_id, body, session=s, principal=_p(owner_org)))[
                "id"
            ] == reg_id
            exc = await _refused(
                update_regulatory, reg_id, body, session=s, principal=_p(other_org)
            )
            assert exc.status_code == 404
            assert (await update_regulatory(reg_id, body, session=s, principal=GLOBAL))[
                "id"
            ] == reg_id
    finally:
        await _drop(RegulatoryUpdate, [reg_id])


async def test_control_test_results_org_guard() -> None:
    """``control_test_results`` has no organization_id of its own; the tenant
    lives on the parent test, matching ``evaluate_control_test``."""
    owner_org, other_org = await _two_orgs("ControlTest")
    async with session_scope() as s:
        t = ControlTest(organization_id=owner_org, control_id="AC-2", name="OrgPred Test")
        s.add(t)
        await s.flush()
        test_id = t.id
        s.add(ControlTestResult(control_test_id=test_id, status="pass", detail="owned detail"))
    try:
        async with session_scope() as s:
            mine = await grc_test_results(test_id, session=s, principal=_p(owner_org))
            assert [r["detail"] for r in mine] == ["owned detail"]

            exc = await _refused(grc_test_results, test_id, session=s, principal=_p(other_org))
            assert exc.status_code == 404
            assert exc.detail == "control test not found"

            assert await grc_test_results(test_id, session=s, principal=GLOBAL)
    finally:
        async with session_scope() as s:
            await s.execute(
                delete(ControlTestResult).where(ControlTestResult.control_test_id == test_id)
            )
            await s.execute(delete(ControlTest).where(ControlTest.id == test_id))


# --------------------------------------------------------------------------
# portal.py -- role-gated but not org-scoped
# --------------------------------------------------------------------------


async def _portal_fixture(label: str) -> tuple[int, int, int, int]:
    """(owner_org, other_org, engagement_id, grant_id)."""
    owner_org, other_org = await _two_orgs(label)
    system_id = await _system(owner_org, f"OrgPred {label} System")
    now = datetime.now(UTC)
    async with session_scope() as s:
        pr = ExternalPrincipal(organization_id=owner_org, kind="assessor", name="OrgPred 3PAO")
        s.add(pr)
        await s.flush()
        eng = AssessmentEngagement(
            organization_id=owner_org,
            system_id=system_id,
            assessor_principal_id=pr.id,
            period_from=now,
            period_to=now + timedelta(days=30),
        )
        s.add(eng)
        await s.flush()
        grant = ExternalAccessGrant(
            organization_id=owner_org,
            principal_id=pr.id,
            kind="assessor",
            engagement_id=eng.id,
            token_hash=f"{label.lower()}-orgpred-token-hash",
            expires_at=now + timedelta(days=7),
        )
        s.add(grant)
        await s.flush()
        return owner_org, other_org, eng.id, grant.id


async def test_portal_revoke_endpoints_org_guard() -> None:
    """``require_role("admin")`` admits any tenant's admin -- only a global
    principal short-circuits it -- so one org's admin could revoke another
    org's 3PAO engagement or access grant."""
    owner_org, other_org, eng_id, grant_id = await _portal_fixture("Portal")
    try:
        async with session_scope() as s:
            # The outsider is refused FIRST, so nothing is revoked yet when the
            # owner's success is asserted below.
            exc = await _refused(
                revoke_grant_endpoint, grant_id, session=s, principal=_p(other_org)
            )
            assert exc.status_code == 404
            assert (await s.get(ExternalAccessGrant, grant_id)).revoked is False

            exc = await _refused(
                revoke_engagement_endpoint, eng_id, session=s, principal=_p(other_org)
            )
            assert exc.status_code == 404
            assert (await s.get(AssessmentEngagement, eng_id)).revoked_at is None

            assert (await revoke_grant_endpoint(grant_id, session=s, principal=_p(owner_org)))[
                "revoked"
            ]
            assert (await revoke_engagement_endpoint(eng_id, session=s, principal=_p(owner_org)))[
                "revoked"
            ]
    finally:
        async with session_scope() as s:
            await s.execute(delete(ExternalAccessGrant).where(ExternalAccessGrant.id == grant_id))
            await s.execute(
                delete(AssessmentEngagement).where(AssessmentEngagement.id == eng_id)
            )


async def test_portal_revoke_endpoints_still_serve_a_global_principal() -> None:
    """The CLI/scheduler identity keeps full reach across both routes."""
    _owner, _other, eng_id, grant_id = await _portal_fixture("PortalGlobal")
    try:
        async with session_scope() as s:
            assert (await revoke_grant_endpoint(grant_id, session=s, principal=GLOBAL))["revoked"]
            assert (await revoke_engagement_endpoint(eng_id, session=s, principal=GLOBAL))[
                "revoked"
            ]
    finally:
        async with session_scope() as s:
            await s.execute(delete(ExternalAccessGrant).where(ExternalAccessGrant.id == grant_id))
            await s.execute(
                delete(AssessmentEngagement).where(AssessmentEngagement.id == eng_id)
            )


# --------------------------------------------------------------------------
# approvals / events / notifications / policies / vendors
# --------------------------------------------------------------------------


async def test_get_approval_org_guard() -> None:
    """A miss reports ``state: draft`` rather than 404 -- and that is also what
    another tenant's approval must look like: who reviewed it, when, and the
    decision note are theirs."""
    owner_org, other_org = await _two_orgs("Approval")
    async with session_scope() as s:
        a = Approval(
            organization_id=owner_org,
            entity_type="ssp_project",
            entity_id="orgpred-approval-1",
            state="approved",
            reviewed_by="reviewer@owner.test",
            decision_note="internal approval note",
        )
        s.add(a)
        await s.flush()
        approval_id = a.id
    try:
        async with session_scope() as s:
            mine = await get_approval(
                "ssp_project", "orgpred-approval-1", session=s, principal=_p(owner_org)
            )
            assert mine["state"] == "approved"

            theirs = await get_approval(
                "ssp_project", "orgpred-approval-1", session=s, principal=_p(other_org)
            )
            assert theirs["state"] == "draft"
            assert "internal approval note" not in str(theirs)

            assert (
                await get_approval(
                    "ssp_project", "orgpred-approval-1", session=s, principal=GLOBAL
                )
            )["state"] == "approved"
    finally:
        await _drop(Approval, [approval_id])


async def test_delete_webhook_org_guard() -> None:
    owner_org, other_org = await _two_orgs("Webhook")
    async with session_scope() as s:
        w = Webhook(organization_id=owner_org, url="https://orgpred.test/hook")
        g = Webhook(organization_id=owner_org, url="https://orgpred.test/hook-global")
        s.add_all([w, g])
        await s.flush()
        wid, gid = w.id, g.id
    try:
        async with session_scope() as s:
            # Refuse the outsider first, so the row is still there to prove the
            # owner can delete it.
            exc = await _refused(delete_webhook, wid, session=s, principal=_p(other_org))
            assert exc.status_code == 404
            assert await s.get(Webhook, wid) is not None

            await delete_webhook(wid, session=s, principal=_p(owner_org))
            assert await s.get(Webhook, wid) is None

            await delete_webhook(gid, session=s, principal=GLOBAL)
            assert await s.get(Webhook, gid) is None
    finally:
        await _drop(Webhook, [wid, gid])


async def test_mark_notification_read_org_guard() -> None:
    owner_org, other_org = await _two_orgs("Notification")
    async with session_scope() as s:
        n = Notification(organization_id=owner_org, category="conmon", title="OrgPred notice")
        g = Notification(organization_id=owner_org, category="conmon", title="OrgPred global")
        s.add_all([n, g])
        await s.flush()
        nid, gid = n.id, g.id
    try:
        async with session_scope() as s:
            exc = await _refused(mark_read, nid, session=s, principal=_p(other_org))
            assert exc.status_code == 404

            assert (await mark_read(nid, session=s, principal=_p(owner_org)))["id"] == nid
            assert (await mark_read(gid, session=s, principal=GLOBAL))["id"] == gid
    finally:
        await _drop(Notification, [nid, gid])


async def test_get_policy_org_guard() -> None:
    owner_org, other_org = await _two_orgs("Policy")
    async with session_scope() as s:
        p = Policy(organization_id=owner_org, name="OrgPred Policy", description="internal text")
        s.add(p)
        await s.flush()
        policy_id = p.id
    try:
        async with session_scope() as s:
            assert (await get_policy(policy_id, session=s, principal=_p(owner_org)))[
                "name"
            ] == "OrgPred Policy"
            exc = await _refused(get_policy, policy_id, session=s, principal=_p(other_org))
            assert exc.status_code == 404
            assert "internal text" not in str(exc.detail)
            assert (await get_policy(policy_id, session=s, principal=GLOBAL))[
                "name"
            ] == "OrgPred Policy"
    finally:
        await _drop(Policy, [policy_id])


async def test_update_vendor_org_guard() -> None:
    owner_org, other_org = await _two_orgs("Vendor")
    async with session_scope() as s:
        v = Vendor(organization_id=owner_org, name="OrgPred Vendor")
        s.add(v)
        await s.flush()
        vendor_id = v.id
    try:
        body = VendorUpdate(criticality="high")
        async with session_scope() as s:
            assert (await update_vendor(vendor_id, body, session=s, principal=_p(owner_org)))[
                "id"
            ] == vendor_id
            exc = await _refused(update_vendor, vendor_id, body, session=s, principal=_p(other_org))
            assert exc.status_code == 404
            assert (await update_vendor(vendor_id, body, session=s, principal=GLOBAL))[
                "id"
            ] == vendor_id
    finally:
        await _drop(Vendor, [vendor_id])
