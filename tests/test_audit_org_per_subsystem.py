"""Every audited subsystem must stamp its events with the *entity's* tenant.

``52daccc`` made ``organization_id`` a required keyword on
:func:`ccf.api.audit.record_event`, classified all 35 call sites, and guarded
the classification two ways:

* ``test_record_event_has_no_default_organization`` -- omitting the argument is
  a ``TypeError``.
* ``test_only_the_classified_global_call_sites_record_a_tenantless_event`` --
  an AST walk requiring a **literal** ``organization_id=None`` to be one of the
  two enumerated deployment-wide sites.

Neither can catch a call site that passes a *wrong expression*. The AST guard
examines only literals, by its own docstring, and an expression that resolves
to ``None`` at runtime is indistinguishable in a diff from one that resolves to
the right tenant. Under migration 0044's ``tenant_isolation`` predicate

    ccf.current_tenant() IS NULL
    OR organization_id IS NULL
    OR organization_id = ccf.current_tenant()

a row that lands ``NULL`` is not merely unscoped -- it is **published to every
organization on the deployment**. So the wrong expression is silent, and the
only thing that can catch it is a behavioural assertion on the real path.

``52daccc`` shipped that assertion for exactly two subsystems (waivers and
retention). This module adds one per remaining audited subsystem: it performs a
real operation through the subsystem's normal path and asserts, by equality
against the entity's own organization, what ``organization_id`` the resulting
``AuditLog`` row carries.

**Where caller and entity genuinely differ, the test is built on that
difference**, because a test where they coincide cannot fail under the most
likely wrong expression (``principal.org_id``):

* ``identity/provisioning`` runs on sessions that are never tenant-clamped --
  the OIDC callback has no principal yet and SCIM authenticates with a bearer
  token. **This used to be the clearest case where the two values disagreed**,
  because SCIM looked its user up by a globally-unique email with no org
  predicate and would update another tenant's account. That write is now
  refused (``ProvisioningConflictError``), so for SCIM the two values are
  provably equal and the mutation this module exists to catch can no longer
  fail there; the OIDC callback, which still resolves its org separately from
  the account, remains the live case.
* ``packs/sync`` adoption and ``packs/service`` installation take the tenant
  from the ``PackSource`` row, on an unscoped scheduler/CLI session.
* ``self_assurance`` audits to the "Concord Platform" organization, never the
  admin's own -- driven here by a *global* principal over HTTP, so the two
  differ by construction.
* The ``patching`` campaign route and the ``enforcement``, ``portal``,
  ``ai_actions``, ``ai_governance`` and ``cr26`` services are driven with no
  caller tenant at all (``SYSTEM_PRINCIPAL``/``session_scope``), so
  ``principal.org_id`` -- or anything derived from the session's RLS clamp --
  would be ``None`` while the entity's org is a real one.

Two call sites cannot be made to differ, and say so at their own test:
``PUT /api/remediation-policy`` and ``POST /api/packs/{key}/sources`` both
*construct* the row from ``principal.org_id``, so the entity's org is the
caller's org by definition.

This module never empties ``audit_log``: it makes no claim about chain
linkage, only about the ``organization_id`` of rows it can name exactly, so it
reads its own rows by ``entity_type``/``entity_id`` and leaves everyone else's
chain untouched.
"""

from __future__ import annotations

import itertools
import os
from collections.abc import AsyncIterator, Iterator, Sequence
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.ai_actions import reject_run, run_action
from ccf.ai_governance import risk_assess
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.cr26.store import put_document
from ccf.db import session_scope
from ccf.enforcement.service import create_plan
from ccf.enforcement.types import RemediationStep, StepOutcome
from ccf.identity import provisioning
from ccf.models import POAM, AuditLog, Organization, System, User
from ccf.models_ai_actions import AiActionRun
from ccf.models_ai_agents import AiAgent
from ccf.models_packs import CompliancePack, PackSource
from ccf.packs.sync import adopt_pending
from ccf.portal import service as portal
from ccf.posture.types import ResourceFinding

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
TODAY = date(2026, 9, 15)

#: Concord's own organization, seeded by ``ccf.self_assurance.service._self_ids``.
SELF_ORG = "Concord Platform"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
def _local_evidence_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Self-assurance init creates evidence objects; keep the bytes local."""
    monkeypatch.setenv("CCF_EVIDENCE_BACKEND", "local")
    monkeypatch.setenv("CCF_EVIDENCE_LOCAL_DIR", str(tmp_path / "ev"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
async def auth_enabled() -> AsyncIterator[None]:
    """Turn real authentication on, for the two tests that need a *scoped* caller.

    Not autouse and not module-wide: every other test here is deliberately
    driven by a caller with **no** tenant (``SYSTEM_PRINCIPAL`` or an unscoped
    ``session_scope``), which is what makes "the entity's org, not the
    caller's" an assertion that can fail.
    """
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


# --- helpers -----------------------------------------------------------------


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org(label: str) -> int:
    async with session_scope() as s:
        org = Organization(name=f"AuditOrgSub-{label}-{next(_SEQ)}")
        s.add(org)
        await s.flush()
        return org.id


async def _system(org_id: int, label: str) -> int:
    async with session_scope() as s:
        sysm = System(
            organization_id=org_id, name=f"AuditOrgSub-{label}-{next(_SEQ)}", baseline="moderate"
        )
        s.add(sysm)
        await s.flush()
        return sysm.id


async def _admin_token(org_id: int, email: str) -> str:
    """A usable bearer token for a fresh admin in ``org_id``.

    The token is **minted here and returned**, never read back off a reloaded
    ``User``: ``api_token`` is a write-only property (IA-09) and only
    ``api_token_hash`` persists, so a reloaded row reports ``None`` and reusing
    it would authenticate as nobody -- a 401 that looks exactly like a
    successful tenant-scoping result.
    """
    async with session_scope() as s:
        user = User(
            email=email,
            organization_id=org_id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
        )
        s.add(user)
        token = new_api_token()
        user.api_token = token
        await s.flush()
        return token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _audit_orgs(entity_type: str, entity_id: str) -> list[int | None]:
    """Every audit row for one entity, oldest first, as stored in Postgres.

    Read on an unscoped ``session_scope`` session on purpose: RLS would happily
    show a NULL-org row to any tenant, so asking "what does org X see" cannot
    separate a correctly scoped row from a broadcast one. The stored column is
    the only thing that answers the question.
    """
    async with session_scope() as s:
        return list(
            (
                await s.execute(
                    select(AuditLog.organization_id)
                    .where(AuditLog.entity_type == entity_type, AuditLog.entity_id == entity_id)
                    .order_by(AuditLog.id)
                )
            )
            .scalars()
            .all()
        )


async def _audit_org(entity_type: str, entity_id: str) -> int | None:
    orgs = await _audit_orgs(entity_type, entity_id)
    assert len(orgs) == 1, f"expected exactly one {entity_type} event for {entity_id}: {orgs}"
    return orgs[0]


# --- patching: the service's campaign event ----------------------------------


@pytest.mark.asyncio
async def test_patching_campaign_event_carries_the_systems_org_not_the_callers() -> None:
    """``POST /api/systems/{id}/patch-campaigns`` as a *global* principal.

    Auth is disabled here, so the route runs as ``SYSTEM_PRINCIPAL``, whose
    ``org_id`` is ``None`` -- and ``get_session`` therefore leaves the session
    unclamped. The campaign nonetheless belongs to the system's organization,
    and so must its audit event. Taking it from the principal (or from the
    session's RLS tenant) would leave it NULL and publish this tenant's
    maintenance plan to every organization on the deployment.
    """
    org_id = await _org("patch")
    system_id = await _system(org_id, "patch-sys")
    async with session_scope() as s:
        s.add(
            POAM(
                system_id=system_id,
                title=f"AuditOrgSub flaw {next(_SEQ)}",
                severity="high",
                status="open",
                source="scan",
                identified_on=TODAY - timedelta(days=10),
            )
        )

    async with _client() as c:
        r = await c.post(
            f"/api/systems/{system_id}/patch-campaigns",
            json={
                "name": "AuditOrgSub campaign",
                "window_start": str(TODAY),
                "window_end": str(TODAY + timedelta(days=7)),
            },
        )
        assert r.status_code == 201, r.text
        campaign_id = r.json()["id"]

    assert await _audit_org("patch_campaign", str(campaign_id)) == org_id


# --- patching: the route's own event -----------------------------------------


@pytest.mark.asyncio
async def test_patching_policy_event_carries_the_policy_rows_org(
    auth_enabled: None,
) -> None:
    """``PUT /api/remediation-policy``, the one ``record_event`` in this router.

    Caller and entity **cannot** genuinely differ here, and that is a property
    of the route rather than an omission in the test: ``set_policy`` selects the
    policy row ``WHERE organization_id = principal.org_id`` and, when none
    exists, constructs it as ``RemediationPolicy(organization_id=principal.
    org_id)``. The entity's org is the caller's org by definition, so a
    mutation to ``principal.org_id`` is a no-op at this call site.

    What the assertion still pins is that the event is scoped at all, by
    equality against a *real* organization -- so any expression that resolves
    to ``None`` (the broadcast value) fails, which is the failure mode that
    matters. It runs with authentication on for that reason: as the global
    ``SYSTEM_PRINCIPAL`` the policy row itself would be NULL-org and the
    assertion would have nothing to say.
    """
    org_id = await _org("policy")
    token = await _admin_token(org_id, f"policy-{next(_SEQ)}@audit-org-sub.test")

    async with _client() as c:
        r = await c.put(
            "/api/remediation-policy",
            json={"moderate_days": 45},
            headers=_auth(token),
        )
        assert r.status_code == 200, r.text

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AuditLog)
                .where(AuditLog.entity_type == "remediation_policy")
                .order_by(AuditLog.id.desc())
            )
        ).scalars().all()
    mine = [r for r in rows if r.actor and r.actor.startswith("policy-")]
    assert mine, "the policy PUT recorded no audit event"
    assert mine[0].organization_id == org_id


# --- packs: the registration route -------------------------------------------


@pytest.mark.asyncio
@pytest.mark.usefixtures("isolate_source_rows")
async def test_pack_source_registration_event_carries_the_sources_org(
    auth_enabled: None,
) -> None:
    """``POST /api/packs/{key}/sources``.

    Like the remediation policy, caller and entity cannot differ: the row is
    built ``organization_id=principal.org_id`` "from the principal, never the
    body", and the route *refuses* a global principal outright (a NULL-org
    source would be polled by nothing). So this pins that the event is scoped
    to a real organization rather than broadcast.
    """
    org_id = await _org("packsrc")
    token = await _admin_token(org_id, f"packsrc-{next(_SEQ)}@audit-org-sub.test")

    async with _client() as c:
        r = await c.post(
            "/api/packs/audit-org-sub-pack/sources",
            json={"url": "https://pack-source.test/audit-org-sub.json", "ref": "main"},
            headers=_auth(token),
        )
        assert r.status_code in (200, 201), r.text
        source_id = r.json()["id"]

    assert await _audit_org("pack_source", str(source_id)) == org_id


# --- packs: service + sync, from the scheduler's unscoped session ------------


def _pack_manifest(pack_id: str, version: str = "1.0.0") -> dict[str, Any]:
    return {
        "id": pack_id,
        "name": "Audit Org Sub Pack",
        "version": version,
        "schema_version": "1",
        "controls": [{"control_id": "AC-2", "title": "Account Management"}],
    }


async def _pending_source(org_id: int, pack_id: str) -> int:
    async with session_scope() as s:
        src = PackSource(
            organization_id=org_id,
            pack_key=pack_id,
            url=f"https://pack-source.test/{pack_id}.json",
            ref="main",
            auto_install=False,
            last_status="pending",
            pending_manifest=_pack_manifest(pack_id),
            pending_sha256="d" * 64,
            pending_commit_sha="e" * 40,
        )
        s.add(src)
        await s.flush()
        return src.id


@pytest.mark.asyncio
@pytest.mark.usefixtures("isolate_source_rows")
async def test_packs_sync_and_service_events_carry_the_pack_sources_org() -> None:
    """Adopting a pending manifest, on a session with no tenant at all.

    ``adopt_pending`` is what an operator's adopt button and the scheduler's
    auto-install path both reach; it takes an ``actor`` string and **no**
    principal, and it runs here on an unscoped ``session_scope`` session, which
    is how ``ccf.scheduler`` runs it. Nothing downstream could infer the
    tenant, so both events it produces -- ``packs/sync``'s ``pack_source``
    event and, underneath it, ``packs/service``'s ``compliance_pack`` install
    event -- must take it from the ``PackSource`` row.
    """
    org_id = await _org("packsync")
    pack_id = f"audit-org-sub-{next(_SEQ)}"
    source_id = await _pending_source(org_id, pack_id)

    async with session_scope() as s:
        src = await s.get(PackSource, source_id)
        assert src is not None
        pack = await adopt_pending(s, src, actor="scheduler")
        pack_row_id = pack.id
        # The adopting session really does carry no tenant, or "the entity's
        # org, not the caller's" would be an untested distinction here.
        assert (await s.execute(select(CompliancePack.organization_id).where(
            CompliancePack.id == pack_row_id
        ))).scalar_one() == org_id

    assert await _audit_org("pack_source", str(source_id)) == org_id, "packs/sync"
    assert await _audit_org("compliance_pack", str(pack_row_id)) == org_id, "packs/service"


# --- enforcement -------------------------------------------------------------


class _UnwritableProvider:
    """A provider with no write credential, so ``create_plan`` records a refusal.

    A refusal is a stored row and an audit event by design ("we considered
    changing this and declined"), which makes it the shortest real path through
    ``create_plan`` that writes an audit event -- no connector credential, no
    recorded scan result, and nothing is changed on a real system.
    """

    key = "audit_org_sub_provider"
    write_credential_type = "audit_org_sub_write"
    required_permissions = ("Fake.ReadWrite.All",)
    handled_checks = ("audit.org.sub",)

    def __init__(self, credential: dict[str, Any] | None = None) -> None:
        self.credential = credential

    def handles(self, check_key: str) -> bool:
        return check_key in self.handled_checks

    async def is_write_configured(self) -> bool:
        return False

    async def plan(self, findings: Sequence[ResourceFinding]) -> list[RemediationStep]:
        raise AssertionError("unreachable: the write credential is refused first")

    async def apply(self, step: RemediationStep) -> StepOutcome:
        raise AssertionError("unreachable: the write credential is refused first")

    async def reverse(self, step: RemediationStep) -> StepOutcome:
        raise AssertionError("unreachable: the write credential is refused first")


@pytest.mark.asyncio
async def test_enforcement_plan_event_carries_the_systems_org() -> None:
    """``create_plan`` takes the tenant from the system, on an unscoped session.

    The plan row is built ``organization_id=system.organization_id`` and its
    event must match: a remediation plan (even a refused one) names a change to
    a production system, and a NULL-org event would put one tenant's refusal in
    every other tenant's audit view.
    """
    org_id = await _org("enforce")
    system_id = await _system(org_id, "enforce-sys")

    async with session_scope() as s:
        plan = await create_plan(
            s,
            system_id=system_id,
            check_key="audit.org.sub",
            actor="operator@audit-org-sub.test",
            provider=_UnwritableProvider(),
        )
        assert plan.status == "refused", plan.status
        plan_id = plan.id

    assert await _audit_org("remediation_plan", str(plan_id)) == org_id


# --- portal ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_portal_revocation_event_carries_the_grants_own_org() -> None:
    """``revoke_grant`` resolves the tenant from the grant it is revoking.

    Unlike ``create_grant``, which is handed ``org_id`` by its caller, the
    revocation path is given only a grant id -- so the org can only come from
    the row. Driven here on an unscoped session (the CLI/admin path), where a
    caller-derived answer would be ``None``.
    """
    org_id = await _org("portal")
    async with session_scope() as s:
        grant = await portal.create_grant(
            s,
            org_id=org_id,
            principal_name="AuditOrgSub Auditor",
            kind="assessor",
            ttl_days=14,
            actor="admin@audit-org-sub.test",
        )
        grant_id = grant.id

    async with session_scope() as s:
        assert await portal.revoke_grant(s, grant_id, actor="admin@audit-org-sub.test") is True

    # Two events for this grant: issuance then revocation. Both are this
    # tenant's, and the revocation is the one resolved from the row.
    assert await _audit_orgs("external_grant", str(grant_id)) == [org_id, org_id]


# --- identity / provisioning -------------------------------------------------


@pytest.mark.asyncio
async def test_scim_refuses_the_call_that_made_caller_and_owner_differ() -> None:
    """This test used to pin the audit org for a cross-tenant SCIM update.

    Its premise was real: ``scim_create_or_update_user`` looked the account up
    by a globally-unique email with no org predicate, on a session that is
    never tenant-clamped, so a call made against org A really did update org
    B's user -- and the event was correctly filed under B, the tenant that owns
    the account, rather than under the caller.

    That was the right answer to the wrong question. The write itself was the
    defect: one deployment-wide SCIM token could rename and deactivate any
    tenant's user. It now raises ``ProvisioningConflictError`` (409 at the
    route), so caller and owner can no longer differ here at all.

    What this pins now is the refusal, and that the refused call leaves no
    trace on the victim -- neither a field change nor an event filed under
    their organization.
    """
    token_org = await _org("scim-caller")
    owner_org = await _org("scim-owner")
    assert token_org != owner_org
    email = f"scim-{next(_SEQ)}@audit-org-sub.test"

    async with session_scope() as s:
        s.add(
            User(
                email=email,
                organization_id=owner_org,
                role="viewer",
                active=True,
                full_name="Owner Original Name",
            )
        )

    async with session_scope() as s:
        with pytest.raises(provisioning.ProvisioningConflictError):
            await provisioning.scim_create_or_update_user(
                s,
                org_id=token_org,
                payload={"userName": email, "active": False, "name": {"formatted": "Renamed"}},
            )

    async with session_scope() as s:
        user = (await s.execute(select(User).where(User.email == email))).scalar_one()
        assert user.organization_id == owner_org
        assert user.full_name == "Owner Original Name"
        assert user.active is True
        user_id = user.id

    # No event under either organization: the caller's, because nothing
    # happened, and the owner's, because nothing happened TO them either.
    # The plural helper, because the singular one asserts exactly one row.
    assert await _audit_orgs("identity", str(user_id)) == []


@pytest.mark.asyncio
async def test_a_scim_event_is_still_filed_under_the_account_owner() -> None:
    """The rule the test above used to carry, on the path that still reaches it.

    ``_audit`` stamps ``user.organization_id`` rather than the caller's
    ``org_id``. Those two are now provably equal for SCIM -- the conflict check
    rejects every call where they would differ -- so this can no longer fail by
    mutating that one expression, and it is kept as defence in depth rather
    than deleted: ``provision_from_oidc`` shares the helper, and a future
    per-tenant SCIM token would make the two values independent again.
    """
    org_id = await _org("scim-same-org")
    email = f"scim-same-{next(_SEQ)}@audit-org-sub.test"

    async with session_scope() as s:
        user, created = await provisioning.scim_create_or_update_user(
            s, org_id=org_id, payload={"userName": email, "active": True}
        )
        assert created is True
        user_id = user.id

    assert await _audit_org("identity", str(user_id)) == org_id


@pytest.mark.asyncio
async def test_jit_provisioning_event_carries_the_provisioned_users_org() -> None:
    """The OIDC callback has no principal yet, and its session is unscoped.

    Pinned alongside the SCIM case because it is the *other* transport into the
    same module and takes a different branch (account creation rather than
    lookup); a regression could easily land on one and not the other.
    """
    org_id = await _org("jit")
    email = f"jit-{next(_SEQ)}@audit-org-sub.test"

    async with session_scope() as s:
        user, created = await provisioning.provision_from_oidc(
            s, claims={"sub": f"sub-{next(_SEQ)}", "email": email, "name": "JIT"}, org_id=org_id
        )
        assert created is True
        user_id = user.id

    assert await _audit_org("identity", str(user_id)) == org_id


# --- ai_actions --------------------------------------------------------------


@pytest.mark.asyncio
async def test_ai_action_rejection_event_carries_the_runs_org() -> None:
    """``reject_run`` is handed a run, not a tenant.

    ``run_action`` is told which org it is acting for; the review decisions that
    follow are not -- they resolve the tenant from ``run.organization_id``.
    Driven on an unscoped session, so anything caller- or session-derived is
    ``None``. An AI review decision that lands NULL is published to every
    tenant, which for a record of what a model was allowed to write into a
    federal package is the worst of the shapes here.
    """
    org_id = await _org("aiaction")
    system_id = await _system(org_id, "aiaction-sys")

    async with session_scope() as s:
        run = await run_action(
            s,
            action_key="generate_assessor_brief",
            entity_type="system",
            entity_id=str(system_id),
            org_id=org_id,
            actor="analyst@audit-org-sub.test",
        )
        run_id = run.id
        assert run.organization_id == org_id

    async with session_scope() as s:
        run = await s.get(AiActionRun, run_id)
        assert run is not None
        await reject_run(s, run, reviewer="reviewer@audit-org-sub.test", note="no")

    # run_action wrote the creation event; reject_run wrote the decision.
    assert await _audit_orgs("ai_action", str(run_id)) == [org_id, org_id]


# --- ai_governance -----------------------------------------------------------


@pytest.mark.asyncio
async def test_ai_agent_risk_assessment_event_carries_the_agents_org() -> None:
    """``risk_assess`` resolves the tenant from the agent row it scores."""
    org_id = await _org("aigov")
    async with session_scope() as s:
        agent = AiAgent(
            organization_id=org_id,
            name=f"AuditOrgSub Agent {next(_SEQ)}",
            autonomy_level="full",
            production_access=True,
            regulated_data_access=True,
            external_action_capability=True,
            human_oversight="none",
            monitoring_coverage="none",
        )
        s.add(agent)
        await s.flush()
        agent_id = agent.id

    async with session_scope() as s:
        agent = await s.get(AiAgent, agent_id)
        assert agent is not None
        await risk_assess(s, agent, actor="governance@audit-org-sub.test")

    assert await _audit_org("ai_agent", str(agent_id)) == org_id


# --- cr26 / store ------------------------------------------------------------


_VALID_SDR = {
    "certificationPackageOverviewUri": "https://example.gov/cpo.json",
    "fedRampRequirements": [{"frrID": "SDR-CSO-FRR", "frrImplementation": ["Implemented."]}],
}


@pytest.mark.asyncio
async def test_cr26_document_event_carries_the_systems_org() -> None:
    """``put_document`` is given a ``system_id`` and derives the tenant from it.

    The caller supplies no organization at all, which is the point: a CR26
    deliverable is a federal filing about one system, and its audit trail is
    the only record that an earlier version of the document existed. Broadcast
    to every tenant, that record names one customer's filing to all of them.
    """
    org_id = await _org("cr26")
    system_id = await _system(org_id, "cr26-sys")

    async with session_scope() as s:
        row = await put_document(
            s,
            system_id=system_id,
            kind="sdr",
            document=_VALID_SDR,
            updated_by="author@audit-org-sub.test",
        )
        row_id = row.id

    assert await _audit_org("cr26_document", str(row_id)) == org_id


# --- self_assurance ----------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.usefixtures("_local_evidence_dir")
async def test_self_assurance_event_carries_concords_org_not_the_callers() -> None:
    """Concord's own assessment is filed under Concord's own organization.

    ``init_self_assurance`` resolves the tenant through ``_self_ids``, which
    finds-or-creates the "Concord Platform" ``Organization`` row -- it never
    looks at who asked. Driven here over HTTP with authentication off, so the
    caller is the global ``SYSTEM_PRINCIPAL`` (``org_id is None``) and the two
    answers are provably different: the event must carry a real organization id
    while the caller has none.

    Whether "Concord Platform" is the *right* tenant is a product question,
    not a scoping one: today the whole feature is operator-only, and an
    org-scoped admin cannot reach it at all (``_self_ids`` cannot see Concord's
    organization row through that caller's RLS clamp). What is not in question
    is that the event must not be NULL: NULL is the broadcast value, and it
    would publish Concord's own internal self-assessment -- including its
    failures -- to every customer's audit view.
    """
    async with _client() as c:
        r = await c.post("/api/admin/self-assurance/init")
        assert r.status_code == 200, r.text
        system_id = r.json()["system_id"]
        caller_org = r.json()["organization_id"]

    async with session_scope() as s:
        self_org = (
            await s.execute(select(Organization.id).where(Organization.name == SELF_ORG))
        ).scalar_one()
    assert caller_org == self_org

    orgs = await _audit_orgs("self_assurance", str(system_id))
    assert orgs, "self-assurance init recorded no audit event"
    assert set(orgs) == {self_org}, (
        "Concord's self-assessment must be filed under Concord's own "
        f"organization ({self_org}), not {orgs}"
    )
    # ...and not under the caller, who has no organization at all.
    assert None not in orgs
