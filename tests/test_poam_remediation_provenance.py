"""A re-scan refreshes its own remediation guidance and never an analyst's.

A failed automated control test seeds ``POAM.remediation_plan`` with
deterministic guidance, and a later scan of the same failing check has to
refresh it: the observed condition and the failing-resource counts move between
runs. What it must not do is overwrite somebody's work.

The first implementation decided that by prose -- overwrite when the stored text
still began ``"Remediation objective:"``. That reads as a marker and behaves as a
trap, because the most natural analyst edit there is (append a milestone, correct
the recommended action) keeps that first line. It is also the same mistake
migration 0089 had just fixed one table over: provenance carried in free text
that nothing maintains. ``POAM.remediation_plan_source`` makes it structural.
"""

from __future__ import annotations

import itertools
import os
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance.control_tests import GENERATED_PLAN, remediation_guidance
from ccf.models import POAM, Organization, System, User
from ccf.models_grc import ControlTest
from ccf.posture import scan as scan_mod
from ccf.posture.checks import CheckOutcome, PostureCheck, ResourceFinding
from ccf.posture.scan import scan_for_system

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()

CHECK = PostureCheck(
    key="demo.bucket.public",
    title="Buckets block public access",
    provider="demo_provider",
    resource_type="bucket",
    expected="public access blocked",
    control_ids=("AC-3",),
)


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _failing(*, failing: int = 1) -> CheckOutcome:
    findings = tuple(
        ResourceFinding(f"res-{i}", "bucket", "fail", f"public bucket {i}")
        for i in range(failing)
    )
    return CheckOutcome.from_findings(CHECK, findings)


def _patch(monkeypatch: pytest.MonkeyPatch, outcome: CheckOutcome) -> None:
    class _Conn:
        key = "demo_provider"

        def is_configured(self) -> bool:
            return True

        async def scan(self, checks: object = None) -> list[CheckOutcome]:
            return [outcome]

    async def _fake_connector(*a: object, **k: object) -> _Conn:
        return _Conn()

    async def _fake_resolve(*a: object, **k: object) -> tuple[object, ...]:
        return (SimpleNamespace(check=CHECK, endpoint="/demo", source="platform"),)

    monkeypatch.setattr(scan_mod, "resolve_checks", _fake_resolve)
    monkeypatch.setattr(scan_mod, "_connector_for_org", _fake_connector)


async def _system() -> int:
    async with session_scope() as s:
        org = Organization(name=f"RemOrg-{next(_SEQ)}-{uuid.uuid4().hex[:6]}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"RemSys-{next(_SEQ)}")
        s.add(sys_)
        await s.flush()
        return sys_.id


async def _poam(system_id: int) -> POAM:
    async with session_scope() as s:
        return (
            await s.execute(select(POAM).where(POAM.system_id == system_id))
        ).scalars().one()


# ---------------------------------------------------------------------------
# What the scan writes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_failed_check_seeds_guidance_labelled_as_generated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _failing())
    system_id = await _system()
    async with session_scope() as s:
        await scan_for_system(s, system_id=system_id, connector_key="demo_provider")

    poam = await _poam(system_id)
    assert poam.remediation_plan_source == GENERATED_PLAN
    # Every section the plan document asks for.
    for section in (
        "Remediation objective",
        "Automated check",
        "Observed condition",
        "Recommended actions",
        "Validation evidence",
        "SSP impact",
    ):
        assert section in poam.remediation_plan, section
    assert "public access blocked" in poam.remediation_plan, "the expected state is not cited"


@pytest.mark.asyncio
async def test_a_generated_plan_is_refreshed_when_the_observation_moves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The count of failing resources is part of the guidance, so it has to follow."""
    _patch(monkeypatch, _failing(failing=1))
    system_id = await _system()
    async with session_scope() as s:
        await scan_for_system(s, system_id=system_id, connector_key="demo_provider")
    first = (await _poam(system_id)).remediation_plan

    _patch(monkeypatch, _failing(failing=3))
    async with session_scope() as s:
        await scan_for_system(s, system_id=system_id, connector_key="demo_provider")
    second = await _poam(system_id)

    assert second.remediation_plan != first, "a generated plan went stale"
    assert "3 of 3" in second.remediation_plan
    assert second.remediation_plan_source == GENERATED_PLAN


# ---------------------------------------------------------------------------
# What the scan must leave alone
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_analyst_edit_survives_a_rescan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The defect this column exists for.

    The analyst keeps the generated first line and appends their own plan --
    the likeliest edit of all. Under a prose-prefix test the next scan wiped it.
    """
    _patch(monkeypatch, _failing())
    system_id = await _system()
    async with session_scope() as s:
        await scan_for_system(s, system_id=system_id, connector_key="demo_provider")

    edited = (
        "Remediation objective: bring AC-3 into alignment so public access blocked.\n"
        "Owner: J. Reyes. Bucket policy change scheduled for the 12 Oct window; "
        "CAB ticket CHG-4471."
    )
    async with session_scope() as s:
        poam = (
            await s.execute(select(POAM).where(POAM.system_id == system_id))
        ).scalars().one()
        poam.remediation_plan = edited
        poam.remediation_plan_source = "analyst"

    _patch(monkeypatch, _failing(failing=5))
    async with session_scope() as s:
        await scan_for_system(s, system_id=system_id, connector_key="demo_provider")

    after = await _poam(system_id)
    assert after.remediation_plan == edited, "the re-scan destroyed an analyst's plan"
    assert after.remediation_plan_source == "analyst"
    # The machine-owned half still moves: the weakness carries the new count.
    assert "5 of 5" in (after.weakness or "")


@pytest.mark.asyncio
async def test_an_approved_ai_draft_survives_a_rescan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An AI draft carries its own provenance badge; overwriting it would
    silently retract what a reviewer approved."""
    _patch(monkeypatch, _failing())
    system_id = await _system()
    async with session_scope() as s:
        await scan_for_system(s, system_id=system_id, connector_key="demo_provider")
    async with session_scope() as s:
        poam = (
            await s.execute(select(POAM).where(POAM.system_id == system_id))
        ).scalars().one()
        poam.remediation_plan = "AI-drafted remediation, approved 2026-09-26."
        poam.remediation_plan_source = "ai"

    _patch(monkeypatch, _failing(failing=2))
    async with session_scope() as s:
        await scan_for_system(s, system_id=system_id, connector_key="demo_provider")

    after = await _poam(system_id)
    assert after.remediation_plan == "AI-drafted remediation, approved 2026-09-26."
    assert after.remediation_plan_source == "ai"


@pytest.mark.asyncio
async def test_an_empty_plan_is_filled_and_claimed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing to protect, so the scan fills it -- and labels it, so the next
    scan may keep it current rather than freezing it forever."""
    _patch(monkeypatch, _failing())
    system_id = await _system()
    async with session_scope() as s:
        await scan_for_system(s, system_id=system_id, connector_key="demo_provider")
    async with session_scope() as s:
        poam = (
            await s.execute(select(POAM).where(POAM.system_id == system_id))
        ).scalars().one()
        poam.remediation_plan = None
        poam.remediation_plan_source = "analyst"

    async with session_scope() as s:
        await scan_for_system(s, system_id=system_id, connector_key="demo_provider")

    after = await _poam(system_id)
    assert after.remediation_plan, "an empty plan was left empty"
    assert after.remediation_plan_source == GENERATED_PLAN


# ---------------------------------------------------------------------------
# Provenance is set by the write, never claimed by the body
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _auth_enabled():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_editing_a_plan_over_the_api_marks_it_the_analysts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The realistic path: a person edits the POA&M through the API.

    They never send the provenance -- it is a fact about who made the call, so a
    body must not be able to claim it.
    """
    _patch(monkeypatch, _failing())
    tag = uuid.uuid4().hex[:6]
    async with session_scope() as s:
        org = Organization(name=f"RemApi {tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"a-{tag}@rem.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        sys_ = System(organization_id=org.id, name=f"RemApiSys {tag}")
        s.add(sys_)
        await s.flush()
        token, system_id = user.api_token, sys_.id

    async with session_scope() as s:
        await scan_for_system(s, system_id=system_id, connector_key="demo_provider")
    poam = await _poam(system_id)
    assert poam.remediation_plan_source == GENERATED_PLAN

    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://t"
    ) as c:
        r = await c.patch(
            f"/api/poams/{poam.id}",
            json={"remediation_plan": "Owner assigned; fix in the 12 Oct window."},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200, r.text

    after = await _poam(system_id)
    assert after.remediation_plan_source == "analyst"

    _patch(monkeypatch, _failing(failing=4))
    async with session_scope() as s:
        await scan_for_system(s, system_id=system_id, connector_key="demo_provider")
    assert (await _poam(system_id)).remediation_plan == (
        "Owner assigned; fix in the 12 Oct window."
    )


@pytest.mark.asyncio
async def test_a_write_that_does_not_touch_the_plan_leaves_its_provenance_alone() -> None:
    """Changing the owner or the due date says nothing about who wrote the plan."""
    tag = uuid.uuid4().hex[:6]
    async with session_scope() as s:
        org = Organization(name=f"RemUntouched {tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"u-{tag}@rem.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        sys_ = System(organization_id=org.id, name=f"RemUntouchedSys {tag}")
        s.add(sys_)
        await s.flush()
        poam = POAM(
            system_id=sys_.id,
            title="Seeded",
            status="open",
            severity="high",
            remediation_plan="Generated text.",
            remediation_plan_source=GENERATED_PLAN,
            identified_on=datetime.now(UTC).date(),
        )
        s.add(poam)
        await s.flush()
        token, pid = user.api_token, poam.id

    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://t"
    ) as c:
        r = await c.patch(
            f"/api/poams/{pid}",
            json={"point_of_contact": "ops@x.gov"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200, r.text

    async with session_scope() as s:
        after = await s.get(POAM, pid)
    assert after.remediation_plan_source == GENERATED_PLAN


def test_the_guidance_never_asserts_the_tenant_has_done_anything() -> None:
    """Guidance is instructions, not a claim about posture.

    A sentence like "this control is now implemented" in a POA&M's remediation
    plan would be an unevidenced claim in an authorization artifact -- the defect
    class this codebase keeps finding. Every line is the check's own expectation,
    this run's observation, or a standing question.
    """
    test = ControlTest(
        organization_id=1,
        system_id=1,
        control_id="AC-3",
        name="Buckets block public access",
        method="connector",
        check_key="demo.bucket.public",
        expected="public access blocked",
        connector_type="demo_provider",
    )
    text = remediation_guidance(test, "1 of 1 bucket(s) failing").lower()
    for claim in ("is implemented", "now compliant", "has been remediated", "is satisfied"):
        assert claim not in text, claim
