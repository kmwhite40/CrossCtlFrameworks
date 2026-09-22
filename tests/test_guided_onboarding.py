"""The guided onboarding path: every state, driven by real rows.

Spec: ``docs/superpowers/specs/2026-09-21-guided-onboarding-design.md`` §8.

**Nothing here stubs :func:`ccf.onboarding.onboarding_state` or any signal it
reads.** Every state is reached by seeding the rows a customer would really
have -- a ``SystemProfile``, a ``ConnectorConfig`` that has or has not synced,
an ``SSPProject`` with entries, a derivation, POA&Ms, packages, CR26 documents,
an ``AssessmentEngagement`` -- because a test that mocks the signal proves only
that the mock works. The one thing that is patched anywhere in this module is
nothing at all.

Two tests exist to stop the page becoming a ratchet (§8.3): a connector that
stops capturing and an engagement that is revoked each take their step *back*
from ``done``. A path that only moved forward would be making a false claim
the day something expires.

Every test cleans up its own rows in ``try``/``finally``. Deleting the
``Organization`` cascades to systems, profiles, POA&Ms, connector configs,
packages, external principals, engagements and CR26 documents; ``SSPProject``
and the global ``KSI`` catalog rows do **not** cascade, so they are deleted by
hand. A leftover ``cr26_documents`` row with a non-NULL ``document_key`` breaks
migration 0081's downgrade for every later session on this database, so this
module writes ``document_key=None`` exclusively and still deletes what it
wrote.
"""

from __future__ import annotations

import itertools
import os
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from markupsafe import escape
from sqlalchemy import delete, select

from ccf.analytics.posture import systems_scorecard
from ccf.api.main import create_app
from ccf.api.routes.ui import ONBOARDING_CHIPS, ONBOARDING_STATE_LABELS
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import automation
from ccf.models import (
    KSI,
    POAM,
    CaptureSnapshot,
    InformationType,
    KSIState,
    Organization,
    SSPControlEntry,
    SSPProject,
    System,
    SystemComponent,
    SystemProfile,
    User,
)
from ccf.models_cr26 import Cr26Document
from ccf.models_grc import ConnectorConfig
from ccf.models_packages import AuthorizationPackage
from ccf.models_portal import AssessmentEngagement, ExternalPrincipal
from ccf.onboarding import (
    DONE,
    IN_PROGRESS,
    NOT_AVAILABLE,
    NOT_STARTED,
    STATES,
    UNKNOWN,
    Step,
    onboarding_state,
)
from ccf.ssp.completeness_query import project_completeness

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
async def auth_on() -> AsyncIterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _tag() -> str:
    return f"gop{next(_SEQ)}"


# Front matter with every ``REQUIRED_METADATA`` entry present -- the front-matter
# half of what it takes for an SSP project to be genuinely ``ready``.
_FULL_META: dict[str, Any] = {
    "system_type": "Cloud information system (CUI)",
    "fips199": {"overall": "moderate"},
    "authorization_boundary": "The tenant and its managed services.",
    "roles": {
        "system_owner": {"name": "Dana Owner"},
        "isso": {"name": "Sam ISSO"},
        "authorizing_official": {"name": "Alex AO"},
    },
}


async def _mk(tag: str, **system_kw: Any) -> tuple[int, int]:
    """An Organization + a System in it. Returns ``(org_id, system_id)``."""
    async with session_scope() as s:
        org = Organization(name=f"Onboarding Org {tag}")
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"Onboarding Sys {tag}", **system_kw)
        s.add(sysrow)
        await s.flush()
        return org.id, sysrow.id


async def _drop(org_id: int, system_id: int) -> None:
    """Remove everything a test seeded. See this module's docstring."""
    async with session_scope() as s:
        # SSPProject.system_id / organization_id are SET NULL, not CASCADE, so
        # dropping the org would leave orphans behind rather than clean up.
        await s.execute(delete(SSPControlEntry).where(
            SSPControlEntry.project_id.in_(
                select(SSPProject.id).where(SSPProject.system_id == system_id)
            )
        ))
        await s.execute(delete(SSPProject).where(SSPProject.system_id == system_id))
        # ``ksis`` is a global reference catalog with no organization at all.
        await s.execute(delete(KSIState).where(KSIState.system_id == system_id))
        await s.execute(delete(KSI).where(KSI.identifier.like("ZZO-%")))
        await s.execute(delete(Cr26Document).where(Cr26Document.system_id == system_id))
        await s.execute(delete(Organization).where(Organization.id == org_id))


async def _steps(system_id: int) -> dict[str, Step]:
    """The real service, against real rows, keyed by step."""
    async with session_scope() as s:
        system = (await session_get(s, system_id))
        steps = await onboarding_state(s, system)
    assert [x.number for x in steps] == [1, 2, 3, 4, 5, 6]
    return {x.key: x for x in steps}


async def session_get(s: Any, system_id: int) -> System:
    row = (await s.execute(select(System).where(System.id == system_id))).scalar_one()
    return row  # type: ignore[no-any-return]


# --- step 1: answer the intake questionnaire -------------------------------


@pytest.mark.asyncio
async def test_step1_walks_not_started_to_in_progress_to_done() -> None:
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        assert (await _steps(sys_id))["intake"].state == NOT_STARTED

        async with session_scope() as s:
            s.add(SystemProfile(system_id=sys_id, cloud_platform="m365_gcc_high"))
        step = (await _steps(sys_id))["intake"]
        # Answers on file but never derived: begun, and the remainder is named
        # rather than counted.
        assert step.state == IN_PROGRESS
        assert "derived" in step.detail

        async with session_scope() as s:
            prof = (
                await s.execute(
                    select(SystemProfile).where(SystemProfile.system_id == sys_id)
                )
            ).scalar_one()
            prof.derived_at = datetime.now(UTC)
        assert (await _steps(sys_id))["intake"].state == DONE
    finally:
        await _drop(org_id, sys_id)


# --- step 2: connect your evidence sources ---------------------------------


@pytest.mark.asyncio
async def test_step2_is_unknown_when_no_platform_is_declared() -> None:
    """No profile at all: Concord cannot tell which connector would apply, and
    must say so rather than report "nothing connected"."""
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        step = (await _steps(sys_id))["connect_evidence"]
        assert step.state == UNKNOWN
        assert step.state not in (DONE, NOT_STARTED)
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step2_is_unknown_for_an_unrecognized_platform() -> None:
    """A declared platform Concord has no mapping for must not silently become
    Microsoft 365 (which ``normalize_platform`` would do), and must not be
    reported as "no connector exists" either."""
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        async with session_scope() as s:
            s.add(SystemProfile(system_id=sys_id, cloud_platform="oracle_gov"))
        step = (await _steps(sys_id))["connect_evidence"]
        assert step.state == UNKNOWN
        assert "oracle_gov" in step.detail
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step2_is_real_work_on_azure_now_that_a_connector_exists() -> None:
    """Spec §8.4, updated by ``feat/azure-gov-connector``.

    Azure used to be the platform Concord shipped no connector for, so step 2
    was ``not_available`` -- not work the customer had failed to do. The ARM
    connector makes it work they genuinely have not started, and reporting
    "nothing to connect" would now tell an Azure customer their SSP cannot be
    evidenced automatically when it can.
    """
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        async with session_scope() as s:
            s.add(SystemProfile(system_id=sys_id, cloud_platform="azure_gov"))
        step = (await _steps(sys_id))["connect_evidence"]
        assert step.state == NOT_STARTED
        assert step.state != NOT_AVAILABLE
        assert step.state != DONE
        # And the sentence names the connector they can actually go configure.
        assert "azure_arm" in step.detail
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step2_is_not_available_when_the_customer_declared_no_cloud() -> None:
    """``cloud_platform='none'`` is a real questionnaire answer, and it is the
    customer spec §4.1 refuses to show a permanently red step 2 to.

    Now the *only* way to reach ``not_available`` from a recognized answer,
    since every platform Concord recognizes has a connector -- so the
    chip-distinctness this state exists for is asserted here rather than on
    the Azure case that used to carry it.
    """
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        async with session_scope() as s:
            s.add(SystemProfile(system_id=sys_id, cloud_platform="none"))
        step = (await _steps(sys_id))["connect_evidence"]
        assert step.state == NOT_AVAILABLE
        assert step.state != NOT_STARTED
        assert step.state != DONE
        # Distinct to a reader, not only to the code: the reader sees the chip.
        assert ONBOARDING_CHIPS[NOT_AVAILABLE] != ONBOARDING_CHIPS[NOT_STARTED]
        assert ONBOARDING_CHIPS[NOT_AVAILABLE] != ONBOARDING_CHIPS[DONE]
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step2_walks_not_started_to_in_progress_to_done() -> None:
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        async with session_scope() as s:
            s.add(SystemProfile(system_id=sys_id, cloud_platform="m365_gcc_high"))
        assert (await _steps(sys_id))["connect_evidence"].state == NOT_STARTED

        async with session_scope() as s:
            s.add(
                ConnectorConfig(
                    organization_id=org_id,
                    name="Graph",
                    connector_type="msgraph",
                    status="not_configured",
                )
            )
        # A row exists but nothing has been captured: begun, not done. An empty
        # capture must never read as the favourable answer.
        assert (await _steps(sys_id))["connect_evidence"].state == IN_PROGRESS

        async with session_scope() as s:
            conn = (
                await s.execute(
                    select(ConnectorConfig).where(ConnectorConfig.organization_id == org_id)
                )
            ).scalar_one()
            conn.status = "configured"
            conn.last_sync = datetime.now(UTC)
            conn.objects_discovered = 42
        # Healthy status columns are no longer the whole answer: the step is
        # done only once a real capture ARTIFACT exists for this org. Without
        # this the credential-free mock sync route -- which writes exactly the
        # three columns above and nothing else -- would report "connected" to a
        # customer who has connected nothing.
        assert (await _steps(sys_id))["connect_evidence"].state == IN_PROGRESS

        async with session_scope() as s:
            s.add(
                CaptureSnapshot(
                    organization_id=org_id,
                    connector="msgraph",
                    odp_key="mfa_enforced",
                    value="true",
                    captured_at=datetime.now(UTC),
                )
            )
        assert (await _steps(sys_id))["connect_evidence"].state == DONE
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step2_goes_backwards_when_a_connector_stops_capturing() -> None:
    """Spec §8.3. This is the test that stops the path becoming a ratchet: a
    step that reached ``done`` must be able to leave it."""
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        async with session_scope() as s:
            s.add(SystemProfile(system_id=sys_id, cloud_platform="m365_gcc_high"))
            s.add(
                ConnectorConfig(
                    organization_id=org_id,
                    name="Graph",
                    connector_type="msgraph",
                    status="configured",
                    last_sync=datetime.now(UTC),
                    objects_discovered=42,
                )
            )
            s.add(
                CaptureSnapshot(
                    organization_id=org_id,
                    connector="msgraph",
                    odp_key="mfa_enforced",
                    value="true",
                    captured_at=datetime.now(UTC),
                )
            )
        assert (await _steps(sys_id))["connect_evidence"].state == DONE

        # The connector is disconnected. The evidence it was producing stops;
        # the step must stop saying it is done.
        async with session_scope() as s:
            conn = (
                await s.execute(
                    select(ConnectorConfig).where(ConnectorConfig.organization_id == org_id)
                )
            ).scalar_one()
            conn.status = "not_configured"
        assert (await _steps(sys_id))["connect_evidence"].state != DONE

        # And again for a sync that has simply gone stale -- nobody revoked
        # anything, time passed.
        async with session_scope() as s:
            conn = (
                await s.execute(
                    select(ConnectorConfig).where(ConnectorConfig.organization_id == org_id)
                )
            ).scalar_one()
            conn.status = "configured"
            conn.last_sync = datetime.now(UTC) - timedelta(days=400)
        assert (await _steps(sys_id))["connect_evidence"].state != DONE

        # And once more for the artifact: the connector reports a healthy,
        # recent, non-empty sync again, but it has produced nothing for a long
        # time. ``last_sync`` says it RAN; ``captured_at`` says what it
        # produced, and where they disagree the artifact is the honest one.
        async with session_scope() as s:
            conn = (
                await s.execute(
                    select(ConnectorConfig).where(ConnectorConfig.organization_id == org_id)
                )
            ).scalar_one()
            conn.last_sync = datetime.now(UTC)
            snap = (
                await s.execute(
                    select(CaptureSnapshot).where(CaptureSnapshot.organization_id == org_id)
                )
            ).scalar_one()
            snap.captured_at = datetime.now(UTC) - timedelta(days=400)
        assert (await _steps(sys_id))["connect_evidence"].state != DONE
    finally:
        await _drop(org_id, sys_id)


# --- step 3: generate and refine the SSP -----------------------------------


async def _seed_ready_boundary(org_id: int, sys_id: int) -> None:
    """The boundary rows ``assess``'s four boundary checks need to pass.

    The System carries no FIPS-199 triad, so ``reconcile_categorization``
    has nothing to disagree with and there are no interconnections to lack an
    agreement.
    """
    async with session_scope() as s:
        s.add(
            SystemComponent(
                organization_id=org_id, system_id=sys_id, type="service", title="API"
            )
        )
        s.add(
            InformationType(
                organization_id=org_id, system_id=sys_id, title="Controlled Unclassified"
            )
        )


async def _add_project(sys_id: int, *, title: str, complete: bool) -> int:
    """One SSPProject with a single entry, deliberately complete or not."""
    async with session_scope() as s:
        project = SSPProject(
            system_id=sys_id,
            customer_name="Onboarding Co",
            title=title,
            metadata_json=dict(_FULL_META) if complete else {},
        )
        s.add(project)
        await s.flush()
        entry = SSPControlEntry(
            project_id=project.id,
            control_id="ZZO.L2-9.9.1",
            sort_order=0,
            responsible_role="Dana Owner" if complete else None,
            # "Planned" is deliberately not an evidence-requiring status, so a
            # complete entry needs no Evidence row to avoid the
            # "implemented without evidence" gap.
            implementation_status=["Planned"] if complete else [],
            control_origination=["Service Provider Corporate"] if complete else [],
            part_narratives=(
                [{"part": "a", "text": "Access is restricted to named administrators."}]
                if complete
                else []
            ),
            odp_values={},
        )
        s.add(entry)
        await s.flush()
        return project.id


@pytest.mark.asyncio
async def test_step3_walks_not_started_to_in_progress_to_done() -> None:
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        assert (await _steps(sys_id))["ssp"].state == NOT_STARTED

        await _add_project(sys_id, title="Draft SSP", complete=False)
        step = (await _steps(sys_id))["ssp"]
        assert step.state == IN_PROGRESS
        # The remainder is named: the incomplete control is identified, not
        # merely counted.
        assert "ZZO.L2-9.9.1" in step.detail

        await _seed_ready_boundary(org_id, sys_id)
        async with session_scope() as s:
            project = (
                await s.execute(select(SSPProject).where(SSPProject.system_id == sys_id))
            ).scalar_one()
            project.metadata_json = dict(_FULL_META)
            entry = (
                await s.execute(
                    select(SSPControlEntry).where(SSPControlEntry.project_id == project.id)
                )
            ).scalar_one()
            entry.responsible_role = "Dana Owner"
            entry.implementation_status = ["Planned"]
            entry.control_origination = ["Service Provider Corporate"]
            entry.part_narratives = [
                {"part": "a", "text": "Access is restricted to named administrators."}
            ]
        assert (await _steps(sys_id))["ssp"].state == DONE
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step3_is_unknown_when_several_projects_are_linked() -> None:
    """``SSPProject.system_id`` is nullable and not unique, so a system can have
    many plans and no column says which one is *the* plan.

    The rule under test: with more than one, the step is ``unknown`` and names
    the ambiguity. Any tie-break would be this page inventing an answer -- and
    scoring the newest, the obvious choice, would make the step move *backwards*
    the moment somebody began a second draft.
    """
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        await _seed_ready_boundary(org_id, sys_id)
        await _add_project(sys_id, title="Plan A", complete=True)
        # One complete plan alone is done...
        assert (await _steps(sys_id))["ssp"].state == DONE

        await _add_project(sys_id, title="Plan B", complete=False)
        step = (await _steps(sys_id))["ssp"]
        # ...and a second plan makes it unanswerable, not averaged and not
        # silently resolved to either one.
        assert step.state == UNKNOWN
        assert step.state not in (DONE, NOT_STARTED)
        assert "Plan A" in step.detail and "Plan B" in step.detail
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step3_score_is_project_completeness_and_not_a_second_number() -> None:
    """The percentage the step reports is ``project_completeness``'s own, by
    equality -- not a figure this page computes from the same rows."""
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        await _seed_ready_boundary(org_id, sys_id)
        await _add_project(sys_id, title="Draft SSP", complete=False)
        async with session_scope() as s:
            project = (
                await s.execute(select(SSPProject).where(SSPProject.system_id == sys_id))
            ).scalar_one()
            expected = await project_completeness(s, project)
        step = (await _steps(sys_id))["ssp"]
        assert f"Scored {expected['score']}%" in step.detail
    finally:
        await _drop(org_id, sys_id)


# --- step 4: close the gaps -------------------------------------------------


def _derivation(*, covered: int, uncovered: int) -> dict[str, Any]:
    """A ``SystemProfile.derivation`` snapshot of the shape ``coverage`` reads.

    ``source`` is a vendor inheritance, never ``"platform:..."``, so the rollup
    does not depend on whether a connector happens to be live -- these tests are
    about step 4's own rules, and step 2 already covers connector liveness.
    """
    d: dict[str, Any] = {}
    for i in range(covered):
        d[f"ZZO.L2-9.1.{i}"] = {
            "state": "implemented", "responsibility": "customer",
            "source": "vendor:acme", "domain": "AC", "point_value": 1,
        }
    for i in range(uncovered):
        d[f"ZZO.L2-9.2.{i}"] = {
            "state": "not_implemented", "responsibility": "customer",
            "source": "default", "domain": "AC", "point_value": 1,
        }
    return d


@pytest.mark.asyncio
async def test_step4_is_unknown_without_a_derivation() -> None:
    """No derivation means no known set of applicable controls. "0 gaps" would
    read as the favourable answer; ``unknown`` says what is true."""
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        step = (await _steps(sys_id))["close_gaps"]
        assert step.state == UNKNOWN
        assert step.state not in (DONE, NOT_STARTED)

        # A profile that exists but was never derived is equally unanswerable.
        async with session_scope() as s:
            s.add(SystemProfile(system_id=sys_id, cloud_platform="m365_gcc_high"))
        assert (await _steps(sys_id))["close_gaps"].state == UNKNOWN
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step4_walks_not_started_to_in_progress_to_done() -> None:
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        async with session_scope() as s:
            s.add(
                SystemProfile(
                    system_id=sys_id,
                    cloud_platform="m365_gcc_high",
                    derived_at=datetime.now(UTC),
                    derivation=_derivation(covered=0, uncovered=3),
                )
            )
        step = (await _steps(sys_id))["close_gaps"]
        # Derived, nothing covered, nothing recorded against it: the platform
        # positively knows no work has started.
        assert step.state == NOT_STARTED

        async with session_scope() as s:
            s.add(
                POAM(
                    system_id=sys_id,
                    title="Encrypt the backup bucket",
                    status="open",
                    due_on=date.today() - timedelta(days=10),
                )
            )
        step = (await _steps(sys_id))["close_gaps"]
        assert step.state == IN_PROGRESS
        assert "1 open POA&M(s)" in step.detail

        async with session_scope() as s:
            prof = (
                await s.execute(
                    select(SystemProfile).where(SystemProfile.system_id == sys_id)
                )
            ).scalar_one()
            prof.derivation = _derivation(covered=3, uncovered=0)
            poam = (
                await s.execute(select(POAM).where(POAM.system_id == sys_id))
            ).scalar_one()
            poam.status = "closed"
        step = (await _steps(sys_id))["close_gaps"]
        assert step.state == DONE
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step4_counts_the_ksis_that_are_not_passing() -> None:
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        async with session_scope() as s:
            s.add(
                SystemProfile(
                    system_id=sys_id,
                    cloud_platform="m365_gcc_high",
                    derived_at=datetime.now(UTC),
                    derivation=_derivation(covered=2, uncovered=0),
                )
            )
            ksi_pass = KSI(identifier="ZZO-01", category="IAM", name="MFA everywhere")
            ksi_fail = KSI(identifier="ZZO-02", category="IAM", name="No standing access")
            s.add_all([ksi_pass, ksi_fail])
            await s.flush()
            s.add(KSIState(system_id=sys_id, ksi_id=ksi_pass.id, status="pass"))
            s.add(KSIState(system_id=sys_id, ksi_id=ksi_fail.id, status="fail"))
        step = (await _steps(sys_id))["close_gaps"]
        assert step.state == IN_PROGRESS
        assert "1 of 2 key security indicators not passing" in step.detail
        assert "fail" in step.detail

        # A KSI recorded as not applicable is a decision, not outstanding work.
        async with session_scope() as s:
            state = (
                await s.execute(
                    select(KSIState)
                    .where(KSIState.system_id == sys_id, KSIState.status == "fail")
                )
            ).scalar_one()
            state.status = "not_applicable"
        assert (await _steps(sys_id))["close_gaps"].state == DONE
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step4_poam_counts_equal_systems_scorecard() -> None:
    """Spec §8.5. Asserted by equality against ``systems_scorecard``'s own
    numbers, including its definition of overdue -- a second overdue count in
    one product is how a dashboard and its source start to disagree."""
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        today = date.today()
        async with session_scope() as s:
            s.add(
                SystemProfile(
                    system_id=sys_id,
                    cloud_platform="m365_gcc_high",
                    derived_at=datetime.now(UTC),
                    derivation=_derivation(covered=1, uncovered=1),
                )
            )
            s.add_all([
                POAM(system_id=sys_id, title="Overdue by due_on", status="open",
                     due_on=today - timedelta(days=5)),
                # No due_on at all: overdue falls back to scheduled_completion,
                # which is exactly the rule this page must not restate.
                POAM(system_id=sys_id, title="Overdue by schedule", status="in_progress",
                     scheduled_completion=today - timedelta(days=2)),
                POAM(system_id=sys_id, title="On track", status="open",
                     due_on=today + timedelta(days=30)),
                POAM(system_id=sys_id, title="Closed", status="closed",
                     due_on=today - timedelta(days=90)),
            ])

        async with session_scope() as s:
            cards = await systems_scorecard(s, today=today, org_id=org_id)
        card = next(c for c in cards if c["system_id"] == sys_id)
        assert card["open_poams"] == 3
        assert card["overdue_poams"] == 2

        step = (await _steps(sys_id))["close_gaps"]
        assert (
            f"{card['open_poams']} open POA&M(s), "
            f"{card['overdue_poams']} of them overdue"
        ) in step.detail
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step4_coverage_equals_the_automation_rollup() -> None:
    """The coverage figures are ``automation.coverage``'s, with
    ``connector_backed`` computed the way ``api/routes/automation.py``
    computes it -- not guessed, and not a second rollup."""
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        async with session_scope() as s:
            s.add(
                SystemProfile(
                    system_id=sys_id,
                    cloud_platform="m365_gcc_high",
                    derived_at=datetime.now(UTC),
                    derivation=_derivation(covered=2, uncovered=5),
                )
            )
        async with session_scope() as s:
            prof = (
                await s.execute(
                    select(SystemProfile).where(SystemProfile.system_id == sys_id)
                )
            ).scalar_one()
            backed = await automation.platform_capture_is_live(
                s,
                organization_id=org_id,
                platform=automation.PLATFORM_TO_SSP.get(prof.cloud_platform or "", ""),
            )
            expected = automation.coverage(prof, connector_backed=backed)
        step = (await _steps(sys_id))["close_gaps"]
        uncovered = expected["total"] - expected["covered"]
        assert f"{uncovered} of {expected['total']} applicable controls" in step.detail
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step4_names_controls_covered_only_by_an_uncaptured_platform_default() -> None:
    """``connector_backed=False`` moves ``platform:``-sourced rows out of
    ``covered`` and into ``manual_evidence_required``. That is a real remainder
    with a name, and the step must say it rather than report those controls as
    covered."""
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        derivation = {
            "ZZO.L2-9.3.0": {
                "state": "inherited", "responsibility": "shared",
                "source": "platform:m365_gcc_high", "domain": "AC", "point_value": 1,
            }
        }
        async with session_scope() as s:
            s.add(
                SystemProfile(
                    system_id=sys_id,
                    cloud_platform="m365_gcc_high",
                    derived_at=datetime.now(UTC),
                    derivation=derivation,
                )
            )
        step = (await _steps(sys_id))["close_gaps"]
        assert step.state == IN_PROGRESS
        assert "a human must attach evidence" in step.detail

        # Once the tenant really is capturing, the same row counts as covered.
        async with session_scope() as s:
            s.add(
                ConnectorConfig(
                    organization_id=org_id,
                    name="Graph",
                    connector_type="msgraph",
                    status="configured",
                    last_sync=datetime.now(UTC),
                    objects_discovered=7,
                )
            )
            s.add(
                CaptureSnapshot(
                    organization_id=org_id,
                    connector="msgraph",
                    odp_key="mfa_enforced",
                    value="true",
                    captured_at=datetime.now(UTC),
                )
            )
        assert (await _steps(sys_id))["close_gaps"].state == DONE
    finally:
        await _drop(org_id, sys_id)


# --- step 5: produce the package -------------------------------------------


def _cr26_doc(org_id: int, sys_id: int, kind: str, *, valid: bool) -> Cr26Document:
    """A CR26 deliverable row. ``document_key`` is left NULL deliberately --
    see this module's docstring."""
    return Cr26Document(
        organization_id=org_id,
        system_id=sys_id,
        kind=kind,
        document_key=None,
        document={"stub": True},
        ruleset_version="2026-01-01",
        schema_version="1.0.0",
        is_valid=valid,
        validation_errors=[] if valid else [{"path": "/", "message": "missing field"}],
    )


@pytest.mark.asyncio
async def test_step5_walks_not_started_to_in_progress_to_done() -> None:
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        assert (await _steps(sys_id))["package"].state == NOT_STARTED

        async with session_scope() as s:
            s.add(
                AuthorizationPackage(
                    organization_id=org_id, system_id=sys_id,
                    label=f"Package {tag}", readiness_pct=97.3, fact_count=5,
                )
            )
        step = (await _steps(sys_id))["package"]
        assert step.state == IN_PROGRESS
        assert "no CR26 deliverable" in step.detail

        async with session_scope() as s:
            s.add(_cr26_doc(org_id, sys_id, "cpo", valid=False))
        step = (await _steps(sys_id))["package"]
        # A row exists, so the deliverable was authored -- but authored is not
        # filed. ``is_valid`` is the done signal, not the row.
        assert step.state == IN_PROGRESS
        assert "cpo" in step.detail

        async with session_scope() as s:
            doc = (
                await s.execute(
                    select(Cr26Document).where(Cr26Document.system_id == sys_id)
                )
            ).scalar_one()
            doc.is_valid = True
            doc.validation_errors = []
        assert (await _steps(sys_id))["package"].state == DONE
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step5_never_renders_the_frozen_readiness_pct() -> None:
    """Spec §5.1. ``AuthorizationPackage.readiness_pct`` is copied at
    package-creation time and is correct only as of ``created_at``; rendering it
    on a live page states a stale number as current."""
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        async with session_scope() as s:
            s.add(
                AuthorizationPackage(
                    organization_id=org_id, system_id=sys_id,
                    label=f"Package {tag}", readiness_pct=63.4, fact_count=5,
                )
            )
            s.add(_cr26_doc(org_id, sys_id, "cpo", valid=True))
        steps = await _steps(sys_id)
        assert steps["package"].state == DONE
        for step in steps.values():
            assert "63.4" not in step.detail

        async with AsyncClient(
            transport=ASGITransport(app=create_app()), base_url="http://t"
        ) as c:
            body = (await c.get(f"/systems/{sys_id}")).text
        assert "63.4" not in body
        # And no second progress story: _derive_status's lifecycle vocabulary
        # (spec §2.1) must not appear on this page either.
        for lifecycle in (
            "initial_build", "evidence_collection",
            "validation_in_progress", "assessor_review", "ready_for_submission",
        ):
            assert lifecycle not in body
    finally:
        await _drop(org_id, sys_id)


# --- step 6: bring in your 3PAO --------------------------------------------


async def _add_engagement(org_id: int, sys_id: int, *, days: int) -> int:
    """An engagement whose period ends ``days`` from now (negative = elapsed)."""
    async with session_scope() as s:
        principal = ExternalPrincipal(
            organization_id=org_id, kind="assessor", name="Third Party Assessors LLC",
            email="lead@3pao.example", organization_name="Third Party Assessors LLC",
        )
        s.add(principal)
        await s.flush()
        engagement = AssessmentEngagement(
            organization_id=org_id,
            system_id=sys_id,
            assessor_principal_id=principal.id,
            period_from=datetime.now(UTC) - timedelta(days=30),
            period_to=datetime.now(UTC) + timedelta(days=days),
        )
        s.add(engagement)
        await s.flush()
        return engagement.id


@pytest.mark.asyncio
async def test_step6_walks_not_started_to_done() -> None:
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        assert (await _steps(sys_id))["3pao"].state == NOT_STARTED
        await _add_engagement(org_id, sys_id, days=90)
        assert (await _steps(sys_id))["3pao"].state == DONE
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step6_goes_backwards_when_the_engagement_is_revoked() -> None:
    """Spec §8.3, the headline case: the step reaches ``done``, the engagement
    is revoked, and the step stops being ``done`` on the next render."""
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        engagement_id = await _add_engagement(org_id, sys_id, days=90)
        assert (await _steps(sys_id))["3pao"].state == DONE

        async with session_scope() as s:
            engagement = await s.get(AssessmentEngagement, engagement_id)
            assert engagement is not None
            engagement.revoked_at = datetime.now(UTC)
        step = (await _steps(sys_id))["3pao"]
        assert step.state != DONE
        assert step.state == IN_PROGRESS
        assert "1 revoked" in step.detail
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_step6_goes_backwards_when_the_period_elapses() -> None:
    """Nobody revoked anything; the assessment window simply ended. A monotonic
    path would keep claiming a 3PAO is engaged."""
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        engagement_id = await _add_engagement(org_id, sys_id, days=90)
        assert (await _steps(sys_id))["3pao"].state == DONE

        async with session_scope() as s:
            engagement = await s.get(AssessmentEngagement, engagement_id)
            assert engagement is not None
            engagement.period_to = datetime.now(UTC) - timedelta(days=1)
        step = (await _steps(sys_id))["3pao"]
        assert step.state == IN_PROGRESS
        assert "period has ended" in step.detail
    finally:
        await _drop(org_id, sys_id)


# --- the states themselves --------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_never_renders_as_done_or_not_started() -> None:
    """Spec §8.2, asserted for every step that can produce ``unknown``.

    Collapsing ``unknown`` into ``done`` is the empty-result-reads-as-favourable
    failure; collapsing it into ``not_started`` renders a guess as a fact. The
    reader only ever sees the chip and the label, so both are checked too.
    """
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        # A bare system with no profile: steps 2 and 4 cannot see enough.
        steps = await _steps(sys_id)
        unknown_keys = ["connect_evidence", "close_gaps"]

        # Step 3 reaches unknown a different way: two linked plans.
        await _add_project(sys_id, title="Plan A", complete=False)
        await _add_project(sys_id, title="Plan B", complete=False)
        steps = {**steps, **{"ssp": (await _steps(sys_id))["ssp"]}}
        unknown_keys.append("ssp")

        for key in unknown_keys:
            step = steps[key]
            assert step.state == UNKNOWN, f"{key} did not reach unknown"
            assert step.state != DONE
            assert step.state != NOT_STARTED
            assert ONBOARDING_CHIPS[step.state] != ONBOARDING_CHIPS[DONE]
            assert ONBOARDING_CHIPS[step.state] != ONBOARDING_CHIPS[NOT_STARTED]
            assert ONBOARDING_STATE_LABELS[step.state] != ONBOARDING_STATE_LABELS[DONE]
            assert (
                ONBOARDING_STATE_LABELS[step.state]
                != ONBOARDING_STATE_LABELS[NOT_STARTED]
            )
    finally:
        await _drop(org_id, sys_id)


def test_every_state_has_its_own_chip_and_label() -> None:
    """Five states, five visibly different chips. If two shared a chip the page
    would be telling the reader something the service refused to say."""
    assert set(ONBOARDING_CHIPS) == STATES
    assert set(ONBOARDING_STATE_LABELS) == STATES
    assert len(set(ONBOARDING_CHIPS.values())) == len(STATES)
    assert len(set(ONBOARDING_STATE_LABELS.values())) == len(STATES)


def test_a_step_refuses_an_invented_state() -> None:
    with pytest.raises(ValueError, match="unknown onboarding state"):
        Step(key="k", number=1, label="L", state="nearly_done", detail="d", href="/")


# --- the page ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_page_renders_all_six_steps_with_their_chips() -> None:
    tag = _tag()
    org_id, sys_id = await _mk(tag)
    try:
        async with session_scope() as s:
            s.add(SystemProfile(system_id=sys_id, cloud_platform="azure_gov"))
        async with AsyncClient(
            transport=ASGITransport(app=create_app()), base_url="http://t"
        ) as c:
            resp = await c.get(f"/systems/{sys_id}")
        assert resp.status_code == 200
        body = resp.text
        assert "Where this system is" in body
        for step in (await _steps(sys_id)).values():
            assert step.label in body
            # Compared escaped: the sentences carry apostrophes and "POA&M",
            # and Jinja autoescaping is what keeps them safe in the page.
            assert str(escape(step.detail)) in body
            assert ONBOARDING_CHIPS[step.state] in body
        # The Azure system's step 2 now renders as work not started -- Concord
        # ships an ARM connector for it (``feat/azure-gov-connector``), so
        # "not available" would be the wrong thing to show this customer.
        assert ONBOARDING_STATE_LABELS[NOT_STARTED] in body
        assert ONBOARDING_STATE_LABELS[NOT_AVAILABLE] not in body
        # The counts that were already on the page are still there -- they are
        # the evidence behind the steps, not a display the path replaces.
        assert "Boundary &amp; inventory" in body
        assert "POA&amp;Ms for this system" in body
    finally:
        await _drop(org_id, sys_id)


@pytest.mark.asyncio
async def test_page_404s_for_a_system_outside_the_principals_org(auth_on: None) -> None:
    """Spec §8.6. Run as a real role-bearing principal: ``SYSTEM_PRINCIPAL``
    (what every auth-disabled test gets) is global, has ``org_id=None``, and
    bypasses the scope check entirely -- a tenant-isolation test written that
    way proves nothing.
    """
    tag = _tag()
    org_a, sys_a = await _mk(f"{tag}a")
    org_b, sys_b = await _mk(f"{tag}b")
    try:
        async with session_scope() as s:
            user_b = User(
                email=f"viewer-{tag}@onboarding.test",
                organization_id=org_b,
                role="viewer",
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(user_b)
            await s.flush()
            token_b = user_b.api_token
        headers = {"Authorization": f"Bearer {token_b}"}
        async with AsyncClient(
            transport=ASGITransport(app=create_app()), base_url="http://t"
        ) as c:
            assert (await c.get(f"/systems/{sys_b}", headers=headers)).status_code == 200
            assert (await c.get(f"/systems/{sys_a}", headers=headers)).status_code == 404

            # Soft-deleted is equally absent, which is the other half of what
            # require_system_in_scope enforces.
            async with session_scope() as s:
                row = await s.get(System, sys_b)
                assert row is not None
                row.deleted_at = datetime.now(UTC)
            assert (await c.get(f"/systems/{sys_b}", headers=headers)).status_code == 404
    finally:
        await _drop(org_a, sys_a)
        await _drop(org_b, sys_b)
