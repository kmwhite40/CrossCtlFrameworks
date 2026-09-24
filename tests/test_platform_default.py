""""No cloud platform" is an answer, not a missing value.

See ``docs/superpowers/specs/2026-09-21-platform-default-design.md``.

The intake questionnaire offers ``none`` as one of four answers to "Primary
cloud platform?". Before this change every answer Concord did not recognize --
including ``none``, which the product itself offers -- was coerced to ``m365``
at three separate layers, so a customer who runs no cloud at all received an
SSP naming Entra ID, Purview and Intune as the mechanisms implementing their
controls.

Every fixture in this module is deliberately free of vendor and product names,
so an assertion that "no Microsoft or AWS service name appears" cannot be
satisfied -- or defeated -- by the fixture's own text.
"""

from __future__ import annotations

import os
import re
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance.automation import (
    PLATFORM_TO_SSP,
    QUESTIONNAIRE,
    derive_system,
    generate_ssp,
)
from ccf.models import (
    Organization,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
    User,
)
from ccf.reliability.checks import (
    _CHECKS,
    BLOCKING_CHECKS,
    FAIL,
    PASS,
    WARN,
    _check_ssp_platform_agreement,
)
from ccf.ssp.platforms import (
    _SERVICES,
    CLOUD_PLATFORMS,
    NO_PLATFORM,
    NO_SERVICES_TEXT,
    PLATFORMS,
    catalog_absence_note,
    connector_key_for_platform,
    environment_for,
    normalize_platform,
    platform_label,
    services_for,
)
from ccf.ssp.seed import _drafting_platform as drafting_platform

#: A platform code Concord genuinely does not support, used wherever these
#: tests need an *unrecognized* value. It was ``"gcp"`` until Google Cloud
#: became a real platform, at which point every assertion using it would have
#: been testing the opposite of what it says.
UNSUPPORTED_PLATFORM = "oracle_cloud"


pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# Product / vendor tokens that must never appear in a narrative drafted for a
# system that declared no cloud platform. Deliberately short and generic --
# the exhaustive, catalog-driven version of this assertion lives in
# ``test_no_other_platform_services_are_drafted_for_none`` below.
_PRODUCT_TOKENS = ("Microsoft", "Entra", "Purview", "Intune", "Defender", "Azure", "AWS")


def _names(token: str, text: str) -> bool:
    """Whole-word, case-insensitive containment.

    Substring matching is not good enough here and quietly gave a false
    failure first time round: the real CMMC catalog's SI.L2-3.14.1 text is
    "correct system flaws in a timely manner", and "flaws" contains "aws".
    """
    return re.search(rf"\b{re.escape(token)}\b", text, re.IGNORECASE) is not None


async def _make_system(session, name: str) -> System:
    org = Organization(name=name)
    session.add(org)
    await session.flush()
    sys_row = System(organization_id=org.id, name=f"{name} system")
    session.add(sys_row)
    await session.flush()
    return sys_row


async def _seed_controls(session, prefix: str) -> list[str]:
    """Two throwaway scoring controls whose own text names no product.

    ``ccf.scoring_controls`` is a GLOBAL table and the suite resets the schema
    only once per session, so these rows are always deleted again by
    :func:`_seeded_none_system`'s ``finally``.
    """
    control_ids = [f"AC.{prefix}-3.1.1", f"SC.{prefix}-3.13.1"]
    session.add_all(
        [
            ScoringControl(
                control_id=control_ids[0],
                nist_id=f"AC-{prefix}-1",
                domain="AC",
                title="Account Management",
                point_value="5",
                requirement="limit system access to authorized users",
                objective_parts=[{"label": "[a]", "text": "authorized users are identified"}],
                sort_order=1,
            ),
            ScoringControl(
                control_id=control_ids[1],
                nist_id=f"SC-{prefix}-1",
                domain="SC",
                title="Boundary Protection",
                point_value="5",
                requirement="monitor and control communications at the system boundary",
                objective_parts=[{"label": "[a]", "text": "the system boundary is defined"}],
                sort_order=2,
            ),
        ]
    )
    await session.flush()
    return control_ids


@asynccontextmanager
async def _seeded_system(
    name: str, prefix: str, cloud_platform: str | None
) -> AsyncIterator[tuple[SSPProject, list[SSPControlEntry]]]:
    control_ids: list[str] = []
    org_id: int | None = None
    try:
        async with session_scope() as session:
            sys_row = await _make_system(session, name)
            org_id = sys_row.organization_id
            control_ids = await _seed_controls(session, prefix)
            profile = SystemProfile(
                system_id=sys_row.id,
                environment_type="on_prem",
                cloud_platform=cloud_platform,
            )
            session.add(profile)
            await session.flush()
            await derive_system(
                session,
                system_id=sys_row.id,
                org_id=sys_row.organization_id,
                profile=profile,
                create_poams=False,
            )
            proj_id = await generate_ssp(session, system=sys_row, profile=profile)
            proj = await session.get(SSPProject, proj_id)
            assert proj is not None
            entries = list(
                (
                    await session.execute(
                        select(SSPControlEntry).where(SSPControlEntry.project_id == proj.id)
                    )
                )
                .scalars()
                .all()
            )
        yield proj, entries
    finally:
        # ``ccf.scoring_controls`` is global and the schema resets once per
        # session, so these rows would otherwise be visible to every later
        # module. The org/system/project rows are cleaned up for the same
        # reason -- and because a leftover project is a row the new
        # ssp_platform_agreement check would go on counting.
        async with session_scope() as session:
            if control_ids:
                await session.execute(
                    delete(ScoringControl).where(ScoringControl.control_id.in_(control_ids))
                )
            if org_id is not None:
                projects = select(SSPProject.id).where(SSPProject.organization_id == org_id)
                await session.execute(
                    delete(SSPControlEntry).where(SSPControlEntry.project_id.in_(projects))
                )
                await session.execute(
                    delete(SSPProject).where(SSPProject.organization_id == org_id)
                )
                systems = select(System.id).where(System.organization_id == org_id)
                await session.execute(
                    delete(SystemProfile).where(SystemProfile.system_id.in_(systems))
                )
                await session.execute(delete(System).where(System.organization_id == org_id))
                await session.execute(delete(Organization).where(Organization.id == org_id))


def _narrative_text(entries: list[SSPControlEntry], prefix: str | None = None) -> str:
    """Every drafted narrative, optionally only for this test's own controls.

    ``prefix`` scopes the text to the throwaway controls a test seeded. The
    SSP project covers whatever is in the global ``ccf.scoring_controls``
    table, which other modules populate with the real 110-practice CMMC
    catalog, so an unscoped assertion would depend on run order.
    """
    return "\n".join(
        (part.get("text") or "")
        for e in entries
        if prefix is None or prefix in e.control_id
        for part in (e.part_narratives or [])
    )


# --- spec §4.1: the headline case, pinned -----------------------------------


@pytest.mark.asyncio
async def test_declared_none_yields_a_project_that_names_no_product() -> None:
    """A customer who answers "none" must not receive a Microsoft 365 SSP.

    ``none`` is one of the four answers the questionnaire itself offers
    (``QUESTIONNAIRE``'s ``cloud_platform`` options), so this is not an edge
    case -- it is a supported answer whose translation was wrong.
    """
    async with _seeded_system("No Platform Org 1", "NPHEAD", "none") as (proj, entries):
        assert proj.platform == "none", (
            f"declared 'none' but the project stored platform {proj.platform!r}"
        )
        label = platform_label(proj.platform)
        for token in _PRODUCT_TOKENS:
            assert not _names(token, label), (
                f"platform label {label!r} names the product {token!r}"
            )
        assert entries, "expected seeded SSP entries"
        text = _narrative_text(entries, prefix="NPHEAD")
        assert text.strip(), "expected narratives for this test's own controls"
        for token in _PRODUCT_TOKENS:
            assert not _names(token, text), (
                f"a statement drafted for a system with no cloud platform names "
                f"{token!r}:\n{text}"
            )


# --- spec §4.2: unrecognized is not the same as none ------------------------


@pytest.mark.asyncio
async def test_unrecognized_platform_stays_distinct_from_none_in_state() -> None:
    """Asserted separately from what the customer is told, on purpose.

    Collapsing "we do not know what they have" into "they told us they have
    nothing" would be this same defect one layer over -- silence presented as
    an answer -- so *state* and *wording* are pinned by two tests, and neither
    can stand in for the other.
    """
    assert normalize_platform("none") == NO_PLATFORM
    assert normalize_platform(UNSUPPORTED_PLATFORM) is None
    assert normalize_platform("") is None
    assert normalize_platform(None) is None
    # ... and NO_PLATFORM is a real, storable platform while an unrecognized
    # code is not.
    assert NO_PLATFORM in PLATFORMS
    assert UNSUPPORTED_PLATFORM not in PLATFORMS


def test_unrecognized_platform_stays_distinct_from_none_in_what_the_customer_is_told() -> None:
    none_label = platform_label(NO_PLATFORM)
    unknown_label = platform_label(UNSUPPORTED_PLATFORM)
    assert none_label != unknown_label
    assert none_label == "No cloud platform declared"
    assert UNSUPPORTED_PLATFORM in unknown_label

    none_env = environment_for(NO_PLATFORM)
    unknown_env = environment_for(UNSUPPORTED_PLATFORM)
    assert none_env != unknown_env
    assert UNSUPPORTED_PLATFORM in unknown_env
    assert "does not recognize" in unknown_env

    none_note = catalog_absence_note(NO_PLATFORM)
    unknown_note = catalog_absence_note(UNSUPPORTED_PLATFORM)
    absent_note = catalog_absence_note(None)
    assert len({none_note, unknown_note, absent_note}) == 3
    assert "does not recognize" in unknown_note and UNSUPPORTED_PLATFORM in unknown_note
    # The unrecognized wording matches what guided onboarding step 2 already
    # tells the same customer, so the two surfaces do not disagree.
    assert "does not recognize the declared platform" in unknown_note


@pytest.mark.asyncio
async def test_generate_ssp_reports_an_unrecognized_platform_rather_than_guessing() -> None:
    """Both an unrecognized declaration and a missing one yield a "none"
    project -- but each says which it was, in the project itself."""
    async with _seeded_system("No Platform Org 2", "NPGCP", "oracle_gov") as (proj, entries):
        assert proj.platform == NO_PLATFORM
        note = (proj.metadata_json or {}).get("platform_note") or ""
        assert "oracle_gov" in note
        assert "does not recognize" in note
        text = _narrative_text(entries, prefix="NPGCP")
        assert "oracle_gov" in text, "the drafted statements must name what was declared"
        for token in _PRODUCT_TOKENS:
            assert not _names(token, text), f"drafted statement names {token!r}:\n{text}"

    async with _seeded_system("No Platform Org 3", "NPNULL", None) as (proj, _entries):
        assert proj.platform == NO_PLATFORM
        note = (proj.metadata_json or {}).get("platform_note") or ""
        assert "has not declared a cloud platform" in note
        assert "does not recognize" not in note

    async with _seeded_system("No Platform Org 4", "NPNONE", "none") as (proj, _entries):
        assert proj.platform == NO_PLATFORM
        # A declared "none" translated cleanly: there is nothing to report.
        assert (proj.metadata_json or {}).get("platform_note") is None


# --- spec §4.4: nothing platform-specific is drafted for "none" -------------


@pytest.mark.asyncio
async def test_no_other_platforms_service_names_are_drafted_for_none() -> None:
    """Iterates the real service catalogs rather than listing strings.

    A hardcoded list of product names silently stops covering a service added
    to a catalog later; this reads ``_SERVICES`` itself, so a new entry is
    covered the moment it exists.

    The catalog phrase is what a statement borrows verbatim -- ``services_for``
    returns it unchanged and ``compose`` interpolates it -- so a phrase is the
    unit searched for. The positive control at the end proves the search can
    actually fail: the identical assertion run against a real Microsoft 365
    project must find those phrases.
    """
    catalog = {
        (plat, domain): phrase
        for plat in CLOUD_PLATFORMS
        for domain, phrase in _SERVICES[plat].items()
    }
    assert len(catalog) >= 3 * 14, "expected a full per-domain catalog per cloud platform"

    async with _seeded_system("No Platform Org 5", "NPCAT", "none") as (_proj, entries):
        none_text = _narrative_text(entries, prefix="NPCAT")
    assert none_text.strip(), "expected narratives to search"
    borrowed = sorted(
        f"{plat}/{domain}" for (plat, domain), phrase in catalog.items() if phrase in none_text
    )
    assert not borrowed, (
        f"a 'none' project's statements borrowed these catalog entries: {borrowed}\n{none_text}"
    )

    # Positive control. Without it "no phrase was found" could equally mean
    # "the phrases are no longer what a statement is built from", and the
    # assertion above would pass for the wrong reason forever.
    async with _seeded_system("M365 Control Org", "M365CTL", "m365_gcc_high") as (proj, entries):
        assert proj.platform == "m365"
        m365_text = _narrative_text(entries, prefix="M365CTL")
    found = sorted(
        domain
        for (plat, domain), phrase in catalog.items()
        if plat == "m365" and phrase in m365_text
    )
    assert found, (
        "no Microsoft 365 catalog phrase appeared in a Microsoft 365 project's own "
        "statements, so the search above proves nothing"
    )


# --- spec §4.5: every read helper handles the unknown branch ----------------


def test_read_helpers_never_substitute_a_product_for_an_unknown_platform() -> None:
    for unknown in (UNSUPPORTED_PLATFORM, "oracle_cloud", "M365", "", None):
        label = platform_label(unknown)
        env = environment_for(unknown)
        services = services_for(unknown, "AC")
        for token in _PRODUCT_TOKENS:
            for rendered in (label, env, services):
                assert not _names(token, rendered), (
                    f"{unknown!r} rendered as {rendered!r}, which names {token!r}"
                )
        assert services == NO_SERVICES_TEXT


def test_connector_key_is_none_for_both_none_and_unrecognized() -> None:
    """``connector_key_for_platform`` answers the support question only.

    It cannot distinguish "Concord ships no connector for this" from "Concord
    does not know what this is", which is exactly why ``ccf.onboarding`` reads
    PLATFORM_CONNECTOR_KEYS directly to tell a customer *why* there is nothing
    to connect. Pinned so a future caller does not mistake ``None`` here for a
    statement about the customer's platform.
    """
    assert connector_key_for_platform(NO_PLATFORM) is None
    assert connector_key_for_platform(UNSUPPORTED_PLATFORM) is None
    assert connector_key_for_platform("m365") == "msgraph"


def test_seed_drafts_for_an_unrecognized_platform_without_resolving_it() -> None:
    """``ssp/seed.py`` is a read path: it renders, it does not refuse -- and it
    does not quietly turn an unrecognized value into NO_PLATFORM."""
    assert drafting_platform(UNSUPPORTED_PLATFORM) == UNSUPPORTED_PLATFORM
    assert drafting_platform(None) == NO_PLATFORM
    assert drafting_platform("") == NO_PLATFORM
    assert drafting_platform("azure_gov") == "azure_gov"  # not an SSP code: carried through
    assert drafting_platform("m365") == "m365"


# --- spec §4.3: write paths refuse, they do not coerce ----------------------


@pytest.fixture
def auth_enabled() -> Iterator[None]:
    """Real auth for the API write-path tests.

    Not autouse: only the API tests below need it. With auth disabled every
    request is ``SYSTEM_PRINCIPAL`` (``org_id=None``, ``is_global=True``) and
    ``require_role`` returns early (``api/auth_deps.py``), so a test written
    that way would pass with or without the role gate these routes carry.
    """
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _admin(tag: str) -> tuple[str, int]:
    """An org and an ``admin`` user in it. Returns ``(bearer_token, org_id)``."""
    async with session_scope() as s:
        org = Organization(name=f"Platform Write Org {tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"platform-write-{tag}@example.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token, org.id


async def _project_row(org_id: int, platform: str) -> int:
    async with session_scope() as s:
        proj = SSPProject(
            organization_id=org_id, customer_name=f"Write Path {org_id}", platform=platform
        )
        s.add(proj)
        await s.flush()
        return proj.id


async def _purge_org(org_id: int) -> None:
    """Remove everything a write-path test created, in dependency order.

    The schema resets once per *session*, so a leftover project is visible to
    every later module -- and to the new ``ssp_platform_agreement`` check,
    which would go on counting it.
    """
    async with session_scope() as s:
        projects = select(SSPProject.id).where(SSPProject.organization_id == org_id)
        await s.execute(delete(SSPControlEntry).where(SSPControlEntry.project_id.in_(projects)))
        await s.execute(delete(SSPProject).where(SSPProject.organization_id == org_id))
        systems = select(System.id).where(System.organization_id == org_id)
        await s.execute(delete(SystemProfile).where(SystemProfile.system_id.in_(systems)))
        await s.execute(delete(System).where(System.organization_id == org_id))
        await s.execute(delete(User).where(User.organization_id == org_id))
        await s.execute(delete(Organization).where(Organization.id == org_id))


async def _stored_platform(project_id: int) -> str:
    async with session_scope() as s:
        proj = await s.get(SSPProject, project_id)
        assert proj is not None
        return proj.platform


@pytest.mark.asyncio
async def test_api_create_project_refuses_an_unrecognized_platform(
    auth_enabled: None,
) -> None:
    """422, and -- the part that matters -- no row claiming a platform nobody
    chose. Asserting only on the status code would not distinguish "refused"
    from "refused after storing"."""
    token, org_id = await _admin("create")
    try:
        async with _client() as c:
            r = await c.post(
                "/api/ssp/projects",
                json={"customer_name": "Coercion Co", "platform": UNSUPPORTED_PLATFORM},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 422, r.text
        async with session_scope() as s:
            rows = (
                (
                    await s.execute(
                        select(SSPProject).where(SSPProject.organization_id == org_id)
                    )
                )
                .scalars()
                .all()
            )
        assert not rows, f"a refused create still stored {[r_.platform for r_ in rows]}"
    finally:
        await _purge_org(org_id)


@pytest.mark.asyncio
async def test_api_create_project_without_a_platform_declares_none(
    auth_enabled: None,
) -> None:
    """The API's own default was "m365": a client that omitted the field had a
    factual claim about its customer's stack made on its behalf."""
    token, org_id = await _admin("default")
    try:
        async with _client() as c:
            r = await c.post(
                "/api/ssp/projects",
                json={"customer_name": "Default Co"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 201, r.text
        assert r.json()["platform"] == NO_PLATFORM
        assert await _stored_platform(r.json()["id"]) == NO_PLATFORM
    finally:
        await _purge_org(org_id)


@pytest.mark.asyncio
async def test_api_update_and_reseed_refuse_an_unrecognized_platform(
    auth_enabled: None,
) -> None:
    token, org_id = await _admin("update")
    try:
        proj_id = await _project_row(org_id, "azure")
        headers = {"Authorization": f"Bearer {token}"}
        async with _client() as c:
            patched = await c.patch(
                f"/api/ssp/projects/{proj_id}",
                json={"platform": UNSUPPORTED_PLATFORM},
                headers=headers,
            )
            reseeded = await c.post(
                f"/api/ssp/projects/{proj_id}/reseed",
                params={"platform": UNSUPPORTED_PLATFORM},
                headers=headers,
            )
        assert patched.status_code == 422, patched.text
        assert reseeded.status_code == 422, reseeded.text
        assert await _stored_platform(proj_id) == "azure", (
            "a refused write changed the stored platform anyway"
        )
    finally:
        await _purge_org(org_id)


@pytest.mark.asyncio
async def test_ui_forms_refuse_an_unrecognized_platform() -> None:
    """The two server-rendered forms, which post a fixed choice list.

    Run without the auth fixture on purpose: neither route carries a role gate,
    so there is none for ``SYSTEM_PRINCIPAL`` to bypass here -- what is under
    test is the refusal, and the stored row afterwards.
    """
    async with session_scope() as s:
        org = Organization(name="Platform UI Org")
        s.add(org)
        await s.flush()
        org_id = org.id
    try:
        proj_id = await _project_row(org_id, "aws_govcloud")
        async with _client() as c:
            created = await c.post(
                "/ssp/new",
                data={"customer_name": "UI Coercion Co", "platform": UNSUPPORTED_PLATFORM},
            )
            regenerated = await c.post(
                f"/ssp/{proj_id}/regenerate", data={"platform": UNSUPPORTED_PLATFORM}
            )
        assert created.status_code == 422, created.text
        assert regenerated.status_code == 422, regenerated.text
        assert await _stored_platform(proj_id) == "aws_govcloud"
        async with session_scope() as s:
            rows = (
                (
                    await s.execute(
                        select(SSPProject).where(SSPProject.customer_name == "UI Coercion Co")
                    )
                )
                .scalars()
                .all()
            )
        assert not rows, "a refused form post still created a project"
    finally:
        await _purge_org(org_id)


# --- spec §4.6: the reliability check ---------------------------------------


@pytest.mark.asyncio
async def test_reliability_check_counts_a_coerced_project_and_not_a_consistent_one() -> None:
    """Detection only. §3: rows already written cannot be silently repaired --
    a project coerced to "m365" is indistinguishable from one legitimately on
    M365, so rewriting them would be a second guess on top of the first."""
    async with session_scope() as session:
        clean = await _check_ssp_platform_agreement(session)
    assert clean.status in (PASS, WARN)

    created: list[int] = []
    try:
        async with session_scope() as s:
            org = Organization(name="Agreement Org")
            s.add(org)
            await s.flush()
            consistent_sys = System(organization_id=org.id, name="Consistent")
            coerced_sys = System(organization_id=org.id, name="Coerced")
            s.add_all([consistent_sys, coerced_sys])
            await s.flush()
            s.add_all(
                [
                    SystemProfile(system_id=consistent_sys.id, cloud_platform="azure_gov"),
                    SystemProfile(system_id=coerced_sys.id, cloud_platform="none"),
                ]
            )
            consistent = SSPProject(
                organization_id=org.id,
                system_id=consistent_sys.id,
                customer_name="Consistent",
                platform="azure",
            )
            # Exactly the row shape the defect produced: declared "none",
            # stored "m365".
            coerced = SSPProject(
                organization_id=org.id,
                system_id=coerced_sys.id,
                customer_name="Coerced",
                platform="m365",
            )
            s.add_all([consistent, coerced])
            await s.flush()
            created = [consistent.id, coerced.id]

        async with session_scope() as session:
            with_coerced = await _check_ssp_platform_agreement(session)
        assert with_coerced.status == WARN
        assert with_coerced.status != FAIL, (
            "a deliberate post-intake platform change is legitimate, so this may never FAIL"
        )
        assert "disagree with a recognized intake answer" in with_coerced.message
        assert with_coerced.remediation and "by hand" in with_coerced.remediation

        # The consistent project alone must not trip it.
        async with session_scope() as s:
            await s.execute(delete(SSPProject).where(SSPProject.id == coerced.id))
        async with session_scope() as session:
            after = await _check_ssp_platform_agreement(session)
        assert after.status == clean.status
        assert after.message == clean.message
    finally:
        if created:
            async with session_scope() as s:
                await s.execute(delete(SSPProject).where(SSPProject.id.in_(created)))
                await s.execute(
                    delete(SystemProfile).where(
                        SystemProfile.system_id.in_(
                            select(System.id).where(
                                System.name.in_(("Consistent", "Coerced"))
                            )
                        )
                    )
                )
                await s.execute(delete(System).where(System.name.in_(("Consistent", "Coerced"))))
                await s.execute(delete(Organization).where(Organization.name == "Agreement Org"))


@pytest.mark.asyncio
async def test_reliability_check_is_registered_and_never_blocking() -> None:
    names = {c.__name__ for c in _CHECKS}
    assert "_check_ssp_platform_agreement" in names
    assert _check_ssp_platform_agreement not in BLOCKING_CHECKS


# --- spec §4.7: the three questionnaire answers still map as before ---------


def test_questionnaire_answers_map_exactly_as_before() -> None:
    """A regression guard against the literal table, since this change touches
    the mapping those three answers travel through."""
    assert PLATFORM_TO_SSP["m365_gcc_high"] == "m365"
    assert PLATFORM_TO_SSP["azure_gov"] == "azure"
    assert PLATFORM_TO_SSP["aws_govcloud"] == "aws_govcloud"
    # One code on both sides, unlike the Microsoft and Azure answers: the
    # questionnaire asks about Assured Workloads and the SSP platform is the
    # same thing.
    assert PLATFORM_TO_SSP["gcp"] == "gcp"
    assert PLATFORM_TO_SSP["none"] == NO_PLATFORM
    assert set(PLATFORM_TO_SSP) == {
        "m365_gcc_high", "azure_gov", "aws_govcloud", "gcp", "none",
    }
    # Every questionnaire option now has a translation, which is the whole
    # point: the fourth used to fall into the default beside every typo.
    options = next(
        q["options"] for q in QUESTIONNAIRE if q.get("field") == "cloud_platform"
    )
    assert set(options) == set(PLATFORM_TO_SSP)
    assert set(PLATFORM_TO_SSP.values()) <= set(PLATFORMS)


@pytest.mark.asyncio
async def test_a_project_created_without_a_platform_stores_none() -> None:
    """The model's own Python-side default, exercised directly.

    Nothing else reaches it: ``ProjectCreate`` and the ``/ssp/new`` form each
    carry their own default, and ``generate_ssp`` always passes one. Left
    untested, ``default="m365"`` could be restored here and every other test
    in this module would still pass -- measured, when this one did not exist.

    No migration accompanies the change, so this is also the assertion that the
    default really is client-side: the column's server default is untouched and
    the value comes from SQLAlchemy.
    """
    async with session_scope() as s:
        org = Organization(name="Model Default Org")
        s.add(org)
        await s.flush()
        org_id = org.id
    try:
        async with session_scope() as s:
            proj = SSPProject(organization_id=org_id, customer_name="Model Default Co")
            s.add(proj)
            await s.flush()
            proj_id = proj.id
        assert await _stored_platform(proj_id) == NO_PLATFORM
    finally:
        await _purge_org(org_id)


def test_the_unsupported_exemplar_is_still_unsupported() -> None:
    """Guards every assertion in this file that uses ``UNSUPPORTED_PLATFORM``.

    Those tests prove that an unrecognized platform is refused on write,
    labelled honestly on read, and never drafted for. They are only meaningful
    while the code they use is genuinely unrecognized -- and the previous one,
    ``"gcp"``, stopped being so the day Google Cloud was added. Without this,
    that change would have turned a dozen assertions into vacuous passes
    against a supported platform.
    """
    assert UNSUPPORTED_PLATFORM not in PLATFORMS, (
        f"{UNSUPPORTED_PLATFORM!r} is now a supported platform, so every "
        "assertion in this file that uses it is testing the opposite of what "
        "it claims; pick a different unsupported code"
    )
    assert normalize_platform(UNSUPPORTED_PLATFORM) is None
