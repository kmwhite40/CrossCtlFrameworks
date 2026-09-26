"""A scan's results, returned in the units of the framework the system is held to.

After `POST /api/systems/{id}/scan` the API answered with Concord's own check
keys and their verdicts. Turning that into "where do we stand against the
framework we are held to" meant a consumer had to know the internal check
vocabulary, the 800-53 ids behind it, and which framework the system had been
categorized under. `framework_posture` computed exactly that answer and was
wired to one HTML page.

Worse, it could only express a FIPS-199 baseline, because its denominator came
from ``Control.fisma_*``. The system this was found on declares
``NIST_800_171`` in its intake profile and carries **no** baseline, so the
function returned zeros -- which reads as "nothing wrong", not "this framework
is not one I can measure".
"""

from __future__ import annotations

import itertools
import os
import uuid

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.analytics.framework_posture import (
    org_framework_posture,
    resolve_applied_framework,
    system_framework_posture,
)
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.catalog.crosswalk import (
    CROSSWALK_COLUMN,
    CROSSWALK_FRAMEWORK,
    practices_for_controls,
    requirement_from_value,
)
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    Control,
    Framework,
    FrameworkMapping,
    Organization,
    ScoringControl,
    ScoringStatus,
    System,
    SystemProfile,
    User,
)
from ccf.models_grc import ControlTest
from ccf.scoring.seed import seed_scoring_controls

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


# ---------------------------------------------------------------------------
# The crosswalk: sourced, not invented
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        # Rev. 2's own spelling, with and without the requirement text.
        ("3.1.1 Limit system access to authorized users", "3.1.1"),
        ("3.13.11", "3.13.11"),
        # Rev. 3's dashed identifier for the same requirement, with and without
        # an objective suffix. A requirement is the unit 800-171A assesses.
        ("03-01-01", "3.1.1"),
        ("03-01-01f.03", "3.1.1"),
        ("03-13-11:", "3.13.11"),
        # Nothing recognisable is refused rather than coerced. A mapping value
        # this cannot read must count as "not mapped", never as a guess.
        ("This requirement addresses policies and procedures", None),
        ("AC-2", None),
        ("", None),
        ("   ", None),
        # A dashed identifier whose family is not 3 is not an 800-171
        # requirement number at all.
        ("05-01-01", None),
    ],
)
def test_a_mapping_value_is_read_or_refused_never_guessed(value, expected) -> None:
    assert requirement_from_value(value) == expected


async def _seed_crosswalk(pairs: list[tuple[str, str]]) -> None:
    """Catalog controls plus their 800-171 mapping rows.

    Seeded, because the test database carries no catalog: without these rows
    every crosswalk assertion would pass against an empty mapping table.
    """
    async with session_scope() as s:
        framework = (
            await s.execute(select(Framework).where(Framework.code == CROSSWALK_FRAMEWORK))
        ).scalars().first()
        if framework is None:
            framework = Framework(code=CROSSWALK_FRAMEWORK, name="NIST SP 800-171 Rev. 2")
            s.add(framework)
            await s.flush()
        for identifier, value in pairs:
            control = (
                await s.execute(select(Control).where(Control.identifier == identifier))
            ).scalars().first()
            if control is None:
                control = Control(identifier=identifier)
                s.add(control)
                await s.flush()
            exists = (
                await s.execute(
                    select(FrameworkMapping).where(
                        FrameworkMapping.control_id == control.id,
                        FrameworkMapping.column_key == CROSSWALK_COLUMN,
                    )
                )
            ).scalars().first()
            if exists is None:
                s.add(
                    FrameworkMapping(
                        control_id=control.id,
                        framework_id=framework.id,
                        column_key=CROSSWALK_COLUMN,
                        value=value,
                    )
                )
        await s.flush()


@pytest.mark.asyncio
async def test_an_enhancement_falls_back_to_its_base_control() -> None:
    """``IA-2(1)`` carries no mapping of its own but is an enhancement of IA-2.

    A check evidencing the enhancement does bear on the base control's
    requirement, and the fallback is the base control's own mapping rather than
    something invented for the enhancement.
    """
    await _seed_crosswalk([("IA-02", "3.5.1 Identify system users")])
    async with session_scope() as s:
        mapped, unmapped = await practices_for_controls(s, {"IA-2", "IA-2(1)"})
    assert mapped["IA-2"] == {"3.5.1"}
    assert mapped["IA-2(1)"] == {"3.5.1"}
    assert unmapped == set()


@pytest.mark.asyncio
async def test_a_control_with_no_mapping_is_reported_not_dropped() -> None:
    """Silently dropping it would make a report understate its own coverage."""
    await _seed_crosswalk([("IA-02", "3.5.1 Identify system users")])
    async with session_scope() as s:
        mapped, unmapped = await practices_for_controls(s, {"IA-2", "ZZ-99"})
    assert "ZZ-99" not in mapped
    assert "ZZ-99" in unmapped


@pytest.mark.asyncio
async def test_the_discussion_column_is_not_read_as_a_mapping() -> None:
    """The same framework also carries explanatory prose under another key.

    Reading it would attribute a discussion paragraph to a requirement.
    """
    ident = f"ZD-{next(_SEQ)}1"
    async with session_scope() as s:
        framework = (
            await s.execute(select(Framework).where(Framework.code == CROSSWALK_FRAMEWORK))
        ).scalars().first() or Framework(code=CROSSWALK_FRAMEWORK, name="x")
        s.add(framework)
        await s.flush()
        control = Control(identifier=ident)
        s.add(control)
        await s.flush()
        s.add(
            FrameworkMapping(
                control_id=control.id,
                framework_id=framework.id,
                column_key="NIST 800-171 Discussion",
                value="3.1.1 is discussed at length in this paragraph",
            )
        )
    async with session_scope() as s:
        mapped, unmapped = await practices_for_controls(s, {ident})
    assert mapped == {}
    assert unmapped == {ident}


@pytest.mark.asyncio
async def test_no_control_ids_means_no_query_and_no_answer() -> None:
    assert await practices_for_controls(_Unusable(), set()) == ({}, set())


class _Unusable:
    """Any use of the session is a bug: the empty case must not reach the DB."""

    async def execute(self, *_a, **_kw):  # pragma: no cover - must not run
        raise AssertionError("queried the database for an empty control set")


# ---------------------------------------------------------------------------
# Which framework applies
# ---------------------------------------------------------------------------


async def _scene(
    *, baseline: str | None, frameworks: list[str] | None, label: str
) -> dict[str, object]:
    tag = f"{next(_SEQ)}-{uuid.uuid4().hex[:6]}"
    async with session_scope() as s:
        await seed_scoring_controls(s)
        org = Organization(name=f"{label} {tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"a-{tag}@fw.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        system = System(organization_id=org.id, name=f"Sys {tag}", baseline=baseline)
        s.add(system)
        await s.flush()
        if frameworks is not None:
            s.add(
                SystemProfile(
                    system_id=system.id,
                    answers={},
                    environment_type="cloud",
                    cloud_platform="m365_gcc_high",
                    frameworks=frameworks,
                )
            )
        await s.flush()
        return {
            "org_id": org.id,
            "system_id": system.id,
            "token": user.api_token,
        }


@pytest.mark.asyncio
async def test_a_declared_baseline_wins_over_a_questionnaire_answer() -> None:
    """The baseline is an authorization decision; the questionnaire is an intent."""
    sc = await _scene(baseline="moderate", frameworks=["NIST_800_171"], label="FW Both")
    async with session_scope() as s:
        system = await s.get(System, int(sc["system_id"]))
        applied = await resolve_applied_framework(s, system)
    assert applied is not None
    assert applied.denominator == "fips199_baseline"
    assert applied.source == "system.baseline"
    assert applied.baseline == "moderate"


@pytest.mark.asyncio
async def test_the_profile_decides_when_there_is_no_baseline() -> None:
    sc = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW Profile")
    async with session_scope() as s:
        system = await s.get(System, int(sc["system_id"]))
        applied = await resolve_applied_framework(s, system)
    assert applied is not None
    assert applied.denominator == "nist_800_171"
    assert applied.source == "profile.frameworks"


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["CMMC_L2", "CMMC", "NIST_800_171_R2", "nist_800_171"])
async def test_cmmc_level_2_and_800_171_share_a_denominator(code) -> None:
    """CMMC L2 assesses exactly the 110 requirements; they differ in scoring."""
    sc = await _scene(baseline=None, frameworks=[code], label=f"FW {code}")
    async with session_scope() as s:
        system = await s.get(System, int(sc["system_id"]))
        applied = await resolve_applied_framework(s, system)
    assert applied is not None, code
    assert applied.denominator == "nist_800_171", code


@pytest.mark.asyncio
async def test_no_framework_declared_is_said_out_loud_not_returned_as_zeros() -> None:
    """The original defect: an unmeasurable system rendering as a clean one."""
    sc = await _scene(baseline=None, frameworks=["CIS"], label="FW None")
    async with session_scope() as s:
        system = await s.get(System, int(sc["system_id"]))
        applied = await resolve_applied_framework(s, system)
        out = await system_framework_posture(
            s, org_id=int(sc["org_id"]), system_id=int(sc["system_id"])
        )
    assert applied is None
    assert out["framework"] is None
    assert out["total"] == 0
    assert out["reason"], "zeros with no explanation read as 'nothing wrong'"
    assert "no framework is declared" in out["reason"]


# ---------------------------------------------------------------------------
# 800-171 posture from 800-53-keyed scan results
# ---------------------------------------------------------------------------


async def _record(system_id: int, org_id: int, control_id: str, status: str) -> None:
    async with session_scope() as s:
        s.add(
            ControlTest(
                organization_id=org_id,
                system_id=system_id,
                control_id=control_id,
                name=f"check for {control_id}",
                method="automated",
                source="generated",
                check_key=f"k.{control_id}",
                last_status=status,
            )
        )


@pytest.mark.asyncio
async def test_a_scan_result_is_reported_against_the_110_requirements() -> None:
    sc = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW 171")
    await _seed_crosswalk(
        [("IA-02", "3.5.1 Identify system users"), ("AC-02", "3.1.1 Limit access")]
    )
    await _record(int(sc["system_id"]), int(sc["org_id"]), "IA-2", "fail")
    await _record(int(sc["system_id"]), int(sc["org_id"]), "AC-2", "pass")

    async with session_scope() as s:
        out = await system_framework_posture(
            s, org_id=int(sc["org_id"]), system_id=int(sc["system_id"])
        )
    assert out["framework"] == "nist_800_171"
    assert out["unit"] == "requirement"
    assert out["total"] == 110, "the denominator is the framework, not what we checked"
    assert "3.5.1" in out["failing"]
    assert "3.1.1" in out["passing"]
    # Everything nobody looked at is named, which is the whole point of a
    # framework denominator.
    assert len(out["unaddressed"]) == 108
    assert out["reason"] is None


@pytest.mark.asyncio
async def test_a_failing_test_beats_a_claimed_implementation() -> None:
    """Machine evidence outranks a documented state, as on the 800-53 path."""
    sc = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW Prec")
    await _seed_crosswalk([("IA-02", "3.5.1 Identify system users")])
    await _record(int(sc["system_id"]), int(sc["org_id"]), "IA-2", "fail")
    async with session_scope() as s:
        practice = (
            await s.execute(select(ScoringControl).where(ScoringControl.nist_id == "3.5.1"))
        ).scalars().one()
        s.add(
            ScoringStatus(
                system_id=int(sc["system_id"]),
                scoring_control_id=practice.id,
                state="implemented",
                source="assessed",
            )
        )
    async with session_scope() as s:
        out = await system_framework_posture(
            s, org_id=int(sc["org_id"]), system_id=int(sc["system_id"])
        )
    assert "3.5.1" in out["failing"]
    assert "3.5.1" not in out["documented"]


@pytest.mark.asyncio
async def test_a_derived_sprs_state_is_not_counted_as_documented() -> None:
    """A state the intake derivation computed is not a claim about this system.

    Crediting it here would put the same unassessed credit into a second report
    (see migration 0089 and the SPRS provenance work).
    """
    sc = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW Derived")
    async with session_scope() as s:
        practice = (
            await s.execute(select(ScoringControl).where(ScoringControl.nist_id == "3.7.1"))
        ).scalars().one()
        s.add(
            ScoringStatus(
                system_id=int(sc["system_id"]),
                scoring_control_id=practice.id,
                state="inherited",
                source="derived",
                derived_from="platform:m365_gcc_high",
            )
        )
    async with session_scope() as s:
        out = await system_framework_posture(
            s, org_id=int(sc["org_id"]), system_id=int(sc["system_id"])
        )
    assert "3.7.1" not in out["documented"], "platform-derived credit leaked into posture"
    assert "3.7.1" in out["unaddressed"]


@pytest.mark.asyncio
async def test_requirements_no_control_maps_to_are_named_as_unreachable() -> None:
    """The ceiling on what any scan can evidence, beside the numbers."""
    sc = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW Reach")
    await _seed_crosswalk([("IA-02", "3.5.1 Identify system users")])
    async with session_scope() as s:
        out = await system_framework_posture(
            s, org_id=int(sc["org_id"]), system_id=int(sc["system_id"])
        )
    assert out["unreachable"], "a scan cannot reach every requirement and must say so"
    assert "3.5.1" not in out["unreachable"], "a mapped requirement is reachable"


@pytest.mark.asyncio
async def test_a_tested_control_the_crosswalk_cannot_place_is_named() -> None:
    sc = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW Unmap")
    await _record(int(sc["system_id"]), int(sc["org_id"]), "ZQ-71", "fail")
    async with session_scope() as s:
        out = await system_framework_posture(
            s, org_id=int(sc["org_id"]), system_id=int(sc["system_id"])
        )
    assert "ZQ-71" in out["unmappable_controls"], (
        "a failing check vanished from the framework view with nothing said"
    )
    assert out["failing"] == [], "an unmapped control must not be attributed to a requirement"


@pytest.mark.asyncio
async def test_requirements_sort_numerically_not_lexically() -> None:
    sc = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW Sort")
    async with session_scope() as s:
        out = await system_framework_posture(
            s, org_id=int(sc["org_id"]), system_id=int(sc["system_id"])
        )
    unaddressed = out["unaddressed"]
    assert unaddressed.index("3.1.2") < unaddressed.index("3.1.10"), (
        "3.1.10 sorted before 3.1.2, which a string sort gets wrong"
    )


# ---------------------------------------------------------------------------
# The organization-wide answer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_two_systems_on_different_frameworks_are_each_reported_in_their_own() -> None:
    tag = uuid.uuid4().hex[:6]
    async with session_scope() as s:
        await seed_scoring_controls(s)
        org = Organization(name=f"FW Org {tag}")
        s.add(org)
        await s.flush()
        mod = System(organization_id=org.id, name=f"Mod {tag}", baseline="moderate")
        cui = System(organization_id=org.id, name=f"CUI {tag}", baseline=None)
        s.add_all([mod, cui])
        await s.flush()
        s.add(
            SystemProfile(
                system_id=cui.id,
                answers={},
                environment_type="cloud",
                cloud_platform="m365_gcc_high",
                frameworks=["NIST_800_171"],
            )
        )
        await s.flush()
        org_id, cui_id = org.id, cui.id

    async with session_scope() as s:
        out = await org_framework_posture(s, org_id)

    frameworks = {e["framework"] for e in out["systems"]}
    assert "nist_800_171" in frameworks
    units = {e["framework"]: e["unit"] for e in out["systems"]}
    assert units["nist_800_171"] == "requirement"
    # Summed within a framework, never across: a requirement count added to a
    # control count is a number that means nothing while looking authoritative.
    assert "total" not in out
    assert out["by_framework"]["nist_800_171"]["total"] == 110
    assert out["by_framework"]["nist_800_171"]["systems"] == 1
    assert cui_id in {e["system_id"] for e in out["systems"]}


@pytest.mark.asyncio
async def test_a_system_with_no_framework_is_listed_rather_than_omitted() -> None:
    sc = await _scene(baseline=None, frameworks=None, label="FW Silent")
    async with session_scope() as s:
        out = await org_framework_posture(s, int(sc["org_id"]))
    undeclared = out["systems_without_a_framework"]
    assert [u["system_id"] for u in undeclared] == [int(sc["system_id"])]
    assert undeclared[0]["reason"]
    assert out["by_framework"] == {}


@pytest.mark.asyncio
async def test_no_organization_returns_the_documented_empty_shape() -> None:
    """A contract test, deliberately not named as a tenant-isolation one.

    Removing the ``org_id is None`` guard leaves this test green, and that is
    correct rather than a hole: ``systems.organization_id`` is ``NOT NULL``, so
    the query's ``== None`` (rendered ``IS NULL``) matches nothing either way.
    Naming this a leak test would make it look like the isolation guarantee
    lives here. It does not --
    ``test_another_tenant_cannot_read_this_systems_framework_posture`` and
    ``test_a_system_with_no_framework_is_listed_rather_than_omitted`` are the
    two that fail when the real scoping is removed.

    What this pins is the shape: every key a caller iterates is present, so a
    no-organization answer is empty rather than malformed.
    """
    async with session_scope() as s:
        out = await org_framework_posture(s, None)
    assert out == {"systems": [], "by_framework": {}, "systems_without_a_framework": []}


# ---------------------------------------------------------------------------
# Over the API
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_org_endpoint_answers_in_framework_terms() -> None:
    sc = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW Api")
    await _seed_crosswalk([("IA-02", "3.5.1 Identify system users")])
    await _record(int(sc["system_id"]), int(sc["org_id"]), "IA-2", "fail")

    async with _client() as c:
        r = await c.get(
            "/api/posture/framework",
            headers={"Authorization": f"Bearer {sc['token']}"},
        )
    assert r.status_code == 200, r.text
    body = r.json()
    entry = next(e for e in body["systems"] if e["system_id"] == int(sc["system_id"]))
    assert entry["framework_label"].startswith("NIST SP 800-171")
    assert entry["total"] == 110
    assert "3.5.1" in entry["failing"]


@pytest.mark.asyncio
async def test_the_per_system_endpoint_answers_beside_the_scan_that_fed_it() -> None:
    sc = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW ApiSys")
    async with _client() as c:
        r = await c.get(
            f"/api/systems/{sc['system_id']}/framework-posture",
            headers={"Authorization": f"Bearer {sc['token']}"},
        )
    assert r.status_code == 200, r.text
    assert r.json()["framework"] == "nist_800_171"


@pytest.mark.asyncio
async def test_another_tenant_cannot_read_this_systems_framework_posture() -> None:
    mine = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW Mine")
    theirs = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW Theirs")
    async with _client() as c:
        r = await c.get(
            f"/api/systems/{mine['system_id']}/framework-posture",
            headers={"Authorization": f"Bearer {theirs['token']}"},
        )
    assert r.status_code == 404

    # And the org endpoint answers only for the caller's own systems.
    async with _client() as c:
        body = (
            await c.get(
                "/api/posture/framework",
                headers={"Authorization": f"Bearer {theirs['token']}"},
            )
        ).json()
    assert int(mine["system_id"]) not in {e["system_id"] for e in body["systems"]}


@pytest.mark.asyncio
async def test_every_entry_in_the_org_answer_names_its_system() -> None:
    """A payload a consumer cannot attribute to a system is unusable.

    The early returns -- no framework declared, baseline resolves to nothing --
    once skipped the lines that stamped `system_id`, so those entries went into
    the list anonymously. Iterating the response then raised a KeyError rather
    than reporting a gap.
    """
    tag = uuid.uuid4().hex[:6]
    async with session_scope() as s:
        await seed_scoring_controls(s)
        org = Organization(name=f"FW Named {tag}")
        s.add(org)
        await s.flush()
        # One of each shape: a framework that measures, a baseline the test
        # catalog cannot resolve, and no framework at all.
        measurable = System(organization_id=org.id, name=f"CUI {tag}", baseline=None)
        unresolved = System(organization_id=org.id, name=f"Mod {tag}", baseline="moderate")
        silent = System(organization_id=org.id, name=f"Bare {tag}", baseline=None)
        s.add_all([measurable, unresolved, silent])
        await s.flush()
        s.add(
            SystemProfile(
                system_id=measurable.id,
                answers={},
                environment_type="cloud",
                cloud_platform="m365_gcc_high",
                frameworks=["NIST_800_171"],
            )
        )
        await s.flush()
        org_id = org.id
        expected = {measurable.id, unresolved.id, silent.id}

    async with session_scope() as s:
        out = await org_framework_posture(s, org_id)

    assert {e["system_id"] for e in out["systems"]} == expected
    assert all(e["system"] for e in out["systems"]), "an entry has no system name"
    # And an entry that could not be measured still says why.
    for entry in out["systems"]:
        if entry["total"] == 0:
            assert entry["reason"], f"system {entry['system_id']} reported zeros in silence"




# ---------------------------------------------------------------------------
# On the pages a customer actually opens
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_workspace_measures_a_system_that_has_no_fips199_baseline() -> None:
    """Step 3 of the flow, for the shape the live tenant actually has.

    The workspace picked its focus system by "has a baseline", so a system held
    to 800-171 through its intake profile was skipped -- and if it was the only
    system, the posture step read "No baseline declared, so coverage cannot be
    measured", which names a remedy the customer may not need.
    """
    sc = await _scene(baseline=None, frameworks=["NIST_800_171"], label="FW Work")
    await _seed_crosswalk([("IA-02", "3.5.1 Identify system users")])
    await _record(int(sc["system_id"]), int(sc["org_id"]), "IA-2", "fail")

    async with _client() as c:
        r = await c.get(
            "/workspace", headers={"Authorization": f"Bearer {sc['token']}"}
        )
    assert r.status_code == 200, r.text
    assert "NIST SP 800-171" in r.text
    assert "No baseline declared" not in r.text, "the old, wrong remedy is still offered"
    # The denominator is the framework's, and the unit is a requirement.
    assert "110 requirements" in r.text or "of 110 requirement" in r.text
    assert "3.5.1" in r.text, "the failing requirement is not named"
    # The ceiling is stated beside the number, not left to be inferred.
    assert "no scan can reach" in r.text


@pytest.mark.asyncio
async def test_the_workspace_says_why_when_no_framework_is_declared() -> None:
    """An absent card reads as 'nothing to report'.

    Both places have to say it: the card, and the posture step's own detail
    line. Asserting only the card left the step free to keep offering "set a
    baseline" -- a remedy that is wrong for a system whose framework is 800-171.
    """
    sc = await _scene(baseline=None, frameworks=["CIS"], label="FW WorkNone")
    async with _client() as c:
        r = await c.get(
            "/workspace", headers={"Authorization": f"Bearer {sc['token']}"}
        )
    assert r.status_code == 200, r.text
    assert "Posture cannot be measured yet" in r.text
    assert "no framework is declared" in r.text
    assert "No baseline declared" not in r.text, "the step still names the wrong remedy"
    assert "Declare a framework" in r.text, "the step's action still sends them to a baseline"


@pytest.mark.asyncio
async def test_the_workspace_focuses_the_system_whose_framework_it_can_measure() -> None:
    """Two systems, neither with a baseline, only one measurable.

    The old rule picked "the first with a baseline, else the first at all", so
    with no baselines anywhere it landed on whichever system happened to be
    created first -- and if that one declared no framework, the workspace
    reported that it could measure nothing while a measurable system sat beside
    it. A single-system test cannot catch this: the fallback lands on the right
    system by accident.
    """
    tag = uuid.uuid4().hex[:6]
    async with session_scope() as s:
        await seed_scoring_controls(s)
        org = Organization(name=f"FW Focus {tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"f-{tag}@fw.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        # Created first, so `systems[0]` under the old rule. No framework.
        bare = System(organization_id=org.id, name=f"Bare {tag}", baseline=None)
        s.add(bare)
        await s.flush()
        cui = System(organization_id=org.id, name=f"CUI {tag}", baseline=None)
        s.add(cui)
        await s.flush()
        s.add(
            SystemProfile(
                system_id=cui.id,
                answers={},
                environment_type="cloud",
                cloud_platform="m365_gcc_high",
                frameworks=["NIST_800_171"],
            )
        )
        await s.flush()
        token, cui_name, bare_name = user.api_token, cui.name, bare.name

    async with _client() as c:
        r = await c.get("/workspace", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    assert "Posture against NIST SP 800-171" in r.text, (
        f"the workspace focused a system it cannot measure; expected {cui_name}"
    )
    assert "Posture cannot be measured yet" not in r.text
    # The other system is still named rather than hidden, with its own status.
    assert bare_name in r.text
    assert "no framework declared" in r.text


@pytest.mark.asyncio
async def test_the_posture_page_reports_each_system_in_its_own_units() -> None:
    """One organization, two frameworks, two denominators, never summed."""
    tag = uuid.uuid4().hex[:6]
    async with session_scope() as s:
        await seed_scoring_controls(s)
        org = Organization(name=f"FW Page {tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"p-{tag}@fw.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        cui = System(organization_id=org.id, name=f"CUI {tag}", baseline=None)
        bare = System(organization_id=org.id, name=f"Bare {tag}", baseline=None)
        s.add_all([cui, bare])
        await s.flush()
        s.add(
            SystemProfile(
                system_id=cui.id,
                answers={},
                environment_type="cloud",
                cloud_platform="m365_gcc_high",
                frameworks=["NIST_800_171"],
            )
        )
        await s.flush()
        token, cui_name, bare_name = user.api_token, cui.name, bare.name

    async with _client() as c:
        r = await c.get("/posture", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    assert "Posture against the applied framework" in r.text
    assert cui_name in r.text
    assert "110 requirements" in r.text, "the 800-171 denominator is not rendered"
    # The system with no framework is shown with its reason, not omitted.
    assert bare_name in r.text
    assert "no framework is declared" in r.text
    # Percentages are per framework; there is no portfolio-wide coverage number
    # mixing requirements with controls.
    assert "assessed of 110 requirements" in r.text
