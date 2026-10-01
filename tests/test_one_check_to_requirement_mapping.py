"""The dashboard and the SSP name the same failing requirements.

Found by reading `framework-posture` and a generated SSP for the same live
system, side by side:

    framework-posture failing : 3.1.1, 3.1.5, 3.1.6, 3.5.1, 3.5.3
    SSP open findings         : 3.1.1, 3.1.5,        3.5.3, 3.5.6

Two surfaces, one system, different answers. There were two independent
check-to-requirement mappings:

* `_nist_171_posture` resolved a verdict's 800-53 control ids through the
  catalog crosswalk (`practices_for_controls`), which reaches 14 of the 32
  registered checks.
* the SSP resolved them through `posture.practices.CHECK_PRACTICES`, which is
  authored per check and reaches 28 of 32.

Neither was wrong about its own question, and that is the problem: the crosswalk
is a **relatedness** map. `IA-2` relates to 3.5.1, 3.5.2 and 3.5.3, so a failing
*MFA-registration* check marked 3.5.1 ("Identify system users") as failing -- a
requirement the check never observed. `CHECK_PRACTICES` says what the check
asserts, and quotes the requirement text beside each entry to show it.

So the crosswalk stops being an attribution source. It remains the source for
`unreachable`, which is a different and still-correct question: the ceiling on
what any scan could evidence, given which requirements any 800-53 control maps
to at all.

**This narrows what the dashboard reports as failing**, which is the point: the
narrower set is the one the evidence supports. The four checks `UNMAPPED`
deliberately excludes now contribute nothing and are named in `unmapped_checks`
rather than silently reaching requirements through a looser map.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config

from ccf.analytics.framework_posture import system_framework_posture
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, SystemProfile
from ccf.models_grc import ControlTest
from ccf.posture.practices import UNMAPPED, practices_for_check
from ccf.scoring.seed import seed_scoring_controls

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _system_with_a_failing_check(check_key: str) -> tuple[int, int]:
    """One system, one failing generated check. Returns (org_id, system_id)."""
    tag = next(_SEQ)
    async with session_scope() as session:
        await seed_scoring_controls(session)
    async with session_scope() as session:
        org = Organization(name=f"OneMapping Org {tag}")
        session.add(org)
        await session.flush()
        # Deliberately no FIPS-199 baseline: `resolve_applied_framework` prefers
        # one on the system record (an authorization decision) over a framework
        # named in the intake profile (an intention), so setting it would route
        # this through the 800-53 baseline path instead of the 110 requirements.
        system = System(organization_id=org.id, name=f"om-{tag}")
        session.add(system)
        await session.flush()
        session.add(
            SystemProfile(
                system_id=system.id,
                answers={},
                environment_type="cloud",
                cloud_platform="m365_gcc_high",
                frameworks=["NIST_800_171"],
                derivation={},
            )
        )
        session.add(
            ControlTest(
                organization_id=org.id,
                system_id=system.id,
                name=check_key,
                check_key=check_key,
                source="generated",
                control_id="IA-2",
                control_ids=["IA-2", "IA-2(1)"],
                last_status="fail",
                last_tested_at=datetime.now(UTC),
                method="api",
            )
        )
        return int(org.id), int(system.id)


@pytest.mark.asyncio
async def test_failing_requirements_are_the_ones_the_check_asserts() -> None:
    """The MFA check evidences 3.5.3. It must not mark 3.5.1 failing.

    `IA-2` relates to 3.5.1 ("Identify system users"), 3.5.2 and 3.5.3 in the
    crosswalk. Only 3.5.3 is what "every user has an MFA method registered"
    actually observes.
    """
    org_id, system_id = await _system_with_a_failing_check("m365.identity.mfa_registered")
    async with session_scope() as session:
        out = await system_framework_posture(session, org_id=org_id, system_id=system_id)

    failing = set(out["failing"])
    assert failing == {"3.5.3"}, (
        f"expected only the requirement the check asserts, got {sorted(failing)}"
    )
    assert "3.5.1" not in failing, (
        "3.5.1 is 'Identify system users'; an MFA-registration check does not "
        "observe it, and the crosswalk's relatedness is not evidence"
    )


@pytest.mark.asyncio
async def test_the_dashboard_and_the_authored_mapping_agree() -> None:
    """Whatever the dashboard calls failing must be what the mapping declares.

    Stated over the mapping rather than over a second hard-coded list, so the two
    cannot drift: this is the property that was broken, not a particular pair of
    numbers.
    """
    check_key = "m365.identity.stale_accounts"
    org_id, system_id = await _system_with_a_failing_check(check_key)
    async with session_scope() as session:
        out = await system_framework_posture(session, org_id=org_id, system_id=system_id)

    declared = {p.split("-", 1)[1] for p in practices_for_check(check_key)}
    assert declared, "this test needs a mapped check"
    assert set(out["failing"]) == declared, (
        f"dashboard says {sorted(out['failing'])}, the mapping declares {sorted(declared)}"
    )


@pytest.mark.asyncio
async def test_an_unmapped_check_reaches_no_requirement_and_is_named() -> None:
    """The four deliberate exclusions must not sneak in through the crosswalk.

    `aws.iam.access_key_rotation` is unmapped because 800-171 has no
    authenticator-lifetime requirement. Reaching 3.5.5 or 3.5.6 through a
    relatedness map would file a finding against a requirement that does not ask
    for what the check measures.
    """
    check_key = "aws.iam.access_key_rotation"
    assert check_key in UNMAPPED
    org_id, system_id = await _system_with_a_failing_check(check_key)
    async with session_scope() as session:
        out = await system_framework_posture(session, org_id=org_id, system_id=system_id)

    assert out["failing"] == [], (
        f"an unmapped check reached {out['failing']} -- the crosswalk is still "
        "being used for attribution"
    )
    assert check_key in out["unmapped_checks"], (
        "a verdict that reaches no requirement must be named, or the zero above "
        "is indistinguishable from nothing being wrong"
    )


@pytest.mark.asyncio
async def test_unreachable_still_describes_the_catalog_not_the_checks() -> None:
    """`unreachable` keeps its own, different question.

    It is the ceiling on what any scan could evidence -- which requirements no
    800-53 control maps to at all -- and that is a fact about the catalog, not
    about which checks happen to be registered. It stays crosswalk-derived.
    """
    org_id, system_id = await _system_with_a_failing_check("m365.identity.mfa_registered")
    async with session_scope() as session:
        out = await system_framework_posture(session, org_id=org_id, system_id=system_id)

    assert out["total"] == 110
    assert out["unreachable"], "unreachable must still be reported"

    # The two sources are independent, and this environment proves it plainly:
    # the test database carries the requirement matrix but not the 800-53
    # crosswalk, so every requirement is unreachable -- *including* 3.5.3, which
    # the authored mapping covers and which this very system is failing.
    #
    # That is the property worth pinning. If `unreachable` were ever rebuilt from
    # `CHECK_PRACTICES`, a mapped requirement could no longer appear here, and
    # the field would quietly stop answering its own question ("what could any
    # scan reach, given the catalog") and start answering the attribution
    # question instead.
    assert "3.5.3" in out["failing"], "the premise: this system fails 3.5.3"
    assert "3.5.3" in out["unreachable"], (
        "unreachable is no longer crosswalk-derived -- a requirement the authored "
        "mapping covers is being treated as reachable regardless of the catalog"
    )
