"""A connector-backed claim must mean *this tenant captured something*.

``ccf.ssp.platforms.has_capture_connector`` answers a **support** question —
"does Concord ship a connector for this platform" — which is a statement about
Concord's feature set, not about the customer's environment. Using it to decide
whether an auto-composed SSP statement needs the manual-evidence caveat meant
an AWS GovCloud or M365 tenant that had configured **nothing** still got the
caveat omitted and a platform-derived "Implemented" retained: an evidenced
claim made to an assessor because Concord *could* capture, not because anything
ever did.

These tests drive the real production path (``derive_system`` →
``generate_ssp`` → ``generate_statements``) against the real database with real
``ConnectorConfig`` rows — never a monkeypatched predicate, which would only
prove the mock works.
"""

from __future__ import annotations

import ast
import inspect
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from ccf.config import get_settings
from ccf.connectors import connector_keys
from ccf.db import session_scope
from ccf.governance.automation import (
    PLATFORM_TO_SSP,
    coverage,
    derive_system,
    generate_ssp,
    platform_capture_is_live,
)
from ccf.models import (
    CaptureSnapshot,
    Organization,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
)
from ccf.models_grc import ConnectorConfig
from ccf.ssp.platforms import (
    MANUAL_EVIDENCE_MARKER,
    MANUAL_EVIDENCE_NOTE,
    NO_TENANT_CAPTURE_NOTE,
    PLATFORM_CONNECTOR_KEYS,
    PLATFORMS,
    connector_key_for_platform,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _now() -> datetime:
    return datetime.now(UTC)


async def _seed_controls(session, prefix: str) -> list[str]:
    """A customer-responsibility domain (AC) and a platform-inherited one (PE).

    ``ScoringControl`` is a GLOBAL shared table, so the caller must delete these
    again or they leak into every later test in the session.
    """
    control_ids = [f"AC.{prefix}-3.1.1", f"PE.{prefix}-3.10.1"]
    session.add_all(
        [
            ScoringControl(
                control_id=control_ids[0],
                nist_id=f"AC-{prefix}-1",
                domain="AC",
                title="Access Control",
                point_value="5",
                requirement="limit system access to authorized users",
                m365_coverage_status="Customer Responsibility",
                sort_order=1,
            ),
            ScoringControl(
                control_id=control_ids[1],
                nist_id=f"PE-{prefix}-1",
                domain="PE",
                title="Physical Access",
                point_value="1",
                requirement="limit physical access to organizational systems",
                m365_coverage_status="Microsoft Coverage",
                sort_order=2,
            ),
        ]
    )
    await session.flush()
    return control_ids


@asynccontextmanager
async def _tenant(
    name: str,
    prefix: str,
    cloud_platform: str | None,
    *,
    connector: dict | None = None,
    captured_at: datetime | None = None,
) -> AsyncIterator[tuple[dict, list[SSPControlEntry]]]:
    """Seed one org + system + (optionally) one real ``ConnectorConfig`` row and
    one real ``CaptureSnapshot``, generate the SSP, and yield
    ``(coverage_rollup, entries)``.

    ``connector`` is the literal column state for the row (connector_type,
    status, last_sync, objects_discovered) so each rung of the "is this
    connector actually producing evidence" ladder can be seeded for real.

    ``captured_at`` seeds the *artifact* a real capture produces. The status
    columns alone stopped being proof once ``POST /connector-configs/{id}/sync``
    -- a credential-free mock that writes exactly those columns -- was measured
    to manufacture an evidenced SSP claim; ``organization_capture_is_live`` now
    also requires a recent ``CaptureSnapshot``, which no status-column writer
    can fabricate. Tests of the unhealthy rungs pass a *fresh* ``captured_at``
    deliberately, so the only thing wrong with the tenant is the rung under
    test and rung 1 is proved to still carry its own weight.

    The snapshot's ``nist_id`` is left NULL on purpose: a captured value keyed
    to one of the seeded controls would be rendered into the narrative, and a
    fixture that supplies the text under assertion proves nothing.
    """
    control_ids: list[str] = []
    org_id: int | None = None
    proj_id: int | None = None
    try:
        async with session_scope() as session:
            org = Organization(name=name)
            session.add(org)
            await session.flush()
            org_id = org.id
            sysrow = System(organization_id=org.id, name=f"{name} system")
            session.add(sysrow)
            await session.flush()
            control_ids = await _seed_controls(session, prefix)
            if connector is not None:
                session.add(
                    ConnectorConfig(
                        organization_id=org.id,
                        name=f"{name} connector",
                        **connector,
                    )
                )
                if captured_at is not None:
                    session.add(
                        CaptureSnapshot(
                            organization_id=org.id,
                            connector=connector["connector_type"],
                            odp_key="mfa_enforced",
                            value="true",
                            captured_at=captured_at,
                        )
                    )
                await session.flush()
            profile = SystemProfile(
                system_id=sysrow.id, environment_type="cloud", cloud_platform=cloud_platform
            )
            session.add(profile)
            await session.flush()
            await derive_system(
                session,
                system_id=sysrow.id,
                org_id=sysrow.organization_id,
                profile=profile,
                create_poams=False,
            )
            proj_id = await generate_ssp(session, system=sysrow, profile=profile)
            entries = list(
                (
                    await session.execute(
                        select(SSPControlEntry).where(SSPControlEntry.project_id == proj_id)
                    )
                )
                .scalars()
                .all()
            )
            cov = coverage(
                profile,
                connector_backed=await platform_capture_is_live(
                    session,
                    organization_id=sysrow.organization_id,
                    platform=PLATFORM_TO_SSP.get(cloud_platform or "", ""),
                ),
            )
        yield cov, entries
    finally:
        async with session_scope() as session:
            if control_ids:
                await session.execute(
                    delete(ScoringControl).where(ScoringControl.control_id.in_(control_ids))
                )
            if proj_id is not None:
                await session.execute(delete(SSPProject).where(SSPProject.id == proj_id))
            if org_id is not None:
                await session.execute(delete(Organization).where(Organization.id == org_id))


def _texts(entries: list[SSPControlEntry]) -> dict[str, str]:
    return {
        e.control_id: "\n".join((p.get("text") or "") for p in e.part_narratives or [])
        for e in entries
    }


# --- 1. The defect ----------------------------------------------------------


@pytest.mark.asyncio
async def test_aws_govcloud_with_no_connector_is_flagged_manual_evidence() -> None:
    """An AWS GovCloud tenant that has configured nothing has captured nothing.

    Concord shipping an AWS connector is not evidence about THIS tenant, so
    every narrative must carry the manual-evidence caveat and the
    platform-derived "Implemented" must be downgraded.
    """
    async with _tenant("Unconnected AWS Org", "AWSNONE", "aws_govcloud") as (cov, entries):
        assert entries, "expected seeded SSP entries"
        for control_id, text in _texts(entries).items():
            assert MANUAL_EVIDENCE_MARKER in text, (
                f"{control_id} narrative claims evidence with no connector configured: {text!r}"
            )
            # The reason stated must be the true one: AWS GovCloud *does* have
            # a connector in Concord, this tenant just never captured with it.
            assert NO_TENANT_CAPTURE_NOTE in text
            assert MANUAL_EVIDENCE_NOTE not in text
        pe = [e for e in entries if e.control_id.startswith("PE.")]
        assert pe, "expected the platform-inherited PE entry"
        for e in pe:
            assert "Implemented" not in (e.implementation_status or []), (
                f"{e.control_id} still claims {e.implementation_status} with nothing captured"
            )
        assert cov["covered"] == 0
        assert cov["manual_evidence_required"] >= 1


# --- 2. The backed case -----------------------------------------------------


@pytest.mark.asyncio
async def test_aws_govcloud_with_live_connector_keeps_implemented() -> None:
    """A configured, recently-synced connector that discovered objects IS
    evidence about this tenant: no caveat, and "Implemented" is retained."""
    async with _tenant(
        "Connected AWS Org",
        "AWSLIVE",
        "aws_govcloud",
        connector={
            "connector_type": "aws_govcloud",
            "status": "configured",
            "last_sync": _now(),
            "objects_discovered": 42,
        },
        captured_at=_now(),
    ) as (cov, entries):
        assert entries
        for control_id, text in _texts(entries).items():
            assert MANUAL_EVIDENCE_MARKER not in text, f"{control_id} over-flagged: {text!r}"
        pe = [e for e in entries if e.control_id.startswith("PE.")]
        assert pe
        assert all("Implemented" in (e.implementation_status or []) for e in pe)
        assert cov["covered"] >= 1
        assert cov["manual_evidence_required"] == 0


# --- 3. Each rung of the ladder, separately ---------------------------------


@pytest.mark.parametrize(
    ("rung", "row"),
    [
        (
            "not configured",
            {
                "connector_type": "aws_govcloud",
                "status": "not_configured",
                "last_sync": None,
                "objects_discovered": 0,
            },
        ),
        (
            "configured but never synced",
            {
                "connector_type": "aws_govcloud",
                "status": "configured",
                "last_sync": None,
                "objects_discovered": 0,
            },
        ),
        (
            "synced but discovered nothing",
            {
                "connector_type": "aws_govcloud",
                "status": "configured",
                "last_sync": None,  # replaced below; parametrize must stay static
                "objects_discovered": 0,
            },
        ),
        (
            "stale sync",
            {
                "connector_type": "aws_govcloud",
                "status": "configured",
                "last_sync": None,  # replaced below
                "objects_discovered": 5,
            },
        ),
    ],
    ids=["not_configured", "never_synced", "empty_sync", "stale_sync"],
)
@pytest.mark.asyncio
async def test_each_unhealthy_rung_counts_as_not_backed(rung: str, row: dict) -> None:
    """Every rung below "current" must count as NOT backed — conservative by
    design, because under-flagging ships a false evidenced claim."""
    row = dict(row)
    if rung == "synced but discovered nothing":
        row["last_sync"] = _now()
    elif rung == "stale sync":
        row["last_sync"] = _now() - timedelta(days=120)
    prefix = "AWS" + "".join(c for c in rung.upper() if c.isalpha())[:8]
    # A FRESH capture artifact, so rung 2 is satisfied and the only thing wrong
    # with this tenant is the status-column rung under test.
    async with _tenant(
        f"Rung Org {rung}", prefix, "aws_govcloud", connector=row, captured_at=_now()
    ) as (
        cov,
        entries,
    ):
        assert entries
        for control_id, text in _texts(entries).items():
            assert MANUAL_EVIDENCE_MARKER in text, (
                f"{control_id} treated '{rung}' as evidenced: {text!r}"
            )
        assert cov["covered"] == 0
        assert cov["manual_evidence_required"] >= 1


@pytest.mark.asyncio
async def test_another_orgs_connector_does_not_back_this_org() -> None:
    """``ConnectorConfig`` is organization-scoped. A healthy connector filed
    under a different org is not evidence about this one."""
    async with _tenant(
        "Neighbour AWS Org",
        "AWSNEIGH",
        "aws_govcloud",
        connector={
            "connector_type": "aws_govcloud",
            "status": "configured",
            "last_sync": _now(),
            "objects_discovered": 31,
        },
        captured_at=_now(),
    ) as (_cov, _entries), _tenant("Isolated AWS Org", "AWSISO", "aws_govcloud") as (cov, entries):
        for control_id, text in _texts(entries).items():
            assert MANUAL_EVIDENCE_MARKER in text, (
                f"{control_id} borrowed another org's connector: {text!r}"
            )
        assert cov["covered"] == 0


@pytest.mark.asyncio
async def test_m365_is_backed_by_the_msgraph_connector_not_an_m365_one() -> None:
    """The SSP platform code and the connector registry key differ. A row filed
    under the SSP code "m365" must NOT back the platform; the real key is
    "msgraph"."""
    wrong = {
        "connector_type": "m365",
        "status": "configured",
        "last_sync": _now(),
        "objects_discovered": 15,
    }
    async with _tenant(
        "M365 Wrong Key Org", "M365WK", "m365_gcc_high", connector=wrong, captured_at=_now()
    ) as (
        cov,
        entries,
    ):
        for control_id, text in _texts(entries).items():
            assert MANUAL_EVIDENCE_MARKER in text, (
                f"{control_id} was backed by a non-registry connector_type: {text!r}"
            )
        assert cov["covered"] == 0

    right = dict(wrong, connector_type="msgraph")
    async with _tenant(
        "M365 Right Key Org", "M365RK", "m365_gcc_high", connector=right, captured_at=_now()
    ) as (
        cov,
        entries,
    ):
        for control_id, text in _texts(entries).items():
            assert MANUAL_EVIDENCE_MARKER not in text, f"{control_id} over-flagged: {text!r}"
        assert cov["manual_evidence_required"] == 0


# --- 4. coverage() stays pure and every caller computes the flag ------------


@pytest.mark.asyncio
async def test_coverage_manual_evidence_required_follows_the_passed_flag() -> None:
    """The rollup is a pure function of the derivation plus the flag — the same
    snapshot rolls up differently depending only on what the caller computed."""
    async with _tenant("Coverage Flag Org", "COVFLAG", "aws_govcloud") as (_cov, _entries):
        async with session_scope() as session:
            profile = (
                (
                    await session.execute(
                        select(SystemProfile).order_by(SystemProfile.id.desc()).limit(1)
                    )
                )
                .scalars()
                .first()
            )
            assert profile is not None
            backed = coverage(profile, connector_backed=True)
            unbacked = coverage(profile, connector_backed=False)
        assert unbacked["manual_evidence_required"] > backed["manual_evidence_required"]
        assert backed["covered"] > unbacked["covered"]
        assert backed["by_state"] == unbacked["by_state"]  # the snapshot itself is untouched


def test_coverage_requires_an_explicit_connector_backed_flag() -> None:
    """No default: a caller that forgets cannot silently get the unsafe
    direction (the one that omits the caveat)."""
    sig = inspect.signature(coverage)
    param = sig.parameters["connector_backed"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY
    assert param.default is inspect.Parameter.empty


def test_every_coverage_caller_passes_a_computed_flag() -> None:
    """Every in-tree call site of ``automation.coverage`` passes the keyword.

    Resolved from the source rather than listed by hand, so a caller added
    later without the flag is caught here and not in a generated document.
    Other modules have their own unrelated ``coverage()`` (``ccf.packs``,
    ``ccf.analytics``), so the callee is resolved through each module's
    imports rather than matched on the bare name.
    """
    root = Path(__file__).resolve().parents[1] / "src"
    found: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text())
        direct: set[str] = set()  # names bound to automation.coverage itself
        modules: set[str] = set()  # names bound to the automation MODULE
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod.endswith("governance.automation") or mod.endswith(".automation"):
                    direct |= {a.asname or a.name for a in node.names if a.name == "coverage"}
                elif mod.endswith("governance") or mod.endswith("ccf"):
                    modules |= {a.asname or a.name for a in node.names if a.name == "automation"}
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.endswith("governance.automation"):
                        modules.add(a.asname or a.name.split(".")[-1])
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Attribute):
                hit = fn.attr == "coverage" and isinstance(fn.value, ast.Name) and (
                    fn.value.id in modules
                )
            elif isinstance(fn, ast.Name):
                hit = fn.id in direct
            else:
                hit = False
            if not hit:
                continue
            where = f"{path}:{node.lineno}"
            assert "connector_backed" in {k.arg for k in node.keywords}, (
                f"{where} calls automation.coverage without connector_backed"
            )
            found.append(where)
    assert len(found) >= 2, f"expected the known automation.coverage call sites, found {found}"


# --- 5. The mapping is self-checking ---------------------------------------


def test_platform_connector_keys_are_real_registry_keys() -> None:
    """Every value in the SSP-platform → connector-key mapping must be a real
    key in the connector registry, so renaming or removing a connector fails
    loudly instead of silently making a platform look unbacked.

    A subset, not an equality: the registry also holds connectors for things
    that are not SSP deployment platforms (e.g. ``puppetdb``).
    """
    registry = set(connector_keys())
    mapped = set(PLATFORM_CONNECTOR_KEYS.values())
    assert mapped, "the mapping must not be empty"
    assert mapped <= registry, f"unknown connector keys in mapping: {sorted(mapped - registry)}"
    assert PLATFORM_CONNECTOR_KEYS["m365"] == "msgraph"
    assert connector_key_for_platform("aws_govcloud") == "aws_govcloud"
    assert connector_key_for_platform("azure") is None


def test_mapping_keys_are_real_ssp_platforms() -> None:
    """And every key is a real SSP platform — ``puppetdb`` is a connector for
    something that is not a deployment platform and must not be here."""
    assert set(PLATFORM_CONNECTOR_KEYS) <= set(PLATFORMS)
    assert "puppetdb" not in PLATFORM_CONNECTOR_KEYS
    assert "puppetdb" not in set(PLATFORM_CONNECTOR_KEYS.values())


# --- 6. A platform with no connector at all stays flagged -------------------


@pytest.mark.asyncio
async def test_azure_stays_flagged_whatever_the_org_has_configured() -> None:
    """Azure has no capture connector in Concord at all, so no amount of
    configured connectors for other platforms can make it evidenced — and the
    reason rendered is the platform one, not the tenant one."""
    async with _tenant(
        "Azure With Other Connectors Org",
        "AZOTHER",
        "azure_gov",
        connector={
            "connector_type": "msgraph",
            "status": "configured",
            "last_sync": _now(),
            "objects_discovered": 99,
        },
        captured_at=_now(),
    ) as (cov, entries):
        assert entries
        for control_id, text in _texts(entries).items():
            assert MANUAL_EVIDENCE_NOTE in text, f"{control_id} unflagged on Azure: {text!r}"
            assert NO_TENANT_CAPTURE_NOTE not in text
        assert cov["covered"] == 0
        assert cov["manual_evidence_required"] >= 1
