"""What adopting a desired-state change would affect here."""

from __future__ import annotations

import itertools

from ccf.db import session_scope
from ccf.models import Organization, System, SystemComponent
from ccf.models_capability import Capability, CapabilityComponent, CapabilityControl
from ccf.models_grc import ControlTest
from ccf.models_waivers import Waiver
from ccf.packs.diff import diff_posture_rules
from ccf.packs.impact import build_config_change_impact
from ccf.posture.providers import m365

_SEQ = itertools.count()

FORM_B = {
    "key": "org.no_guest_accounts",
    "kind": "posture",
    "definition": {
        "provider": "msgraph",
        "resource_type": "entra_user",
        "endpoint": "/v1.0/users",
        "expected": "no guest account exists",
        "control_ids": ["AC-2", "AC-6"],
        "mode": "per_resource",
        "predicate": {"op": "not_equals", "path": "userType", "value": "Guest"},
    },
}

FORM_A = {
    "key": "org.stale_accounts.60d",
    "kind": "posture",
    "definition": {
        "evaluator": m365.STALE_ACCOUNTS.key,
        "parameters": {"threshold_days": 60},
    },
}


def _manifest(*rules: dict, version: str = "1.0.0") -> dict:
    return {
        "id": "impact-pack",
        "name": "Impact Pack",
        "version": version,
        "schema_version": "1",
        "controls": [{"control_id": "AC-2"}],
        "rules": list(rules),
    }


async def _org(session) -> Organization:
    org = Organization(name=f"ImpactOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    return org


async def _system(session, org) -> System:
    sys_ = System(organization_id=org.id, name=f"ImpactSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    return sys_


# ── controls and capabilities ────────────────────────────────────────────────


async def test_an_added_rule_reports_the_controls_it_would_evidence() -> None:
    async with session_scope() as session:
        org = await _org(session)
        diff = diff_posture_rules(_manifest(), _manifest(FORM_B))
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        assert {c["control_id"] for c in impact.controls_affected} == {"AC-2", "AC-6"}
        assert {c["change"] for c in impact.controls_affected} == {"added"}


async def test_a_removed_rule_reports_its_controls_as_removed() -> None:
    async with session_scope() as session:
        org = await _org(session)
        diff = diff_posture_rules(_manifest(FORM_B), _manifest())
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        assert {c["change"] for c in impact.controls_affected} == {"removed"}


async def test_a_changed_rule_reports_its_controls_as_changed() -> None:
    async with session_scope() as session:
        org = await _org(session)
        tightened = {
            **FORM_A,
            "definition": {**FORM_A["definition"], "parameters": {"threshold_days": 30}},
        }
        diff = diff_posture_rules(_manifest(FORM_A), _manifest(tightened))
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        assert {c["change"] for c in impact.controls_affected} == {"changed"}


async def test_a_form_a_rule_inherits_the_platform_checks_controls() -> None:
    """A parameterized rule restates no control ids; the evaluator's apply."""
    async with session_scope() as session:
        org = await _org(session)
        diff = diff_posture_rules(_manifest(), _manifest(FORM_A))
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        assert {c["control_id"] for c in impact.controls_affected} == set(
            m365.STALE_ACCOUNTS.control_ids
        )


async def test_capabilities_covering_an_affected_control_are_reported() -> None:
    """A rule change reaches authored SSP prose through the capability."""
    async with session_scope() as session:
        org = await _org(session)
        sys_ = await _system(session, org)
        comp = SystemComponent(
            organization_id=org.id, system_id=sys_.id, type="service", title="Entra ID"
        )
        session.add(comp)
        cap = Capability(
            organization_id=org.id,
            key=f"impact-cap-{next(_SEQ)}",
            title="Account management",
            statement="Accounts are reviewed quarterly.",
            status="implemented",
        )
        session.add(cap)
        await session.flush()
        session.add(
            CapabilityComponent(
                organization_id=org.id, capability_id=cap.id, component_id=comp.id
            )
        )
        session.add(
            CapabilityControl(organization_id=org.id, capability_id=cap.id, control_id="AC-2")
        )
        await session.flush()

        diff = diff_posture_rules(_manifest(), _manifest(FORM_B))
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        reported = {c["capability_key"]: c for c in impact.capabilities_affected}
        assert cap.key in reported
        assert "AC-2" in reported[cap.key]["controls"]


# ── retirement and orphaned acceptance ───────────────────────────────────────


async def test_a_removed_rule_reports_the_check_it_would_retire() -> None:
    """With its current status: retiring a failing check is a different
    decision from retiring a passing one."""
    async with session_scope() as session:
        org = await _org(session)
        sys_ = await _system(session, org)
        test = ControlTest(
            organization_id=org.id,
            system_id=sys_.id,
            control_id="AC-2",
            name="No guests",
            method="connector",
            source="generated",
            check_key=FORM_B["key"],
            last_status="fail",
        )
        session.add(test)
        await session.flush()

        diff = diff_posture_rules(_manifest(FORM_B), _manifest())
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        assert len(impact.checks_retired) == 1
        row = impact.checks_retired[0]
        assert row["check_key"] == FORM_B["key"]
        assert row["last_status"] == "fail"
        assert row["system_id"] == sys_.id


async def test_a_changed_rule_does_not_retire_its_check() -> None:
    async with session_scope() as session:
        org = await _org(session)
        sys_ = await _system(session, org)
        session.add(
            ControlTest(
                organization_id=org.id, system_id=sys_.id, control_id="AC-2",
                name="Stale", method="connector", check_key=FORM_A["key"],
            )
        )
        await session.flush()
        tightened = {
            **FORM_A,
            "definition": {**FORM_A["definition"], "parameters": {"threshold_days": 30}},
        }
        diff = diff_posture_rules(_manifest(FORM_A), _manifest(tightened))
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        assert impact.checks_retired == []


async def test_a_removed_rule_reports_a_waiver_left_orphaned() -> None:
    """A waiver keyed on check_key survives removal of the check it accepts --
    a formal acceptance of a finding that can no longer be produced."""
    async with session_scope() as session:
        org = await _org(session)
        sys_ = await _system(session, org)
        w = Waiver(
            organization_id=org.id,
            system_id=sys_.id,
            check_key=FORM_B["key"],
            rationale="accepted",
            status="approved",
        )
        session.add(w)
        await session.flush()

        diff = diff_posture_rules(_manifest(FORM_B), _manifest())
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        assert [x["waiver_id"] for x in impact.waivers_orphaned] == [w.id]
        assert impact.waivers_orphaned[0]["status"] == "approved"


async def test_an_added_rule_orphans_no_waiver() -> None:
    async with session_scope() as session:
        org = await _org(session)
        sys_ = await _system(session, org)
        session.add(
            Waiver(
                organization_id=org.id, system_id=sys_.id, check_key=FORM_B["key"],
                rationale="r", status="approved",
            )
        )
        await session.flush()
        diff = diff_posture_rules(_manifest(), _manifest(FORM_B))
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        assert impact.waivers_orphaned == []


# ── scoping and refusals ─────────────────────────────────────────────────────


async def test_another_tenants_check_is_not_reported_as_retiring() -> None:
    async with session_scope() as session:
        mine = await _org(session)
        theirs = await _org(session)
        their_sys = await _system(session, theirs)
        session.add(
            ControlTest(
                organization_id=theirs.id, system_id=their_sys.id, control_id="AC-2",
                name="Theirs", method="connector", check_key=FORM_B["key"],
            )
        )
        await session.flush()
        diff = diff_posture_rules(_manifest(FORM_B), _manifest())
        impact = await build_config_change_impact(session, org_id=mine.id, diff=diff)
        assert impact.checks_retired == []


async def test_another_tenants_waiver_is_not_reported_as_orphaned() -> None:
    async with session_scope() as session:
        mine = await _org(session)
        theirs = await _org(session)
        their_sys = await _system(session, theirs)
        session.add(
            Waiver(
                organization_id=theirs.id, system_id=their_sys.id, check_key=FORM_B["key"],
                rationale="r", status="approved",
            )
        )
        await session.flush()
        diff = diff_posture_rules(_manifest(FORM_B), _manifest())
        impact = await build_config_change_impact(session, org_id=mine.id, diff=diff)
        assert impact.waivers_orphaned == []


async def test_an_unknown_baseline_yields_an_empty_impact_with_a_reason() -> None:
    """Guessing at what changed from missing history is what diff refuses; the
    impact must not undo that."""
    async with session_scope() as session:
        org = await _org(session)
        diff = diff_posture_rules({}, _manifest(FORM_B))
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        assert impact.is_empty()
        assert impact.reason == "no retained manifest to compare"


async def test_an_empty_diff_is_an_empty_impact() -> None:
    async with session_scope() as session:
        org = await _org(session)
        diff = diff_posture_rules(_manifest(FORM_B), _manifest(FORM_B))
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        assert impact.is_empty()
        assert impact.reason is None


async def test_an_unresolvable_form_a_evaluator_reports_no_controls_not_a_crash() -> None:
    """A rule naming an evaluator this build does not have must degrade, not
    raise: the pack may target a newer platform version."""
    async with session_scope() as session:
        org = await _org(session)
        bogus = {
            "key": "org.from_the_future",
            "kind": "posture",
            "definition": {"evaluator": "m365.identity.invented_later"},
        }
        diff = diff_posture_rules(_manifest(), _manifest(bogus))
        impact = await build_config_change_impact(session, org_id=org.id, diff=diff)
        assert impact.controls_affected == []
        assert impact.unresolved == ["org.from_the_future"]
