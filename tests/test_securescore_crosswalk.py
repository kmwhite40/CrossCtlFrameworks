"""Microsoft Secure Score through Concord's crosswalk.

Every control attribution here is Concord's claim, because Microsoft publishes no
800-53 mapping for Secure Score (measured on a live GCC High tenant; see the
runbook). These pin the rules that keep that claim honest: the mapping names real
800-53 controls, full points or it is not a pass, an administrator's assertion is
never a pass, the rows are labelled and tiered as a crosswalk, and posture never
counts them as Concord's own verified checks.

All profiles below are synthetic. The ids are real Secure Score ids, but no tenant
data is committed -- this repository is public.
"""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from ccf.analytics.framework_posture import system_framework_posture
from ccf.catalog.canonical import canonicalize
from ccf.catalog.crosswalk import CROSSWALK_COLUMN, CROSSWALK_FRAMEWORK
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import (
    POAM,
    Control,
    Framework,
    FrameworkMapping,
    Organization,
    System,
    SystemProfile,
    Task,
)
from ccf.models_grc import ControlTest
from ccf.posture import securescore as ss
from ccf.posture import securescore_scan as ingest_mod
from ccf.posture.attested import CHECK_SOURCE as ATTESTED
from ccf.posture.scan import trust_tier
from ccf.posture.securescore_scan import ingest_securescore
from ccf.scoring.seed import seed_scoring_controls

_SEQ = itertools.count()
_CATALOG = Path("src/ccf/catalog/oscal_data/NIST_SP-800-53_rev5_catalog.json")


def _catalog_ids() -> dict[str, bool]:
    """OSCAL control id -> withdrawn, over the bundled 800-53 Rev. 5 catalog."""
    out: dict[str, bool] = {}

    def walk(controls: list[dict[str, Any]]) -> None:
        for c in controls:
            out[c["id"]] = any(
                p.get("name") == "status" and p.get("value") == "withdrawn"
                for p in c.get("props", [])
            )
            walk(c.get("controls", []))

    for group in json.loads(_CATALOG.read_text(encoding="utf-8"))["catalog"]["groups"]:
        walk(group.get("controls", []))
    return out


def _oscal(control: str) -> str:
    return re.sub(r"\((\d+)\)", r".\1", control).lower()


# --------------------------------------------------------------------------
# The mapping itself
# --------------------------------------------------------------------------


def test_every_mapped_control_is_a_live_800_53_rev5_control() -> None:
    """``canonicalize`` checks the format only. A misremembered enhancement
    number or a withdrawn control would pass it and reach a package."""
    catalog = _catalog_ids()
    problems = []
    for family in ss.CROSSWALK:
        for control in family.controls:
            canon = canonicalize(control)
            if canon is None or canon.value != control:
                problems.append(f"{family.key}: {control!r} is not canonical")
            elif _oscal(control) not in catalog:
                problems.append(f"{family.key}: {control} is not in 800-53 Rev. 5")
            elif catalog[_oscal(control)]:
                problems.append(f"{family.key}: {control} is withdrawn")
    assert problems == []


def test_no_profile_is_in_two_families() -> None:
    """One measurement crediting two primaries is the over-attribution the
    asymmetric rule exists to prevent."""
    seen: dict[str, str] = {}
    for family in ss.CROSSWALK:
        for profile in family.profiles:
            assert profile not in seen, (profile, seen.get(profile), family.key)
            seen[profile] = family.key


def test_a_duplicate_profile_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    a = ss.Family("a", "SI-3", (), "r", ("scid_1",))
    b = ss.Family("b", "SI-4", (), "r", ("scid_1",))
    monkeypatch.setattr(ss, "CROSSWALK", (a, b))
    with pytest.raises(ValueError, match="scid_1"):
        ss.crosswalk_index()


def test_every_family_states_its_rationale() -> None:
    """The rationale is what a reviewer accepts or rejects; an empty one is a
    mapping nobody can review."""
    assert all(f.rationale.strip() and f.profiles for f in ss.CROSSWALK)


# --------------------------------------------------------------------------
# Verdicts
# --------------------------------------------------------------------------


def _profile(state: str | None = None, *, max_score: float = 8.0) -> dict[str, Any]:
    updates = [{"state": state}] if state else []
    return {"id": "scid_2010", "title": "Turn on AV", "maxScore": max_score,
            "controlStateUpdates": updates}


def test_full_points_is_a_pass() -> None:
    assert ss.verdict_for(_profile(), {"score": 8.0})[0] == "pass"


@pytest.mark.parametrize("score", [7.83, 0.44, 0.0])
def test_less_than_full_points_is_a_fail_with_the_fraction(score: float) -> None:
    """A device profile is a fleet ratio: 7.83 of 8 means some devices are not
    compliant, and the worst resource decides everywhere else in Concord."""
    status, detail = ss.verdict_for(_profile(), {"score": score})
    assert status == "fail"
    assert f"{score:g} of 8" in detail


@pytest.mark.parametrize("state", ["ThirdParty", "thirdParty", "Ignored", "Reviewed"])
def test_an_administrator_s_assertion_is_never_a_pass(state: str) -> None:
    """The live tenant has Linux real-time antivirus at 10 of 10 and marked
    ThirdParty: full points Microsoft did not observe."""
    status, detail = ss.verdict_for(_profile(state), {"score": 8.0})
    assert status == "manual_review_required"
    assert detail.startswith("Not observed")


def test_an_unrecognised_state_is_not_a_pass() -> None:
    assert ss.verdict_for(_profile("SomethingNew"), {"score": 8.0})[0] == (
        "manual_review_required"
    )


@pytest.mark.parametrize("score", [None, "n/a", {}])
def test_an_unreadable_score_is_not_a_pass(score: object) -> None:
    assert ss.verdict_for(_profile(), {"score": score})[0] == "manual_review_required"


def test_a_profile_worth_no_points_is_not_a_pass() -> None:
    assert ss.verdict_for(_profile(max_score=0), {"score": 0})[0] == (
        "manual_review_required"
    )


def test_an_unscored_or_deprecated_profile_writes_no_row() -> None:
    """Nothing was measured, so nothing is recorded -- and the report says so."""
    profiles = [
        {"id": "scid_2010", "title": "AV", "maxScore": 10.0},
        {"id": "scid_2012", "title": "RTP", "maxScore": 10.0, "deprecated": True},
        {"id": "scid_2016", "title": "Cloud", "maxScore": 8.0},
    ]
    scores = [{"controlName": "scid_2010", "score": 10.0},
              {"controlName": "scid_2012", "score": 10.0},
              {"controlName": "not_mapped_anywhere", "score": 1.0}]
    rows, report = ss.crosswalk_rows(profiles, scores)
    assert [r.profile_id for r in rows] == ["scid_2010"]
    assert "scid_2016" in report["mapped_but_not_scored"]
    assert report["scored_but_not_mapped"] == ["not_mapped_anywhere"]


# --------------------------------------------------------------------------
# Ingest
# --------------------------------------------------------------------------


class _Graph:
    key = "msgraph"

    def __init__(self, snapshot: dict[str, Any]) -> None:
        self.snapshot = snapshot

    def is_configured(self) -> bool:
        return True

    async def securescore_snapshot(self) -> dict[str, Any]:
        return self.snapshot


def _snapshot(*pairs: tuple[str, float, float, str | None]) -> dict[str, Any]:
    profiles, scores = [], []
    for profile_id, achieved, maximum, state in pairs:
        profiles.append({"id": profile_id, "title": profile_id, "maxScore": maximum,
                         "controlStateUpdates": [{"state": state}] if state else []})
        scores.append({"controlName": profile_id, "score": achieved})
    return {"available": True, "reason": None, "profiles": profiles,
            "control_scores": scores, "scored_on": "2026-10-02T00:00:00Z"}


def _patch(monkeypatch: pytest.MonkeyPatch, conn: _Graph | None) -> None:
    async def _fake(*a: object, **k: object) -> _Graph | None:
        return conn

    monkeypatch.setattr(ingest_mod, "_connector_for_org", _fake)
    get_settings.cache_clear()


async def _system(session: Any) -> System:
    org = Organization(name=f"SecureScoreOrg{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"ss-{next(_SEQ)}", baseline="moderate")
    session.add(sys_)
    await session.flush()
    return sys_


async def _tests(session: Any, system_id: int) -> dict[str, ControlTest]:
    rows = (
        await session.execute(select(ControlTest).where(ControlTest.system_id == system_id))
    ).scalars().all()
    return {str(t.check_key): t for t in rows}


async def test_rows_are_labelled_as_the_crosswalk_with_the_family_s_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Graph(_snapshot(("exo_mailboxaudit", 3.0, 3.0, None))))
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await ingest_securescore(session, system_id=sys_.id)
        tests = await _tests(session, sys_.id)

    test = tests[ss.check_key_for("exo_mailboxaudit")]
    assert out["written"] == 1 and out["available"] is True
    assert test.check_source == ss.CHECK_SOURCE
    assert test.connector_type == "msgraph"
    assert test.control_id == "AU-12"
    assert test.control_ids == ["AU-12", "AU-2"]
    assert test.last_status == "pass"
    assert "Concord's crosswalk" in (test.expected or "")


async def test_a_failure_is_recorded_but_files_no_poam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The attribution is Concord's, so filing the weakness is a human's call."""
    _patch(monkeypatch, _Graph(_snapshot(("exo_mailboxaudit", 0.0, 3.0, None))))
    async with session_scope() as session:
        sys_ = await _system(session)
        await ingest_securescore(session, system_id=sys_.id)
        tests = await _tests(session, sys_.id)
        poams = (await session.execute(
            select(POAM).where(POAM.system_id == sys_.id))).scalars().all()
        tasks = (await session.execute(
            select(Task).where(Task.system_id == sys_.id))).scalars().all()
    assert tests[ss.check_key_for("exo_mailboxaudit")].last_status == "fail"
    assert poams == [] and tasks == []


async def test_an_unavailable_read_writes_nothing_and_says_why(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Graph({"available": False, "reason": "no Graph token",
                                "profiles": [], "control_scores": [], "scored_on": None}))
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await ingest_securescore(session, system_id=sys_.id)
        tests = await _tests(session, sys_.id)
    assert tests == {}
    assert out["available"] is False and out["reason"] == "no Graph token"


async def test_no_connector_is_reported_not_crashed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, None)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await ingest_securescore(session, system_id=sys_.id)
    assert out["available"] is False and "not configured" in out["reason"]


async def test_a_dry_run_measures_the_same_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snap = _snapshot(("exo_mailboxaudit", 3.0, 3.0, None), ("scid_2010", 5.0, 10.0, None))
    _patch(monkeypatch, _Graph(snap))
    async with session_scope() as session:
        sys_ = await _system(session)
        dry = await ingest_securescore(session, system_id=sys_.id, write=False)
        assert await _tests(session, sys_.id) == {}
        real = await ingest_securescore(session, system_id=sys_.id)
    assert dry["statuses"] == real["statuses"] == {"pass": 1, "fail": 1}
    assert (dry["written"], real["written"]) == (0, 2)


async def test_every_report_has_one_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    """Three paths build this report; hand-built copies are how keys drift."""
    _patch(monkeypatch, _Graph(_snapshot(("exo_mailboxaudit", 3.0, 3.0, None))))
    async with session_scope() as session:
        sys_ = await _system(session)
        read = await ingest_securescore(session, system_id=sys_.id, write=False)
    unread = ingest_mod.report(sys_.id, available=False, reason="x")
    assert set(read) == set(unread)


# --------------------------------------------------------------------------
# Trust and posture
# --------------------------------------------------------------------------


def _row(check_source: str | None) -> ControlTest:
    return ControlTest(control_id="SI-3", name="x", method="connector",
                       source="generated", check_key="x", check_source=check_source)


def test_the_crosswalk_ranks_below_attestation_and_above_a_pack() -> None:
    platform = trust_tier(_row("platform"))
    attested = trust_tier(_row(ATTESTED))
    crosswalk = trust_tier(_row(ss.CHECK_SOURCE))
    pack = trust_tier(_row("pack:some-pack"))
    assert platform < attested < crosswalk < pack


async def _moderate(session: Any, *controls: str) -> System:
    sys_ = await _system(session)
    for identifier in controls:
        existing = (await session.execute(
            select(Control).where(Control.identifier == identifier))).scalars().first()
        if existing is None:
            # High alongside Moderate: FIPS-199 baselines nest, and setting
            # Moderate alone breaks that for the shared catalog.
            session.add(Control(identifier=identifier, sequence_control=identifier,
                                fisma_mod=True, fisma_high=True))
        else:
            existing.fisma_mod = True
            existing.fisma_high = True
    await session.flush()
    return sys_


async def _passing_row(session: Any, sys_: System, control: str, source: str) -> None:
    test = ControlTest(organization_id=sys_.organization_id, system_id=sys_.id,
                       control_id=control, control_ids=[control], name=f"{source}:{control}",
                       method="connector", source="generated",
                       check_key=f"{source}.{control}.{next(_SEQ)}", check_source=source,
                       connector_type="msgraph")
    session.add(test)
    await session.flush()
    await record_result(session, test, status="pass", detail="ok", evaluated=1)


async def test_a_control_passed_only_by_the_crosswalk_is_named_as_such() -> None:
    """Counted in passing -- it is real evidence -- and named, never folded into
    what Concord verified."""
    async with session_scope() as session:
        sys_ = await _moderate(session, "SI-3")
        await _passing_row(session, sys_, "SI-3", ss.CHECK_SOURCE)
        posture = await system_framework_posture(
            session, org_id=sys_.organization_id, system_id=sys_.id)
    assert "SI-3" in posture["passing"]
    assert posture["securescore_crosswalk_only"] == ["SI-3"]
    assert posture["provider_attested_only"] == []


async def test_a_control_concord_also_verified_is_not_named() -> None:
    async with session_scope() as session:
        sys_ = await _moderate(session, "SI-4")
        await _passing_row(session, sys_, "SI-4", ss.CHECK_SOURCE)
        await _passing_row(session, sys_, "SI-4", "platform")
        posture = await system_framework_posture(
            session, org_id=sys_.organization_id, system_id=sys_.id)
    assert "SI-4" in posture["passing"]
    assert posture["securescore_crosswalk_only"] == []


async def test_the_171_view_names_a_crosswalk_only_requirement() -> None:
    """The 800-171 path reaches a crosswalk row through the catalog's 800-53 ->
    800-171 map, where the row's ``check_source`` is no longer recoverable, so
    the provenance has to be carried alongside or every Secure Score pass would
    read as Concord's own. Mirrors the attested test of the same route."""
    async with session_scope() as session:
        await seed_scoring_controls(session)
        framework = (
            await session.execute(
                select(Framework).where(Framework.code == CROSSWALK_FRAMEWORK)
            )
        ).scalars().first()
        if framework is None:
            framework = Framework(code=CROSSWALK_FRAMEWORK, name="NIST SP 800-171 Rev. 2")
            session.add(framework)
            await session.flush()
        control = (
            await session.execute(select(Control).where(Control.identifier == "AU-11"))
        ).scalars().first()
        if control is None:
            control = Control(identifier="AU-11")
            session.add(control)
            await session.flush()
        exists = (
            await session.execute(
                select(FrameworkMapping).where(
                    FrameworkMapping.control_id == control.id,
                    FrameworkMapping.column_key == CROSSWALK_COLUMN,
                )
            )
        ).scalars().first()
        if exists is None:
            session.add(
                FrameworkMapping(
                    control_id=control.id,
                    framework_id=framework.id,
                    column_key=CROSSWALK_COLUMN,
                    value="3.3.1 Create and retain system audit logs",
                )
            )
        sys_ = await _system(session)
        # No baseline: a declared baseline outranks the profile's framework, and
        # this test is about the 800-171 view.
        sys_.baseline = None
        session.add(
            SystemProfile(
                system_id=sys_.id,
                answers={},
                environment_type="cloud",
                cloud_platform="m365_gcc_high",
                frameworks=["NIST_800_171"],
            )
        )
        session.add(
            ControlTest(
                organization_id=sys_.organization_id,
                system_id=sys_.id,
                control_id="AU-11",
                control_ids=["AU-11"],
                name="crosswalk row",
                method="connector",
                source="generated",
                check_key=ss.check_key_for("exo_mailboxaudit"),
                check_source=ss.CHECK_SOURCE,
                last_status="pass",
            )
        )
        await session.flush()
        out = await system_framework_posture(
            session, org_id=sys_.organization_id, system_id=sys_.id
        )
    assert out["framework"] == "nist_800_171"
    assert "3.3.1" in out["passing"]
    assert out["securescore_crosswalk_only"] == ["3.3.1"]
    assert out["provider_attested_only"] == []
