"""Automated methods: posture checks that can contradict a KSI, never pass it."""

from __future__ import annotations

import itertools
import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.cr26.sdr import seed_sdr
from ccf.db import session_scope
from ccf.fedramp20x import catalog, readiness, validation
from ccf.fedramp20x import methods as m
from ccf.fedramp20x.validation import Verdict
from ccf.models import KSI, Organization, System
from ccf.models_grc import ControlTest

pytestmark = pytest.mark.usefixtures("fresh_engine", "isolate_ksi_rows")

_SEQ = itertools.count()
_OVERLAY = Path(__file__).parents[1] / "src/ccf/fedramp20x/rules_data/ksi_rules.json"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
async def _shipped_catalog() -> AsyncIterator[None]:
    async with session_scope() as s:
        await catalog.seed_ksis(s)
    yield
    async with session_scope() as s:
        await catalog.seed_ksis(s)


# --- the shipped curation -----------------------------------------------------


def test_every_shipped_method_is_a_platform_check_with_a_quoted_rationale() -> None:
    known = m.platform_checks()
    doc = json.loads(_OVERLAY.read_text())
    assert doc["rules"], "the overlay ships curated methods"
    for ident, entry in doc["rules"].items():
        assert set(entry) == {"methods"}, f"{ident}: only methods are authored so far"
        for method in entry["methods"]:
            assert method["check"] in known, (ident, method["check"])
            # The bar: name the words of the statement the failure contradicts.
            assert '"' in method["rationale"] or "Fails when" in method["rationale"]
            assert method["rationale"].startswith("Fails when"), (ident, method["check"])


def test_methods_seed_onto_the_catalog_and_mark_it_partial_not_automated() -> None:
    recs = {r["identifier"]: r for r in catalog.load_records()}
    apm = recs["KSI-IAM-APM"]
    assert [x["check"] for x in apm["methods"]][:2] == [
        "m365.identity.phishing_resistant_mfa",
        "m365.identity.phishable_methods_disabled",
    ]
    assert apm["automation_level"] == "partial"
    assert apm["rule"] == {"kind": "manual"}  # a method is not a verdict rule
    assert recs["KSI-CED-RAT"]["methods"] == []
    assert recs["KSI-CED-RAT"]["automation_level"] == "manual"


@pytest.mark.parametrize(
    ("methods", "match"),
    [
        ([{"check": "aws.not.a.check", "rationale": "x"}], "not a Concord platform"),
        ([{"check": "aws.iam.root_mfa_enabled", "rationale": "  "}], "no rationale"),
        (
            [
                {"check": "aws.iam.root_mfa_enabled", "rationale": "Fails when a"},
                {"check": "aws.iam.root_mfa_enabled", "rationale": "Fails when b"},
            ],
            "listed twice",
        ),
    ],
)
def test_a_bad_method_is_refused(tmp_path: Path, methods: list, match: str) -> None:
    overlay = tmp_path / "rules.json"
    overlay.write_text(json.dumps({"rules": {"KSI-IAM-APM": {"methods": methods}}}))
    with pytest.raises(m.MethodsError, match=match):
        catalog.load_records(overlay_path=overlay)


# --- folding a result into a verdict -----------------------------------------

_TWO = [
    {"check": "m365.identity.phishable_methods_disabled", "rationale": "r"},
    {"check": "m365.identity.phishing_resistant_mfa", "rationale": "r"},
]


def _manual() -> Verdict:
    return Verdict("manual_review_required", "low", "manual", assessor_review_required=True)


def test_a_failing_method_raises_a_manual_ksi_to_warn_and_names_it() -> None:
    v = m.apply(_manual(), _TWO, {"m365.identity.phishable_methods_disabled": "fail"})
    assert v.status == "warn"
    assert "m365.identity.phishable_methods_disabled" in (v.failure_reason or "")
    assert v.assessor_review_required
    assert "method:m365.identity.phishing_resistant_mfa:not_run" in v.evidence_refs


def test_passing_methods_are_evidence_never_a_pass() -> None:
    status = {k["check"]: "pass" for k in _TWO}
    v = m.apply(_manual(), _TWO, status)
    assert v.status == "manual_review_required"
    assert set(v.evidence_refs) == {f"method:{k['check']}:pass" for k in _TWO}


def test_a_method_lowers_a_pass_but_never_deepens_a_fail() -> None:
    failing = {"m365.identity.phishable_methods_disabled": "warn"}
    assert m.apply(Verdict("pass", "high", "rule"), _TWO, failing).status == "warn"
    assert m.apply(Verdict("fail", "high", "rule"), _TWO, failing).status == "fail"


def test_no_methods_leaves_the_verdict_untouched() -> None:
    v = _manual()
    assert m.apply(v, [], {"x": "fail"}) is v


# --- end to end ----------------------------------------------------------------


async def _system(cls: str | None = None) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"Methods Org {next(_SEQ)}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"Methods {next(_SEQ)}", certification_class=cls)
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


async def _result(org_id: int, sid: int, key: str, status: str, source: str = "platform") -> None:
    async with session_scope() as s:
        s.add(
            ControlTest(
                organization_id=org_id,
                system_id=sid,
                control_id="IA-2",
                name=key,
                method="connector",
                source="generated",
                check_key=key,
                check_source=source,
                last_status=status,
            )
        )


async def test_a_failing_platform_check_warns_its_ksi() -> None:
    org, sid = await _system()
    await _result(org, sid, "m365.identity.phishable_methods_disabled", "fail")
    async with session_scope() as s:
        out = {r["ksi_identifier"]: r for r in await validation.validate_system(s, system_id=sid)}
    assert out["KSI-IAM-APM"]["validation_status"] == "warn"
    assert out["KSI-CED-RAT"]["validation_status"] == "manual_review_required"


async def test_a_non_platform_row_with_the_same_key_is_ignored() -> None:
    org, sid = await _system()
    await _result(
        org, sid, "m365.identity.phishable_methods_disabled", "fail", source="pack:tenant"
    )
    async with session_scope() as s:
        out = {r["ksi_identifier"]: r for r in await validation.validate_system(s, system_id=sid)}
    assert out["KSI-IAM-APM"]["validation_status"] == "manual_review_required"


async def test_methods_that_ran_count_toward_frc_csx_vvk() -> None:
    org, sid = await _system("B")
    await _result(org, sid, "m365.identity.phishing_resistant_mfa", "pass")
    await _result(org, sid, "aws.inspector.enabled", "fail")  # ran; still a method
    async with session_scope() as s:
        score = await readiness.score_system(s, system_id=sid, persist=False)
    auto = score["automation_requirement"]
    assert auto["min_automated_methods_per_ksi"] == 1
    # KSI-IAM-APM and KSI-SCR-MON each have one method that ran here.
    assert auto["ksis_meeting"] == 2
    # Partial is not automated: readiness's automation coverage is unchanged.
    assert score["automation_coverage"] == 0


async def test_the_sdr_names_the_methods_as_tests() -> None:
    _org, sid = await _system()
    async with session_scope() as s:
        apm = (await s.execute(select(KSI).where(KSI.identifier == "KSI-IAM-APM"))).scalar_one()
        from ccf.cr26.sdr import _tests  # noqa: PLC0415

        tests = _tests(apm)
    assert tests[0] == (
        "Automated: A phishing-resistant authentication method is enabled "
        "(m365.identity.phishing_resistant_mfa)"
    )
    assert len(tests) == 6
    async with session_scope() as s:
        result = await seed_sdr(s, system_id=sid)
    assert "KSI-IAM-APM" in result.omitted_ksi_ids  # still owed a human narrative
