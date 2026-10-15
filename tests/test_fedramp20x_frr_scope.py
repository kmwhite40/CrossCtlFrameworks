"""Which FedRAMP process requirements a provider owes, read from the rules."""

from __future__ import annotations

import itertools

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.cr26.sdr import seed_sdr
from ccf.cr26.store import put_document
from ccf.db import session_scope
from ccf.fedramp20x import frr_scope, rules
from ccf.models import Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


R = rules.load_rules()


@pytest.mark.parametrize(
    ("cls", "path", "expected"),
    [
        ("A", None, [("20x", "Program")]),  # Class A is 20x-only, 20x is Program-only
        ("A", "agency", []),  # impossible: reported, not guessed
        ("C", "agency", [("Rev5", "Agency")]),
        ("C", "program", [("20x", "Program"), ("Rev5", "Program")]),
        ("B", None, [("20x", "Program"), ("Rev5", "Agency"), ("Rev5", "Program")]),
    ],
)
def test_scenarios_are_the_pairs_the_rules_allow(
    cls: str, path: str | None, expected: list
) -> None:
    assert frr_scope.certification_scenarios(R, cls, path) == expected


def test_class_a_owes_what_frc_cla_names_beyond_subset_applicability() -> None:
    owed = {r["id"]: r for r in frr_scope.scope(R, "A", None)["owed"]}
    cla = R.data["FRR"]["FRC"]["data"]["all"]["CLA"]
    for list_id in ("FRC-CLA-MFR", "FRC-CLA-RFR", "FRC-CLA-OFR"):
        for rid in cla[list_id]["related"]:
            if not rid.startswith("KSI-"):
                assert rid in owed, (list_id, rid)
    assert owed["CCM-OCR-AVL"]["force"] == "MUST"  # named by MFR
    assert frr_scope.scope(R, "A", None)["conditional"] == []


def test_an_impossible_class_and_path_owes_nothing_and_says_why() -> None:
    s = frr_scope.scope(R, "A", "agency")
    assert s["owed"] == [] and "allow no certification" in s["basis"]


def test_a_process_marked_placeholder_drops_out(monkeypatch: pytest.MonkeyPatch) -> None:
    import copy  # noqa: PLC0415

    data = copy.deepcopy(R.data)
    assert any(r["process"] == "SCN" for r in frr_scope.scope(R, "C", None)["owed"])
    data["FRR"]["SCN"]["info"]["status"] = "placeholder"
    tampered = rules.ConsolidatedRules(R.version, R.last_updated, R.upstream_commit_sha, data)
    s = frr_scope.scope(tampered, "C", None)
    assert not any(r["process"] == "SCN" for r in s["owed"] + s["conditional"])


def test_assessor_only_requirements_are_not_a_providers() -> None:
    s = frr_scope.scope(R, "C", None)
    ids = {r["id"] for r in s["owed"] + s["conditional"]}
    ias = set(R.data["FRR"]["IVV"]["data"]["all"]["IAS"])
    assert ias and not (ids & ias)


def test_placeholder_processes_are_left_out() -> None:
    placeholder = [k for k, p in R.data["FRR"].items() if p["info"].get("status") == "placeholder"]
    assert placeholder  # the dataset has some today; if not, this proves nothing
    for cls in "BCD":
        s = frr_scope.scope(R, cls, None)
        assert not any(r["process"] in placeholder for r in s["owed"] + s["conditional"])


def test_a_class_with_no_variant_gets_no_borrowed_force() -> None:
    s = frr_scope.scope(R, "D", None)
    unforced = [r for r in s["owed"] + s["conditional"] if r["force"] is None]
    assert unforced, "the dataset has a D-less variant today"
    for r in unforced:
        process = R.data["FRR"][r["process"]]["data"]
        req = next(
            reqs[r["id"]]
            for subsets in process.values()
            for reqs in subsets.values()
            if r["id"] in reqs
        )
        assert "d" not in req["varies_by_class"]


def test_conditional_entries_name_their_scenarios() -> None:
    s = frr_scope.scope(R, "C", "program")
    assert s["conditional"]
    for r in s["conditional"]:
        assert r["scenarios"] and set(r["scenarios"]) < {"20x/Program", "Rev5/Program"}
    assert all(set(r["scenarios"]) == {"20x/Program", "Rev5/Program"} for r in s["owed"])


def test_no_class_no_scope() -> None:
    s = frr_scope.scope(R, None, None)
    assert s["owed"] == [] and s["conditional"] == []


async def _system(cls: str | None, path: str | None) -> int:
    async with session_scope() as s:
        org = Organization(name=f"FRR Org {next(_SEQ)}")
        s.add(org)
        await s.flush()
        sysm = System(
            organization_id=org.id,
            name=f"FRR {next(_SEQ)}",
            certification_class=cls,
            certification_path=path,
        )
        s.add(sysm)
        await s.flush()
        return sysm.id


async def test_the_sdr_names_hard_requirements_not_yet_authored() -> None:
    sid = await _system("C", "agency")
    owed_hard = {
        r["id"] for r in frr_scope.scope(R, "C", "agency")["owed"] if r["force"] in frr_scope.HARD
    }
    assert "SDR-CSO-FRR" in owed_hard
    async with session_scope() as s:
        await put_document(
            s,
            system_id=sid,
            kind="sdr",
            document={
                "fedRampRequirements": [
                    {"frrID": "SDR-CSO-FRR", "frrImplementation": ["We file the SDR."]}
                ]
            },
        )
    async with session_scope() as s:
        result = await seed_sdr(s, system_id=sid)
    assert set(result.frr_unaddressed) == owed_hard - {"SDR-CSO-FRR"}


async def test_the_requirements_endpoint() -> None:
    sid = await _system("A", "program")
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        body = (await c.get(f"/api/fedramp/20x/systems/{sid}/requirements")).json()
    assert body["certification_class"] == "A"
    assert len(body["owed"]) == len(frr_scope.scope(R, "A", "program")["owed"])
