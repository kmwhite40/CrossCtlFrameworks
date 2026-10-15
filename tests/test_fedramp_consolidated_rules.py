"""FedRAMP's Consolidated Rules as the KSI catalog's source, and KSI retirement.

Three guarantees, each tested by trying to break it:

* the vendored dataset is exactly what FedRAMP published (hash-pinned,
  schema-validated) and the catalog says only what FedRAMP says;
* a KSI the dataset no longer defines is retired, never deleted, so tenant
  history survives the 2026 cut-over;
* a retired KSI reaches no list, score, package or deliverable -- checked
  behaviourally, consumer by consumer, not by scanning source.
"""

from __future__ import annotations

import itertools
import json
import shutil
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.analytics import overview
from ccf.api.main import create_app
from ccf.assurance import builder
from ccf.catalog import impact
from ccf.catalog.oscal import load_oscal_catalog
from ccf.config import get_settings
from ccf.cr26 import scn
from ccf.cr26.sdr import _derived_indicators, merge_requirements
from ccf.db import session_scope
from ccf.etl import sources
from ccf.fedramp20x import catalog, package, readiness, rules, validation
from ccf.models import (
    KSI,
    KSIAssessorReview,
    KSIException,
    KSIState,
    KSIValidationResult,
    Organization,
    System,
)
from ccf.packages import service as packages_service
from ccf.reliability import checks as reliability

pytestmark = pytest.mark.usefixtures("fresh_engine", "isolate_ksi_rows")

_SEQ = itertools.count()
_DATASET = rules.DATA_DIR / rules.DATASET_FILE


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
async def _shipped_catalog() -> AsyncIterator[None]:
    """Every test starts and ends on the shipped catalog, all rows current."""
    async with session_scope() as s:
        await catalog.seed_ksis(s)
    yield
    async with session_scope() as s:
        await catalog.seed_ksis(s)


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _raw() -> dict:
    return json.loads(_DATASET.read_text(encoding="utf-8"))


# --- the dataset ----------------------------------------------------------


def test_the_vendored_dataset_is_the_pinned_2026_revision() -> None:
    r = rules.load_rules()
    assert r.version == "2026.10.13.01"
    assert r.upstream_commit_sha == "a89d78477ddea98dc57eca24f5007794c2b4eeb6"
    assert len(rules.ksi_ids(r)) == 46
    assert len(rules.frr_ids(r)) == 245
    # Every rule id the CR26 deliverables cite is one FedRAMP defines.
    from ccf.cr26.validation import CR26_KINDS  # noqa: PLC0415

    cited = {rule for _file, rule in CR26_KINDS.values() if rule != "-"}
    assert cited and cited <= rules.frr_ids(r)


def test_catalog_records_say_only_what_fedramp_says() -> None:
    raw = _raw()["KSI"]
    records = {rec["identifier"]: rec for rec in catalog.load_records()}
    assert len(records) == 46
    for theme_key, theme in raw.items():
        for ident, ind in theme["indicators"].items():
            rec = records[ident]
            assert rec["category"] == theme_key
            assert rec["name"] == ind["name"]
            if ind.get("statement"):
                assert rec["description"] == ind["statement"]  # verbatim
                assert rec["statement_by_class"] == {}
            assert rec["cmmc_refs"] == []  # FedRAMP publishes none
            assert rec["source"] == "fedramp-rules:2026.10.13.01"
            # The shipped overlay is empty: nothing claims to evaluate it.
            assert rec["rule"] == {"kind": "manual"}
            assert len(rec["nist_refs"]) == len(ind["controls"])


def test_every_fedramp_control_mapping_resolves_in_the_800_53_catalog() -> None:
    oscal = load_oscal_catalog()
    refs = {ref for rec in catalog.load_records() for ref in rec["nist_refs"]}
    assert "AT-2(2)" in refs  # FedRAMP's "at-2.2", canonicalised
    assert sorted(r for r in refs if not oscal.exists(r)) == []


def test_class_variants_are_kept_verbatim_and_none_is_chosen() -> None:
    raw = _raw()["KSI"]["SVC"]["indicators"]["KSI-SVC-RUD"]["varies_by_class"]
    rec = next(r for r in catalog.load_records() if r["identifier"] == "KSI-SVC-RUD")
    assert rec["statement_by_class"] == {k: v["statement"] for k, v in raw.items()}
    for cls, variant in raw.items():
        assert f"Class {cls.upper()}: {variant['statement']}" in rec["description"]


def _copy_data(tmp_path: Path) -> Path:
    d = tmp_path / "rules_data"
    shutil.copytree(rules.DATA_DIR, d)
    return d


def _repin(d: Path, name: str) -> None:
    import hashlib  # noqa: PLC0415

    manifest = json.loads((d / "MANIFEST.json").read_text())
    manifest["files"][name]["sha256"] = hashlib.sha256((d / name).read_bytes()).hexdigest()
    (d / "MANIFEST.json").write_text(json.dumps(manifest))


def test_an_altered_dataset_is_refused(tmp_path: Path) -> None:
    d = _copy_data(tmp_path)
    body = (d / rules.DATASET_FILE).read_text()
    (d / rules.DATASET_FILE).write_text(body.replace("Reviewing All Training", "Reviewing"))
    with pytest.raises(rules.RulesDatasetError, match="sha256 mismatch"):
        rules.load_rules(d)


def test_a_manifest_that_stops_pinning_a_file_is_refused(tmp_path: Path) -> None:
    d = _copy_data(tmp_path)
    manifest = json.loads((d / "MANIFEST.json").read_text())
    del manifest["files"][rules.SCHEMA_FILE]
    (d / "MANIFEST.json").write_text(json.dumps(manifest))
    with pytest.raises(rules.RulesDatasetError, match="does not pin"):
        rules.load_rules(d)


def test_a_repinned_dataset_that_breaks_fedramps_schema_is_refused(tmp_path: Path) -> None:
    d = _copy_data(tmp_path)
    data = json.loads((d / rules.DATASET_FILE).read_text())
    del data["KSI"]["CED"]["indicators"]["KSI-CED-RAT"]["name"]
    (d / rules.DATASET_FILE).write_text(json.dumps(data))
    _repin(d, rules.DATASET_FILE)
    with pytest.raises(rules.RulesDatasetError, match="schema violation"):
        rules.load_rules(d)


def test_a_manifest_naming_a_different_revision_is_refused(tmp_path: Path) -> None:
    d = _copy_data(tmp_path)
    manifest = json.loads((d / "MANIFEST.json").read_text())
    manifest["dataset_version"] = "2026.07.14.01"
    (d / "MANIFEST.json").write_text(json.dumps(manifest))
    with pytest.raises(rules.RulesDatasetError, match="MANIFEST pins"):
        rules.load_rules(d)


def test_a_rule_for_an_indicator_fedramp_does_not_define_is_refused(tmp_path: Path) -> None:
    overlay = tmp_path / "rules.json"
    overlay.write_text(json.dumps({"rules": {"KSI-IAM-01": {"rule": {"kind": "manual"}}}}))
    with pytest.raises(rules.RulesDatasetError, match="KSI-IAM-01"):
        catalog.load_records(overlay_path=overlay)


def test_the_upstream_is_watched_against_the_pinned_digest() -> None:
    spec = next(s for s in sources.DEFAULT_SOURCES if s["key"] == "fedramp_consolidated_rules")
    assert spec["url"].startswith("https://raw.githubusercontent.com/FedRAMP/rules/")
    assert spec["auto_ingest"] is False
    manifest = json.loads((rules.DATA_DIR / "MANIFEST.json").read_text())
    assert sources._SEED_DIGEST_READERS[spec["key"]]() == {
        spec["key"]: manifest["files"][rules.DATASET_FILE]["sha256"]
    }


# --- retirement -----------------------------------------------------------


async def _system(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=f"{name} Org {next(_SEQ)}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} {next(_SEQ)}")
        s.add(sysm)
        await s.flush()
        return sysm.id


async def _phase_one_row(system_id: int, ident: str = "KSI-IAM-01") -> int:
    """A phase-one KSI with a system's whole history hanging off it."""
    async with session_scope() as s:
        await s.execute(delete(KSI).where(KSI.identifier == ident))
        # IA-2, so a consumer that indexes KSIs by control could actually find it.
        k = KSI(
            identifier=ident,
            category="IAM",
            name="Phishing-resistant MFA",
            sort_order=-1,
            nist_refs=["IA-2"],
        )
        s.add(k)
        await s.flush()
        s.add(KSIState(system_id=system_id, ksi_id=k.id, status="fail"))
        s.add(
            KSIValidationResult(
                system_id=system_id, ksi_id=k.id, ksi_identifier=ident, status="fail"
            )
        )
        s.add(KSIAssessorReview(system_id=system_id, ksi_id=k.id, status="accepted"))
        s.add(KSIException(system_id=system_id, ksi_id=k.id, rationale="legacy", status="open"))
        await s.flush()
        return k.id


async def test_seeding_retires_a_phase_one_ksi_and_keeps_its_history() -> None:
    sid = await _system("Retire")
    kid = await _phase_one_row(sid)
    async with session_scope() as s:
        result = await catalog.seed_ksis(s)
    assert result["retired"] == 1 and result["total"] == 46
    async with session_scope() as s:
        row = await s.get(KSI, kid)
        assert row is not None and row.retired_at is not None
        for model in (KSIState, KSIValidationResult, KSIAssessorReview, KSIException):
            kept = (await s.execute(select(model).where(model.ksi_id == kid))).scalars().all()
            assert len(kept) == 1, model.__name__
    # Idempotent: a second seed retires nothing new.
    async with session_scope() as s:
        assert (await catalog.seed_ksis(s))["retired"] == 0


async def test_an_indicator_that_returns_is_un_retired() -> None:
    async with session_scope() as s:
        row = (await s.execute(select(KSI).where(KSI.identifier == "KSI-CED-RAT"))).scalar_one()
        row.retired_at = datetime.now(UTC)
    async with session_scope() as s:
        await catalog.seed_ksis(s)
    async with session_scope() as s:
        row = (await s.execute(select(KSI).where(KSI.identifier == "KSI-CED-RAT"))).scalar_one()
        assert row.retired_at is None


async def test_no_consumer_sees_a_retired_ksi() -> None:
    """One retired and one current KSI, both carrying state; every reader is asked."""
    sid = await _system("Consumers")
    retired_id = await _phase_one_row(sid)
    async with session_scope() as s:
        await catalog.seed_ksis(s)  # retires it
        org_id = (await s.get(System, sid)).organization_id  # type: ignore[union-attr]
        current = (await s.execute(select(KSI).where(KSI.identifier == "KSI-CED-RAT"))).scalar_one()
        s.add(KSIState(system_id=sid, ksi_id=current.id, status="pass"))
        current_id = current.id

    async with session_scope() as s:
        listed = {k.id for k in await catalog.list_ksis(s)}
        assert retired_id not in listed and current_id in listed

        score = await readiness.score_system(s, system_id=sid, persist=False)
        assert score["ksi_total"] == 46
        # The retired row's failing state, open exception and accepted review
        # must count toward nothing.
        assert score["high_risk_findings"] == 0
        assert score["open_exceptions"] == 0
        assert score["assessor_completion"] == 0

        pkg = json.dumps(await package.build_package(s, system_id=sid))
        assert "KSI-IAM-01" not in pkg and "legacy" not in pkg

        derived = await _derived_indicators(s, sid)
        assert "KSI-IAM-01" not in derived and "KSI-CED-RAT" in derived

        facts = await packages_service._ksi_facts(s, sid)
        assert {f["fact_key"] for f in facts} == {str(current_id)}

        graph = builder._Graph()
        await builder._ksis(s, org_id, graph)
        assert ("ksi", f"{sid}:{retired_id}") not in graph.nodes
        assert ("ksi", f"{sid}:{current_id}") in graph.nodes

        states = await overview._ksi_states(s, org_id)
        assert states["fail"] == 0 and states["pass"] == 1

        refs = await impact._ksi_references(s, {"IA-2"})
        assert all(r["ksi_id"] != retired_id for r in refs)

        unrecognised = await scn._resolve_impacted_controls(s, ["KSI-IAM-01", "ksi-ced-rat"])
        assert unrecognised == [("KSI-IAM-01", "a retired KSI, not in FedRAMP's current rules")]

        results = await validation.validate_system(s, system_id=sid)
        assert {r["ksi_identifier"] for r in results} == rules.ksi_ids(rules.load_rules())

    async with _client() as c:
        api = (await c.get("/api/fedramp/20x/ksis")).json()
        assert "KSI-IAM-01" not in {k["identifier"] for k in api}
        one = (await c.get("/api/fedramp/20x/ksis/KSI-IAM-01")).json()
        assert one["retired"] is True  # history still resolves
        vals = (await c.get(f"/api/fedramp/20x/systems/{sid}/validations")).json()
        assert all(v["ksi_identifier"] != "KSI-IAM-01" for v in vals)
        hist = (
            await c.get(f"/api/fedramp/20x/systems/{sid}/validations?include_retired=true")
        ).json()
        assert any(v["ksi_identifier"] == "KSI-IAM-01" for v in hist)
        excs = (await c.get(f"/api/fedramp/20x/systems/{sid}/exceptions")).json()
        assert all(e["ksi_id"] != retired_id for e in excs)
        revs = (await c.get(f"/api/fedramp/20x/assessor-reviews?system_id={sid}")).json()
        assert all(r["ksi_id"] != retired_id for r in revs)
        page = await c.get(f"/fedramp20x?system_id={sid}")
        assert page.status_code == 200
        assert "KSI-IAM-01" not in page.text and "legacy" not in page.text


async def test_writes_against_a_retired_ksi_are_refused() -> None:
    sid = await _system("Writes")
    retired_id = await _phase_one_row(sid)
    async with session_scope() as s:
        await catalog.seed_ksis(s)
        review_id = (
            await s.execute(
                select(KSIAssessorReview.id).where(KSIAssessorReview.ksi_id == retired_id)
            )
        ).scalar_one()
        exc_id = (
            await s.execute(select(KSIException.id).where(KSIException.ksi_id == retired_id))
        ).scalar_one()
    async with _client() as c:
        r = await c.post(
            "/api/fedramp/20x/assessor-reviews",
            json={"system_id": sid, "ksi_id": retired_id, "status": "accepted"},
        )
        assert r.status_code == 409 and "KSI-IAM-01" in r.text
        r = await c.patch(
            f"/api/fedramp/20x/assessor-reviews/{review_id}", json={"status": "closed"}
        )
        assert r.status_code == 409
        r = await c.post(
            "/api/fedramp/20x/exceptions",
            json={"system_id": sid, "ksi_id": retired_id, "rationale": "x"},
        )
        assert r.status_code == 409
        r = await c.patch(f"/api/fedramp/20x/exceptions/{exc_id}", json={"status": "closed"})
        assert r.status_code == 409
        # The form path refuses silently (it redirects either way): nothing is written.
        await c.post(
            f"/fedramp20x/{sid}/exception",
            data={"ksi_id": str(retired_id), "rationale": "form"},
            follow_redirects=False,
        )
    async with session_scope() as s:
        rows = (
            (await s.execute(select(KSIException).where(KSIException.ksi_id == retired_id)))
            .scalars()
            .all()
        )
        assert [e.rationale for e in rows] == ["legacy"]


async def test_capability_links_accept_only_current_ksis() -> None:
    async with _client() as c:
        created = await c.post(
            "/api/capabilities", json={"key": f"ksi-link-{next(_SEQ)}", "title": "Links"}
        )
        assert created.status_code == 201, created.text
        cap_id = created.json()["id"]
        bad = await c.put(
            f"/api/capabilities/{cap_id}/ksis", json={"ksi_identifiers": ["KSI-IAM-01"]}
        )
        assert bad.status_code == 422 and "KSI-IAM-01" in bad.text
        good = await c.put(
            f"/api/capabilities/{cap_id}/ksis", json={"ksi_identifiers": ["KSI-IAM-APM"]}
        )
        assert good.status_code == 200 and good.json()["ksi_identifiers"] == ["KSI-IAM-APM"]


# --- deliverables ---------------------------------------------------------


def test_an_frr_id_fedramp_does_not_define_is_kept_and_named() -> None:
    r = rules.load_rules()
    rendered, notes = merge_requirements(
        [
            {"frrID": "SDR-CSO-FRR", "frrImplementation": ["We publish it."]},
            {"frrID": "SDR-CSO-XXX", "frrImplementation": ["A typo'd id."]},
        ],
        known_frr_ids=rules.frr_ids(r),
        rules_version=r.version,
    )
    assert [e["frrID"] for e in rendered] == ["SDR-CSO-FRR", "SDR-CSO-XXX"]
    assert [n for n in notes if "not defined" in n[1]] == [
        (
            "SDR-CSO-XXX",
            "frrID not defined by FedRAMP Consolidated Rules 2026.10.13.01: "
            "kept, correct before submission",
        )
    ]


async def test_an_sdr_citing_a_phase_one_ksi_names_it() -> None:
    from ccf.cr26.sdr import seed_sdr  # noqa: PLC0415
    from ccf.cr26.store import put_document  # noqa: PLC0415

    sid = await _system("Sdr")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=sid,
            kind="sdr",
            document={
                "keySecurityIndicators": [
                    {"ksiId": "KSI-IAM-01", "ksiImplementation": ["Written in 2025."]},
                    {"ksiId": "KSI-CED-RAT", "ksiImplementation": ["We review training."]},
                ]
            },
        )
    async with session_scope() as s:
        result = await seed_sdr(s, system_id=sid)
    assert result.undefined_ksi_ids == ["KSI-IAM-01"]
    assert result.rules_version == "2026.10.13.01"
    kept = {e["ksiId"] for e in result.document.document["keySecurityIndicators"]}
    assert kept == {"KSI-IAM-01", "KSI-CED-RAT"}  # the narrative is not destroyed
    ced = next(
        e
        for e in result.document.document["keySecurityIndicators"]
        if e["ksiId"] == "KSI-CED-RAT"
    )
    # No rule is authored for it, so no test exists to name.
    assert ced["ksiTests"] == []


async def test_reliability_warns_when_the_database_is_not_on_the_pinned_catalog() -> None:
    sid = await _system("Reliability")
    async with session_scope() as s:
        ok = await reliability._check_ksi_loaded(s)
        assert ok.status == reliability.PASS and "2026.10.13.01" in ok.message
        await s.execute(
            KSI.__table__.update()
            .where(KSI.identifier == "KSI-CED-RAT")
            .values(retired_at=datetime.now(UTC))
        )
        await _phase_one_row(sid, "KSI-CED-01")
        stale = await reliability._check_ksi_loaded(s)
        assert stale.status == reliability.WARN
        assert "1 not in the dataset, 1 of its indicators not seeded" in stale.message


# --- review findings, each pinned -----------------------------------------

#: Pinned here, outside MANIFEST.json, so editing the dataset and its manifest
#: together cannot pass unnoticed.
_PINNED_SHA256 = {
    rules.DATASET_FILE: "fb48d677a85d77fb72735a325de2c1945a1e0ceab1d2e655292fe9ebe3e4e0b4",
    rules.SCHEMA_FILE: "eb4710bee0b06d0f8f803302ac2e88b934ef2bc942d0b548738c7304f0cb418f",
}


def test_the_vendored_bytes_match_digests_pinned_outside_the_manifest() -> None:
    import hashlib  # noqa: PLC0415

    for name, want in _PINNED_SHA256.items():
        assert hashlib.sha256((rules.DATA_DIR / name).read_bytes()).hexdigest() == want


def test_schema_formats_are_enforced(tmp_path: Path) -> None:
    d = _copy_data(tmp_path)
    data = json.loads((d / rules.DATASET_FILE).read_text())
    data["info"]["last_updated"] = "2026-13-45"
    (d / rules.DATASET_FILE).write_text(json.dumps(data))
    _repin(d, rules.DATASET_FILE)
    with pytest.raises(rules.RulesDatasetError, match="schema violation"):
        rules.load_rules(d)


def test_a_placeholder_theme_contributes_no_indicators(tmp_path: Path) -> None:
    d = _copy_data(tmp_path)
    data = json.loads((d / rules.DATASET_FILE).read_text())
    data["KSI"]["CED"]["status"] = "placeholder"
    (d / rules.DATASET_FILE).write_text(json.dumps(data))
    _repin(d, rules.DATASET_FILE)
    r = rules.load_rules(d)
    assert "KSI-CED-RAT" not in rules.ksi_ids(r)
    assert all(rec["category"] != "CED" for rec in rules.ksi_records(r))


async def test_unauthored_ksis_are_not_counted_as_continuously_monitored() -> None:
    sid = await _system("Conmon")
    async with session_scope() as s:
        await validation.validate_system(s, system_id=sid)
        score = await readiness.score_system(s, system_id=sid, persist=False)
    # 46 manual indicators with no frequency: nothing monitors them.
    assert score["conmon_coverage"] == 0
    assert score["automation_coverage"] == 0


async def test_an_explicit_ksi_list_cannot_record_state_on_a_retired_ksi() -> None:
    sid = await _system("Explicit")
    retired_id = await _phase_one_row(sid, "KSI-IAM-02")
    async with session_scope() as s:
        await catalog.seed_ksis(s)
        retired = await s.get(KSI, retired_id)
        assert retired is not None and retired.retired_at is not None
        results = await validation.validate_system(s, system_id=sid, ksis=[retired])
        assert results == []


async def test_a_tenant_admin_cannot_seed_the_global_catalog() -> None:
    from ccf.api.auth_deps import get_principal  # noqa: PLC0415
    from ccf.auth import Principal  # noqa: PLC0415

    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(
        user_id=1, email="admin@tenant.example", org_id=1, role="admin"
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/api/fedramp/20x/ksis/seed")
    assert r.status_code == 403


async def test_reliability_warns_when_rows_predate_the_pinned_revision() -> None:
    async with session_scope() as s:
        await s.execute(
            KSI.__table__.update()
            .where(KSI.identifier == "KSI-CED-RAT")
            .values(source="fedramp-rules:2026.07.14.01")
        )
        check = await reliability._check_ksi_loaded(s)
        assert check.status == reliability.WARN
        assert "1 seeded KSIs predate" in check.message


async def test_the_mappings_check_counts_only_current_ksis() -> None:
    sid = await _system("Mappings")
    await _phase_one_row(sid, "KSI-IAM-03")
    async with session_scope() as s:
        await catalog.seed_ksis(s)
        check = await reliability._check_ksi_mappings(s)
    # FedRAMP maps KSI-PIY-RES (executive support) to no control, so 45 of the
    # 46 current indicators carry a mapping; the retired IA-2 row must not
    # lift that to 46/47.
    assert check.message.startswith("45/46 ")


async def test_the_ui_review_form_refuses_a_retired_ksi() -> None:
    sid = await _system("UiReview")
    retired_id = await _phase_one_row(sid)
    async with session_scope() as s:
        await catalog.seed_ksis(s)
    async with _client() as c:
        await c.post(
            f"/fedramp20x/{sid}/assessor-review",
            data={"ksi_id": str(retired_id), "status": "closed", "assessor": "3PAO"},
            follow_redirects=False,
        )
    async with session_scope() as s:
        statuses = (
            (
                await s.execute(
                    select(KSIAssessorReview.status).where(KSIAssessorReview.ksi_id == retired_id)
                )
            )
            .scalars()
            .all()
        )
    assert statuses == ["accepted"]  # only the one _phase_one_row wrote


async def test_a_phase_one_sdr_entry_loses_its_frozen_status_and_reads_report_it() -> None:
    from ccf.cr26.sdr import seed_sdr  # noqa: PLC0415
    from ccf.cr26.store import put_document  # noqa: PLC0415

    sid = await _system("SdrStale")
    async with session_scope() as s:
        org_id = (await s.get(System, sid)).organization_id  # type: ignore[union-attr]
        await put_document(
            s,
            system_id=sid,
            kind="sdr",
            document={
                "keySecurityIndicators": [
                    {
                        "ksiId": "KSI-IAM-01",
                        "ksiImplementation": ["Written in 2025."],
                        "ksiImplementationStatus": "Implemented",
                        "ksiValidation": ["pass at 2026-01-01"],
                    }
                ]
            },
        )
    async with session_scope() as s:
        result = await seed_sdr(s, system_id=sid)
    entry = next(
        e for e in result.document.document["keySecurityIndicators"] if e["ksiId"] == "KSI-IAM-01"
    )
    assert "ksiImplementationStatus" not in entry
    assert entry["ksiImplementation"] == ["Written in 2025."]
    assert entry["ksiValidation"] == ["pass at 2026-01-01"]  # history, kept

    from ccf.api.auth_deps import get_principal  # noqa: PLC0415
    from ccf.auth import Principal  # noqa: PLC0415

    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(
        user_id=1, email="isso@tenant.example", org_id=org_id, role="admin"
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        got = await c.get(f"/api/systems/{sid}/cr26-documents/sdr")
    assert got.status_code == 200, got.text
    assert got.json()["undefined_ksi_ids"] == ["KSI-IAM-01"]


async def test_the_suite_reset_clears_retired_ksis_its_wipe_would_destroy() -> None:
    """``clean_migrated_db`` must not be blocked by 0093's downgrade guard."""
    from tests.conftest import _delete_retired_ksis_before_wipe  # noqa: PLC0415

    sid = await _system("Wipe")
    kid = await _phase_one_row(sid, "KSI-INR-01")
    async with session_scope() as s:
        await catalog.seed_ksis(s)
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    _delete_retired_ksis_before_wipe(cfg)
    async with session_scope() as s:
        assert await s.get(KSI, kid) is None
        current = (await s.execute(catalog.current_ksis())).scalars().all()
        assert len(current) == 46  # only retired rows went


async def test_open_gaps_lists_current_ksis_only() -> None:
    sid = await _system("Gaps")
    await _phase_one_row(sid)  # retired below, with a failing state
    async with session_scope() as s:
        await catalog.seed_ksis(s)
        await validation.validate_system(s, system_id=sid)
        gaps = await readiness.open_gaps(s, system_id=sid)
    assert {g["ksi"] for g in gaps} == rules.ksi_ids(rules.load_rules())
    assert {g["status"] for g in gaps} == {"manual_review_required"}
