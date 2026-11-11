"""The crosswalk engine: one coverage state per baseline control, honestly.

Pure functions over FedRAMP's own reference data and its sample certification
package (tests/fixtures/cr26_sample, CC0). See
docs/superpowers/specs/2026-11-11-crosswalk-20x-design.md.
"""

from __future__ import annotations

import copy
import csv
import io
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from openpyxl import load_workbook

from ccf.fedramp20x import crosswalk as xw
from ccf.oscal.validation import validate_document

SAMPLES = Path(__file__).parent / "fixtures" / "cr26_sample"


def _sample() -> dict[str, dict]:
    pkg: dict[str, dict] = {}
    for f in sorted(SAMPLES.glob("*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        kind = xw.detect_kind(doc)
        assert kind is not None, f.name
        pkg[kind] = doc
    return pkg


def _entry(status: str = xw.IMPLEMENTED) -> xw.Entry:
    return xw.Entry("X", status)


def _link(entry: xw.Entry | None) -> xw.Link:
    return xw.Link("KSI-X", "n", "g", "s", entry)


# ── the states ───────────────────────────────────────────────────────────────


def test_every_sample_document_is_recognised() -> None:
    assert set(_sample()) == set(xw.PACKAGE_KINDS)


@pytest.mark.parametrize(
    ("direct", "links", "state"),
    [
        (None, [], "no_mapping"),
        (None, [None, None], "not_reported"),
        (None, [xw.IMPLEMENTED, None], "partly_reported"),
        (None, [xw.IMPLEMENTED, xw.IMPLEMENTED], "traced"),
        (xw.IMPLEMENTED, [None], "documented"),
        (None, [xw.IMPLEMENTED, "Partially Implemented"], "needs_review"),
        ("Not Implemented", [xw.IMPLEMENTED], "needs_review"),
        # A missing status is not Implemented.
        (None, [""], "needs_review"),
        ("", [], "needs_review"),
    ],
)
def test_coverage_state(direct, links, state) -> None:
    d = _entry(direct) if direct is not None else None
    ls = [_link(_entry(s) if s is not None else None) for s in links]
    assert xw.coverage_state(d, ls) == state


@pytest.mark.parametrize("cls", ["B", "C", "D"])
def test_counts_cover_the_baseline_exactly_once(cls: str) -> None:
    model = xw.build_model(_sample(), cls)
    assert sum(model.counts.values()) == model.total == len(xw.reference().baselines[cls])
    assert len({c.id for c in model.controls}) == model.total


def test_a_traced_control_has_every_mapped_entry_reported() -> None:
    """Upstream's Traced admitted controls with mapped entries the package never
    reports; on FedRAMP's own sample those are Partly reported here."""
    model = xw.build_model(_sample(), "C")
    traced = [c for c in model.controls if c.state == "traced"]
    partly = [c for c in model.controls if c.state == "partly_reported"]
    assert traced and partly
    assert all(not c.missing and c.reported for c in traced)
    assert all(c.missing and c.reported and not c.weak for c in partly)


def test_class_a_and_unknown_classes_are_refused() -> None:
    for cls in ("A", "E", ""):
        with pytest.raises(xw.CrosswalkError, match="Rev5 control baseline"):
            xw.build_model(_sample(), cls)


def test_a_rev5_package_is_not_expected_to_report_indicators() -> None:
    pkg = _sample()
    pkg["cpo"]["serviceIdentification"]["certificationType"] = "Rev5"
    model = xw.build_model(pkg, "C")
    assert model.certification_type == "Rev5"
    assert model.completeness["ksi"]["expected"] == 0
    assert "IVV-CSF-AIA" in model.completeness["ksi"]["basis"]


def test_unknown_ids_are_reported_not_dropped() -> None:
    pkg = _sample()
    pkg["sdr"]["keySecurityIndicators"].append(
        {"ksiId": "KSI-NOPE-01", "ksiImplementationStatus": "Implemented"}
    )
    pkg["sdr"]["securityControls"].append(
        {"controlId": "not a control", "controlImplementationStatus": "Implemented"}
    )
    model = xw.build_model(pkg, "C")
    assert "KSI-NOPE-01" in model.unknown["ksi"]
    assert "not a control" in model.unknown["controls"]


@pytest.mark.parametrize(
    ("raw", "canon"),
    [
        ("AC-02 (01)", "AC-2(1)"),
        ("ac-2.1", "AC-2(1)"),
        ("AC-2(1)", "AC-2(1)"),
        ("sc-07", "SC-7"),
        ("nope", None),
        ("", None),
    ],
)
def test_control_ids_in_every_fedramp_spelling(raw: str, canon: str | None) -> None:
    assert xw.to_control(raw) == canon


def test_guidance_is_verified_against_its_pin(tmp_path, monkeypatch) -> None:
    for name in ("MANIFEST.json", xw.GUIDANCE_FILE):
        (tmp_path / name).write_bytes((xw.GUIDANCE_DIR / name).read_bytes())
    (tmp_path / xw.GUIDANCE_FILE).write_bytes(b'{"controls": {}}')
    monkeypatch.setattr(xw, "GUIDANCE_DIR", tmp_path)
    with pytest.raises(xw.CrosswalkError, match="sha256 mismatch"):
        xw._load_guidance()


def test_class_d_only_controls_say_no_guidance_is_published() -> None:
    model = xw.build_model(_sample(), "D")
    only_d = set(xw.reference().baselines["D"]) - set(xw.reference().baselines["C"])
    assert only_d
    assert all(not c.guidance for c in model.controls if c.id in only_d)


# ── the register ─────────────────────────────────────────────────────────────


def _vuln(tid: str, **extra) -> dict:
    return {"providerTrackingId": tid, "vulnerabilityDescription": "d", **extra}


def test_the_newest_document_decides_a_register_row() -> None:
    """An older snapshot read later must not overwrite newer detail."""
    pkg = {
        "vdr": {
            "reportPeriod": {"to": "2026-08-31T23:59:59Z"},
            "vulnerabilities": [_vuln("V1", currentRating=2)],
        },
        "ver_history": {
            "generatedAt": "2026-07-01T00:00:00Z",
            "activeVulnerabilities": [_vuln("V1", currentRating=5)],
        },
    }
    (row,) = xw.build_register(pkg)
    assert row["rating"] == 2 and row["as_of_kind"] == "vdr"
    assert row["sources"] == ["Historical Vulnerability Activity", "Vulnerability Detail Report"]


def test_an_acceptance_is_what_the_newest_observation_says() -> None:
    pkg = {
        "avi": {
            "reportPeriod": {"to": "2026-06-30T23:59:59Z"},
            "acceptedVulnerabilities": [
                {"vulnerabilityDetail": _vuln("V1"), "acceptanceRationale": "r"}
            ],
        },
        "ver_history": {
            "generatedAt": "2026-07-15T00:00:00Z",
            "activeVulnerabilities": [_vuln("V1")],
        },
    }
    (row,) = xw.build_register(pkg)
    assert row["status"] == "Open"
    pkg["avi"]["reportPeriod"]["to"] = "2026-08-01T00:00:00Z"
    (row,) = xw.build_register(pkg)
    assert row["status"] == "Accepted" and row["rationale"] == "r"


def test_closed_dispositions_and_ordering() -> None:
    pkg = {
        "vdr": {
            "reportPeriod": {"to": "2026-06-30"},
            "vulnerabilities": [
                _vuln("A", currentRating=1),
                _vuln("B", currentRating=4),
                _vuln("C", finalDisposition="Remediated", currentRating=5),
            ],
        }
    }
    assert [(r["id"], r["status"]) for r in xw.build_register(pkg)] == [
        ("B", "Open"),
        ("A", "Open"),
        ("C", "Closed"),
    ]


def test_a_boolean_is_not_a_rating() -> None:
    pkg = {
        "vdr": {
            "reportPeriod": {"to": "2026-06-30"},
            "vulnerabilities": [_vuln("A", currentRating=True)],
        }
    }
    assert xw.build_register(pkg)[0]["rating"] is None


# ── exports ──────────────────────────────────────────────────────────────────


def test_csv_never_carries_a_formula() -> None:
    text = xw.to_csv([["h"], ["=HYPERLINK(1)"], ["+1"], ["-1"], ["@x"], ["fine"]])
    rows = list(csv.reader(io.StringIO(text.lstrip("﻿"))))
    assert [r[0] for r in rows] == ["h", "'=HYPERLINK(1)", "'+1", "'-1", "'@x", "fine"]


def test_determinations_list_exactly_the_unsettled_controls() -> None:
    model = xw.build_model(_sample(), "C")
    rows = xw.determination_rows(model)[1:]
    unsettled = [c.id for c in model.controls if c.state not in ("documented", "traced")]
    assert [r[0] for r in rows] == unsettled
    review = next(r for r in rows if r[2] == "Needs review")
    assert ":" in review[3]  # names the entry and its status


def test_exports_do_not_mutate_the_package() -> None:
    pkg = _sample()
    before = copy.deepcopy(pkg)
    model = xw.build_model(pkg, "C")
    xw.to_csv(xw.control_rows(model))
    xw.to_csv(xw.register_rows(model))
    assert pkg == before


# ── the independent review's findings ───────────────────────────────────────


def test_a_package_without_a_stated_type_is_not_read_as_20x() -> None:
    """With no CPO, KSI and rule gaps cannot be known: a Rev5 package owes no KSIs."""
    pkg = _sample()
    del pkg["cpo"]
    model = xw.build_model(pkg, "C")
    assert model.certification_type is None
    assert model.completeness["ksi"]["expected"] is None
    assert model.completeness["ksi"]["missing"] == []
    assert "does not state its certification type" in model.completeness["ksi"]["basis"]
    assert model.completeness["frr"]["expected"] is None
    # Coverage per control does not depend on the type.
    assert sum(model.counts.values()) == model.total


def test_a_known_path_narrows_the_rules_a_provider_owes() -> None:
    pkg = _sample()
    pkg["cpo"]["serviceIdentification"]["certificationType"] = "Rev5"
    either = xw.build_model(pkg, "C").completeness["frr"]
    program = xw.build_model(pkg, "C", path="program").completeness["frr"]
    assert program["path_applied"] is True and either["path_applied"] is False
    assert program["expected"] < either["expected"]
    ref = xw.reference()
    assert all(not ref.frr[r].paths or "Program" in ref.frr[r].paths for r in program["missing"])


def test_the_register_orders_by_instant_not_by_text() -> None:
    """-04:00 on the 30th is after 01:00Z on the 1st; as text it sorted before."""
    pkg = {
        "avi": {
            "reportPeriod": {"to": "2026-06-30T23:59:59-04:00"},
            "acceptedVulnerabilities": [
                {"vulnerabilityDetail": _vuln("V1"), "acceptanceRationale": "r"}
            ],
        },
        "ver_history": {
            "generatedAt": "2026-07-01T01:00:00Z",
            "activeVulnerabilities": [_vuln("V1")],
        },
    }
    (row,) = xw.build_register(pkg)
    assert row["status"] == "Accepted"


def test_fractional_seconds_order_as_instants() -> None:
    pkg = {
        "vdr": {
            "reportPeriod": {"to": "2026-07-01T00:00:00.500Z"},
            "vulnerabilities": [_vuln("V1", currentRating=2)],
        },
        "ver_history": {
            "generatedAt": "2026-07-01T00:00:00Z",
            "activeVulnerabilities": [_vuln("V1", currentRating=5)],
        },
    }
    (row,) = xw.build_register(pkg)
    assert row["rating"] == 2


# ── package overview ─────────────────────────────────────────────────────────


def test_the_overview_is_what_the_package_states() -> None:
    o = xw.package_overview(_sample()["cpo"])
    assert o is not None
    assert o["service"] == "MeridianOps Cloud Platform" and o["service_model"] == "SaaS"
    assert o["deployment_model"] == "Government-Only Cloud"
    assert (o["assessor"], o["assessor_id"]) == ("Beacon Assurance Partners, LLC", "384021")
    assert o["next_ongoing_report"] == "2026-10-15"
    assert o["trust_center"]["href"] == "https://trust.meridianfed.com/mocp"
    assert o["secure_configuration"]["auth_required"] is False
    assert [t["id"] for t in o["certified_third_party"]] == ["F0009182736", "F0004455667"]
    assert o["non_certified_third_party"][0]["name"] == "SendSecure Notifications"
    assert xw.package_overview(None) is None and xw.package_overview({}) is None


@pytest.mark.parametrize(
    ("raw", "ok"),
    [
        ("https://trust.example.gov/x?y=1", True),
        ("HTTP://example.gov", True),
        ("javascript:alert(1)", False),
        ("JavaScript:alert(1)", False),
        ("data:text/html,<script>", False),
        ("https://example.gov/a b", False),
        ('https://example.gov/"onmouseover=x', False),
        ("//example.gov", False),
        ("", False),
        (None, False),
        (42, False),
    ],
)
def test_only_http_urls_become_links(raw, ok: bool) -> None:
    assert (xw.safe_url(raw) is not None) is ok


def test_a_hostile_url_in_the_overview_is_kept_as_text_not_as_a_link() -> None:
    cpo = copy.deepcopy(_sample()["cpo"])
    cpo["serviceProperties"]["trustCenter"]["url"] = "javascript:alert(1)"
    o = xw.package_overview(cpo)
    assert o is not None
    assert o["trust_center"]["url"] == "javascript:alert(1)" and o["trust_center"]["href"] is None


def test_the_ongoing_report_keeps_not_stated_apart_from_none_reported() -> None:
    ocr = _sample()["ocr"]
    r = xw.ongoing_report(ocr)
    assert r is not None
    assert (r["period_from"], r["period_to"]) == ("2026-04-01", "2026-06-30")
    assert r["planned_through"] == "2026-12-31" and len(r["planned"]) == 2
    assert r["transformative"] == []  # the report says none
    assert r["incidents"][0]["occurred_at"] == "2026-05-22T03:14:00Z"
    assert r["incidents"][0]["lessons"] and len(r["agencies"]) == 3
    assert r["accepted_vulnerabilities"].startswith("One accepted vulnerability")
    bare = xw.ongoing_report({"certificationDataChanges": ["x"]})
    assert bare is not None
    assert bare["transformative"] is None and bare["incidents"] is None  # not stated
    assert bare["agencies"] is None and bare["changes"] == ["x"]


def test_the_model_carries_the_overview_and_the_vulnerability_files() -> None:
    m = xw.build_model(_sample(), "C")
    assert m.overview and m.ongoing and m.vulnerability_files == ["vdr", "avi", "ver_history"]
    bare = xw.build_model({"sdr": _sample()["sdr"]}, "C")
    assert bare.overview is None and bare.ongoing is None and not bare.has_vulnerability_files


def test_schema_errors_are_listed_with_path_and_message_then_counted() -> None:
    errs = [f"keySecurityIndicators/{n}/ksiId: bad {n}" for n in range(30)] + ["<root>: x"]
    e = xw.schema_errors(errs)
    assert e["count"] == 31 and len(e["shown"]) == xw.SHOWN_ERRORS and e["more"] == 6
    assert e["shown"][0] == {"path": "keySecurityIndicators/0/ksiId", "message": "bad 0"}
    assert e["capped"] is False
    assert xw.schema_errors(errs[:3], kept=3)["capped"] is True  # more may have been dropped
    assert xw.schema_errors(errs[:2], kept=3)["capped"] is False
    assert xw.schema_errors(["no separator"])["shown"] == [{"path": "", "message": "no separator"}]


# ── review workbook ──────────────────────────────────────────────────────────

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)


def _workbook(model: xw.Model):
    return load_workbook(io.BytesIO(xw.to_xlsx(xw.workbook_sheets(model, NOW), NOW)))


def test_the_workbook_has_four_sheets_with_frozen_bold_headers() -> None:
    m = xw.build_model(_sample(), "C")
    wb = _workbook(m)
    assert wb.sheetnames == [
        "Summary",
        "Control inheritance",
        "Agency determinations",
        "Vulnerability register",
    ]
    for ws in wb.worksheets:
        assert ws.freeze_panes == "A2" and ws["A1"].font.b
    assert wb["Control inheritance"].max_row == m.total + 1
    assert wb["Vulnerability register"].max_row == len(m.register) + 1
    summary = {r[0]: r[1] for r in wb["Summary"].iter_rows(values_only=True)}
    assert summary["How to read this"] == xw.NOTICE
    assert summary["Partly reported"] == m.counts["partly_reported"]  # a number, not text


def test_workbook_cells_never_carry_a_formula_or_an_illegal_character() -> None:
    sheets = [("S", [["h"], ['=HYPERLINK("http://x")'], ["\x01=1+1"], ["a\x0bb"], [7]])]
    ws = load_xlsx(xw.to_xlsx(sheets, NOW))["S"]
    values = [c.value for c in ws["A"]]
    assert values == ["h", '\'=HYPERLINK("http://x")', "'=1+1", "ab", 7]
    assert all(c.data_type != "f" for c in ws["A"])


def load_xlsx(data: bytes):
    return load_workbook(io.BytesIO(data))


def test_a_workbook_without_vulnerability_files_says_so() -> None:
    m = xw.build_model({"sdr": _sample()["sdr"]}, "B")
    summary = {r[0]: r[1] for r in _workbook(m)["Summary"].iter_rows(values_only=True)}
    assert "holds no vulnerability files" in summary["Vulnerability register"]
    assert summary["Certification type"] == "not stated in the package"
    assert summary["Key Security Indicators reported (required)"] == "not known"


# ── OSCAL exports ────────────────────────────────────────────────────────────


def _validate(doc: dict, kind: str):
    report = validate_document(doc, kind)
    assert report.mode == "official", "the vendored NIST OSCAL 1.1.2 schema was not used"
    return report


def _reqs(ssp: dict) -> list[dict]:
    return ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]


def _state(req: dict) -> str | None:
    by = (req.get("by-components") or [{}])[0]
    return by.get("implementation-status", {}).get("state")


def _prop_values(obj: dict, name: str) -> list[str]:
    return [p["value"] for p in obj.get("props", []) if p["name"] == name]


@pytest.mark.parametrize("cls", xw.BASELINE_CLASSES)
def test_both_oscal_exports_validate_against_the_official_schema(cls: str) -> None:
    m = xw.build_model(_sample(), cls)
    for doc, kind in (
        (xw.oscal_ssp(m, generated=NOW, scope="t"), "ssp"),
        (xw.oscal_poam(m, generated=NOW, scope="t"), "poam"),
    ):
        report = _validate(doc, kind)
        assert report.ok, report.errors[:5]
        root = doc[next(iter(doc))]
        assert root["metadata"]["oscal-version"] == "1.1.2"
        assert xw.NOTICE in root["metadata"]["remarks"]


def test_the_schema_check_can_fail() -> None:
    """The harness is not vacuous: a broken export is refused by the same check."""
    ssp = xw.oscal_ssp(xw.build_model(_sample(), "C"), generated=NOW, scope="t")
    del ssp["system-security-plan"]["metadata"]
    assert not _validate(ssp, "ssp").ok
    poam = xw.oscal_poam(xw.build_model(_sample(), "C"), generated=NOW, scope="t")
    poam["plan-of-action-and-milestones"]["poam-items"] = []
    assert not _validate(poam, "poam").ok


def test_oscal_uuids_are_deterministic_and_scoped() -> None:
    m = xw.build_model(_sample(), "C")
    later = datetime(2027, 1, 1, tzinfo=UTC)
    a = xw.oscal_ssp(m, generated=NOW, scope="vendor-1")
    b = xw.oscal_ssp(m, generated=later, scope="vendor-1")
    c = xw.oscal_ssp(m, generated=NOW, scope="vendor-2")
    ids = lambda d: [r["uuid"] for r in _reqs(d)]  # noqa: E731
    assert ids(a) == ids(b) and ids(a) != ids(c)
    assert len(set(ids(a))) == len(ids(a))
    assert all(uuid.UUID(i).version == 5 for i in ids(a))


def _ssp_for(direct: str | None, links: list[str | None]) -> tuple[xw.ControlRow, dict]:
    """A one-control model, so each status rule is checked on its own."""
    entry = None if direct is None else xw.Entry("AC-2", direct, ["stmt"])
    ls = [
        xw.Link(f"KSI-{n}", "n", "g", "s", None if s is None else xw.Entry(f"KSI-{n}", s, ["x"]))
        for n, s in enumerate(links)
    ]
    row = xw.ControlRow(
        "AC-2", "AC", "Account Management", xw.coverage_state(entry, ls), ls, [], entry, ()
    )
    m = xw.build_model(_sample(), "C")
    m.controls = [row]
    ssp = xw.oscal_ssp(m, generated=NOW, scope="t")
    assert _validate(ssp, "ssp").ok
    return row, _reqs(ssp)[0]


@pytest.mark.parametrize(
    ("direct", "links", "state"),
    [
        (xw.IMPLEMENTED, [], "implemented"),  # documented
        (None, [xw.IMPLEMENTED, xw.IMPLEMENTED], "implemented"),  # traced
        (None, [xw.IMPLEMENTED, None], None),  # partly reported: never implemented
        (xw.IMPLEMENTED, [None], "implemented"),  # documented, by the provider's own entry
        ("Partially Implemented", [], "partial"),
        (None, [xw.IMPLEMENTED, "Partially Implemented"], "partial"),
        ("Not Implemented", [], None),  # never "planned"
        (None, ["Not Implemented", xw.IMPLEMENTED], None),
        ("", [], None),  # no status given
        ("Planned", [], None),  # not OSCAL's word to take
        (None, [None], None),  # nothing reported: no by-component
    ],
)
def test_oscal_implementation_status_asserts_no_more_than_the_package(direct, links, state) -> None:
    _row, req = _ssp_for(direct, links)
    assert _state(req) == state
    if direct is None and not any(s is not None for s in links):
        assert "by-components" not in req
        return
    by = req["by-components"][0]
    # The provider's own words are kept, whether or not a state is exported.
    statuses = _prop_values(by, "provider-status")
    if direct is not None:
        assert f"AC-2: {direct or 'no status given'}" in statuses
    if state is None:
        assert "No implementation status is exported" in by["remarks"]
        # ...and the remark gives the real reason: the provider's own status.
        raw = {s or "no status given" for s in [direct, *links] if s is not None}
        unmapped = sorted(raw - {xw.IMPLEMENTED, "Partially Implemented"})
        if unmapped:
            assert f"the provider reports {', '.join(unmapped)}," in by["remarks"]
        else:
            assert "not reported, so the control is not shown as implemented" in by["remarks"]


def test_no_oscal_export_says_planned_or_approved() -> None:
    m = xw.build_model(_sample(), "D")
    text = json.dumps(xw.oscal_ssp(m, generated=NOW, scope="t")) + json.dumps(
        xw.oscal_poam(m, generated=NOW, scope="t")
    )
    assert '"planned"' not in text and "deviation-approved" not in text


def test_a_partly_reported_sample_control_is_never_exported_as_implemented() -> None:
    m = xw.build_model(_sample(), "C")
    reqs = {r["control-id"]: r for r in _reqs(xw.oscal_ssp(m, generated=NOW, scope="t"))}
    partly = [c for c in m.controls if c.state == "partly_reported"]
    assert partly, "the sample has partly reported controls"
    for c in partly:
        req = reqs[xw.canonical_to_oscal_id(c.id)]
        assert _state(req) != "implemented", c.id
        assert _prop_values(req, "coverage") == ["partly_reported"]
    settled = [c for c in m.controls if c.state in ("documented", "traced")]
    assert all(
        _state(reqs[xw.canonical_to_oscal_id(c.id)]) in ("implemented", "partial") for c in settled
    )


def _register_pkg(detected_at: str | None) -> dict:
    pkg = _sample()
    vdr = pkg["vdr"]
    v = copy.deepcopy(vdr["vulnerabilities"][0])
    v["providerTrackingId"] = "T-1"
    v.pop("finalDisposition", None)
    if detected_at is None:
        v["detection"].pop("detectedAt")
    else:
        v["detection"]["detectedAt"] = detected_at
    vdr["vulnerabilities"] = [v]
    return {"cpo": pkg["cpo"], "vdr": vdr}


def _poam(pkg: dict) -> dict:
    doc = xw.oscal_poam(xw.build_model(pkg, "C"), generated=NOW, scope="t")
    assert _validate(doc, "poam").ok
    return doc["plan-of-action-and-milestones"]


@pytest.mark.parametrize(
    "detected_at", [None, "", "yesterday", "2026-06-10", "2026-13-40T00:00:00Z"]
)
def test_a_missing_detection_time_is_not_replaced_by_the_export_time(detected_at) -> None:
    p = _poam(_register_pkg(detected_at))
    assert "observations" not in p
    item = p["poam-items"][0]
    assert "related-observations" not in item
    assert "no valid detection time" in item["remarks"] and "none is substituted" in item["remarks"]
    assert xw.utc_stamp(NOW) not in json.dumps(p["risks"])


def test_a_valid_detection_time_is_the_observations_collected_time() -> None:
    p = _poam(_register_pkg("2026-06-10T08:00:00-04:00"))
    (obs,) = p["observations"]
    assert obs["collected"] == "2026-06-10T08:00:00-04:00"
    assert p["poam-items"][0]["related-observations"] == [{"observation-uuid": obs["uuid"]}]


def test_an_accepted_vulnerability_is_open_not_an_approved_deviation() -> None:
    p = _poam(_sample())
    m = xw.build_model(_sample(), "C")
    accepted = {v["id"] for v in m.register if v["status"] == "Accepted"}
    assert accepted, "the sample has an accepted vulnerability"
    for risk in p["risks"]:
        tid = _prop_values(risk, "provider-tracking-id")[0]
        if tid in accepted:
            assert risk["status"] == "open"
            assert _prop_values(risk, "provider-status") == ["Accepted"]
    items = [i for i in p["poam-items"] if _prop_values(i, "provider-status") == ["Accepted"]]
    assert items and all("not show that a deviation was" in i["remarks"] for i in items)


def test_no_poam_without_vulnerability_files_or_vulnerabilities() -> None:
    with pytest.raises(xw.CrosswalkError, match="no vulnerability files"):
        xw.oscal_poam(xw.build_model({"sdr": _sample()["sdr"]}, "C"), generated=NOW, scope="t")
    empty = {"vdr": {**_sample()["vdr"], "vulnerabilities": []}, "sdr": _sample()["sdr"]}
    with pytest.raises(xw.CrosswalkError, match="list no vulnerabilities"):
        xw.oscal_poam(xw.build_model(empty, "C"), generated=NOW, scope="t")


def test_the_export_time_must_carry_a_zone() -> None:
    with pytest.raises(xw.CrosswalkError):
        xw.utc_stamp(datetime(2026, 11, 11))


def test_ssp_parameters_and_evidence_links_carry_only_what_oscal_can_hold() -> None:
    direct = xw.Entry(
        "AC-2",
        xw.IMPLEMENTED,
        ["stmt"],
        parameters=[
            {"id": "bad id", "value": "x"},
            {"id": "ac-2_prm_1", "value": "   "},
            {"id": "ac-2_prm_2", "value": "24\nhours"},
        ],
    )
    ksi = xw.Entry(
        "KSI-1",
        xw.IMPLEMENTED,
        ["x"],
        evidence=[
            {"type": "t", "description": "d", "location": "javascript:alert(1)", "updated": ""},
            {"type": "t", "description": "d", "location": "https://e.example/x", "updated": ""},
        ],
    )
    link = xw.Link("KSI-1", "n", "g", "s", ksi)
    row = xw.ControlRow("AC-2", "AC", "Account Management", "documented", [link], [], direct, ())
    m = xw.build_model(_sample(), "C")
    m.controls = [row]
    ssp = xw.oscal_ssp(m, generated=NOW, scope="t")
    assert _validate(ssp, "ssp").ok
    by = _reqs(ssp)[0]["by-components"][0]
    assert by["set-parameters"] == [{"param-id": "ac-2_prm_2", "values": ["24 hours"]}]
    assert [x["href"] for x in by["links"]] == ["https://e.example/x"]
