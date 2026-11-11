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
from pathlib import Path

import pytest

from ccf.fedramp20x import crosswalk as xw

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
