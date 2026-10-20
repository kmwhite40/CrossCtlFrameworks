"""The AWS DevSecOps evidence pack cites real controls and claims no retention it cannot source.

The table it came from (m365-docs-hub's required-artifact list) mapped KMS key
policies to SC-13, DAST to RA-5, SBOMs to SA-15 and federation to IA-5, and
gave every artifact a 365- or 90-day retention with no source. These tests pin
the corrections, and check every control against the NIST OSCAL catalog
Concord ships, so a mis-typed or withdrawn control cannot be listed.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from typing import Any

import pytest

from ccf.catalog.canonical import canonicalize
from ccf.packs import catalog

PACK_ID = "aws-devsecops-evidence"


@pytest.fixture(scope="module")
def manifest() -> dict[str, Any]:
    return catalog.load_pack(PACK_ID)


@pytest.fixture(scope="module")
def active_controls() -> dict[str, str]:
    """OSCAL id (``sa-11.8``) -> title, for every control not withdrawn."""
    raw = (
        resources.files("ccf.catalog")
        .joinpath("oscal_data/NIST_SP-800-53_rev5_catalog.json")
        .read_text()
    )
    out: dict[str, str] = {}

    def walk(ctrls: list[dict[str, Any]]) -> None:
        for c in ctrls:
            props = c.get("props", [])
            if not any(p.get("name") == "status" and p.get("value") == "withdrawn" for p in props):
                out[c["id"]] = c["title"]
            walk(c.get("controls", []))

    for group in json.loads(raw)["catalog"]["groups"]:
        walk(group.get("controls", []))
    return out


def _oscal_id(cid: str) -> str:
    m = re.fullmatch(r"([A-Z]{2})-(\d+)(?:\((\d+)\))?", cid)
    assert m, f"{cid!r} is not written as a canonical 800-53 id"
    base = f"{m[1].lower()}-{int(m[2])}"
    return f"{base}.{int(m[3])}" if m[3] else base


def _artifacts_for(manifest: dict[str, Any], name: str) -> set[str]:
    return {
        e["control_id"]
        for e in manifest["evidence_requirements"]
        if e["description"].startswith(name + " [")
    }


def test_pack_is_valid(manifest: dict[str, Any]) -> None:
    assert catalog.validate_manifest(manifest) == []


def test_every_control_is_an_active_800_53_control(
    manifest: dict[str, Any], active_controls: dict[str, str]
) -> None:
    for ctl in manifest["controls"]:
        cid = ctl["control_id"]
        # A non-canonical id is matched by catalog identity alone in
        # packs.service.coverage and reads as a gap on every system.
        assert canonicalize(cid) is not None, cid
        oid = _oscal_id(cid)
        assert oid in active_controls, f"{cid} is withdrawn or not in 800-53 rev5"
        assert ctl["title"] == active_controls[oid], cid


def test_requirements_and_controls_match_one_to_one(manifest: dict[str, Any]) -> None:
    controls = {c["control_id"] for c in manifest["controls"]}
    evidenced = {e["control_id"] for e in manifest["evidence_requirements"]}
    assert evidenced <= controls, evidenced - controls
    # A control with no artifact would sit in the pack with nothing to collect.
    assert controls <= evidenced, controls - evidenced


def test_retention_is_sourced_or_left_to_the_records_schedule(manifest: dict[str, Any]) -> None:
    for e in manifest["evidence_requirements"]:
        text = e["description"]
        assert ("OMB M-21-31" in text) != ("records schedule" in text), text
        assert not re.search(r"\b(365|90)\b", text), text
    logs = [e for e in manifest["evidence_requirements"] if "M-21-31" in e["description"]]
    assert logs and all("12 months" in e["description"] for e in logs)
    assert all("18 months" in e["description"] for e in logs)


@pytest.mark.parametrize(
    ("artifact", "expected", "not_expected"),
    [
        ("KMS key policies", {"SC-12"}, {"SC-13"}),
        ("DAST reports", {"SA-11(8)"}, {"RA-5"}),
        ("SBOMs", {"SR-4", "CM-8"}, {"SA-15"}),
        ("Federation configuration", {"IA-2", "IA-8"}, {"IA-5"}),
        ("Container image scan reports", {"RA-5"}, {"SI-2"}),
        ("Build provenance", {"SR-4"}, {"SA-10"}),
    ],
)
def test_source_mappings_are_corrected(
    manifest: dict[str, Any], artifact: str, expected: set[str], not_expected: set[str]
) -> None:
    got = _artifacts_for(manifest, artifact)
    assert expected <= got, (artifact, got)
    assert not (got & not_expected), (artifact, got)


def test_the_source_s_empty_network_domain_is_filled(manifest: dict[str, Any]) -> None:
    network = [e for e in manifest["evidence_requirements"] if "[network]" in e["description"]]
    names = {e["description"].split(" [", 1)[0] for e in network}
    assert {"Security group export", "Network ACL export", "Transit Gateway route tables",
            "WAF rule sets"} <= names


def test_pack_test_floors_match_its_contents(manifest: dict[str, Any]) -> None:
    floors = {t["key"]: int(t["assert"].split(">=")[1]) for t in manifest["tests"]}
    assert floors["has_controls"] == len(manifest["controls"])
    assert floors["has_evidence"] == len(manifest["evidence_requirements"])
