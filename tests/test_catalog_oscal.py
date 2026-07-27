# tests/test_catalog_oscal.py
import json
import shutil
from pathlib import Path

import pytest

from ccf.catalog.oscal import (
    OscalManifestError,
    load_oscal_catalog,
    oscal_id_to_canonical,
)

FIX = Path(__file__).parent / "fixtures" / "oscal_mini"


def test_oscal_id_to_canonical():
    assert oscal_id_to_canonical("ac-2") == "AC-2"
    assert oscal_id_to_canonical("ac-2.1") == "AC-2(1)"
    assert oscal_id_to_canonical("ac-2.1.2") == "AC-2(1)(2)"


def test_loads_and_indexes_controls_and_enhancements():
    cat = load_oscal_catalog(FIX)
    assert cat.version == "5.2.0"
    assert cat.exists("AC-1") and cat.exists("AC-2") and cat.exists("AC-2(1)")
    ac2 = cat.get("AC-2")
    assert ac2.title == "Account Management"
    assert "Manage system accounts." in ac2.statement
    assert ac2.param_ids == ["ac-02_odp.01"]


def test_withdrawn_and_incorporated_into():
    cat = load_oscal_catalog(FIX)
    ac13 = cat.get("AC-13")
    assert ac13.withdrawn is True
    assert "AC-2" in ac13.incorporated_into


def test_baseline_membership():
    cat = load_oscal_catalog(FIX)
    assert cat.in_baseline("AC-2", "moderate") is True
    assert cat.in_baseline("AC-2(1)", "low") is False
    assert cat.in_baseline("AC-2(1)", "high") is True


def test_manifest_sha_mismatch_raises(tmp_path):
    # copy fixture, corrupt one file, expect OscalManifestError
    dst = tmp_path / "oscal"
    shutil.copytree(FIX, dst)
    p = dst / "NIST_SP-800-53_rev5_catalog.json"
    p.write_text(p.read_text() + " ")  # change bytes -> sha mismatch
    with pytest.raises(OscalManifestError):
        load_oscal_catalog(dst)


def test_manifest_missing_required_file_raises(tmp_path):
    # A manifest that omits a required OSCAL file must NOT silently pass — the
    # dropped file would otherwise be parsed unverified.
    dst = tmp_path / "oscal"
    shutil.copytree(FIX, dst)
    manifest = json.loads((dst / "MANIFEST.json").read_text())
    manifest["files"].pop("NIST_SP-800-53_rev5_catalog.json", None)
    (dst / "MANIFEST.json").write_text(json.dumps(manifest))
    with pytest.raises(OscalManifestError):
        load_oscal_catalog(dst)


def test_default_resolution_loads_packaged_catalog():
    # No base_dir → must resolve the packaged in-package oscal_data dir (the one
    # that ships in the wheel + Docker image) and load the real pinned catalog.
    cat = load_oscal_catalog()
    assert cat.version == "5.2.0"
    assert len(cat.controls) > 1000  # full 800-53r5 incl. enhancements
    assert cat.exists("AC-2") and cat.in_baseline("AC-2", "moderate")
    assert cat.catalog_sha256 and len(cat.catalog_sha256) == 64
