"""Generated manifests must satisfy the loader's own verification contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ccf.catalog.oscal import OscalManifestError, _verify, generate_manifest


def _write(d: Path, name: str, payload: dict) -> None:
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


def _full_set(d: Path) -> None:
    _write(d, "NIST_SP-800-53_rev5_catalog.json", {"catalog": {"metadata": {}}})
    for name in (
        "NIST_SP-800-53_rev5_LOW-baseline_profile.json",
        "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
        "NIST_SP-800-53_rev5_HIGH-baseline_profile.json",
    ):
        _write(d, name, {"profile": {"imports": []}})


def test_generated_manifest_passes_verify(tmp_path: Path) -> None:
    _full_set(tmp_path)
    manifest = generate_manifest(
        tmp_path,
        oscal_version="5.2.0",
        source_url="https://example.test/catalog.json",
        upstream_commit_sha="a" * 40,
        retrieved_at="2026-09-14",
    )
    assert manifest["oscal_version"] == "5.2.0"
    assert manifest["upstream_commit_sha"] == "a" * 40
    # Round-trips through the real verifier untouched.
    assert _verify(tmp_path)["files"] == manifest["files"]


def test_generated_manifest_rejects_missing_required_file(tmp_path: Path) -> None:
    # Catalog present, baselines absent — _verify's structural guard must fire.
    _write(tmp_path, "NIST_SP-800-53_rev5_catalog.json", {"catalog": {"metadata": {}}})
    generate_manifest(
        tmp_path,
        oscal_version="5.2.0",
        source_url="https://example.test/catalog.json",
        upstream_commit_sha=None,
        retrieved_at="2026-09-14",
    )
    with pytest.raises(OscalManifestError):
        _verify(tmp_path)


def test_manifest_itself_is_not_hashed(tmp_path: Path) -> None:
    _full_set(tmp_path)
    manifest = generate_manifest(
        tmp_path,
        oscal_version="5.2.0",
        source_url="https://example.test/catalog.json",
        upstream_commit_sha=None,
        retrieved_at="2026-09-14",
    )
    assert "MANIFEST.json" not in manifest["files"]


def test_recorded_hashes_match_bytes_on_disk(tmp_path: Path) -> None:
    _full_set(tmp_path)
    manifest = generate_manifest(
        tmp_path,
        oscal_version="5.2.0",
        source_url="https://example.test/catalog.json",
        upstream_commit_sha=None,
        retrieved_at="2026-09-14",
    )
    for name, want in manifest["files"].items():
        got = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        assert got == want


def test_regenerating_over_an_existing_manifest_excludes_it(tmp_path: Path) -> None:
    """The exclusion only bites on the second call -- the first has none to glob.

    Re-importing into a directory that already holds a manifest must not hash
    the manifest into its own files map, which would make it unverifiable.
    """
    _full_set(tmp_path)
    first = generate_manifest(
        tmp_path,
        oscal_version="5.2.0",
        source_url="https://example.test/catalog.json",
        upstream_commit_sha=None,
        retrieved_at="2026-09-14",
    )
    assert (tmp_path / "MANIFEST.json").is_file()

    second = generate_manifest(
        tmp_path,
        oscal_version="5.2.0",
        source_url="https://example.test/catalog.json",
        upstream_commit_sha=None,
        retrieved_at="2026-09-15",
    )
    assert "MANIFEST.json" not in second["files"]
    assert second["files"] == first["files"]
    # And it still round-trips through the real verifier.
    assert _verify(tmp_path)["files"] == second["files"]
