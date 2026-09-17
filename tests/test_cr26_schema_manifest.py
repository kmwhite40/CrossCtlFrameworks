"""The vendored CR26 schemas match their manifest, and the manifest matches them.

FedRAMP publishes the CR26 deliverables as JSON schemas at stable URLs. Concord
vendors them so validation works with no network and no configuration, and pins
each by sha256 so a silent substitution is impossible. This file is the pin.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "src" / "ccf" / "cr26" / "schemas"
MANIFEST = SCHEMA_DIR / "MANIFEST.json"
RULESET_VERSION = "2026-06-24"
EXPECTED_COUNT = 11


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_the_manifest_records_the_ruleset_revision() -> None:
    """The date in every filename is the RULESET revision, not a schema version."""
    assert _manifest()["ruleset_version"] == RULESET_VERSION


def test_all_eleven_schemas_are_vendored() -> None:
    """Pinning a subset guarantees a second spine job before the 2026-12-07
    VDR/VER deadline -- see the spec's section 2."""
    on_disk = sorted(p.name for p in SCHEMA_DIR.glob("*.json") if p.name != "MANIFEST.json")
    assert len(on_disk) == EXPECTED_COUNT, on_disk
    assert sorted(_manifest()["files"]) == on_disk


def test_every_vendored_file_matches_its_recorded_hash() -> None:
    """The pin itself. A substituted or hand-edited schema fails here."""
    mismatches = []
    for name, entry in _manifest()["files"].items():
        digest = hashlib.sha256((SCHEMA_DIR / name).read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            mismatches.append(f"{name}: manifest {entry['sha256'][:12]} != file {digest[:12]}")
    assert mismatches == []


def test_every_entry_records_the_schema_s_own_version_and_id() -> None:
    """Two-level versioning: one ruleset date, a separate semver per schema.

    The spread is live -- certification-package-overview is 0.1.4 while
    assessor-information is 1.0.1 -- so a single version field cannot describe
    this set.
    """
    wrong = []
    for name, entry in _manifest()["files"].items():
        doc = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
        if entry.get("schema_version") != doc.get("$schemaVersion"):
            wrong.append(
                f"{name}: manifest {entry.get('schema_version')!r} "
                f"!= file {doc.get('$schemaVersion')!r}"
            )
        if entry.get("id") != doc.get("$id"):
            wrong.append(f"{name}: manifest id != file $id")
    assert wrong == []


def test_the_schema_versions_are_not_all_identical() -> None:
    """Guards the manifest generator against writing one version everywhere --
    which would look right and silently defeat the per-schema pin."""
    versions = {e["schema_version"] for e in _manifest()["files"].values()}
    assert len(versions) > 1, versions


def test_each_filename_carries_the_ruleset_revision() -> None:
    for name in _manifest()["files"]:
        assert name.endswith(f"-schema-{RULESET_VERSION}.json"), name
