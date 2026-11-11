"""Vendored front-end files are exactly what VENDOR.json says they are."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

VENDOR = Path(__file__).parents[1] / "src/ccf/api/static/vendor"


def test_every_recorded_file_matches_its_hash() -> None:
    manifest = json.loads((VENDOR / "VENDOR.json").read_text(encoding="utf-8"))
    assert "cytoscape.min.js" in manifest
    for name, entry in manifest.items():
        assert set(entry) == {"package", "version", "license", "source", "sha256"}, name
        digest = hashlib.sha256((VENDOR / name).read_bytes()).hexdigest()
        assert digest == entry["sha256"], f"{name} differs from the recorded hash"


def test_the_renderer_is_the_pinned_mit_release() -> None:
    entry = json.loads((VENDOR / "VENDOR.json").read_text(encoding="utf-8"))["cytoscape.min.js"]
    assert entry["version"] == "3.30.2" and entry["license"] == "MIT"
    assert entry["version"] in entry["source"]
