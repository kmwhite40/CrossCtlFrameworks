# src/ccf/catalog/oscal.py
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_DEFAULT_DIR = Path(__file__).resolve().parents[3] / "data" / "oscal"
_PACKAGED_DIR = Path(__file__).with_name("oscal_data")  # wheel/Docker fallback
_BASELINE_FILES = {
    "low": "NIST_SP-800-53_rev5_LOW-baseline_profile.json",
    "moderate": "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
    "high": "NIST_SP-800-53_rev5_HIGH-baseline_profile.json",
}
_CATALOG_FILE = "NIST_SP-800-53_rev5_catalog.json"


class OscalManifestError(RuntimeError):
    """Raised when a bundled OSCAL file is missing or fails sha256 verification."""


@dataclass(frozen=True)
class OscalControl:
    canonical_id: str
    title: str
    statement: str
    guidance: str
    withdrawn: bool
    incorporated_into: list[str]
    param_ids: list[str]


@dataclass
class OscalCatalog:
    version: str
    controls: dict[str, OscalControl] = field(default_factory=dict)
    baselines: dict[str, set[str]] = field(default_factory=dict)
    # sha256 of the pinned catalog file this was loaded from (per-report provenance).
    catalog_sha256: str | None = None

    def get(self, cid: str) -> OscalControl | None:
        return self.controls.get(cid)

    def exists(self, cid: str) -> bool:
        return cid in self.controls

    def in_baseline(self, cid: str, level: str) -> bool:
        return cid in self.baselines.get(level, set())


def oscal_id_to_canonical(oscal_id: str) -> str:
    parts = oscal_id.split(".")
    base = parts[0]
    m = re.match(r"^([a-zA-Z]+)-(\d+)$", base)
    fam, num = (m.group(1).upper(), str(int(m.group(2)))) if m else (base.upper(), "")
    canon = f"{fam}-{num}" if num else base.upper()
    for enh in parts[1:]:
        canon += f"({int(enh)})" if enh.isdigit() else f"({enh})"
    return canon


def _resolve_dir(base_dir: Path | None) -> Path:
    # Packaged in-package dir first (ships in the wheel + Docker `COPY src`), then
    # the repo-relative data/ dir as a dev override.
    for d in [base_dir] if base_dir else [_PACKAGED_DIR, _DEFAULT_DIR]:
        if d and (d / "MANIFEST.json").is_file():
            return d
    raise OscalManifestError(
        f"OSCAL data dir not found (looked in {base_dir or [_DEFAULT_DIR, _PACKAGED_DIR]})"
    )


def _verify(d: Path) -> dict[str, Any]:
    manifest: dict[str, Any] = json.loads((d / "MANIFEST.json").read_text(encoding="utf-8"))
    files: dict[str, Any] = manifest.get("files", {})
    # Structurally couple verification to what load_oscal_catalog actually reads:
    # every required file MUST be listed in the manifest, so a manifest that drops
    # an entry cannot silently skip that file's hash check (the file would then be
    # parsed unverified). Guards the "MUST verify each bundled file" guarantee.
    required = {_CATALOG_FILE, *_BASELINE_FILES.values()}
    unlisted = sorted(required - files.keys())
    if unlisted:
        raise OscalManifestError(f"MANIFEST.json is missing required OSCAL file(s): {unlisted}")
    for name, want in files.items():
        p = d / name
        if not p.is_file():
            raise OscalManifestError(f"missing OSCAL file {name}")
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        if got != want:
            raise OscalManifestError(f"sha256 mismatch for {name}: {got} != {want}")
    return manifest


def _iter_controls(node: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for c in node.get("controls", []):
        yield c
        yield from _iter_controls(c)
    for g in node.get("groups", []):
        yield from _iter_controls(g)


def _part_prose(control: dict[str, Any], name: str) -> str:
    out = []
    for part in control.get("parts", []):
        if part.get("name") == name and part.get("prose"):
            out.append(part["prose"])
    return "\n".join(out)


def _parse_control(c: dict[str, Any]) -> OscalControl:
    props = c.get("props", [])
    withdrawn = any(p.get("name") == "status" and p.get("value") == "withdrawn" for p in props)
    inc = [
        oscal_id_to_canonical(link["href"].lstrip("#"))
        for link in c.get("links", [])
        if link.get("rel") == "incorporated-into" and link.get("href")
    ]
    return OscalControl(
        canonical_id=oscal_id_to_canonical(c["id"]),
        title=c.get("title", ""),
        statement=_part_prose(c, "statement"),
        guidance=_part_prose(c, "guidance"),
        withdrawn=withdrawn,
        incorporated_into=inc,
        param_ids=[p["id"] for p in c.get("params", []) if p.get("id")],
    )


def load_oscal_catalog(base_dir: Path | None = None) -> OscalCatalog:
    d = _resolve_dir(base_dir)
    manifest = _verify(d)
    raw: dict[str, Any] = json.loads((d / _CATALOG_FILE).read_text(encoding="utf-8"))
    cat_meta = raw["catalog"]["metadata"]
    catalog = OscalCatalog(
        version=cat_meta.get("version", manifest.get("oscal_version", "")),
        catalog_sha256=manifest.get("files", {}).get(_CATALOG_FILE),
    )
    for c in _iter_controls(raw["catalog"]):
        oc = _parse_control(c)
        catalog.controls[oc.canonical_id] = oc
    for level, fname in _BASELINE_FILES.items():
        prof: dict[str, Any] = json.loads((d / fname).read_text(encoding="utf-8"))
        ids: set[str] = set()
        for imp in prof["profile"].get("imports", []):
            for inc in imp.get("include-controls", []):
                ids.update(oscal_id_to_canonical(x) for x in inc.get("with-ids", []))
        catalog.baselines[level] = ids
    return catalog
