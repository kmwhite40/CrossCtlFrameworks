"""Pack catalog + manifest validation.

Loads bundled packs from ``ccf/packs/bundled/<id>/pack.json`` (plus any directory
named by ``CCF_PACKS_DIR``) and validates a manifest's schema before install.
Validation is fail-closed and returns human-readable errors — never raises.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..config import get_settings

BUNDLED_DIR = Path(__file__).parent / "bundled"

# Required top-level manifest keys and their expected python types.
_REQUIRED: dict[str, type | tuple[type, ...]] = {
    "id": str,
    "name": str,
    "version": str,
    "schema_version": str,
    "controls": list,
}
_LIST_KEYS = (
    "controls", "mappings", "evidence_requirements", "rules",
    "policy_templates", "questionnaire_templates", "connector_mappings",
    "dashboard_cards", "tests",
)


def _pack_dirs() -> list[Path]:
    dirs = [BUNDLED_DIR]
    override = get_settings().packs_dir
    if override is not None and Path(override).is_dir():
        dirs.append(Path(override))
    return dirs


def list_available() -> list[dict[str, Any]]:
    """List available (loadable) packs across the bundled + override directories."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for base in _pack_dirs():
        for manifest_path in sorted(base.glob("*/pack.json")):
            try:
                m = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            key = str(m.get("id", manifest_path.parent.name))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "id": key, "name": m.get("name", key), "version": m.get("version", "?"),
                "controls": len(m.get("controls", [])), "path": str(manifest_path),
            })
    return out


def load_pack(path_or_id: str) -> dict[str, Any]:
    """Load a pack manifest by filesystem path or by bundled/override pack id."""
    p = Path(path_or_id)
    if p.is_file():
        return _read(p)
    if p.is_dir() and (p / "pack.json").is_file():
        return _read(p / "pack.json")
    for base in _pack_dirs():
        candidate = base / path_or_id / "pack.json"
        if candidate.is_file():
            return _read(candidate)
    raise FileNotFoundError(f"pack not found: {path_or_id}")


def _read(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def manifest_sha(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate_manifest(manifest: Any) -> list[str]:
    """Validate a pack manifest; returns a list of errors (empty = valid)."""
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]
    for key, typ in _REQUIRED.items():
        if key not in manifest:
            errors.append(f"missing required key '{key}'")
        elif not isinstance(manifest[key], typ):
            errors.append(f"key '{key}' must be {getattr(typ, '__name__', typ)}")
    for key in _LIST_KEYS:
        if key in manifest and not isinstance(manifest[key], list):
            errors.append(f"key '{key}' must be a list")
    for i, ctl in enumerate(manifest.get("controls", []) if isinstance(manifest, dict) else []):
        if not isinstance(ctl, dict) or "control_id" not in ctl:
            errors.append(f"controls[{i}] must be an object with 'control_id'")
    if isinstance(manifest.get("controls"), list) and not manifest["controls"]:
        errors.append("pack must define at least one control")
    return errors
