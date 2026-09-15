"""Pack catalog + manifest validation.

Loads bundled packs from ``ccf/packs/bundled/<id>/pack.json`` (plus any directory
named by ``CCF_PACKS_DIR``) and validates a manifest's schema before install.
Validation is fail-closed and returns human-readable errors — never raises.

A rule with ``kind == "posture"`` gets a second, much stricter pass
(:func:`validate_posture_rule`), because unlike the other rule kinds it is
*executed* against a customer tenant. The principle: **a pack that installs
must be evaluable.** Every unknown op, mode, evaluator, or parameter is
refused here rather than discovered mid-scan inside a tenant's scheduled job,
where the failure is a swallowed exception and a check that quietly stops
reporting. The vocabularies are imported from the posture package rather than
restated, so adding an op cannot leave validation behind.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..catalog.canonical import canonicalize
from ..config import get_settings
from ..posture.checks import platform_check_keys
from ..posture.declared import MODES, validate_predicate
from ..posture.parameters import validate_parameters

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


#: Form B fields with no sensible default. ``mode`` is absent on purpose: it
#: defaults to ``per_resource``, the shape most checks take.
_FORM_B_REQUIRED = ("provider", "resource_type", "endpoint", "expected", "control_ids")


def _validate_control_ids(raw: Any, where: str) -> list[str]:
    """Control ids must canonicalize, or the check evidences nothing.

    Findings are filed against canonical 800-53 ids -- the same key space
    ``CapabilityControl.control_id`` and ``SSPControlEntry.control_id`` use -- so
    an id that does not canonicalize (a CMMC practice such as ``AC.L2-3.1.1``,
    say) would store findings nothing ever looks up. Refusing at install is the
    only point at which the author can still fix it.
    """
    if not isinstance(raw, list) or not raw:
        return [f"{where} requires a non-empty 'control_ids' list"]
    errors = []
    for cid in raw:
        if not isinstance(cid, str) or canonicalize(cid) is None:
            errors.append(
                f"{where} control id {cid!r} is not a canonical 800-53 id (e.g. 'AC-2', 'AC-2(1)')"
            )
    return errors


def validate_posture_rule(
    rule: Any, *, platform_keys: frozenset[str], seen_keys: set[str]
) -> list[str]:
    """Validate one ``kind == "posture"`` rule. Empty list means evaluable."""
    if not isinstance(rule, dict):
        return ["posture rule must be an object"]
    key = rule.get("key")
    if not isinstance(key, str) or not key:
        return ["posture rule requires a non-empty 'key'"]
    where = f"posture rule {key!r}"

    errors: list[str] = []
    if key in platform_keys:
        # Never an override in either direction: the alternative lets a pack
        # weaken a platform check with an audit trail showing only "pack
        # installed". A tenant wanting different thresholds uses its own key.
        errors.append(
            f"{where} collides with the platform check {key!r}; "
            "choose a distinct key rather than overriding a platform check"
        )
    if key in seen_keys:
        errors.append(f"{where} is a duplicate key within this manifest")
    seen_keys.add(key)

    definition = rule.get("definition")
    if not isinstance(definition, dict):
        return [*errors, f"{where} 'definition' must be an object"]

    has_evaluator = "evaluator" in definition
    has_predicate = "predicate" in definition
    if has_evaluator == has_predicate:
        return [
            *errors,
            f"{where} must supply exactly one of 'evaluator' (a platform check to "
            "parameterize) or 'predicate' (a declarative check)",
        ]

    if has_evaluator:
        errors.extend(
            f"{where}: {e}"
            for e in validate_parameters(
                str(definition.get("evaluator")), definition.get("parameters", {})
            )
        )
        if "control_ids" in definition:
            errors.extend(_validate_control_ids(definition["control_ids"], where))
        return errors

    for field in _FORM_B_REQUIRED:
        if field not in definition:
            errors.append(f"{where} requires {field!r}")
    mode = definition.get("mode", "per_resource")
    if mode not in MODES:
        errors.append(f"{where} has unknown mode {mode!r} (allowed: {', '.join(sorted(MODES))})")
    if "control_ids" in definition:
        errors.extend(_validate_control_ids(definition["control_ids"], where))
    errors.extend(f"{where}: {e}" for e in validate_predicate(definition.get("predicate")))
    return errors


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
    rules = manifest.get("rules")
    if isinstance(rules, list):
        platform_keys = platform_check_keys()
        seen: set[str] = set()
        for rule in rules:
            if isinstance(rule, dict) and rule.get("kind") == "posture":
                errors.extend(
                    validate_posture_rule(rule, platform_keys=platform_keys, seen_keys=seen)
                )
    return errors
