"""Validate Concord's OSCAL documents against official schema or structural checks.

Resolution order per document:

1. If ``CCF_OSCAL_SCHEMA_DIR`` holds the matching upstream NIST OSCAL JSON Schema
   *and* ``jsonschema`` is importable → validate against the **official** schema
   (``mode="official"``).
2. Otherwise → validate with Concord's built-in **structural** checks
   (``mode="structural"``) and attach a warning that official conformance was not
   checked. When ``CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA`` is set, the missing schema
   is promoted to an error so the report fails closed.

Everything is best-effort and exception-safe — a missing dependency, an unreadable
schema file, or an unknown document shape yields a report, never a crash.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import get_settings

# Concord document kind -> (OSCAL root key, candidate official schema filenames).
KINDS: dict[str, tuple[str, tuple[str, ...]]] = {
    "ssp": (
        "system-security-plan",
        ("oscal_ssp_schema.json", "oscal_complete_schema.json"),
    ),
    "component": (
        "component-definition",
        ("oscal_component_schema.json", "oscal_complete_schema.json"),
    ),
    "poam": (
        "plan-of-action-and-milestones",
        ("oscal_poam_schema.json", "oscal_complete_schema.json"),
    ),
    "assessment": (
        "assessment-results",
        ("oscal_assessment-results_schema.json", "oscal_complete_schema.json"),
    ),
}
# Accept a few friendly aliases for the bundle/assessment kind.
_ALIASES = {"ksi_bundle": "assessment", "bundle": "assessment", "ar": "assessment"}


@dataclass
class ValidationReport:
    """Outcome of validating one OSCAL document."""

    kind: str  # ssp|component|poam|assessment|unknown
    mode: str  # official|structural|none
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "mode": self.mode,
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def detect_kind(doc: dict[str, Any]) -> str:
    """Infer the document kind from its OSCAL root key."""
    if isinstance(doc, dict):
        for kind, (root_key, _) in KINDS.items():
            if root_key in doc:
                return kind
    return "unknown"


def official_schema_path(kind: str) -> Path | None:
    """Path to the official OSCAL schema for ``kind`` under ``CCF_OSCAL_SCHEMA_DIR``."""
    kind = _ALIASES.get(kind, kind)
    schema_dir = get_settings().oscal_schema_dir
    if schema_dir is None or kind not in KINDS:
        return None
    directory = Path(schema_dir)
    for name in KINDS[kind][1]:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def official_schema_available(kind: str) -> bool:
    return official_schema_path(kind) is not None and _jsonschema_available()


def _jsonschema_available() -> bool:
    try:
        import jsonschema  # noqa: F401,PLC0415
    except Exception:
        return False
    return True


def validate_document(doc: Any, kind: str = "auto") -> ValidationReport:
    """Validate ``doc`` as an OSCAL document, resolving the best available backend."""
    if not isinstance(doc, dict):
        return ValidationReport(
            "unknown", "none", ok=False, errors=["document must be a JSON object"]
        )
    resolved = _ALIASES.get(kind, kind)
    if resolved in ("auto", ""):
        resolved = detect_kind(doc)
    if resolved == "unknown" or resolved not in KINDS:
        return ValidationReport(
            "unknown", "none", ok=False,
            errors=["unrecognized OSCAL document (no known root key)"],
        )

    require_official = get_settings().oscal_require_official_schema
    schema_path = official_schema_path(resolved)

    if schema_path is not None and _jsonschema_available():
        errors = _validate_against_schema(doc, schema_path)
        return ValidationReport(resolved, "official", ok=not errors, errors=errors)

    # Structural fallback.
    errors = _validate_structural(doc, resolved)
    warnings: list[str] = []
    if require_official:
        errors = [
            "official OSCAL schema required but not available "
            "(set CCF_OSCAL_SCHEMA_DIR to the NIST OSCAL schema directory)",
            *errors,
        ]
    else:
        warnings.append(
            "validated with Concord structural checks only — official OSCAL schema "
            "not available (set CCF_OSCAL_SCHEMA_DIR for full conformance checking)"
        )
    return ValidationReport(resolved, "structural", ok=not errors, errors=errors, warnings=warnings)


def _validate_against_schema(doc: dict[str, Any], schema_path: Path) -> list[str]:
    try:
        import jsonschema  # noqa: PLC0415

        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        return [
            f"{'/'.join(str(p) for p in e.absolute_path) or 'root'}: {e.message}"
            for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
        ]
    except Exception as e:  # unreadable/invalid schema — surface, don't crash
        return [f"could not validate against official schema {schema_path.name}: {e}"]


# --- structural fallback -----------------------------------------------------

# kind -> list of required array/object children under the root object.
_REQUIRED_CHILDREN: dict[str, tuple[str, ...]] = {
    "ssp": ("system-characteristics", "control-implementation"),
    "component": ("components",),
    "poam": ("poam-items",),
    "assessment": ("results",),
}


def _validate_structural(doc: dict[str, Any], kind: str) -> list[str]:
    """Minimal OSCAL structural checks shared across models."""
    errors: list[str] = []
    root_key = KINDS[kind][0]
    root = doc.get(root_key)
    if not isinstance(root, dict):
        return [f"root: missing required object '{root_key}'"]
    if not isinstance(root.get("uuid"), str):
        errors.append(f"{root_key}: missing required string 'uuid'")
    meta = root.get("metadata")
    if not isinstance(meta, dict):
        errors.append(f"{root_key}: missing required object 'metadata'")
    else:
        for key in ("title", "last-modified", "oscal-version"):
            if not isinstance(meta.get(key), str):
                errors.append(f"{root_key}.metadata: missing required string '{key}'")
    for child in _REQUIRED_CHILDREN.get(kind, ()):
        val = root.get(child)
        if val is None:
            errors.append(f"{root_key}: missing required '{child}'")
        elif isinstance(val, list) and not val:
            errors.append(f"{root_key}.{child}: must contain at least one item")
    return errors
