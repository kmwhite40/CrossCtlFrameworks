"""Validate Concord's OSCAL documents against official schema or structural checks.

Resolution order per document:

1. If the matching upstream NIST OSCAL JSON Schema is available — either the
   in-package vendored copy under ``ccf/oscal/schemas/`` (the default) or a
   directory pointed to by ``CCF_OSCAL_SCHEMA_DIR`` (overrides the default) —
   *and* ``jsonschema`` is importable → validate against the **official** schema
   (``mode="official"``). The vendored schemas declare JSON Schema draft-07 and
   use ``#anchor``-style ``$ref``s, so the adapter resolves the validator class
   via ``jsonschema.validators.validator_for`` instead of hardcoding a dialect,
   and translates OSCAL's ECMA Unicode-property regex patterns (``\\p{L}`` etc.)
   into Python-``re``-compatible equivalents before compiling.
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
    """Path to the official OSCAL schema for ``kind``.

    Resolves ``CCF_OSCAL_SCHEMA_DIR`` when set; otherwise falls back to the
    in-package vendored schemas under ``ccf/oscal/schemas/`` so official
    validation works by default with no environment configuration.
    """
    kind = _ALIASES.get(kind, kind)
    if kind not in KINDS:
        return None
    schema_dir = get_settings().oscal_schema_dir
    directory = Path(schema_dir) if schema_dir is not None else Path(__file__).with_name("schemas")
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


def _translate_ecma_pattern(pattern: str) -> str:
    """Translate ECMA Unicode-property regex classes into Python-``re`` equivalents.

    OSCAL's official schemas use ECMA 262 Unicode property escapes (``\\p{L}``,
    ``\\p{N}``, ...) in ``pattern`` constraints. Python's ``re`` module does not
    support ``\\p{...}`` at all (``bad escape \\p``), so any schema pattern using
    them crashes validation once a token/uuid-like field is populated. This maps
    the classes OSCAL actually uses to ASCII-equivalent character classes — a
    deliberate approximation (not a full Unicode-property engine), sufficient for
    OSCAL's token/uuid/date patterns. Two-letter classes are replaced before the
    single-letter ``\\p{L}``/``\\p{N}`` so they aren't partially matched first.
    Pure and idempotent: re-running on already-translated text is a no-op.
    """
    pattern = pattern.replace(r"\p{Lu}", "[A-Z]")
    pattern = pattern.replace(r"\p{Ll}", "[a-z]")
    pattern = pattern.replace(r"\p{L}", r"[^\W\d_]")
    pattern = pattern.replace(r"\p{Nd}", "[0-9]")
    pattern = pattern.replace(r"\p{N}", "[0-9]")
    return pattern


def _walk_translate_patterns(node: Any) -> None:
    """Recursively translate every ``"pattern"`` string in a JSON schema, in place."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                node[key] = _translate_ecma_pattern(value)
            else:
                _walk_translate_patterns(value)
    elif isinstance(node, list):
        for item in node:
            _walk_translate_patterns(item)


_ADAPTED_CACHE: dict[str, Any] = {}


def _load_adapted_schema(schema_path: Path) -> Any:
    """Load ``schema_path``, translate its ECMA patterns once, and cache the result."""
    key = str(schema_path)
    if key not in _ADAPTED_CACHE:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        _walk_translate_patterns(schema)
        _ADAPTED_CACHE[key] = schema
    return _ADAPTED_CACHE[key]


def _validate_against_schema(doc: dict[str, Any], schema_path: Path) -> list[str]:
    try:
        import jsonschema  # noqa: F401,PLC0415
        from jsonschema.validators import validator_for  # noqa: PLC0415

        schema = _load_adapted_schema(schema_path)
        validator = validator_for(schema)(schema)
        return sorted(e.message for e in validator.iter_errors(doc))[:50]
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
