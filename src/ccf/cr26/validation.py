# src/ccf/cr26/validation.py
"""Validate a document against a vendored FedRAMP CR26 schema.

FedRAMP publishes the CR26 deliverables as JSON schemas. Concord validates
against those schemas and never invents the shape of a FedRAMP artefact -- so
this module resolves every reference through the vendored copies under
``schemas/`` and never reaches the network.

That is not a preference. Ten of the eleven schemas reference
``common-definitions`` by absolute URL. ``jsonschema`` resolves a ``$ref``
through whatever ``referencing.Registry`` it is given: pass none, and it falls
back to fetching the reference over the network; pass one, and anything absent
from it raises ``Unresolvable`` with zero sockets attempted. So ``registry=``
is not a convenience -- it is the entire network barrier, and building it from
the vendored files here is what keeps every reference resolved locally, never
remotely. Note "complete": ``$ref`` resolution is lazy, so a document that
fails an earlier ``required`` check -- or simply never includes the property
carrying the reference -- never descends into it and appears to validate fine
regardless of whether the registry is present. That asymmetry is why the
tests here use documents complete enough to reach a ``$ref``.

Unlike :mod:`ccf.oscal.validation` this module has no ``detect_kind`` (CR26
documents do not self-identify by root key), no structural fallback (the schema
is vendored in-package and cannot be missing; a fallback would assert a shape
we invented) and no ECMA pattern translation (CR26's four patterns are all
Python-compatible).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

_SCHEMA_DIR = Path(__file__).with_name("schemas")
_MANIFEST = _SCHEMA_DIR / "MANIFEST.json"

#: Concord document kind -> (vendored filename, FedRAMP rule id).
#:
#: ``kind`` is required rather than inferred: an SDR's root keys are
#: ``certificationPackageOverviewUri`` and ``fedRampRequirements``, which name
#: no document type, so guessing would be a silent mis-validation.
CR26_KINDS: dict[str, tuple[str, str]] = {
    "common": ("fedramp-common-definitions-schema-2026-06-24.json", "-"),
    "cpo": ("fedramp-certification-package-overview-schema-2026-06-24.json", "FRC-CSO-PKG"),
    "sdr": ("fedramp-security-decision-record-schema-2026-06-24.json", "SDR-CSO-FRR"),
    "ocr": ("fedramp-ongoing-certification-report-schema-2026-06-24.json", "CCM-OCR-AVL"),
    "incident": ("fedramp-incident-report-schema-2026-06-24.json", "IEC-CSO-IIR"),
    "scn": ("fedramp-significant-change-notifications-schema-2026-06-24.json", "SCN-CSO-INF"),
    "vdr": ("fedramp-vulnerability-detail-report-schema-2026-06-24.json", "VER-RPT-VDT"),
    "avi": ("fedramp-accepted-vulnerability-info-schema-2026-06-24.json", "VER-RPT-AVI"),
    "ver_history": ("fedramp-historical-ver-activity-schema-2026-06-24.json", "-"),
    "advisor": ("fedramp-advisor-information-schema-2026-06-24.json", "MKT-CAS-WEB"),
    "assessor": ("fedramp-assessor-information-schema-2026-06-24.json", "MKT-IAS-WEB"),
}


@dataclass
class ValidationReport:
    """Outcome of validating one CR26 document.

    Same shape as :class:`ccf.oscal.validation.ValidationReport`, so a caller
    that handles one handles the other.
    """

    kind: str
    mode: str  # official|none
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


def schema_path(kind: str) -> Path | None:
    """Path to the vendored schema for ``kind``, or ``None`` if unknown."""
    entry = CR26_KINDS.get(kind)
    if entry is None:
        return None
    candidate = _SCHEMA_DIR / entry[0]
    return candidate if candidate.is_file() else None


def vendored_digests() -> dict[str, str]:
    """Kind -> the sha256 ``MANIFEST.json`` pins for that kind's vendored file.

    The digest of what we actually vendored, which is the only baseline a
    drift check can usefully start from: a freshly seeded ``CatalogSource``
    with a NULL ``last_sha256`` reports "changed" on its very first poll and
    then tracks upstream against upstream, so a schema that moved between the
    vendoring and that first poll would be adopted as the new baseline and
    never reported. Seeding this digest makes the first comparison
    upstream-against-what-we-vendored, which is what the rows claim to watch.

    Read on demand rather than at import: :mod:`ccf.etl.sources` does no file
    I/O at module import and that property is worth keeping. Raises
    ``KeyError`` naming the file if a :data:`CR26_KINDS` entry is absent from
    the manifest -- a packaging failure, and one that must be loud rather than
    silently yield a row with no baseline. Returns a fresh dict each call, so
    no caller can corrupt a shared one.
    """
    manifest: dict[str, Any] = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    files: dict[str, Any] = manifest["files"]
    return {
        kind: str(files[filename]["sha256"])
        for kind, (filename, _rule) in CR26_KINDS.items()
    }


@lru_cache(maxsize=1)
def _registry() -> Any:
    """Every vendored schema, keyed by its own ``$id``.

    This is what keeps validation offline: references resolve here or not at
    all. Built once -- the files cannot change under a running process.

    Driven by ``MANIFEST.json`` -- Task 1's single source of truth for which
    files are vendored -- rather than by :data:`CR26_KINDS`, so the registry
    can never silently end up smaller than what was actually pinned. Raises
    loudly, naming what is missing, if any manifest-listed file cannot be read
    or lacks an ``$id``: a registry that is quietly missing one schema is
    exactly how most of the other ten kinds would start failing resolution in
    production, since all of them point at the one schema most likely to be
    the casualty (``common-definitions``).
    """
    from referencing import Registry, Resource  # noqa: PLC0415

    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    filenames = sorted(manifest["files"])

    resources = []
    unusable = []
    for name in filenames:
        path = _SCHEMA_DIR / name
        if not path.is_file():
            unusable.append(name)
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        uri = doc.get("$id")
        if not uri:
            unusable.append(name)
            continue
        resources.append((uri, Resource.from_contents(doc)))

    if unusable:
        raise RuntimeError(
            "CR26 schema registry is incomplete -- manifest-listed file(s) "
            f"missing or without an $id: {unusable!r}"
        )
    return Registry().with_resources(resources)


@lru_cache(maxsize=1)
def _format_checker() -> Any:
    from jsonschema import FormatChecker  # noqa: PLC0415

    return FormatChecker()


def enforced_formats() -> tuple[str, ...]:
    """Which ``format`` values this environment actually checks.

    ``jsonschema`` registers a checker for a format only when that format's
    optional validator library is installed, so the answer is environmental,
    not a property of the schemas. Reported rather than assumed: a caller that
    needs ``uri`` or ``date-time`` enforced must install
    ``rfc3986-validator`` / ``rfc3339-validator`` and can check here.

    Only a missing ``jsonschema`` yields the empty tuple -- matching the rest
    of this module's ``mode="none"`` degradation. Anything else (a broken
    ``jsonschema`` install, say) propagates rather than being reported as the
    legitimate-looking, and false, answer "this environment enforces nothing".
    """
    try:
        return tuple(sorted(_format_checker().checkers))
    except ImportError:
        return ()


def _jsonschema_available() -> bool:
    try:
        import jsonschema  # noqa: F401,PLC0415
    except ImportError:
        return False
    return True


def validate_document(doc: Any, kind: str) -> ValidationReport:
    """Validate ``doc`` against the vendored CR26 schema for ``kind``.

    Returns a report rather than raising: an unknown kind, a non-object
    document, a missing backend, or any unexpected failure building or running
    the validator yields a report, never a crash. That last case is deliberate
    defense in depth -- ``_registry()`` already raises loudly if it is ever
    built incomplete, and this catches that (or any other surprise, such as
    ``referencing`` itself being uninstalled, or a vendored file becoming
    corrupt on disk) before it can reach a caller as a traceback.
    """
    if kind not in CR26_KINDS:
        return ValidationReport(
            kind, "none", ok=False, errors=[f"unknown CR26 document kind: {kind!r}"]
        )
    if not isinstance(doc, dict):
        return ValidationReport(kind, "none", ok=False, errors=["document must be a JSON object"])

    path = schema_path(kind)
    if path is None:
        return ValidationReport(
            kind, "none", ok=False, errors=[f"vendored schema missing for kind {kind!r}"]
        )
    if not _jsonschema_available():
        return ValidationReport(
            kind, "none", ok=False, errors=["jsonschema is not installed"]
        )

    try:
        from jsonschema.validators import validator_for  # noqa: PLC0415

        schema = json.loads(path.read_text(encoding="utf-8"))
        # Dialect from the schema itself, never hardcoded.
        cls = validator_for(schema)
        validator = cls(schema, registry=_registry(), format_checker=_format_checker())
        errors = [
            f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
        ]
    except Exception as exc:
        return ValidationReport(
            kind, "none", ok=False, errors=[f"validation failed unexpectedly: {exc}"]
        )
    return ValidationReport(kind, "official", ok=not errors, errors=errors)
