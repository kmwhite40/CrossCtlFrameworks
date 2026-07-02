"""OSCAL export validation — official-schema-capable, with a structural fallback.

:mod:`ccf.oscal.validation` validates the OSCAL documents Concord produces (SSP,
Component Definition, POA&M, and the FedRAMP 20x assessment bundle) against the
upstream NIST OSCAL JSON Schemas when they are available (``CCF_OSCAL_SCHEMA_DIR``),
and degrades gracefully to built-in structural checks otherwise — never crashing
when the official schema or ``jsonschema`` is absent.
"""

from __future__ import annotations

from .validation import (
    KINDS,
    ValidationReport,
    detect_kind,
    official_schema_available,
    official_schema_path,
    validate_document,
)

__all__ = [
    "KINDS",
    "ValidationReport",
    "detect_kind",
    "official_schema_available",
    "official_schema_path",
    "validate_document",
]
