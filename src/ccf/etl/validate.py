"""Header contract validation + row reject helpers.

Strict on required-header *removal* (breaks contract → fail run).
Soft on *additions* (log only; they're classified into frameworks).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

# Packaged alongside this module (declared in [tool.setuptools.package-data]).
# It must NOT be resolved by walking out of the package with ``parents[N]``: the
# repo checkout, the installed wheel, the Docker image and the PyInstaller
# one-file build all put ``__file__`` at a different depth, so a relative walk
# resolves correctly in a source tree and nowhere else. The contract gates
# ingestion, and ingestion truncates the catalog, so "cannot find the contract"
# must never be indistinguishable from "the workbook is fine".
CONTRACT_PATH = Path(__file__).with_name("headers.v1_1.json")


class HeaderContractError(RuntimeError):
    """Raised when a workbook is missing a required header."""


class HeaderContractUnavailableError(HeaderContractError):
    """Raised when the packaged header contract itself cannot be loaded.

    A deployment fault, not a workbook fault — but it subclasses
    ``HeaderContractError`` so the ingest pipeline's existing handler records
    the run as failed instead of letting an unvalidated workbook through.
    """


@dataclass(frozen=True)
class HeaderDiff:
    missing: list[str]
    added: list[str]


def load_contract(path: Path | None = None) -> dict[str, list[str]]:
    p = path or CONTRACT_PATH
    if not p.is_file():
        raise HeaderContractUnavailableError(
            f"Header contract not found at {p}. It ships as package data next to "
            "ccf/etl/validate.py; a missing file means a packaging fault, not a "
            "workbook problem. Refusing to ingest, because an empty contract "
            "would validate every workbook and ingestion truncates the catalog."
        )
    raw = json.loads(p.read_text(encoding="utf-8"))
    required_headers = raw.get("required_headers", [])
    if not isinstance(required_headers, list):
        required_headers = []
    return {"required_headers": [str(header) for header in required_headers]}


def validate_headers(
    observed: set[str], contract: Mapping[str, list[str]] | None = None
) -> HeaderDiff:
    """Return (missing, added); raise HeaderContractError on any missing header."""
    contract = contract or load_contract()
    required = set(contract.get("required_headers", []))
    missing = sorted(required - observed)
    added = sorted(observed - required)
    if missing:
        raise HeaderContractError(
            f"Workbook is missing required headers: {missing}. "
            "Either update src/ccf/etl/headers.v1_1.json or fix the source."
        )
    return HeaderDiff(missing=missing, added=added)
