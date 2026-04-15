"""Header contract validation + row reject helpers.

Strict on required-header *removal* (breaks contract → fail run).
Soft on *additions* (log only; they're classified into frameworks).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


CONTRACT_PATH = Path(__file__).resolve().parents[3] / "contracts" / "headers.v1_1.json"


class HeaderContractError(RuntimeError):
    """Raised when a workbook is missing a required header."""


@dataclass(frozen=True)
class HeaderDiff:
    missing: list[str]
    added: list[str]


def load_contract(path: Path | None = None) -> dict:
    p = path or CONTRACT_PATH
    if not p.is_file():
        return {"required_headers": []}
    return json.loads(p.read_text(encoding="utf-8"))


def validate_headers(observed: set[str], contract: dict | None = None) -> HeaderDiff:
    """Return (missing, added); raise HeaderContractError on any missing header."""
    contract = contract or load_contract()
    required = set(contract.get("required_headers", []))
    missing = sorted(required - observed)
    added = sorted(observed - required)
    if missing:
        raise HeaderContractError(
            f"Workbook is missing required headers: {missing}. "
            "Either update contracts/headers.v1_1.json or fix the source."
        )
    return HeaderDiff(missing=missing, added=added)
