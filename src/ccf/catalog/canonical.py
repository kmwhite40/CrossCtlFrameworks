# src/ccf/catalog/canonical.py
"""Canonicalize NIST 800-53 control ids to a single display form.

One pure function that maps the many real-world spellings of a control id
(``AC-2``, ``AC-02``, ``AC-2 (1)``, ``ac-2(1)``) onto a canonical string
(``AC-2``, ``AC-2(1)``). Never guesses: anything not confidently an 800-53
control id — prose, CMMC ids like ``AC.L2-3.1.1``, empties — returns ``None``
and is reported by the reconciler rather than silently mis-matched.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Family (two letters) then -NN, then zero or more (N) or " (N)" enhancement
# groups. Anchored + full-match so prose and CMMC ids (which contain '.') are
# rejected.
_PATTERN = re.compile(
    r"^\s*(?P<fam>[A-Za-z]{2})-0*(?P<num>\d{1,3})"
    r"(?P<enh>(?:\s*\(\s*0*\d{1,3}\s*\))*)\s*$"
)
_ENH = re.compile(r"\(\s*0*(\d{1,3})\s*\)")


@dataclass(frozen=True)
class CanonicalId:
    value: str
    family: str
    number: int
    enhancements: tuple[int, ...]


def canonicalize(raw: str | None) -> CanonicalId | None:
    if not raw or not raw.strip():
        return None
    m = _PATTERN.match(raw)
    if not m:
        return None
    fam = m.group("fam").upper()
    num = int(m.group("num"))
    enh = tuple(int(x) for x in _ENH.findall(m.group("enh") or ""))
    value = f"{fam}-{num}" + "".join(f"({e})" for e in enh)
    return CanonicalId(value=value, family=fam, number=num, enhancements=enh)


def canonical_to_oscal_id(canonical: str) -> str:
    """Inverse of :func:`ccf.catalog.oscal.oscal_id_to_canonical`.

    ``"AC-2" -> "ac-2"``, ``"AC-2(1)" -> "ac-2.1"``, ``"AC-2(1)(2)" ->
    "ac-2.1.2"``. A plain id with no enhancement is just lowercased.
    """
    return re.sub(r"\((\d+)\)", r".\1", canonical).lower()
