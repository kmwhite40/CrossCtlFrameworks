"""NIST Cybersecurity Framework 2.0 — authoritative catalog loader.

Concord already carried CSF 2.0, but only as free text. The workbook contributes
four crosswalk columns (Function, Category, Subcategory, Requirements) whose
values arrive in at least five different shapes:

    DE.CM-01                                          bare subcategory id
    PR.AT-04:                                         id with a trailing colon
    PR.AT-01: Personnel are provided with awareness…  id plus full prose
    Protect: Platform Security (PR.PS)                function + category name
    Respond: Incident Analysis (RS.AN); Respond: …    several, semicolon-joined

Nothing checked any of it, so a typo was indistinguishable from a real
subcategory and the UI showed whatever the spreadsheet happened to contain.

This module loads NIST's published OSCAL catalog so those strings can be
*resolved* instead of trusted: :func:`extract_ids` pulls candidate ids out of a
crosswalk value and :meth:`CsfCatalog.get` answers whether each one is real,
with the authoritative title and statement.

Shape of the OSCAL document (verified against v2.0, oscal-version v1.2.2)::

    catalog.groups[]              class="function"      GV, ID, PR, DE, RS, RC
      └── controls[]              class="category"      GV.OC
            └── controls[]        class="subcategory"   GV.OC-01

Note the middle level is a *control*, not a nested group — which is why this
module walks the tree explicitly rather than reusing ``oscal._iter_controls``,
whose flattening would merge categories and subcategories into one namespace.

Integrity: the file is listed in the same ``MANIFEST.json`` as the 800-53
catalog and is therefore SHA-256 verified by :func:`ccf.catalog.oscal._verify`
on every load of that directory.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .oscal import OscalManifestError, _resolve_dir, _verify

CSF_CATALOG_FILE = "NIST_CSF_v2.0_catalog.json"

# Subcategory ids look like ``GV.OC-01`` — two-letter function, dot, two-letter
# category, hyphen, two digits. Anchored on a word boundary so it still matches
# inside prose ("...see PR.AT-01: Personnel...") without catching a longer token.
_ID_RE = re.compile(r"\b([A-Z]{2}\.[A-Z]{2}-\d{2})\b")

# Category ids are the same without the numeric suffix: ``GV.OC``.
_CATEGORY_RE = re.compile(r"\b([A-Z]{2}\.[A-Z]{2})\b(?!-\d)")


@dataclass(frozen=True)
class CsfSubcategory:
    """A CSF 2.0 subcategory — the leaf a crosswalk value should resolve to."""

    id: str
    title: str
    statement: str
    category_id: str
    category_title: str
    function_id: str
    function_title: str

    @property
    def label(self) -> str:
        """``GV.OC-01 — The organizational mission is understood…`` for display."""
        return f"{self.id} — {self.statement or self.title}"


@dataclass
class CsfCatalog:
    version: str = ""
    oscal_version: str = ""
    functions: dict[str, str] = field(default_factory=dict)
    categories: dict[str, str] = field(default_factory=dict)
    subcategories: dict[str, CsfSubcategory] = field(default_factory=dict)

    def get(self, cid: str) -> CsfSubcategory | None:
        return self.subcategories.get(cid.upper())

    def has(self, cid: str) -> bool:
        return cid.upper() in self.subcategories

    def is_known(self, cid: str) -> bool:
        """True for a real subcategory, category or function id."""
        c = cid.upper()
        return c in self.subcategories or c in self.categories or c in self.functions


def _part_prose(node: dict[str, Any], name: str) -> str:
    for part in node.get("parts", []) or []:
        if part.get("name") == name:
            return str(part.get("prose") or "").strip()
    return ""


@lru_cache(maxsize=1)
def load_csf_catalog(base_dir: Path | None = None) -> CsfCatalog:
    """Load and verify the packaged CSF 2.0 catalog.

    Cached: the document is ~350 KB and immutable once verified.
    """
    d = _resolve_dir(base_dir)
    manifest = _verify(d)
    if CSF_CATALOG_FILE not in manifest.get("files", {}):
        raise OscalManifestError(
            f"MANIFEST.json does not list {CSF_CATALOG_FILE}; it would be parsed "
            "unverified. Add its sha256 to the manifest."
        )
    raw = json.loads((d / CSF_CATALOG_FILE).read_text(encoding="utf-8"))
    cat = raw["catalog"]
    meta = cat.get("metadata", {})
    out = CsfCatalog(
        version=str(meta.get("version") or ""),
        oscal_version=str(meta.get("oscal-version") or ""),
    )
    for func in cat.get("groups", []) or []:
        fid, ftitle = str(func.get("id", "")), str(func.get("title", ""))
        out.functions[fid] = ftitle
        for category in func.get("controls", []) or []:
            cid, ctitle = str(category.get("id", "")), str(category.get("title", ""))
            out.categories[cid] = ctitle
            for sub in category.get("controls", []) or []:
                sid = str(sub.get("id", ""))
                out.subcategories[sid] = CsfSubcategory(
                    id=sid,
                    title=str(sub.get("title", "")),
                    statement=_part_prose(sub, "statement"),
                    category_id=cid,
                    category_title=ctitle,
                    function_id=fid,
                    function_title=ftitle,
                )
    if not out.subcategories:
        raise OscalManifestError(f"{CSF_CATALOG_FILE} parsed to zero subcategories")
    return out


def extract_ids(value: str | None) -> list[str]:
    """Pull CSF subcategory ids out of a crosswalk value, in order, deduplicated.

    Handles every shape the workbook uses — a bare id, an id with a trailing
    colon, an id followed by prose, and several joined by semicolons. Returns
    ``[]`` for a value that names only a function or category, which is not an
    error: those columns legitimately carry coarser references.
    """
    if not value:
        return []
    seen: dict[str, None] = {}
    for m in _ID_RE.finditer(value.upper()):
        seen.setdefault(m.group(1), None)
    return list(seen)


def extract_category_ids(value: str | None) -> list[str]:
    """Pull CSF *category* ids (``GV.OC``) out of a value, excluding subcategories."""
    if not value:
        return []
    seen: dict[str, None] = {}
    for m in _CATEGORY_RE.finditer(value.upper()):
        seen.setdefault(m.group(1), None)
    return list(seen)
