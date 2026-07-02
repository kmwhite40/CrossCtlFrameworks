"""Parse the *CMMC L2 Assessment Methods Scoring Matrix* workbook.

The workbook is the single source of truth for the 110 CMMC Level 2 practices,
their SPRS point values, NIST SP 800-171A determination statements (parts
``[a]``, ``[b]``…), assessment cases, and the Microsoft 365 evidence/inheritance
placemat columns.

``parse_workbook`` reads the ``Matrix_By_Control`` sheet (one row per control)
and enriches each record with the parsed objective parts. ``build_seed`` writes
the result to ``seed.json`` so the application can bootstrap the reference data
without shipping the proprietary spreadsheet into the runtime image.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import openpyxl

SHEET = "Matrix_By_Control"
SEED_PATH = Path(__file__).with_name("seed.json")

# Column index → record key for the Matrix_By_Control sheet.
_COLUMNS: dict[int, str] = {
    0: "point_value",
    1: "scoring_bucket",
    2: "scoring_notes",
    3: "domain",
    4: "control_id",
    5: "title",
    6: "requirement",
    7: "objectives",
    8: "examine_cases",
    9: "interview_cases",
    10: "test_cases",
    11: "considerations",
    12: "key_references",
    13: "guide_page",
    14: "pdf_page",
    15: "source",
    16: "m365_coverage_status",
    17: "m365_primary_services",
    18: "m365_secondary_services",
    19: "m365_implementation_statement",
    20: "m365_inheritance",
    21: "recommended_customer_evidence",
    22: "recommended_provider_evidence",
    23: "evidence_notes",
    24: "m365_source",
}

# Columns that hold newline-delimited lists of M365 services.
_LIST_COLUMNS = {
    "m365_primary_services",
    "m365_secondary_services",
}

_PART_RE = re.compile(r"\[([a-z])\]")


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def split_objectives(text: str) -> list[dict[str, str]]:
    """Split an NIST 800-171A objectives blob into per-part determination items.

    ``"[a] foo;\n[b] bar."`` → ``[{"label": "a", "text": "foo"}, ...]``.
    Returns a single unlabeled part when no ``[x]`` markers are present.
    """
    text = _clean(text)
    if not text:
        return []
    matches = list(_PART_RE.finditer(text))
    if not matches:
        return [{"label": "", "text": text}]
    parts: list[dict[str, str]] = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        # Trailing connectors like "and"/"or" left dangling before the next item,
        # then any separator punctuation they were joined with ("...defined; and").
        body = re.sub(r"\b(and|or)$", "", body).strip().rstrip(";").strip()
        parts.append({"label": m.group(1), "text": body})
    return parts


def _nist_id(control_id: str) -> str:
    """``AC.L2-3.1.1`` → ``3.1.1`` (the NIST SP 800-171 requirement number)."""
    m = re.search(r"(\d+\.\d+\.\d+)", control_id)
    return m.group(1) if m else control_id


def parse_workbook(path: str | Path) -> list[dict[str, Any]]:
    """Return one structured record per control row in the scoring matrix."""
    wb = openpyxl.load_workbook(path, data_only=True, read_only=True)
    try:
        ws = wb[SHEET]
    except KeyError as exc:  # pragma: no cover - defensive
        raise ValueError(f"workbook missing required sheet {SHEET!r}") from exc

    records: list[dict[str, Any]] = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        control_id = _clean(row[4] if len(row) > 4 else "")
        if not control_id:
            continue
        rec: dict[str, Any] = {}
        for idx, key in _COLUMNS.items():
            raw = row[idx] if idx < len(row) else None
            if key in _LIST_COLUMNS:
                rec[key] = [s.strip() for s in _clean(raw).splitlines() if s.strip()]
            else:
                rec[key] = _clean(raw)
        rec["nist_id"] = _nist_id(control_id)
        rec["objective_parts"] = split_objectives(rec["objectives"])
        records.append(rec)

    wb.close()
    records.sort(key=lambda r: (r["domain"], r["control_id"]))
    return records


def build_seed(workbook: str | Path, out: str | Path = SEED_PATH) -> int:
    """Parse ``workbook`` and write the committed ``seed.json``. Returns row count."""
    records = parse_workbook(workbook)
    Path(out).write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
    return len(records)


def load_seed(path: str | Path = SEED_PATH) -> list[dict[str, Any]]:
    """Load the committed reference matrix shipped with the package."""
    data: list[dict[str, Any]] = json.loads(Path(path).read_text(encoding="utf-8"))
    return data


if __name__ == "__main__":  # pragma: no cover
    import sys

    src = sys.argv[1] if len(sys.argv) > 1 else None
    if not src:
        raise SystemExit("usage: python -m ccf.scoring.parser <workbook.xlsx>")
    n = build_seed(src)
    print(f"wrote {n} controls to {SEED_PATH}")
