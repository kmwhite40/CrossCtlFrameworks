"""Render a custom compliance report to .xlsx or .docx bytes.

Both renderers consume the same ``(summary, rows)`` shape produced by the
report builder in :mod:`ccf.api.routes.reports`, so the API can offer CSV,
JSON, XLSX, and DOCX from one query.
"""

from __future__ import annotations

import io
from collections.abc import Mapping, Sequence
from typing import Any

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

# Column order / human labels for the tabular report rows.
_COLUMNS: tuple[tuple[str, str], ...] = (
    ("identifier", "Control"),
    ("family", "Family"),
    ("control_name", "Control Name"),
    ("baseline_low", "Low"),
    ("baseline_mod", "Moderate"),
    ("baseline_high", "High"),
    ("implementation_status", "Implementation"),
    ("responsibility", "Responsibility"),
    ("owner", "Owner"),
    ("last_assessed_on", "Last Assessed"),
    ("crosswalk_framework", "Crosswalk"),
    ("crosswalk_values", "Crosswalk Values"),
)

_BRAND = "4F46E5"  # indigo, matches the app brand
_HEADER_FILL = PatternFill("solid", fgColor=_BRAND)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else ""
    return str(value)


def _summary_pairs(summary: Mapping[str, Any]) -> list[tuple[str, str]]:
    return [
        ("Generated", _cell(summary.get("generated_at"))),
        ("Organization", _cell(summary.get("organization")) or "(catalog)"),
        ("System", _cell(summary.get("system")) or "(any)"),
        ("Baseline", _cell(summary.get("baseline")) or "(all)"),
        ("Crosswalk framework", _cell(summary.get("framework")) or "(none)"),
        ("Family filter", _cell(summary.get("family_filter")) or "(all)"),
        ("Total rows", _cell(summary.get("total_rows"))),
    ]


def report_to_xlsx(summary: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> bytes:
    """Render the report as a two-sheet workbook (Summary + Controls)."""
    wb = Workbook()

    meta = wb.active
    meta.title = "Summary"
    meta["A1"] = "Concord compliance report"
    meta["A1"].font = Font(size=14, bold=True, color=_BRAND)
    for i, (label, value) in enumerate(_summary_pairs(summary), start=3):
        meta.cell(row=i, column=1, value=label).font = Font(bold=True)
        meta.cell(row=i, column=2, value=value)
    meta.column_dimensions["A"].width = 22
    meta.column_dimensions["B"].width = 48

    ws = wb.create_sheet("Controls")
    headers = [label for _, label in _COLUMNS]
    ws.append(headers)
    for col, _ in enumerate(headers, start=1):
        c = ws.cell(row=1, column=col)
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = _HEADER_FILL
        c.alignment = Alignment(vertical="center", wrap_text=True)
    for row in rows:
        ws.append([_cell(row.get(key)) for key, _ in _COLUMNS])

    # Reasonable widths + a frozen, filterable header.
    widths = (16, 9, 40, 7, 10, 7, 16, 16, 12, 14, 12, 32)
    for col, width in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(col)].width = width
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{ws.max_row}"

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _shade(cell: Any, fill: str) -> None:
    shd = cell._tc.get_or_add_tcPr().makeelement(qn("w:shd"), {qn("w:fill"): fill})
    cell._tc.get_or_add_tcPr().append(shd)


def report_to_docx(summary: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> bytes:
    """Render the report as a titled Word document with a control table."""
    doc = Document()

    title = doc.add_heading(level=0)
    run = title.add_run("Concord Compliance Report")
    run.font.color.rgb = RGBColor.from_string(_BRAND)

    for label, value in _summary_pairs(summary):
        p = doc.add_paragraph()
        p.add_run(f"{label}: ").bold = True
        p.add_run(value)

    doc.add_heading("Controls", level=1)
    headers = [label for _, label in _COLUMNS]
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Light Grid Accent 1"
    for i, label in enumerate(headers):
        cell = table.rows[0].cells[i]
        cell.text = label
        _shade(cell, _BRAND)
        for para in cell.paragraphs:
            para.alignment = WD_ALIGN_PARAGRAPH.CENTER
            for r in para.runs:
                r.font.bold = True
                r.font.size = Pt(8)
                r.font.color.rgb = RGBColor.from_string("FFFFFF")
    for row in rows:
        cells = table.add_row().cells
        for i, (key, _) in enumerate(_COLUMNS):
            cells[i].text = _cell(row.get(key))
            for para in cells[i].paragraphs:
                for r in para.runs:
                    r.font.size = Pt(8)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
