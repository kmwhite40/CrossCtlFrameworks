"""The derived Rev. 5 CCI workbook.

Not DISA-published, and its filename lies: 1,010 of its 3,626 rows are in Rev.
4 spelling (``AC-1``, ``AC-1 (a) (1)``), a second copy of CCIs that also appear
in Rev. 5 spelling (``AC-01``, ``AC-01a``). Loading it unfiltered gives two
conflicting rows per CCI, so only the Rev. 5 generation is returned.

Read with stdlib ``zipfile`` plus ``defusedxml`` -- an .ods is a zip of XML and
the project already depends on both, so no spreadsheet dependency is added.
"""
from __future__ import annotations

import re
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml import ElementTree

DEFAULT_CCI_ODS = Path(__file__).resolve().parents[3] / "data" / "cci" / "All Rev. 5 CCIs.ods"
OVERLAY_SOURCE = "derived:All Rev. 5 CCIs.ods"

_TABLE_NS = "urn:oasis:names:tc:opendocument:xmlns:table:1.0"
_REPEAT = f"{{{_TABLE_NS}}}number-columns-repeated"
#: Rev. 5 spelling zero-pads the control number: AC-01, not AC-1.
_REV5_CONTROL = re.compile(r"^[A-Z]{2}-\d{2}")
_CCI = re.compile(r"^CCI-\d{6}$")

# Column order in the published sheet.
_INHERITANCE, _CONTROL, _AP, _CCI_COL, _EMASS, _DEFINITION, _PROCEDURE, _METHODS = range(8)


@dataclass(frozen=True)
class OverlayRow:
    cci: str
    control_number: str
    ap_acronym: str
    emass_identifier: str | None
    assessment_procedure: str | None
    assessment_methods: str | None


def _cell_text(cell: Element) -> str:
    return "".join(cell.itertext()).strip()


def _rows(content: bytes) -> Iterator[list[str]]:
    root = ElementTree.fromstring(content)
    for row in root.iter(f"{{{_TABLE_NS}}}table-row"):
        cells: list[str] = []
        for cell in row.findall(f"{{{_TABLE_NS}}}table-cell"):
            text = _cell_text(cell)
            repeat = int(cell.get(_REPEAT, "1"))
            cells.extend([text] * min(repeat, 3))
        yield cells


def read_overlay_ods(path: Path) -> list[OverlayRow]:
    """Rev. 5 rows only. See the module docstring for why filtering is required."""
    with zipfile.ZipFile(path) as z:
        content = z.read("content.xml")

    out: list[OverlayRow] = []
    for cells in _rows(content):
        if len(cells) <= _METHODS:
            continue
        control = cells[_CONTROL].strip()
        cci = cells[_CCI_COL].strip()
        if not _REV5_CONTROL.match(control) or not _CCI.match(cci):
            continue
        out.append(
            OverlayRow(
                cci=cci,
                control_number=control,
                ap_acronym=cells[_AP].strip(),
                emass_identifier=cells[_EMASS].strip() or None,
                assessment_procedure=cells[_PROCEDURE].strip() or None,
                assessment_methods=cells[_METHODS].strip() or None,
            )
        )
    return out
