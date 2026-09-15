"""The derived Rev. 5 CCI workbook.

Not DISA-published, and its filename lies: 1,010 of its 3,626 rows are in Rev.
4 spelling (``AC-1``, ``AC-1 (a) (1)``), a second copy of CCIs that also appear
in Rev. 5 spelling (``AC-01``, ``AC-01a``). Loading it unfiltered gives two
conflicting rows per CCI, so only the Rev. 5 generation is returned.

Zero-padded spelling alone does NOT discriminate generations: it only
distinguishes single-digit control numbers (``AC-1`` vs ``AC-01``). A
two-digit control like ``AC-10`` is spelled identically in both revisions, so
a spelling-only filter lets 254 Rev. 4/STIG-wording rows through disguised as
Rev. 5, producing 51 duplicate ``(control_number, ap_acronym, cci)`` triples
with materially different assessment text (measured against the committed
file). The reliable discriminator is the Assessment Procedures wording: every
one of the 2,616 zero-padded rows that is genuinely Rev. 5 (2,362 of them)
opens with the 800-53A objective phrasing "Determine if"; none of the 1,010
Rev. 4/STIG-spelled rows do (they open with "The organization being
inspected/assessed...", "The information system...", or "DoD has
defined..."). Filtering on wording alone yields the same 2,362 rows as
wording-plus-spelling, with zero duplicate triples either way -- the wording
test subsumes the spelling test. The spelling check is kept as a secondary
guard (belt and braces, and it documents intent) but the wording test is the
one actually doing the discrimination; do not simplify this back to spelling
alone.

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
#: Cap on how many times a column-9+ merged/blank cell's
#: number-columns-repeated is expanded. The 8 columns this reader actually
#: uses (indices 0-7) never carry a repeat count in the committed file -- only
#: trailing blank cells past column 7 do -- so a cap of 3 is harmless today.
#: It exists as a defensive bound, not a tuned value: a differently-exported
#: file that DID put a repeat count on an early column could otherwise shift
#: every later index and silently store, say, an assessment procedure into
#: the eMASS identifier field with no error. The cap alone doesn't prevent
#: that -- the ``_CCI`` regex check below on column 3 is what makes a
#: shifted row fail loudly (a shifted cell there won't look like ``CCI-######``
#: and the row is dropped) rather than silently mis-store.
_REPEAT_CAP = 3
#: Rev. 5 spelling zero-pads the control number: AC-01, not AC-1. This alone
#: cannot discriminate two-digit controls (AC-10 is spelled the same in both
#: revisions) -- kept as a secondary guard. See the module docstring.
_REV5_CONTROL = re.compile(r"^[A-Z]{2}-\d{2}")
_CCI = re.compile(r"^CCI-\d{6}$")
#: The reliable Rev. 5 discriminator: 800-53A objective wording. See the
#: module docstring for the measured evidence that this subsumes spelling.
_REV5_PROCEDURE_PREFIX = "Determine if"

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
            cells.extend([text] * min(repeat, _REPEAT_CAP))
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
        procedure = cells[_PROCEDURE].strip()
        if not _REV5_CONTROL.match(control) or not _CCI.match(cci):
            continue
        if not procedure.startswith(_REV5_PROCEDURE_PREFIX):
            continue
        out.append(
            OverlayRow(
                cci=cci,
                control_number=control,
                ap_acronym=cells[_AP].strip(),
                emass_identifier=cells[_EMASS].strip() or None,
                assessment_procedure=procedure or None,
                assessment_methods=cells[_METHODS].strip() or None,
            )
        )
    return out
