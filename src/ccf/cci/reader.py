"""Read DISA's published CCI List.

The published artifact is XML; this is DISA's HTML rendering of it, which is
what we hold. The parse is deliberately sealed behind :func:`read_cci_html`
returning typed records, so an ``U_CCI_List.xml`` reader can be added later
without any downstream change.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from html.parser import HTMLParser
from pathlib import Path

from ..etl.sources import sha256_bytes
from ..logging import get_logger

log = get_logger(__name__)

DEFAULT_CCI_HTML = Path(__file__).resolve().parents[3] / "data" / "cci" / "CCI List.html"

#: Reference titles DISA publishes -> the short revision code we store. An
#: unrecognised title is stored verbatim rather than dropped: losing an
#: authority's reference silently is worse than carrying an unexpected string.
_REVISIONS: dict[str, str] = {
    "NIST SP 800-53 (v3)": "3",
    "NIST SP 800-53 Revision 4 (v4)": "4",
    "NIST SP 800-53 Revision 5 (v5)": "5",
    "NIST SP 800-53A (v1)": "800-53A",
}

_VERSION_RE = re.compile(r"Version\s+(\d{4}-\d{2}-\d{2})")
_CCI_RE = re.compile(r"^CCI-\d{6}$")


@dataclass(frozen=True)
class CciReference:
    revision: str
    raw_index: str


@dataclass(frozen=True)
class CciItem:
    cci: str
    status: str
    type: str
    contributor: str | None
    published_date: date | None
    definition: str
    references: tuple[CciReference, ...]


@dataclass(frozen=True)
class CciList:
    version: str
    source_sha256: str
    items: tuple[CciItem, ...]


@dataclass
class _Cell:
    text: str = ""
    links: list[str] = field(default_factory=list)


class _TableParser(HTMLParser):
    """Collect every <table> as rows of cells, keeping anchor text per cell.

    Anchor text is kept separately because a reference cell reads
    ``NIST:  <a>NIST SP 800-53 Revision 5 (v5)</a>:  AC-1 a 1 (a)`` -- the
    title and the index are only separable if we know where the anchor ended.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[_Cell]]] = []
        self.preamble: str = ""
        self._table: list[list[_Cell]] | None = None
        self._row: list[_Cell] | None = None
        self._cell: _Cell | None = None
        self._in_anchor = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag == "td" and self._row is not None:
            self._cell = _Cell()
        elif tag == "a" and self._cell is not None:
            self._in_anchor = True
            self._cell.links.append("")

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._in_anchor = False
        elif tag == "td" and self._cell is not None and self._row is not None:
            self._row.append(self._cell)
            self._cell = None
        elif tag == "tr" and self._row is not None and self._table is not None:
            self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None

    def handle_data(self, data: str) -> None:
        if self._cell is None:
            if self._table is None:
                self.preamble += data
            return
        self._cell.text += data
        if self._in_anchor and self._cell.links:
            self._cell.links[-1] += data


def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _parse_date(raw: str) -> date | None:
    try:
        return date.fromisoformat(_clean(raw))
    except ValueError:
        return None


def _reference(cell: _Cell) -> CciReference | None:
    """A reference cell: an anchor naming the publication, then ': index'."""
    if not cell.links:
        return None
    title = _clean(cell.links[0])
    tail = cell.text.split(cell.links[0], 1)[-1]
    index = _clean(tail.lstrip(": "))
    if not index:
        return None
    revision = _REVISIONS.get(title)
    if revision is None:
        revision = title[:64]
        log.warning("cci.unknown_reference_title", title=title)
    return CciReference(revision=revision, raw_index=index)


def _item(table: list[list[_Cell]]) -> CciItem | None:
    fields: dict[str, str] = {}
    references: list[CciReference] = []
    cci = ""
    for row in table:
        if not row:
            continue
        label = _clean(row[0].text).rstrip(":").lower()
        if label == "cci" and len(row) > 1:
            cci = _clean(row[1].text)
            if len(row) > 3:
                fields[_clean(row[2].text).rstrip(":").lower()] = _clean(row[3].text)
            continue
        if label in {"contributor", "published date"} and len(row) > 1:
            fields[label] = _clean(row[1].text)
            if len(row) > 3:
                fields[_clean(row[2].text).rstrip(":").lower()] = _clean(row[3].text)
            continue
        if label in {"definition", "type"} and len(row) > 1:
            fields[label] = _clean(row[1].text)
            continue
        ref = _reference(row[-1]) if row else None
        if ref is not None:
            references.append(ref)
    if not _CCI_RE.match(cci):
        return None
    return CciItem(
        cci=cci,
        status=fields.get("status", ""),
        type=fields.get("type", ""),
        contributor=fields.get("contributor") or None,
        published_date=_parse_date(fields.get("published date", "")),
        definition=fields.get("definition", ""),
        references=tuple(references),
    )


def read_cci_html(path: Path) -> CciList:
    """Parse DISA's CCI List HTML into typed records."""
    body = path.read_bytes()
    parser = _TableParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    m = _VERSION_RE.search(parser.preamble)
    items = tuple(i for i in (_item(t) for t in parser.tables) if i is not None)
    if not items:
        raise ValueError(f"no CCI entries parsed from {path}")
    return CciList(
        version=m.group(1) if m else "",
        source_sha256=sha256_bytes(body),
        items=items,
    )
