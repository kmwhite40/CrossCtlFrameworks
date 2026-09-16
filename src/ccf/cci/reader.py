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


@dataclass
class _TableFrame:
    """One open <table>'s in-progress state.

    A stack of these -- rather than three bare instance attributes -- is what
    lets a <table> nested inside a cell push a new frame and pop back to the
    outer one afterwards, instead of the outer table's in-progress row and
    cell being silently overwritten and lost.
    """

    table: list[list[_Cell]]
    row: list[_Cell] | None = None
    cell: _Cell | None = None


class _TableParser(HTMLParser):
    """Collect every <table> as rows of cells, keeping anchor text per cell.

    Anchor text is kept separately because a reference cell reads
    ``NIST:  <a>NIST SP 800-53 Revision 5 (v5)</a>:  AC-1 a 1 (a)`` -- the
    title and the index are only separable if we know where the anchor ended.

    Tables nest via a stack of :class:`_TableFrame`, one per currently-open
    <table>, so a <table> nested inside another (e.g. a stray one in a
    future DISA revision, or a hand-edited file) pushes and pops instead of
    clobbering the outer table's state.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[_Cell]]] = []
        self.preamble: str = ""
        self._stack: list[_TableFrame] = []
        self._in_anchor = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self._stack.append(_TableFrame(table=[]))
            return
        if not self._stack:
            return
        frame = self._stack[-1]
        if tag == "tr":
            frame.row = []
        elif tag == "td" and frame.row is not None:
            frame.cell = _Cell()
        elif tag == "a" and frame.cell is not None:
            self._in_anchor = True
            frame.cell.links.append("")

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._in_anchor = False
            return
        if not self._stack:
            return
        frame = self._stack[-1]
        row, cell = frame.row, frame.cell
        if tag == "td" and cell is not None and row is not None:
            row.append(cell)
            frame.cell = None
        elif tag == "tr" and row is not None:
            frame.table.append(row)
            frame.row = None
        elif tag == "table":
            self._stack.pop()
            self.tables.append(frame.table)

    def handle_data(self, data: str) -> None:
        if not self._stack:
            self.preamble += data
            return
        cell = self._stack[-1].cell
        if cell is None:
            return
        cell.text += data
        if self._in_anchor and cell.links:
            cell.links[-1] += data


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
    raw_title = cell.links[0]
    title = _clean(raw_title)
    if not title:
        # An anchor with no (or only whitespace) text names nothing to
        # decompose the reference against, and splitting the cell's text on
        # an empty separator would raise -- skip the row instead of crashing
        # the parse of the other entries in the file.
        return None
    tail = cell.text.split(raw_title, 1)[-1]
    index = _clean(tail.lstrip(": "))
    if not index:
        # The anchor names a real publication but nothing follows it to
        # record as the index -- there is no part to resolve, so the
        # reference is dropped, but silently would hide a future DISA file
        # that starts omitting indices instead of just this one.
        log.warning("cci.empty_reference_index", title=title)
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
        ref = _reference(row[-1])
        if ref is not None:
            references.append(ref)
    if not _CCI_RE.match(cci):
        # Not a trustworthy item -- storing it would let a hand-edited or
        # mis-rendered table entry masquerade as real DISA content -- but
        # dropping it without a trace would lose the signal that something
        # in the source file didn't match the expected shape.
        log.warning("cci.malformed_cci_id", cci=cci)
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
