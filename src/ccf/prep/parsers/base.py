"""Shared parser contract.

Every parser returns a :class:`ParsedDocument` regardless of source format, so
the pipeline's parse stage is format-agnostic. Structure is preserved on the way
through — heading path, table identity, row and column index, and the inherited
column header for a cell — because a bare table value ("Quarterly") is only
evidence when you know which column it sat under.

:meth:`ParsedDocument.iter_lines` is the flattening step: it walks pages and
blocks in document order and emits the line-level records the parse stage
persists to ``prep_lines``.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ParsedCell:
    """One native cell inside a parsed table row."""

    text: str
    row_index: int
    col_index: int
    header: str | None = None


@dataclass(slots=True)
class ParsedBlock:
    """A logical source block — paragraph, heading, list item, or table cell."""

    block_id: str
    block_type: str
    text: str
    heading_path: list[str] = field(default_factory=list)
    row_index: int | None = None
    col_index: int | None = None
    table_id: str | None = None
    cell_label: str | None = None
    cells: list[ParsedCell] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedPage:
    """One page, slide, or sheet."""

    page_number: int
    blocks: list[ParsedBlock] = field(default_factory=list)
    section_title: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedLineRecord:
    """A flattened line ready to persist as a ``prep_lines`` row."""

    line_number: int
    content: str
    page_number: int | None = None
    section_path: str | None = None
    block_id: str | None = None
    block_type: str | None = None
    table_id: str | None = None
    row_index: int | None = None
    col_index: int | None = None
    cell_label: str | None = None


@dataclass(slots=True)
class ParsedDocument:
    """The parser-neutral result for one source document."""

    filename: str
    media_type: str
    parser_name: str
    pages: list[ParsedPage] = field(default_factory=list)
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None and any(page.blocks for page in self.pages)

    def iter_lines(self) -> Iterator[ParsedLineRecord]:
        """Walk pages and blocks in document order, numbering lines from 1."""
        line_number = 0
        for page in self.pages:
            for block in page.blocks:
                text = block.text.strip()
                if not text:
                    continue
                line_number += 1
                yield ParsedLineRecord(
                    line_number=line_number,
                    content=text,
                    page_number=page.page_number,
                    section_path=" > ".join(block.heading_path) or None,
                    block_id=block.block_id,
                    block_type=block.block_type,
                    table_id=block.table_id,
                    row_index=block.row_index,
                    col_index=block.col_index,
                    cell_label=block.cell_label,
                )


def decode_text(data: bytes) -> str:
    """Decode bytes to text, degrading rather than raising.

    Evidence arrives in every encoding and a single bad byte must not fail a
    whole document — losing one character is always better than losing the file.
    """
    return data.decode("utf-8", errors="replace")
