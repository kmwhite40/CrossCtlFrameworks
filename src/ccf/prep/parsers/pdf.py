"""PDF parser built on PyMuPDF.

Page number is the citation that matters for a PDF — an assessor checking a
finding turns to a page, not a byte offset. Text is extracted per block in
PyMuPDF's reading order and each block becomes one line record carrying its page.

A page with no extractable text is a scanned image. This slice has no OCR (see
the design spec), so such a page is flagged ``text_extractable = False`` rather
than raising: the gap belongs in the data where it can be reported, not hidden
behind a failed run.
"""

from __future__ import annotations

from typing import Any

import fitz

from ...logging import get_logger
from .base import ParsedBlock, ParsedDocument, ParsedPage

log = get_logger(__name__)

PARSER_NAME = "pdf"
MEDIA_TYPE = "application/pdf"

#: Index of the text payload in PyMuPDF's ``get_text("blocks")`` tuples
#: (x0, y0, x1, y1, text, block_no, block_type).
_BLOCK_TEXT = 4
_BLOCK_NO = 5


def parse_pdf(data: bytes, filename: str, media_type: str = MEDIA_TYPE) -> ParsedDocument:
    """Parse a PDF into one page per source page of text blocks."""
    try:
        document = fitz.open(stream=data, filetype="pdf")
    except Exception as exc:  # a malformed file must not kill the run
        log.warning("prep.parse.pdf_failed", filename=filename, error=str(exc))
        return ParsedDocument(
            filename=filename, media_type=media_type, parser_name=PARSER_NAME,
            error=f"could not open PDF: {exc}",
        )

    pages: list[ParsedPage] = []
    try:
        for page_index, page in enumerate(document, start=1):
            blocks: list[ParsedBlock] = []
            for raw in sorted(page.get_text("blocks"), key=lambda b: (b[1], b[0])):
                text = str(raw[_BLOCK_TEXT]).strip()
                if not text:
                    continue
                blocks.append(
                    ParsedBlock(
                        block_id=f"p{page_index}b{raw[_BLOCK_NO]}",
                        block_type="paragraph",
                        text=text,
                    )
                )
            metadata: dict[str, Any] = {"text_extractable": bool(blocks)}
            if not blocks:
                log.info(
                    "prep.parse.pdf_page_not_extractable",
                    filename=filename,
                    page=page_index,
                )
            pages.append(
                ParsedPage(page_number=page_index, blocks=blocks, metadata=metadata)
            )
    finally:
        document.close()

    return ParsedDocument(
        filename=filename, media_type=media_type, parser_name=PARSER_NAME, pages=pages
    )
