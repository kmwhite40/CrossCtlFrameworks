"""Plain-text parser — one block per non-blank line."""

from __future__ import annotations

from .base import ParsedBlock, ParsedDocument, ParsedPage, decode_text

PARSER_NAME = "text"


def parse_text(data: bytes, filename: str, media_type: str = "text/plain") -> ParsedDocument:
    """Parse plain text into a single page of paragraph blocks."""
    blocks = [
        ParsedBlock(block_id=f"p{index}", block_type="paragraph", text=stripped)
        for index, raw in enumerate(decode_text(data).splitlines(), start=1)
        if (stripped := raw.strip())
    ]
    return ParsedDocument(
        filename=filename,
        media_type=media_type,
        parser_name=PARSER_NAME,
        pages=[ParsedPage(page_number=1, blocks=blocks)],
    )
