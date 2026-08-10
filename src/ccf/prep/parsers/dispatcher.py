"""Route a source document to the right parser by media type or extension.

Unsupported formats raise :class:`UnsupportedMediaType` rather than failing
silently — the pipeline records the run as ``unsupported`` so the coverage gap is
visible in the data. Image OCR and Visio are deliberately out of scope for this
slice (see the design spec).
"""

from __future__ import annotations

from pathlib import Path

from .base import ParsedDocument
from .docx import MEDIA_TYPE as DOCX_MEDIA_TYPE
from .docx import parse_docx
from .text import parse_text


class UnsupportedMediaType(RuntimeError):  # noqa: N818 -- name fixed by parser contract
    """No parser is registered for this document's format."""


#: Extension → media type. Consulted when the caller has no media type, which is
#: common for policy documents referenced only by URI.
_EXTENSION_MEDIA_TYPES = {
    ".txt": "text/plain",
    ".md": "text/plain",
    ".csv": "text/plain",
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


def resolve_media_type(filename: str, media_type: str | None) -> str:
    """Prefer the declared media type; fall back to the filename extension."""
    if media_type:
        return media_type.split(";")[0].strip().lower()
    suffix = Path(filename).suffix.lower()
    resolved = _EXTENSION_MEDIA_TYPES.get(suffix)
    if resolved is None:
        raise UnsupportedMediaType(f"no parser for '{suffix or filename}'")
    return resolved


def dispatch(data: bytes, filename: str, media_type: str | None = None) -> ParsedDocument:
    """Parse ``data`` with the parser registered for its format."""
    resolved = resolve_media_type(filename, media_type)
    if resolved.startswith("text/"):
        return parse_text(data, filename, resolved)
    if resolved == DOCX_MEDIA_TYPE:
        return parse_docx(data, filename, resolved)
    raise UnsupportedMediaType(f"no parser for '{resolved}'")
