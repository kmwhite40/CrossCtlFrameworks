"""Parser contract and the plain-text parser."""

from __future__ import annotations

import pytest

from ccf.prep.parsers import UnsupportedMediaType, dispatch
from ccf.prep.parsers.text import parse_text


def test_text_parser_produces_one_line_per_nonblank_line() -> None:
    doc = parse_text(b"First line.\n\nSecond line.\n", "policy.txt")
    assert doc.success
    assert doc.parser_name == "text"
    lines = list(doc.iter_lines())
    assert [line.content for line in lines] == ["First line.", "Second line."]


def test_line_numbers_are_sequential_from_one() -> None:
    doc = parse_text(b"a\nb\nc\n", "x.txt")
    assert [line.line_number for line in doc.iter_lines()] == [1, 2, 3]


def test_text_parser_decodes_utf8_and_survives_bad_bytes() -> None:
    doc = parse_text("Café requires MFA.".encode(), "p.txt")
    assert "Café" in next(iter(doc.iter_lines())).content
    # Invalid UTF-8 must degrade, not raise — evidence arrives in every encoding.
    doc2 = parse_text(b"\xff\xfe bad bytes but readable", "p.txt")
    assert doc2.success


def test_dispatch_routes_plain_text_by_media_type() -> None:
    doc = dispatch(b"hello", "note.txt", "text/plain")
    assert doc.parser_name == "text"


def test_dispatch_falls_back_to_extension_when_media_type_missing() -> None:
    doc = dispatch(b"hello", "note.txt", None)
    assert doc.parser_name == "text"


def test_dispatch_raises_for_unsupported_media_type() -> None:
    with pytest.raises(UnsupportedMediaType) as exc:
        dispatch(b"\x00", "diagram.vsdx", None)
    assert "vsdx" in str(exc.value)
