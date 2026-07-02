"""Unit tests for the generic register exporter (pure render layer)."""

from __future__ import annotations

import json

from ccf.governance.exporter import (
    FORMATS,
    IMPORT_FORMATS,
    _coerce_date,
    _parse_rows,
    _render,
)

ROWS = [
    {"id": 1, "title": "Unencrypted backups", "severity": "high", "status": "open"},
    {"id": 2, "title": "Missing MFA", "severity": "critical", "status": "in_progress"},
]


def test_formats_registered() -> None:
    assert set(FORMATS) == {"csv", "json", "md"}


def test_json_roundtrips() -> None:
    content, media = _render(ROWS, "json", "poams")
    assert media == "application/json"
    assert json.loads(content)[1]["severity"] == "critical"


def test_csv_has_header_and_rows() -> None:
    content, media = _render(ROWS, "csv", "poams")
    assert media == "text/csv"
    text = content.decode()
    assert text.splitlines()[0] == "id,title,severity,status"
    assert "Unencrypted backups" in text


def test_markdown_table() -> None:
    content, media = _render(ROWS, "md", "poams")
    assert media == "text/markdown"
    text = content.decode()
    assert "# poams register" in text
    assert "| id | title | severity | status |" in text
    assert text.count("|") >= 12  # header + separator + 2 rows


def test_empty_dataset_still_renders_header() -> None:
    content, _ = _render([], "csv", "risks")
    assert content.decode().strip() == "id"


# --- import (parse layer) ---------------------------------------------------


def test_import_formats_registered() -> None:
    assert set(IMPORT_FORMATS) == {"csv", "json"}


def test_parse_csv_rows() -> None:
    csv_bytes = b"title,severity\nUnencrypted backups,high\nMissing MFA,critical\n"
    rows = _parse_rows(csv_bytes, "csv")
    assert len(rows) == 2
    assert rows[0]["title"] == "Unencrypted backups"
    assert rows[1]["severity"] == "critical"


def test_parse_json_accepts_list_and_wrapped() -> None:
    assert _parse_rows(b'[{"title":"a"}]', "json")[0]["title"] == "a"
    assert _parse_rows(b'{"rows":[{"title":"b"}]}', "json")[0]["title"] == "b"
    # bare object is treated as a single row
    assert _parse_rows(b'{"title":"c"}', "json")[0]["title"] == "c"


def test_parse_json_rejects_scalar() -> None:
    try:
        _parse_rows(b"42", "json")
    except ValueError:
        return
    raise AssertionError("expected ValueError for non-list/dict JSON")


def test_coerce_date_handles_blanks_and_iso() -> None:
    assert _coerce_date("") is None
    assert _coerce_date("None") is None
    assert _coerce_date("2026-07-01").isoformat() == "2026-07-01"
    assert _coerce_date("2026-07-01T12:00:00").isoformat() == "2026-07-01"
