"""Unit tests for the generic register exporter (pure render layer)."""

from __future__ import annotations

import json

from ccf.governance.exporter import FORMATS, _render

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
