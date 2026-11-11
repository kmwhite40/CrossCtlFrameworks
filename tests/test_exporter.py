"""Unit tests for the generic register exporter (pure render layer)."""

from __future__ import annotations

import json

import pytest

from ccf.governance.exporter import (
    _IMPORT_SPEC,
    FORMATS,
    IMPORT_FORMATS,
    _apply_fields,
    _coerce_date,
    _parse_rows,
    _render,
)
from ccf.models import Risk

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


# ── risk scores stay in step with levels on import (0099 five-point scale) ──


def _risk_spec() -> dict:
    return next(spec for spec in _IMPORT_SPEC.values() if spec["model"].__name__ == "Risk")


def test_an_imported_level_sets_its_score() -> None:
    r = Risk()
    _apply_fields(
        r, {"likelihood": "high", "impact": "moderate", "treatment": "accept"}, _risk_spec()
    )
    assert (r.likelihood_score, r.impact_score) == (5, 3)
    assert (r.inherent_score, r.residual_score) == (15, 15)


def test_reimporting_the_same_level_keeps_a_finer_score() -> None:
    """A risk scored 4 (high) re-imported as 'high' stays 4, not 5."""
    r = Risk(likelihood="high", likelihood_score=4, impact="low", impact_score=2)
    _apply_fields(r, {"likelihood": "high", "impact": "low"}, _risk_spec())
    assert (r.likelihood_score, r.impact_score) == (4, 2)
    assert r.inherent_score == 8


def test_an_imported_score_sets_its_level_and_a_contradiction_is_refused() -> None:
    r = Risk()
    _apply_fields(r, {"likelihood_score": "2", "impact_score": 4}, _risk_spec())
    assert (r.likelihood, r.impact) == ("low", "high")
    with pytest.raises(ValueError):
        _apply_fields(Risk(), {"likelihood": "high", "likelihood_score": "2"}, _risk_spec())
