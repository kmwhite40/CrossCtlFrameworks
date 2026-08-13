"""PDF parser — page fidelity, block ordering, and the scanned-page gap."""

from __future__ import annotations

import logging

import fitz

from ccf.prep.parsers import dispatch
from ccf.prep.parsers.pdf import parse_pdf


def _pdf_bytes() -> bytes:
    doc = fitz.open()
    page1 = doc.new_page()
    page1.insert_text((72, 72), "Access control policy")
    page1.insert_text((72, 120), "Accounts are reviewed quarterly.")
    page2 = doc.new_page()
    page2.insert_text((72, 72), "Audit logs are retained for one year.")
    data: bytes = doc.tobytes()
    doc.close()
    return data


def test_lines_carry_their_true_page_number() -> None:
    doc = parse_pdf(_pdf_bytes(), "policy.pdf")
    line = next(x for x in doc.iter_lines() if "Audit logs" in x.content)
    assert line.page_number == 2


def test_page_count_matches_the_source() -> None:
    doc = parse_pdf(_pdf_bytes(), "policy.pdf")
    assert len(doc.pages) == 2


def test_blocks_are_emitted_in_reading_order_within_a_page() -> None:
    doc = parse_pdf(_pdf_bytes(), "policy.pdf")
    page_one = [x.content for x in doc.iter_lines() if x.page_number == 1]
    assert page_one.index("Access control policy") < page_one.index(
        "Accounts are reviewed quarterly."
    )


def test_page_with_no_extractable_text_is_flagged_not_failed() -> None:
    doc = fitz.open()
    doc.new_page()
    data = doc.tobytes()
    doc.close()
    parsed = parse_pdf(data, "scan.pdf")
    assert parsed.pages[0].metadata["text_extractable"] is False
    assert parsed.error is None


def test_corrupt_pdf_returns_an_error_document_rather_than_raising() -> None:
    parsed = parse_pdf(b"not a pdf at all", "broken.pdf")
    assert not parsed.success
    assert parsed.error is not None


def test_dispatch_routes_pdf() -> None:
    parsed = dispatch(_pdf_bytes(), "policy.pdf", "application/pdf")
    assert parsed.parser_name == "pdf"


def test_corrupt_pdf_failure_path_survives_an_enabled_logger() -> None:
    """Regression for the reserved-LogRecord-attribute defect.

    tests/conftest.py runs Alembic migrations, and migrations/env.py calls
    logging.config.fileConfig(..., disable_existing_loggers=True), which disables
    this module's stdlib logger for the whole pytest session. A logger.warning()
    call on a *disabled* logger short-circuits before building a LogRecord, so a
    bug in the log call itself (e.g. passing `extra={"filename": ...}`, which
    collides with LogRecord's own reserved `filename` attribute and raises
    KeyError from stdlib logging) would never fire and this suite would pass
    while the same call raises outside pytest. Force the logger enabled so this
    test genuinely exercises the log call instead of being masked by that side
    effect.
    """
    logger = logging.getLogger("ccf.prep.parsers.pdf")
    original = logger.disabled
    logger.disabled = False
    try:
        parsed = parse_pdf(b"not a pdf at all", "broken.pdf")
    finally:
        logger.disabled = original
    assert not parsed.success
    assert parsed.error is not None
