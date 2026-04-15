"""Shared pytest fixtures."""

from __future__ import annotations

import os
from pathlib import Path

import openpyxl
import pytest

# Run against a real Postgres — CI service container; locally, docker compose.
os.environ.setdefault(
    "CCF_DATABASE_URL",
    "postgresql+asyncpg://ccf:ccf@localhost:5432/ccf_test",
)
os.environ.setdefault(
    "CCF_DATABASE_URL_SYNC",
    "postgresql+psycopg://ccf:ccf@localhost:5432/ccf_test",
)


@pytest.fixture(scope="session")
def mini_workbook(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A 10-row fixture workbook with the assessment sheet and one generic tab."""
    path = tmp_path_factory.mktemp("wb") / "mini.xlsx"
    wb = openpyxl.Workbook()
    a = wb.active
    a.title = "SP.800-53Ar5_assessment"
    headers = [
        "family",
        "identifier",
        "Sequence Control",
        "sort-as",
        "control-name",
        "Security Control Description",
        "Security Control Discussion",
        "NIST SP 800-53 Rev. 5 related controls",
        "assessment-objective",
        "EXAMINE",
        "INTERVIEW",
        "TEST",
        "FISMA Low",
        "FISMA Mod",
        "FISMA High",
        "ISO 27001 Mapping",
        "CMMC Rev. 2L2",
        "FedRAMP Moderate",
    ]
    a.append(headers)
    rows = [
        [
            "(AC) ACCESS CONTROL",
            "AC-01",
            "AC-01",
            "AC-01-00-00",
            "Policy and Procedures",
            "Develop, document, and disseminate...",
            "Discussion text",
            "AC-02",
            "Determine if:",
            "policy docs",
            "personnel",
            "",
            "X",
            "X",
            "X",
            "A.5.15",
            "AC.L2-3.1.1",
            "AC-1",
        ],
        [
            "(AC) ACCESS CONTROL",
            "AC-02",
            "AC-02",
            "AC-02-00-00",
            "Account Management",
            "Identify and select account types...",
            "Discussion text",
            "AC-03",
            "Determine if:",
            "config",
            "admins",
            "test",
            "",
            "X",
            "X",
            "A.5.16",
            "AC.L2-3.1.2",
            "AC-2",
        ],
        [
            "(AU) AUDIT AND ACCOUNTABILITY",
            "AU-01",
            "AU-01",
            "AU-01-00-00",
            "Policy and Procedures",
            "Develop audit policy...",
            "Discussion text",
            "",
            "Determine if:",
            "policy docs",
            "personnel",
            "",
            "X",
            "X",
            "X",
            "A.5.28",
            "AU.L2-3.3.1",
            "AU-1",
        ],
    ]
    for r in rows:
        a.append(r)

    b = wb.create_sheet("Data Dictionary")
    b.append(["Term", "Definition"])
    b.append(["Identifier", "The unique ID of a control"])

    wb.save(path)
    return path
