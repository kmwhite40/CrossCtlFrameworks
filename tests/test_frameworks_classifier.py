"""Unit tests for the header → framework classifier."""
from __future__ import annotations

import pytest

from ccf.etl.frameworks import classify_header


@pytest.mark.parametrize(
    "header,expected",
    [
        ("ISO 27001 Mapping", "ISO_27001"),
        ("SOC 2 ",            "SOC2"),
        ("HIPAA Security Rule Reference Document Element", "HIPAA"),
        ("HITRUST Control Reference", "HITRUST"),
        ("FedRAMP Moderate",  "FEDRAMP"),
        ("StateRAMP Ready",   "STATERAMP"),
        ("CMMC Rev. 2 L1",    "CMMC"),
        ("NIST 800-171 Rev 3","NIST_800_171_R3"),
        ("NIST CSF 2.0 Function", "NIST_CSF_2_0"),
        ("CIS v.8 Control",   "CIS_V8"),
        ("AWS Evidence",      "AWS"),
        ("Azure Gov Policy",  "AZURE"),
        ("GDPR",              "GDPR"),
        ("CSA 4.3",           "CSA"),
    ],
)
def test_classifier_prefixes(header: str, expected: str) -> None:
    assert classify_header(header) == expected


def test_classifier_core_headers_return_none() -> None:
    assert classify_header("identifier") is None
    assert classify_header("control-name") is None
    assert classify_header("FISMA Low") is None


def test_classifier_unknown_goes_to_other() -> None:
    assert classify_header("Some Random Column") == "OTHER"
