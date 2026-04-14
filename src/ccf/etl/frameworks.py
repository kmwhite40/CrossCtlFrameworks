"""Classify workbook header columns into framework codes.

The assessment tab mixes control-identity columns with ~500+ framework-mapping
columns. This module owns the heuristic that maps a raw header to one of our
canonical framework codes, so we can build a normalized framework_mappings
table instead of only stashing everything in JSONB.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FrameworkSpec:
    code: str
    name: str
    family: str
    description: str


FRAMEWORKS: list[FrameworkSpec] = [
    FrameworkSpec("NIST_800_53_R5", "NIST SP 800-53 Rev. 5", "NIST", "Federal control catalog"),
    FrameworkSpec("NIST_800_53A_R5", "NIST SP 800-53A Rev. 5", "NIST", "Assessment procedures"),
    FrameworkSpec("NIST_800_171_R2", "NIST SP 800-171 Rev. 2", "NIST", "CUI protection"),
    FrameworkSpec("NIST_800_171_R3", "NIST SP 800-171 Rev. 3", "NIST", "CUI protection"),
    FrameworkSpec("NIST_800_172",    "NIST SP 800-172",        "NIST", "Enhanced CUI"),
    FrameworkSpec("NIST_CSF_1_1",    "NIST Cybersecurity Framework 1.1", "NIST", ""),
    FrameworkSpec("NIST_CSF_2_0",    "NIST Cybersecurity Framework 2.0", "NIST", ""),
    FrameworkSpec("FEDRAMP",         "FedRAMP",                "Federal", ""),
    FrameworkSpec("STATERAMP",       "StateRAMP",              "State",   ""),
    FrameworkSpec("CMMC",            "CMMC Rev. 2",            "DoD",     ""),
    FrameworkSpec("FISMA",           "FISMA",                  "Federal", ""),
    FrameworkSpec("CJIS",            "FBI CJIS Security Policy", "Federal", ""),
    FrameworkSpec("MARS_E",          "CMS MARS-E",             "HHS",     ""),
    FrameworkSpec("HIPAA",           "HIPAA Security Rule",    "HHS",     ""),
    FrameworkSpec("HITRUST",         "HITRUST CSF",            "Industry", ""),
    FrameworkSpec("ISO_27001",       "ISO/IEC 27001",          "ISO",     ""),
    FrameworkSpec("SOC2",            "AICPA SOC 2",            "AICPA",   ""),
    FrameworkSpec("CIS_V8",          "CIS Controls v8",        "CIS",     ""),
    FrameworkSpec("CSA",             "Cloud Security Alliance CCM", "Industry", ""),
    FrameworkSpec("GDPR",            "GDPR",                   "EU",      ""),
    FrameworkSpec("AWS",             "AWS",                    "Cloud",   ""),
    FrameworkSpec("AZURE",           "Microsoft Azure",        "Cloud",   ""),
    FrameworkSpec("GCP",             "Google Cloud",           "Cloud",   ""),
    FrameworkSpec("CDM",             "CISA CDM",               "Federal", ""),
    FrameworkSpec("CUI_OVERLAY",     "CUI Overlay",            "Federal", ""),
]

# Headers treated as control-identity / non-framework-mapping.
CORE_HEADERS: set[str] = {
    "family",
    "Family Category",
    "Implemented By",
    "Rev 5 Assurance Control?",
    "NIST SP 800-53R5  Control",
    "identifier",
    "AP Acronym (from IGAP Control Export on RMF KS)",
    "Sequence Control",
    "OPD?",
    "sort-as",
    "control-name",
    "Security Control Description",
    "Security Control Discussion",
    "NIST SP 800-53 Rev. 5 related controls",
    "Owner",
    "Overall Control Type",
    "assessment-objective",
    "EXAMINE",
    "INTERVIEW",
    "TEST",
    "FISMA Low",
    "FISMA Mod",
    "FISMA High",
}


# Ordered prefix rules — first hit wins.
_PREFIX_RULES: list[tuple[str, str]] = [
    ("NIST SP 800-53A",  "NIST_800_53A_R5"),
    ("NIST SP 800-53",   "NIST_800_53_R5"),
    ("NIST 800-171 Rev 3", "NIST_800_171_R3"),
    ("NIST 800-171 Rev. 3", "NIST_800_171_R3"),
    ("NIST 800-171 Rev. 2", "NIST_800_171_R2"),
    ("NIST 800-171",     "NIST_800_171_R2"),
    ("NIST 800-172",     "NIST_800_172"),
    ("NIST SP 800-172",  "NIST_800_172"),
    ("NIST CSF 2.0",     "NIST_CSF_2_0"),
    ("NIST CSF",         "NIST_CSF_1_1"),
    ("FedRAMP",          "FEDRAMP"),
    ("StateRAMP",        "STATERAMP"),
    ("CMMC",             "CMMC"),
    ("FISMA",            "FISMA"),
    ("CJIS",             "CJIS"),
    ("MARS",             "MARS_E"),
    ("HIPAA",            "HIPAA"),
    ("HITRUST",          "HITRUST"),
    ("ISO 27001",        "ISO_27001"),
    ("ISO/IEC 27001",    "ISO_27001"),
    ("SOC 2",            "SOC2"),
    ("SOC TS",           "SOC2"),
    ("CIS ",             "CIS_V8"),
    ("CIS v",            "CIS_V8"),
    ("IG1",              "CIS_V8"),
    ("IG2",              "CIS_V8"),
    ("IG3",              "CIS_V8"),
    ("CSA ",             "CSA"),
    ("GDPR",             "GDPR"),
    ("AWS ",             "AWS"),
    ("Azure ",           "AZURE"),
    ("GCP ",             "GCP"),
    ("CDM ",             "CDM"),
    ("Container from Tech", "CDM"),
    ("CUI Overlay",      "CUI_OVERLAY"),
    ("DoD Organization Defined", "NIST_800_171_R3"),
]


def classify_header(header: str) -> str | None:
    """Return the framework code for a mapping header, or None if it's core."""
    if header in CORE_HEADERS:
        return None
    for prefix, code in _PREFIX_RULES:
        if header.startswith(prefix):
            return code
    return "OTHER"
