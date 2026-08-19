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
    FrameworkSpec("NIST_800_172", "NIST SP 800-172", "NIST", "Enhanced CUI"),
    FrameworkSpec("NIST_CSF_1_1", "NIST Cybersecurity Framework 1.1", "NIST", ""),
    FrameworkSpec("NIST_CSF_2_0", "NIST Cybersecurity Framework 2.0", "NIST", ""),
    FrameworkSpec("FEDRAMP", "FedRAMP", "Federal", ""),
    FrameworkSpec("STATERAMP", "StateRAMP", "State", ""),
    FrameworkSpec("CMMC", "CMMC Rev. 2", "DoD", ""),
    FrameworkSpec("FISMA", "FISMA", "Federal", ""),
    FrameworkSpec("CJIS", "FBI CJIS Security Policy", "Federal", ""),
    FrameworkSpec("MARS_E", "CMS MARS-E", "HHS", ""),
    FrameworkSpec("HIPAA", "HIPAA Security Rule", "HHS", ""),
    FrameworkSpec("HITRUST", "HITRUST CSF", "Industry", ""),
    FrameworkSpec("ISO_27001", "ISO/IEC 27001", "ISO", ""),
    FrameworkSpec("SOC2", "AICPA SOC 2", "AICPA", ""),
    FrameworkSpec("CIS_V8", "CIS Controls v8", "CIS", ""),
    FrameworkSpec("CSA", "Cloud Security Alliance CCM", "Industry", ""),
    FrameworkSpec("GDPR", "GDPR", "EU", ""),
    FrameworkSpec("AWS", "AWS", "Cloud", ""),
    FrameworkSpec("AZURE", "Microsoft Azure", "Cloud", ""),
    FrameworkSpec("GCP", "Google Cloud", "Cloud", ""),
    FrameworkSpec("CDM", "CISA CDM", "Federal", ""),
    FrameworkSpec("CUI_OVERLAY", "CUI Overlay", "Federal", ""),
    # DoD / IC frameworks that were previously swept into OTHER. Each is a real,
    # named authority carried as its own column family in the source workbook —
    # not org-specific inheritance, which stays in OTHER by design.
    FrameworkSpec(
        "DOD_SRG_IL", "DoD Cloud Computing SRG Impact Levels", "DoD",
        "IL-2/4/5/6 Moderate and High baselines",
    ),
    FrameworkSpec(
        "DISA_CCI", "DISA Control Correlation Identifiers", "DoD",
        "CCI decomposition of control text",
    ),
    FrameworkSpec(
        "CNSSI_1253", "CNSSI 1253", "IC",
        "Security categorization for National Security Systems (C/I/A)",
    ),
    FrameworkSpec(
        "RMF_TAG", "RMF KS Technical Advisory Group", "DoD",
        "RMF Knowledge Service assessment procedures and BoE",
    ),
    FrameworkSpec("JSIG", "Joint SAP Implementation Guide", "DoD", ""),
    FrameworkSpec("DOD_RAR", "DoD Risk Assessment Report", "DoD", ""),
    FrameworkSpec(
        "NIST_800_53B", "NIST SP 800-53B", "NIST",
        "Control baselines (non-NSS Low/Moderate/High by C/I/A)",
    ),
    FrameworkSpec("ZERO_TRUST", "DoD Zero Trust Overlay", "DoD", ""),
    FrameworkSpec("EMASS", "eMASS", "DoD", "Enterprise Mission Assurance Support Service"),
    FrameworkSpec(
        "DOD_DSPAV", "DoD Specific Assigned Values", "DoD",
        "DoD-assigned organization-defined parameter values",
    ),
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
    ("NIST SP 800-53A", "NIST_800_53A_R5"),
    ("NIST SP 800-53", "NIST_800_53_R5"),
    ("NIST 800-171 Rev 3", "NIST_800_171_R3"),
    ("NIST 800-171 Rev. 3", "NIST_800_171_R3"),
    ("NIST 800-171 Rev. 2", "NIST_800_171_R2"),
    ("NIST 800-171", "NIST_800_171_R2"),
    ("NIST 800-172", "NIST_800_172"),
    ("NIST SP 800-172", "NIST_800_172"),
    ("NIST CSF 2.0", "NIST_CSF_2_0"),
    ("NIST CSF", "NIST_CSF_1_1"),
    ("FedRAMP", "FEDRAMP"),
    ("StateRAMP", "STATERAMP"),
    ("CMMC", "CMMC"),
    ("FISMA", "FISMA"),
    ("CJIS", "CJIS"),
    ("MARS", "MARS_E"),
    ("HIPAA", "HIPAA"),
    ("HITRUST", "HITRUST"),
    ("ISO 27001", "ISO_27001"),
    ("ISO/IEC 27001", "ISO_27001"),
    ("SOC 2", "SOC2"),
    ("SOC TS", "SOC2"),
    ("CIS ", "CIS_V8"),
    ("CIS v", "CIS_V8"),
    ("IG1", "CIS_V8"),
    ("IG2", "CIS_V8"),
    ("IG3", "CIS_V8"),
    ("CSA ", "CSA"),
    ("GDPR", "GDPR"),
    ("AWS ", "AWS"),
    ("Azure ", "AZURE"),
    ("GCP ", "GCP"),
    ("CDM ", "CDM"),
    ("Container from Tech", "CDM"),
    ("CUI Overlay", "CUI_OVERLAY"),
    ("DoD Organization Defined", "NIST_800_171_R3"),
    # --- DoD / IC families -------------------------------------------------
    # NOTE: these are appended, so every rule above still wins first. Within
    # this block the C/I/A-prefixed variants must precede the bare ones,
    # because the source spells them "Integrity CNSSI 1253 High" etc.
    ("Confidentiality NIST SP 800-53B", "NIST_800_53B"),
    ("Integrity NIST SP 800-53B", "NIST_800_53B"),
    ("Availability NIST SP 800-53B", "NIST_800_53B"),
    ("NIST SP 800-53B", "NIST_800_53B"),
    ("Confidentiality CNSSI", "CNSSI_1253"),
    ("Integrity CNSSI", "CNSSI_1253"),
    ("Availability CNSSI", "CNSSI_1253"),
    ("CNSSI", "CNSSI_1253"),
    ("IL-2", "DOD_SRG_IL"),
    ("IL-4", "DOD_SRG_IL"),
    ("IL-5", "DOD_SRG_IL"),
    ("IL-6", "DOD_SRG_IL"),
    ("CCI ", "DISA_CCI"),
    ("CCI Rev", "DISA_CCI"),
    ("Consolidated CCIs", "DISA_CCI"),
    ("SSDF Consolidated CCIs", "DISA_CCI"),
    ("RMF TAG", "RMF_TAG"),
    ("RMFKS", "RMF_TAG"),
    ("Associated with STIG?", "RMF_TAG"),
    ("JSIG", "JSIG"),
    ("DoD RAR", "DOD_RAR"),
    ("DoD Specific Assigned Values", "DOD_DSPAV"),
    ("Zero Trust Overlay", "ZERO_TRUST"),
    ("ZT Overlay", "ZERO_TRUST"),
    ("Appendix C ZT", "ZERO_TRUST"),
    ("Appendix D ZT", "ZERO_TRUST"),
    ("Appendix E ZT", "ZERO_TRUST"),
    ("eMASS", "EMASS"),
    # --- columns that belong to an ALREADY-REGISTERED framework but whose
    # header does not start with the existing prefix. These were bugs, not
    # gaps: the framework existed and the mapping still landed in OTHER.
    ("All MARS", "MARS_E"),
    ("CDM?", "CDM"),
    ("NIST SP 800-171 Rev 3", "NIST_800_171_R3"),
    ("SP 800-171 Rev 3", "NIST_800_171_R3"),
    ("Microsoft NIST 800-172", "NIST_800_172"),
    ("Microsoft Azure", "AZURE"),
    ("Landing Zone Accelerator on AWS", "AWS"),
]


def classify_header(header: str) -> str | None:
    """Return the framework code for a mapping header, or None if it's core."""
    if header in CORE_HEADERS:
        return None
    for prefix, code in _PREFIX_RULES:
        if header.startswith(prefix):
            return code
    return "OTHER"
