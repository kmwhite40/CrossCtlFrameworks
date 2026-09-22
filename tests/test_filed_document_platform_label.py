"""A filed document names the platform, never the code.

Three render sites wrote ``SSPProject.platform`` raw into documents that leave
the building: the OSCAL SSP ``description`` (``api/routes/oscal.py``) and both
docx front-matter tables (``ssp/generator.py``). With ``"none"`` now a real
platform, a raw ``Cloud Platform: none`` in a filed SSP reads as a blank -- the
exact ambiguity the ``none`` platform exists to remove -- and a raw ``m365`` was
never a phrase a reviewer should have to decode.

These sites now go through ``platform_label``. That changed the rendered
output for *every* platform, and the golden tests passed without a fixture
change, which means nothing pinned it: reverting to the raw code would leave
the suite green. These tests exist so it would not.

Asserted on individual table cells and the description string, not on a
flattened blob, so a label appearing *somewhere* cannot satisfy a check meant
for one field.
"""

from __future__ import annotations

import io

import pytest
from docx import Document
from sqlalchemy import delete

from ccf.api.routes.oscal import build_ssp_doc
from ccf.db import session_scope, set_session_tenant
from ccf.models import Organization, SSPProject, System
from ccf.ssp.generator import generate_ssp_docx
from ccf.ssp.platforms import PLATFORMS, platform_label

pytestmark = pytest.mark.usefixtures("fresh_engine")

_PROJECT = {
    "title": "System Security Plan (SSP)",
    "customer_name": "Label Test LLC",
    "system_name": "Label Test Enclave",
    "version": "0.1",
    "document_date": "01/01/2026",
    "prepared_by": "Jane Doe",
}
_ENTRIES = [
    {
        "control_id": "AC.L2-3.1.1",
        "nist_id": "3.1.1",
        "domain": "AC",
        "title": "Authorized Access Control",
        "responsible_role": "Access Control Lead",
        "implementation_status": ["Implemented"],
        "control_origination": ["Organization System Specific"],
        "part_narratives": [{"label": "a", "text": "Access is limited to authorized users."}],
    }
]


def _cells(docx_bytes: bytes) -> list[str]:
    """Every table cell's text, individually -- not flattened."""
    doc = Document(io.BytesIO(docx_bytes))
    return [cell.text for t in doc.tables for row in t.rows for cell in row.cells]


@pytest.mark.parametrize("code", sorted(PLATFORMS))
def test_docx_front_matter_renders_the_label_not_the_code(code: str) -> None:
    """Both front-matter tables carry the label; no cell is the bare code.

    Parametrized over the real platform table so a platform added later is
    covered without editing this test.
    """
    cells = _cells(generate_ssp_docx({**_PROJECT, "platform": code}, _ENTRIES))
    label = platform_label(code)
    assert label in cells, (code, label, cells)
    # The raw code must not stand alone in any cell. For 'none' that cell
    # would read as a blank; for the others it is an internal key.
    assert code not in cells, (code, cells)


def test_docx_none_platform_does_not_read_as_a_missing_value() -> None:
    """The headline case: 'none' must be stated as an answer, not left as a
    token a reader will take for an unfilled field."""
    cells = _cells(generate_ssp_docx({**_PROJECT, "platform": "none"}, _ENTRIES))
    assert "No cloud platform declared" in cells, cells
    assert "none" not in cells, cells
    assert "" not in [c for c in cells if "Cloud Platform" in c], cells


@pytest.mark.asyncio
@pytest.mark.parametrize("code", sorted(PLATFORMS))
async def test_oscal_ssp_description_renders_the_label_not_the_code(code: str) -> None:
    """The OSCAL system-characteristics description names the platform."""
    async with session_scope() as s:
        await set_session_tenant(s, None)
        org = Organization(name=f"OSCAL Label Org {code}")
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"OSCAL Label Sys {code}")
        s.add(sysrow)
        await s.flush()
        proj = SSPProject(
            organization_id=org.id,
            system_id=sysrow.id,
            customer_name="OSCAL Label Co",
            system_name="OSCAL Label Sys",
            platform=code,
        )
        s.add(proj)
        await s.flush()
        org_id = org.id
        try:
            doc = await build_ssp_doc(s, proj)
            desc = doc["system-security-plan"]["system-characteristics"]["description"]
            assert platform_label(code) in desc, (code, desc)
            assert f"({code})" not in desc, (code, desc)
        finally:
            await s.execute(delete(Organization).where(Organization.id == org_id))
