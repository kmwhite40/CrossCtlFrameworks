"""Parse DISA's published CCI List.

Asserted against the real committed file, not an invented fixture: a fixture
I wrote would encode my assumptions about the format rather than DISA's.
"""
from datetime import date

import pytest

from ccf.cci.reader import DEFAULT_CCI_HTML, read_cci_html


@pytest.fixture(scope="module")
def cci_list():
    return read_cci_html(DEFAULT_CCI_HTML)


def test_reads_every_cci_with_its_version(cci_list) -> None:
    assert cci_list.version == "2026-07-14"
    assert len(cci_list.items) == 5149
    assert len(cci_list.source_sha256) == 64


def test_first_item_carries_every_field(cci_list) -> None:
    item = next(i for i in cci_list.items if i.cci == "CCI-000002")
    assert item.status == "draft"
    assert item.type == "policy"
    assert item.contributor == "DISA FSO"
    assert item.published_date == date(2009, 9, 14)
    assert item.definition.startswith("Disseminate the organization-level")


def test_references_carry_revision_and_verbatim_index(cci_list) -> None:
    item = next(i for i in cci_list.items if i.cci == "CCI-000002")
    by_rev = {r.revision: r.raw_index for r in item.references}
    assert by_rev["5"] == "AC-1 a 1 (a)"
    assert by_rev["4"] == "AC-1 a 1"
    assert by_rev["3"] == "AC-1 a"
    assert by_rev["800-53A"] == "AC-1.1 (iii)"


def test_reference_totals_match_the_published_list(cci_list) -> None:
    refs = [r for i in cci_list.items for r in i.references]
    assert len(refs) == 10216
    assert sum(1 for r in refs if r.revision == "5") == 3849
    ccis_with_rev5 = {
        i.cci for i in cci_list.items if any(r.revision == "5" for r in i.references)
    }
    assert len(ccis_with_rev5) == 3847


def test_deprecated_status_is_preserved(cci_list) -> None:
    # 91 deprecated CCIs must survive the load: a STIG in the field may still
    # cite one, and silently dropping it would make that finding unroutable.
    assert sum(1 for i in cci_list.items if i.status == "deprecated") == 91
