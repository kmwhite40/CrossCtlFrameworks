"""Parse DISA's published CCI List.

Asserted against the real committed file, not an invented fixture: a fixture
I wrote would encode my assumptions about the format rather than DISA's.
"""
from datetime import date

import pytest

from ccf.cci.reader import DEFAULT_CCI_HTML, CciReference, read_cci_html


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


def test_nested_table_does_not_lose_outer_rows(tmp_path) -> None:
    # A <table> nested inside a table cell (e.g. a future DISA revision, or a
    # hand-edited file) must not clobber the outer table's in-progress rows.
    # The inner "junk" table has no CCI: row, so it parses to nothing; the
    # outer entry must still come through intact, definition text on both
    # sides of the nested table included.
    html = """<html><body><b>CCI List</b><br><b>Version 2020-01-01</b><hr>
<table>
<tr>
<td class="header">CCI:</td><td>CCI-900001</td>
<td class="header">Status:</td><td>draft</td>
</tr>
<tr>
<td class="header">Contributor:</td><td>Test</td>
<td class="header">Published Date:</td><td>2020-01-01</td>
</tr>
<tr><td class="header">Definition:</td><td colspan="3">Outer definition text
<table><tr><td>inner junk that must not swallow the outer table</td></tr></table>
tail text</td></tr>
<tr><td class="header">Type:</td><td colspan="3">policy</td></tr>
<tr><td class="header">References:</td><td colspan="3">NIST:
<a href="http://x">NIST SP 800-53 Revision 5 (v5)</a>:  AC-1 a</td></tr>
</table>
</body></html>"""
    path = tmp_path / "nested.html"
    path.write_text(html, encoding="utf-8")

    result = read_cci_html(path)

    item = next(i for i in result.items if i.cci == "CCI-900001")
    assert item.status == "draft"
    assert item.type == "policy"
    assert "Outer definition text" in item.definition
    assert "tail text" in item.definition
    assert item.references == (CciReference(revision="5", raw_index="AC-1 a"),)


def test_empty_anchor_in_reference_row_is_skipped_not_raised(tmp_path) -> None:
    # An <a></a> with no text makes the naive `cell.text.split(anchor_text)`
    # split on an empty separator, which raises. That must not crash the
    # parse of the other entries in the file -- the malformed row is simply
    # skipped, same as a reference row with no index already is.
    html = """<html><body><b>CCI List</b><br><b>Version 2020-01-01</b><hr>
<table>
<tr>
<td class="header">CCI:</td><td>CCI-900002</td>
<td class="header">Status:</td><td>draft</td>
</tr>
<tr>
<td class="header">Contributor:</td><td>Test</td>
<td class="header">Published Date:</td><td>2020-01-01</td>
</tr>
<tr><td class="header">Definition:</td><td colspan="3">A definition.</td></tr>
<tr><td class="header">Type:</td><td colspan="3">policy</td></tr>
<tr><td class="header">References:</td><td colspan="3">NIST:
<a href="http://x"></a>:  AC-1 a</td></tr>
<tr><td class="header"></td><td colspan="3">NIST:
<a href="http://x">NIST SP 800-53 Revision 5 (v5)</a>:  AC-1 a 1 (a)</td></tr>
</table>
<hr>
<table>
<tr>
<td class="header">CCI:</td><td>CCI-900003</td>
<td class="header">Status:</td><td>draft</td>
</tr>
<tr>
<td class="header">Contributor:</td><td>Test</td>
<td class="header">Published Date:</td><td>2020-01-01</td>
</tr>
<tr><td class="header">Definition:</td><td colspan="3">Another definition.</td></tr>
<tr><td class="header">Type:</td><td colspan="3">policy</td></tr>
</table>
</body></html>"""
    path = tmp_path / "empty_anchor.html"
    path.write_text(html, encoding="utf-8")

    result = read_cci_html(path)  # must not raise

    assert {i.cci for i in result.items} == {"CCI-900002", "CCI-900003"}
    item = next(i for i in result.items if i.cci == "CCI-900002")
    assert item.references == (CciReference(revision="5", raw_index="AC-1 a 1 (a)"),)


def test_unrecognised_reference_title_is_kept_verbatim_not_dropped(tmp_path) -> None:
    # An authority whose title isn't in _REVISIONS is still a real reference:
    # storing it as the (truncated) verbatim title is what makes an
    # unexpected publication visible instead of silently vanishing as "".
    html = """<html><body><b>CCI List</b><br><b>Version 2020-01-01</b><hr>
<table>
<tr>
<td class="header">CCI:</td><td>CCI-900004</td>
<td class="header">Status:</td><td>draft</td>
</tr>
<tr>
<td class="header">Contributor:</td><td>Test</td>
<td class="header">Published Date:</td><td>2020-01-01</td>
</tr>
<tr><td class="header">Definition:</td><td colspan="3">A definition.</td></tr>
<tr><td class="header">Type:</td><td colspan="3">policy</td></tr>
<tr><td class="header">References:</td><td colspan="3">Other:
<a href="http://x">Some Future Publication (v9)</a>:  AC-1 a</td></tr>
</table>
</body></html>"""
    path = tmp_path / "unknown_title.html"
    path.write_text(html, encoding="utf-8")

    result = read_cci_html(path)

    item = next(i for i in result.items if i.cci == "CCI-900004")
    assert item.references == (
        CciReference(revision="Some Future Publication (v9)", raw_index="AC-1 a"),
    )


def test_a_malformed_cci_id_is_not_stored_as_an_item(tmp_path) -> None:
    # A "CCI:" cell whose value doesn't look like CCI-###### is not a
    # trustworthy item -- storing it anyway would let a hand-edited or
    # mis-rendered table entry masquerade as real DISA content.
    html = """<html><body><b>CCI List</b><br><b>Version 2020-01-01</b><hr>
<table>
<tr>
<td class="header">CCI:</td><td>CCI-900005</td>
<td class="header">Status:</td><td>draft</td>
</tr>
<tr><td class="header">Definition:</td><td colspan="3">A definition.</td></tr>
<tr><td class="header">Type:</td><td colspan="3">policy</td></tr>
</table>
<hr>
<table>
<tr>
<td class="header">CCI:</td><td>CCI-NOTANUMBER</td>
<td class="header">Status:</td><td>draft</td>
</tr>
<tr><td class="header">Definition:</td><td colspan="3">Malformed cci id.</td></tr>
<tr><td class="header">Type:</td><td colspan="3">policy</td></tr>
</table>
</body></html>"""
    path = tmp_path / "malformed_cci.html"
    path.write_text(html, encoding="utf-8")

    result = read_cci_html(path)

    assert {i.cci for i in result.items} == {"CCI-900005"}
