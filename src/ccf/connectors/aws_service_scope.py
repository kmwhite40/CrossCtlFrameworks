"""Which AWS services AWS itself lists as authorized at each DoD impact level.

The data is AWS's own table, "AWS Services in Scope by Compliance Program:
DoD CC SRG", shipped as ``data/aws_dod_srg_scope.json`` with the page's URL,
its stated "Last updated" date, the date it was read and the page's SHA-256.
Refresh it with ``ccf aws-scope-refresh`` (or :func:`parse_scope_table` on a
saved copy of the page) -- never by hand.

m365-docs-hub hand-maintained a list instead. Checked against this table on
2026-10-20, six of the eleven services it called "prohibited at IL5" were
authorized at IL5, five it called authorized were not, and it named about 50
of the 146 authorized services -- so legitimate services would have been
reported as violations. A list of this kind is only as good as its source, so
the source is the table, and the date is part of every verdict.

Reading the table honestly:

* ``authorized`` is AWS's checkmark. Any other text in a cell ("Independent
  Assessment", "3PAO Assessment") is not an authorization.
* A service **with a row and an empty cell** at the system's level is not in
  AWS's scope at that level -- the only case a check may call a failure.
* A service **with no row** is not in this table at all -- Elastic Load
  Balancing and EC2 Auto Scaling have none, though both are in everyday use in
  GovCloud. That is a question for the authorizing official, never a finding.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime
from functools import lru_cache
from html.parser import HTMLParser
from importlib import resources
from typing import Any

#: The system's declared impact level -> the table column that answers it.
LEVEL_COLUMN = {
    "IL2": ("il2_east_west", "il2_govcloud"),
    "IL4": ("il4_govcloud",),
    "IL5": ("il5_govcloud",),
    "IL6": ("il6_secret",),
}
COLUMNS = ("il2_east_west", "il2_govcloud", "il4_govcloud", "il5_govcloud", "il6_secret")

#: AWS Config resource-type namespace (``AWS::<Namespace>::...``, lowercased)
#: -> the SDK name the table lists, where the two differ. A namespace that is
#: neither here nor an SDK name in the table is "not listed", never assumed.
NAMESPACE_ALIASES = {
    "config": "configservice",
    "apigatewayv2": "apigateway",
    "acmpca": "acm-pca",
    "networkfirewall": "network-firewall",
    "opensearchservice": "opensearch",
    "elasticsearch": "opensearch",
    "codedeploy": "deploy",
    "shieldregional": "shield",
    "kinesisfirehose": "firehose",
    "msk": "kafka",
    "cognito": "cognito-idp",
    "inspectorv2": "inspector2",
    "wafregional": "wafv2",
    "waf": "wafv2",
}


@lru_cache(maxsize=1)
def load() -> dict[str, Any]:
    raw = resources.files("ccf.connectors").joinpath("data/aws_dod_srg_scope.json").read_text()
    return dict(json.loads(raw))


def provenance() -> str:
    doc = load()
    return (
        f"AWS's DoD CC SRG services-in-scope page, last updated {doc['source_last_updated']}"
        f" (read {doc['retrieved_on']})"
    )


def row_for_namespace(namespace: str) -> dict[str, Any] | None:
    """The table row for a Config namespace, or None when the table has none."""
    sdk = NAMESPACE_ALIASES.get(namespace.lower(), namespace.lower())
    for row in load()["services"]:
        if sdk in row["sdk_names"]:
            return dict(row)
    return None


def status_at(row: dict[str, Any], level: str) -> str:
    """``authorized``, ``not_in_scope`` (a blank cell) or ``other`` (AWS's text)."""
    values = [row.get(c) for c in LEVEL_COLUMN[level]]
    if any(v == "authorized" for v in values):
        return "authorized"
    if all(v is None for v in values):
        return "not_in_scope"
    return "other"


class _Tables(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self._t: list[list[str]] | None = None
        self._r: list[str] | None = None
        self._c: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag == "table":
            self._t = []
        elif tag == "tr" and self._t is not None:
            self._r = []
        elif tag in ("td", "th") and self._r is not None:
            self._c = []

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and self._c is not None and self._r is not None:
            self._r.append(" ".join("".join(self._c).split()))
            self._c = None
        elif tag == "tr" and self._r is not None and self._t is not None:
            self._t.append(self._r)
            self._r = None
        elif tag == "table" and self._t is not None:
            self.tables.append(self._t)
            self._t = None

    def handle_data(self, data: str) -> None:
        if self._c is not None:
            self._c.append(data)


def parse_scope_table(page: str) -> list[dict[str, Any]]:
    """The DoD CC SRG table from AWS's page, as rows of this module's shape.

    The page embeds the table as escaped HTML inside a script; it is unescaped
    first. Raises ``ValueError`` when no table with an "IL5 (GovCloud)" column
    is found, rather than returning an empty scope that would read as "nothing
    is authorized".
    """
    html = page.replace('\\"', '"').replace("\\n", "\n").replace("\\/", "/")
    parser = _Tables()
    parser.feed(html)
    table = next(
        (t for t in parser.tables if t and any("IL5 (GovCloud)" in c for c in t[0])), None
    )
    if table is None:
        raise ValueError("the page has no DoD CC SRG table with an IL5 (GovCloud) column")
    rows: list[dict[str, Any]] = []
    for cells in table[1:]:
        if len(cells) < 2 + len(COLUMNS):
            continue
        values = {
            col: ("authorized" if v in ("✓", "✔") else (v or None))
            for col, v in zip(COLUMNS, cells[2:2 + len(COLUMNS)], strict=True)
        }
        rows.append({
            "service": cells[0],
            "sdk_names": [s for s in cells[1].replace(",", " ").split() if s],
            **values,
        })
    if not rows:
        raise ValueError("the DoD CC SRG table on the page has no service rows")
    return rows


SOURCE_URL = "https://aws.amazon.com/compliance/services-in-scope/DoD_CC_SRG/"
_LAST_UPDATED = re.compile(r"Last updated:\s*([A-Z][a-z]+ \d{1,2}, \d{4})")


def build_document(page: str, *, retrieved_on: date) -> dict[str, Any]:
    """The data file's content from a copy of AWS's page.

    The page's own "Last updated" date is required: a scope table with no
    date cannot tell a reader how current its verdicts are.
    """
    m = _LAST_UPDATED.search(page)
    if m is None:
        raise ValueError("the page states no 'Last updated' date")
    updated = datetime.strptime(m.group(1), "%B %d, %Y").date()
    current = load()
    return {
        "source": SOURCE_URL,
        "source_title": current.get("source_title"),
        "source_last_updated": updated.isoformat(),
        "retrieved_on": retrieved_on.isoformat(),
        "source_sha256": hashlib.sha256(page.encode("utf-8")).hexdigest(),
        "columns": current.get("columns"),
        "note": current.get("note"),
        "services": parse_scope_table(page),
    }


def il5_changes(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Services whose IL5 (GovCloud) cell changed, for the refresh to report."""
    before = {r["service"]: r.get("il5_govcloud") for r in old.get("services", [])}
    after = {r["service"]: r.get("il5_govcloud") for r in new.get("services", [])}
    out = []
    for name in sorted(set(before) | set(after)):
        if before.get(name) != after.get(name):
            out.append(f"{name}: {before.get(name)!r} -> {after.get(name)!r}")
    return out
