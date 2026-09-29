"""The production runbook's stated coverage matches the code.

Section 7 of ``docs/runbooks/production-deployment.md`` is what an authorizing
official is told the platform can and cannot assess. It said "9 checks across 7
controls" for several releases after the real figure had more than doubled --
prose asserting a number that nothing kept true, which is the defect class this
platform exists to catch in *other people's* documents.

A number in a compliance deliverable needs the same discipline as a number in
the product: something has to fail when it stops being true.
"""

from __future__ import annotations

import re
from pathlib import Path

from ccf.analytics.framework_posture import fold_to_control
from ccf.connectors import connector_keys
from ccf.posture.checks import checks_for

RUNBOOK = Path(__file__).resolve().parents[1] / "docs" / "runbooks" / "production-deployment.md"


def _runbook() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def test_the_stated_check_total_is_the_real_one() -> None:
    total = sum(len(checks_for(k)) for k in connector_keys())
    text = _runbook()
    match = re.search(r"Posture check coverage is (\d+) checks", text)
    assert match, "section 7 no longer states a check total"
    stated = int(match.group(1))
    assert stated == total, (
        f"the runbook says {stated} posture checks; the registry has {total}. "
        "Update docs/runbooks/production-deployment.md section 7."
    )


def test_the_per_provider_table_matches_the_registry() -> None:
    """Every provider is listed, with its real check count.

    Including the providers that register none: `azure_arm` and `gcp` are
    connectable and capture configuration, so a reader who does not see them
    named reasonably assumes scanning them does something.
    """
    text = _runbook()
    for key in connector_keys():
        assert f"`{key}`" in text, (
            f"provider {key!r} is not named in the runbook's coverage table"
        )
        count = len(checks_for(key))
        if count:
            assert re.search(rf"`{re.escape(key)}`[^|]*\|\s*{count}\s*\|", text), (
                f"the runbook does not state {count} checks for {key!r}"
            )


def test_every_control_the_table_claims_is_actually_evidenced() -> None:
    """The stronger direction: the document must not name a control no check covers.

    Overstating is the failure that matters here -- an AO reading "AC-17" in this
    table concludes remote access is machine-tested. The old text named CM-8 and
    IA-5 alongside controls that were `msgraph`'s, which no `msgraph` check
    evidences.
    """
    text = _runbook()
    section = text.split("## 7. Known limits")[1]
    table = "\n".join(
        line for line in section.splitlines() if line.strip().startswith("|")
    )
    # Both sides folded to one spelling. Comparing raw regex groups against
    # hand-split ids is how a guard ends up asserting two shapes that can never
    # be equal -- which the first version of this test did, failing on every
    # control including the ones plainly covered.
    claimed = {
        folded
        for raw in re.findall(r"\b[A-Z]{2,3}-\d+(?:\(\d+\))?", table)
        if (folded := fold_to_control(raw))
    }
    evidenced = {
        folded
        for key in connector_keys()
        for check in checks_for(key)
        for cid in check.control_ids
        if (folded := fold_to_control(cid))
    }
    unevidenced = claimed - evidenced
    assert not unevidenced, (
        "the runbook names controls no registered check evidences: "
        f"{sorted(unevidenced)}"
    )
    assert claimed, "no control ids were parsed out of the table at all"
