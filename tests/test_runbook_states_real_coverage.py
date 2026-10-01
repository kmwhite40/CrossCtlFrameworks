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


def test_the_table_names_every_control_a_check_evidences() -> None:
    """The other direction, which was missing.

    ``test_every_control_the_table_claims_is_actually_evidenced`` catches
    overstating, and overstating is the worse failure -- an AO reading "AC-17"
    concludes remote access is machine-tested. But only checking that direction
    let the table *understate*: the `msgraph` row omitted ``AC-2(12)`` and
    ``IA-2(11)`` for a release while both were evidenced, and the "of 288"
    figure beside it was computed from the real set, so the table and the
    sentence above it disagreed and neither was flagged.

    Understating is still a wrong number in a document an authorizing official
    reads, and it is the direction that makes the product look worse than it is
    -- which is how a table stops being maintained.
    """
    text = _runbook()
    section = text.split("## 7. Known limits")[1]
    table = "\n".join(line for line in section.splitlines() if line.strip().startswith("|"))
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
    unlisted = evidenced - claimed
    assert not unlisted, (
        "these controls are evidenced by a registered check but are missing from "
        f"the runbook's coverage table: {sorted(unlisted)}"
    )


def test_the_runbook_says_how_the_baseline_figure_was_measured() -> None:
    """"37 of the 288" cannot be guarded here, so it must be reproducible.

    The other numbers in section 7 are asserted against the registry, which the
    test process can always read. This one is an intersection with the Moderate
    baseline, and baseline membership lives in ``controls.fisma_mod`` -- loaded
    by a catalog ingest, not by a migration, so the test database does not have
    it and a guard over it would skip in CI forever. A permanently skipped guard
    is worse than none: it appears in the run as a test that exists.

    Measuring it from the shipped OSCAL Moderate profile instead was tried and
    rejected. That file spells enhancements ``ac-2.3`` where ``fisma_mod`` and
    every check spell them ``AC-2(3)``, so it needs its own folding rule -- a
    second definition of "is this control in the baseline", free to drift from
    the one the product uses. Two answers to one question is the defect this
    codebase keeps finding; adding one to guard a number in a document would be
    a poor trade.

    So the number stays measured by hand, and what is guarded is that the
    runbook tells the next person the exact command to re-measure it with. An
    unguarded number with a reproduction recipe is honest; an unguarded number
    presented like the guarded ones is not.
    """
    text = _runbook()
    assert re.search(r"checks touching (\d+) of the (\d+) controls", text), (
        "section 7 no longer states a baseline intersection"
    )
    assert "baseline_controls" in text, (
        "section 7 states a baseline intersection without naming how to "
        "re-measure it; see the note in this test for why it cannot be asserted"
    )


def test_the_stated_practice_coverage_is_the_real_one() -> None:
    """"18 of the 110 practices" and "28 of 32 checks" must stay true.

    Same discipline as the check total above, for the number that says what a
    **CMMC document can display**. It is the one an authorizing official reads
    when asking what the SSP will actually show, and it moves every time a check
    is mapped or added.
    """
    from ccf.posture.practices import CHECK_PRACTICES, UNMAPPED  # noqa: PLC0415
    from ccf.scoring.parser import load_seed  # noqa: PLC0415

    text = _runbook()
    practices = {p for ps in CHECK_PRACTICES.values() for p in ps}
    total_practices = {r["control_id"] for r in load_seed() if r.get("control_id")}

    match = re.search(r"evidence for (\d+) of the (\d+) practices", text)
    assert match, "the runbook must state practice coverage as 'N of the M practices'"
    assert (int(match.group(1)), int(match.group(2))) == (
        len(practices),
        len(total_practices),
    ), (
        f"runbook says {match.group(1)} of {match.group(2)}; the mapping covers "
        f"{len(practices)} of {len(total_practices)}"
    )

    split = re.search(r"from the (\d+) of (\d+)\s*\n?\s*checks that declare one", text)
    assert split, "the runbook must state how many checks declare a practice"
    registered = sum(len(checks_for(k)) for k in connector_keys())
    assert (int(split.group(1)), int(split.group(2))) == (
        len(CHECK_PRACTICES),
        registered,
    )
    # And that the unmapped count is stated in words, matching the table. Spelt
    # out rather than derived, so changing one without the other fails here --
    # which is the point: the runbook's prose is the thing a reader trusts.
    assert "Five checks are deliberately unmapped" in text
    assert len(UNMAPPED) == 5, (
        f"{len(UNMAPPED)} checks are unmapped; the runbook still says five"
    )


def test_every_practice_the_runbook_lists_is_actually_mapped() -> None:
    """The per-domain list must not name a practice the mapping does not cover.

    Both directions, because a list that is merely *a subset* of the truth is
    the failure mode the check-total guard was written for: it stays plausible
    while drifting.
    """
    from ccf.posture.practices import CHECK_PRACTICES  # noqa: PLC0415

    text = _runbook()
    section = text.split("Practices covered, by domain:")[1].split("\n- ")[0]
    listed: set[str] = set()
    for domain_part in re.finditer(r"\*\*([A-Z]{2})\*\*\s*([0-9.,\s]+)", section):
        domain = domain_part.group(1)
        for raw in domain_part.group(2).split(","):
            # The last item in each domain run carries the sentence's full stop.
            # No requirement number ends in a dot, so stripping it is safe.
            number = raw.strip().rstrip("·").strip().rstrip(".")
            if number:
                listed.add(f"{domain}.L2-{number}")
    mapped = {p for ps in CHECK_PRACTICES.values() for p in ps}
    assert listed, "the runbook's per-domain practice list did not parse"
    assert listed == mapped, (
        f"runbook lists but mapping does not cover: {sorted(listed - mapped)}; "
        f"mapping covers but runbook omits: {sorted(mapped - listed)}"
    )
