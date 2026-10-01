"""The M365 template gets asked a question it can answer.

Found by reading a live scheduler cycle: `posture_checks_expected=164,
posture_checks_run=0, posture_manual_review=192`. Org 2's msgraph connector was
`ready`, all fourteen of its checks worked, and `scan_all_providers` filtered
every one of them out as `manual_scope_review`.

The cause was not the template declining to guess. `responsibility_for("m365",
domain)` reads **only** `coverage_status`:

    if platform == "m365":
        return _M365_COVERAGE_TO_RESPONSIBILITY.get(coverage_status or "", "unknown")

and no production caller passed one. `connectors/readiness.py` calls
`responsibility_entry_for(platform, domain)` with no coverage status at all, so
the answer was "unknown" unconditionally -- for every domain, for every tenant,
forever. `responsibility_for("m365", "ZZZZ")` returned exactly what
`responsibility_for("m365", "IA")` returned. The parameter was dead in
production and alive only in `test_shared_responsibility_templates.py`, which
supplied a `coverage_status` by hand and so proved the function worked while the
system it serves could not use it.

The descriptor then reported `{"scope": "domain", "domain": "IA",
"responsibility": "unknown", "source": "m365-coverage-status"}` -- naming a
domain it never consulted and a source it never read. A value that validates and
is wrong.

The fix gives M365 a domain-level fallback for callers that hold a control's
domain but not its CMMC practice (a posture check carries NIST 800-53 ids, and
the 800-53 -> 800-171 crosswalk cannot close that gap: its `value` is prose, and
only 4 of the 14 M365 check families resolve through it). Per-practice coverage
still wins wherever it is known.

The table is a *summary*, so the tests below hold it to the data it summarises
rather than to my reading of it: `test_the_domain_table_matches_the_placemat`
recomputes every entry from `ccf.scoring_controls` with its own arithmetic, and
fails if the two ever drift apart.
"""

from __future__ import annotations

from collections import Counter

from ccf.posture.checks import checks_for
from ccf.scoring import seed as scoring_seed
from ccf.scoring.parser import load_seed
from ccf.ssp import constants
from ccf.ssp.responsibility import (
    TEMPLATE_VERSION,
    control_domain,
    responsibility_entry_for,
    responsibility_for,
    scan_applicability,
    template_entries,
)

# The placemat's coverage vocabulary, mapped the way the resolver maps it. Spelled
# out here rather than imported so a change to the production mapping has to be
# made twice, on purpose, and cannot quietly redefine what this file checks.
_COVERAGE = {
    "Shared Coverage": "shared",
    "Customer Responsibility": "customer",
    "Microsoft Coverage": "inherited",
    "Not Applicable": "not_applicable",
}


def _domains_the_m365_checks_touch() -> set[str]:
    """Domains the msgraph posture checks actually reach the template with."""
    return {
        d
        for check in checks_for("msgraph")
        if (d := control_domain(check.control_ids[0] if check.control_ids else None))
    }


def test_the_defect_every_m365_check_resolved_to_manual_scope_review() -> None:
    """The regression itself: a ready connector that scans none of its checks."""
    domains = _domains_the_m365_checks_touch()
    assert domains, "msgraph must register checks carrying control ids"
    unscannable = {
        d for d in domains if scan_applicability(responsibility_for("m365", d)) != "scan"
    }
    assert unscannable == set(), (
        f"these M365 domains still cannot be scanned: {sorted(unscannable)}; "
        "a ready connector whose checks all resolve to manual_scope_review "
        "evidences nothing for the live-audit path"
    )


def test_every_msgraph_check_is_in_api_scope() -> None:
    """End to end over the real check registry, not a sampled domain."""
    checks = checks_for("msgraph")
    # Not a literal. This said `== 14` and broke the moment three checks were
    # added -- a hardcoded count beside the registry measures when the suite last
    # changed, not whether the registry is populated.
    assert checks, "msgraph must register checks"
    out_of_scope = []
    for check in checks:
        domain = control_domain(check.control_ids[0] if check.control_ids else None)
        entry = responsibility_entry_for("m365", domain)
        if scan_applicability(entry.responsibility) != "scan":
            out_of_scope.append((check.key, domain, entry.responsibility))
    assert out_of_scope == []


def test_domain_is_consulted_at_all() -> None:
    """The bug in one line: the answer used to be identical for every domain."""
    assert responsibility_for("m365", "PE") != responsibility_for("m365", "AC")
    assert responsibility_for("m365", "PE") == "inherited"
    assert responsibility_for("m365", "AC") == "shared"
    # An unmodelled domain is still unknown -- the fallback is a table, not a
    # blanket "yes".
    assert responsibility_for("m365", "ZZZZ") == "unknown"
    assert scan_applicability(responsibility_for("m365", "ZZZZ")) == "manual_scope_review"


def test_a_known_coverage_status_still_wins_over_the_domain_summary() -> None:
    """Per-practice data is more precise; the fallback must never override it."""
    # AC's domain plurality is "shared", but a Customer Responsibility practice
    # inside AC is customer-owned, and an AC practice Microsoft covers is not.
    assert responsibility_for("m365", "AC") == "shared"
    assert (
        responsibility_for("m365", "AC", coverage_status="Customer Responsibility")
        == "customer"
    )
    assert (
        responsibility_for("m365", "AC", coverage_status="Microsoft Coverage")
        == "inherited"
    )
    # PE's plurality is "inherited", but its one Shared Coverage practice is not.
    assert responsibility_for("m365", "PE") == "inherited"
    assert (
        responsibility_for("m365", "PE", coverage_status="Shared Coverage") == "shared"
    )


def test_an_unrecognised_coverage_status_stays_unknown() -> None:
    """A placemat change must surface, not be absorbed by the domain summary."""
    assert responsibility_for("m365", "AC", coverage_status="Partial Coverage") == "unknown"


def test_the_entry_names_the_question_it_answered() -> None:
    """Source and scope used to claim a coverage status that was never read."""
    per_practice = responsibility_entry_for("m365", "AC", coverage_status="Shared Coverage")
    assert per_practice.source == "m365-coverage-status"
    assert per_practice.scope == "control"

    per_domain = responsibility_entry_for("m365", "AC")
    assert per_domain.source == "m365-placemat-domain"
    assert per_domain.scope == "domain"

    assert per_practice.source != per_domain.source, (
        "a reader must be able to tell a per-practice answer from a domain summary"
    )


def test_other_platforms_are_unchanged() -> None:
    """The fallback is M365's; nothing else gained or lost an answer."""
    assert responsibility_for("aws_govcloud", "IA") == "unknown"
    assert responsibility_for("aws_govcloud", "PE") == "inherited"
    assert responsibility_for("none", "AC") == "customer"
    assert responsibility_entry_for("azure", "PE").source == "concord-default"


def test_ssp_origination_still_uses_per_practice_coverage_only() -> None:
    """The SSP path must not start reading the domain summary.

    `platform_origination` short-circuits M365 to its per-practice coverage
    status. If that ever fell through to the domain table, an M365 SSP would
    originate controls from a plurality rather than from the practice's own
    coverage -- the domain summary leaking into a regulator-facing document.
    """
    assert constants.platform_origination("m365", "Microsoft Coverage", "AC") == ["Inherited"]
    # AC's domain plurality is "shared"; with no coverage status the SSP must
    # still decline rather than borrow it.
    assert constants.platform_origination("m365", None, "AC") == []
    assert constants.needs_manual_responsibility_assignment("m365", "AC") is False


def test_template_entries_and_the_resolver_agree() -> None:
    """One definition: the entry set and `responsibility_for` cannot diverge."""
    entries = template_entries("m365")
    assert entries, "M365 must expose its domain template like every other platform"
    assert {e.version for e in entries} == {TEMPLATE_VERSION}
    for entry in entries:
        assert entry.domain is not None
        assert responsibility_for("m365", entry.domain) == entry.responsibility
        assert entry.source == "m365-placemat-domain"
        assert entry.scope == "domain"
        assert entry.rationale, "a summarised answer must say it is summarised"


def test_the_m365_template_did_not_leak_into_ssp_domain_responsibility() -> None:
    """`PLATFORM_DOMAIN_RESPONSIBILITY` is for platforms with *only* domain data."""
    assert "m365" not in constants.PLATFORM_DOMAIN_RESPONSIBILITY


def _placemat_counts() -> dict[str, Counter[str]]:
    """Per-domain coverage tallies straight from the committed placemat.

    `seed.json` is what `seed_scoring_controls` loads into
    `ccf.scoring_controls`, so it is the provenance of the domain table -- and
    unlike a database it is the same for everyone, cannot be half-seeded, and
    makes this guard impossible to skip.
    """
    counts: dict[str, Counter[str]] = {}
    for record in load_seed():
        domain = (record.get("domain") or "").upper()
        coverage = record.get("m365_coverage_status")
        if domain and coverage:
            counts.setdefault(domain, Counter())[coverage] += 1
    return counts


def test_the_domain_table_matches_the_placemat() -> None:
    """Recompute every entry from the placemat and compare.

    The production table is a literal, so it can drift from the data it was
    derived from without anything noticing. This recomputes it with its own
    arithmetic -- deliberately not by calling the production rule, which would
    mutate both sides together and pass no matter what either said.

    The rule: a domain takes the responsibility held by the plurality of its
    practices, ties going to "shared".
    """
    counts = _placemat_counts()
    assert counts, "the committed placemat must carry M365 coverage statuses"

    expected: dict[str, str] = {}
    for domain, coverage_counts in counts.items():
        tally: Counter[str] = Counter()
        for coverage, n in coverage_counts.items():
            resp = _COVERAGE.get(coverage)
            assert resp is not None, (
                f"placemat coverage status {coverage!r} is not mapped; the M365 "
                "template cannot be recomputed until it is"
            )
            tally[resp] += n
        top = max(tally.values())
        winners = {resp for resp, n in tally.items() if n == top}
        expected[domain] = "shared" if len(winners) > 1 else winners.pop()

    actual = {
        entry.domain: entry.responsibility
        for entry in template_entries("m365")
        if entry.domain
    }
    assert actual == expected, (
        "the hardcoded M365 domain table no longer matches the committed "
        "placemat; recompute it rather than editing one side"
    )


def test_no_m365_domain_is_summarised_against_its_own_majority() -> None:
    """A spot-check with literal expectations, independent of any recomputation.

    If the recompute above and the production table ever shared a misconception,
    these would still catch it: PE is Microsoft's (physical protection of
    Microsoft datacentres), AC and IA are overwhelmingly shared, CM is mostly the
    customer's.
    """
    counts = _placemat_counts()

    assert counts["PE"]["Microsoft Coverage"] > counts["PE"]["Shared Coverage"]
    assert responsibility_for("m365", "PE") == "inherited"

    assert counts["AC"]["Shared Coverage"] > counts["AC"]["Customer Responsibility"]
    assert responsibility_for("m365", "AC") == "shared"

    assert counts["CM"]["Customer Responsibility"] > counts["CM"]["Shared Coverage"]
    assert responsibility_for("m365", "CM") == "customer"


def test_the_seeded_table_and_the_placemat_are_the_same_data() -> None:
    """The guard above reads `seed.json`; the running system reads the database.

    `seed_scoring_controls` is the only thing that puts M365 coverage into
    `ccf.scoring_controls`, and it loads exactly these records -- so pinning the
    field list keeps the guard pointed at the column the resolver would use if
    it ever read per-practice coverage directly.
    """
    assert "m365_coverage_status" in scoring_seed._FIELDS
    assert {
        record["m365_coverage_status"]
        for record in load_seed()
        if record.get("m365_coverage_status")
    } <= set(_COVERAGE), "the placemat gained a coverage status nothing maps"
