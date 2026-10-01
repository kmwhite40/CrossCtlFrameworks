"""Provider-attested control results: reading AWS's own 800-53 mapping.

Concord's posture checks are Concord's judgement -- a check in
:mod:`ccf.posture.providers.aws` declares which controls it evidences because a
human decided so. This module handles a second, different kind of evidence: a
provider evaluating *its own* control catalog and publishing which 800-53
requirements each of its controls relates to.

AWS Security Hub's NIST SP 800-53 Rev 5 standard does exactly that. Each
finding carries ``Compliance.SecurityControlId`` (``"S3.8"``),
``Compliance.Status`` (one of ``PASSED``, ``WARNING``, ``FAILED``,
``NOT_AVAILABLE`` -- botocore's ``ComplianceStatus`` enum) and
``Compliance.RelatedRequirements`` (``["NIST.800-53.r5 AC-3", ...]``). AWS
asserts the mapping, so reading it reaches controls Concord has no check for
without anybody hand-authoring a crosswalk.

Everything here is pure. No boto3, no database, no network -- the transport
lives in :mod:`ccf.connectors.aws` and the persistence in
:mod:`ccf.posture.attested_scan`, the same division of labour the Graph and AWS
posture providers already follow.

Why one row per (security control, requirement)
-----------------------------------------------
A Security Hub control routinely relates to several requirements: ``S3.8``
relates to ``AC-3``, ``AC-4`` and ``SC-7``. Recording that as one result
carrying three controls would let a single narrow automated check mark three
controls satisfied -- the over-claim :mod:`ccf.posture.evidence` exists to
prevent, in a document a regulator acts on.

:func:`attested_rows` therefore emits one row per pair, each carrying exactly
one control in both ``control_id`` and ``control_ids``. The consequence is that
Concord's existing per-control rollup does the right thing with no new rule:
``AC-3`` is decided by *every* Security Hub control related to ``AC-3``, so it
reads as passing only when all of them passed, and as failing the moment one of
them fails. The asymmetry in ``posture.evidence`` is preserved because there is
no secondary control for a pass to widen out to.

What is deliberately not inherited
----------------------------------
A working implementation of this same idea (documented as-built elsewhere)
scores Security Hub data three ways this module refuses:

* it keeps ``RelatedRequirements`` raw and matches them against
  ``/^[A-Z]{2}-\\d+/``, which no real entry matches, so a populated account
  scores zero covered. Here :func:`requirement_ids` normalizes through
  :func:`ccf.catalog.canonical.canonicalize` -- the normalizer Concord already
  owns -- rather than growing a second one;
* it derives a posture percentage from finding severities
  (``100 - (crit*10 + high*4 + ...)``) and reports ``100`` when the fetch
  fails. Nothing here produces a score; it produces verdicts, which the
  existing rollups count;
* it defaults controls with no specific check to ``pass``. Here every status
  that is not one of the four documented values -- including a missing
  ``Compliance`` block -- resolves to ``manual_review_required``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..catalog.canonical import canonicalize
from .rollup import roll_up_findings

#: ``Compliance.AssociatedStandards[].StandardsId`` for the standard this
#: module reads. Also the value ``ComplianceAssociatedStandardsId`` is filtered
#: on when fetching, so a scan does not pull CIS or PCI findings it will drop.
NIST_80053_R5_STANDARD_ID = "standards/nist-800-53-revision-5"

#: The token Security Hub prefixes an 800-53 Rev 5 requirement with. Matched as
#: a whole first token, never as a substring: ``NIST.800-53.r4`` is a different
#: revision, and attributing an r4 mapping to an r5 attestation is a claim AWS
#: did not make.
REQUIREMENT_PREFIX = "NIST.800-53.r5"

#: ``Compliance.Status`` -> Concord verdict. Exhaustive over botocore's
#: ``ComplianceStatus`` enum as of API version 2018-10-26. Anything absent
#: resolves to ``manual_review_required`` via :func:`verdict_for`; see that
#: function on why there is no ``pass`` default.
_STATUS_VERDICTS: dict[str, str] = {
    "PASSED": "pass",
    "FAILED": "fail",
    "WARNING": "warn",
    "NOT_AVAILABLE": "manual_review_required",
}

#: Prefix for the synthetic check key each row is stored under. Distinct from
#: any registered check key, so an attested row can never be mistaken for one
#: of Concord's own checks -- and, because it is not in the registry,
#: ``tests/test_every_check_can_be_scanned.py`` is not asserting about it.
CHECK_KEY_PREFIX = "aws.securityhub."

#: ``ControlTest.check_source`` for these rows. A third value beside
#: ``"platform"`` and ``"pack:<key>"``: AWS attested this, which is neither
#: Concord's own assessment nor a tenant's self-attestation. The trust ordering
#: between the three lives in ``ccf.posture.scan``.
CHECK_SOURCE = "attested:securityhub"

#: ``ControlTest.check_key`` is ``String(128)``.
_MAX_CHECK_KEY = 128


def verdict_for(compliance_status: str | None) -> str:
    """One ``Compliance.Status`` as a Concord verdict.

    Unrecognised, empty and missing statuses all resolve to
    ``manual_review_required`` -- Concord not knowing, which the posture view
    renders as "could not assess". The one thing this must never do is default
    to ``pass``: that turns a control AWS could not evaluate into a control AWS
    says is fine, in a report an assessor reads.

    The lookup is case-sensitive on purpose. Upper-casing an unexpected
    spelling would quietly absorb an API change as a wave of passes nobody
    authored; failing to recognise it surfaces as manual review instead.
    """
    if not isinstance(compliance_status, str):
        return "manual_review_required"
    return _STATUS_VERDICTS.get(compliance_status.strip(), "manual_review_required")


def requirement_ids(
    related_requirements: Iterable[str] | None,
) -> tuple[list[str], list[str]]:
    """``(canonical 800-53 ids, 800-53 entries that would not canonicalize)``.

    Entries for other frameworks -- ``"PCI DSS v3.2.1/2.2"``, CIS Benchmark
    references -- are dropped and *not* reported as unreadable. They are not
    800-53 ids and not failures; reporting them would fill the diagnostic
    channel with normal traffic until nobody reads it.

    An entry that does carry the r5 prefix but whose remainder
    :func:`~ccf.catalog.canonical.canonicalize` rejects is returned verbatim in
    the second list. The case that matters in practice is a statement part such
    as ``AC-2(j)``: mapping it onto ``AC-2`` would let one part-scoped
    attestation credit a control with a dozen parts, so it is named instead and
    the cost of naming it can be measured from real data.

    Order is the provider's, so a reader comparing against the Security Hub
    console sees the same sequence. Duplicates collapse, because two rows for
    one pair would be two votes on one control.
    """
    readable: list[str] = []
    unreadable: list[str] = []
    for raw in related_requirements or ():
        if not isinstance(raw, str):
            continue
        entry = raw.strip()
        if not entry:
            continue
        head, _, rest = entry.partition(" ")
        if head != REQUIREMENT_PREFIX:
            continue
        canonical = canonicalize(rest)
        if canonical is None:
            if entry not in unreadable:
                unreadable.append(entry)
            continue
        if canonical.value not in readable:
            readable.append(canonical.value)
    return readable, unreadable


@dataclass(frozen=True)
class AttestedControl:
    """One Security Hub control's state across every resource it evaluated."""

    security_control_id: str
    #: Rolled up across resources by :func:`~ccf.posture.rollup.roll_up_findings`
    #: -- one failing resource fails the control, and nothing in scope is
    #: ``not_applicable`` rather than ``pass``.
    verdict: str
    #: Canonical 800-53 ids AWS related this control to, provider order.
    requirements: tuple[str, ...]
    #: r5-prefixed entries that would not canonicalize. The only channel that
    #: reports coverage this ingest could not attribute.
    unreadable_requirements: tuple[str, ...]
    title: str
    evaluated: int
    failing: int


@dataclass(frozen=True)
class AttestedRow:
    """One (Security Hub control, 800-53 requirement) pair, ready to persist."""

    check_key: str
    security_control_id: str
    control_id: str
    #: Always exactly ``[control_id]``. Present so the row satisfies the same
    #: contract a generated test does, and so ``posture.evidence`` has nothing
    #: to widen a pass out to.
    control_ids: list[str]
    verdict: str
    title: str
    evaluated: int
    failing: int


def attested_controls(findings: Iterable[Mapping[str, Any]]) -> tuple[AttestedControl, ...]:
    """Group Security Hub findings into one state per security control.

    A finding with no ``Compliance.SecurityControlId`` is not a control result.
    Third-party products write into the same findings store, and inventing a
    control id for their findings would mix another vendor's verdicts into
    AWS's attestation.

    Requirements are unioned across a control's findings. They should agree, but
    if AWS revises a mapping between two pages of one scan, a requirement AWS
    related this control to is one it related it to -- the union is the honest
    answer and the alternative (last page wins) is order-dependent.
    """
    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        compliance = finding.get("Compliance")
        if not isinstance(compliance, Mapping):
            continue
        control_id = compliance.get("SecurityControlId")
        if not isinstance(control_id, str) or not control_id.strip():
            continue
        key = control_id.strip()
        bucket = grouped.setdefault(
            key,
            {
                "verdicts": [],
                "requirements": [],
                "unreadable": [],
                "title": "",
                "failing": 0,
            },
        )
        verdict = verdict_for(compliance.get("Status"))
        bucket["verdicts"].append(verdict)
        if verdict == "fail":
            bucket["failing"] += 1
        readable, unreadable = requirement_ids(compliance.get("RelatedRequirements"))
        for req in readable:
            if req not in bucket["requirements"]:
                bucket["requirements"].append(req)
        for req in unreadable:
            if req not in bucket["unreadable"]:
                bucket["unreadable"].append(req)
        title = finding.get("Title")
        if not bucket["title"] and isinstance(title, str) and title.strip():
            bucket["title"] = title.strip()

    return tuple(
        AttestedControl(
            security_control_id=control_id,
            verdict=roll_up_findings(bucket["verdicts"]),
            requirements=tuple(bucket["requirements"]),
            unreadable_requirements=tuple(bucket["unreadable"]),
            title=bucket["title"] or control_id,
            evaluated=len(bucket["verdicts"]),
            failing=bucket["failing"],
        )
        for control_id, bucket in sorted(grouped.items())
    )


def check_key_for(security_control_id: str, control_id: str) -> str:
    """The synthetic check key one pair is stored under.

    Deterministic, so re-ingesting the same account updates rows in place
    rather than duplicating them -- ``control_tests`` is unique on
    ``(system_id, check_key)``, and that constraint is what makes the ingest
    idempotent.
    """
    return f"{CHECK_KEY_PREFIX}{security_control_id}::{control_id}"


def attested_rows(controls: Sequence[AttestedControl]) -> tuple[AttestedRow, ...]:
    """Expand each control into one row per readable requirement.

    A control with no readable requirement yields nothing: there is no control
    to attribute it to, and writing it against a guessed id is the defect this
    whole module is shaped to avoid. The loss is carried on the
    :class:`AttestedControl` as ``unreadable_requirements`` for the ingest to
    report.

    A key that would exceed ``ControlTest.check_key``'s 128 characters is
    dropped rather than truncated: two truncated keys could collide, and a
    collision on that column means two different controls sharing one row.
    """
    rows: list[AttestedRow] = []
    for control in controls:
        for requirement in control.requirements:
            key = check_key_for(control.security_control_id, requirement)
            if len(key) > _MAX_CHECK_KEY:
                continue
            rows.append(
                AttestedRow(
                    check_key=key,
                    security_control_id=control.security_control_id,
                    control_id=requirement,
                    control_ids=[requirement],
                    verdict=control.verdict,
                    title=control.title,
                    evaluated=control.evaluated,
                    failing=control.failing,
                )
            )
    return tuple(rows)
