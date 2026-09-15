"""Coverage: whether an accepted finding stops alerting -- and when it must not."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from ccf.governance.waivers import REQUIRES_COVER, cover, is_active
from ccf.posture.types import ResourceFinding

TODAY = date(2026, 9, 15)


@dataclass(frozen=True)
class _FakeWaiver:
    id: int
    status: str
    expires_on: date | None
    resource_id: str | None


def _w(
    resource_id: str | None,
    *,
    status: str = "approved",
    expires_on: date | None = None,
    id: int = 7,
) -> _FakeWaiver:
    return _FakeWaiver(id=id, status=status, expires_on=expires_on, resource_id=resource_id)


def _verdicts(*pairs: tuple[str, str]) -> list[ResourceFinding]:
    return [
        ResourceFinding(resource_id=rid, resource_type="entra_user", verdict=v, observed="o")
        for rid, v in pairs
    ]


def _findings(*verdicts: str) -> list[ResourceFinding]:
    return _verdicts(*[(f"res-{i}", v) for i, v in enumerate(verdicts)])


# ── is_active ────────────────────────────────────────────────────────────────


def test_an_approved_waiver_with_no_expiry_is_active() -> None:
    assert is_active(_w(None), today=TODAY) is True


def test_a_requested_waiver_is_not_active() -> None:
    assert is_active(_w(None, status="requested"), today=TODAY) is False


def test_a_revoked_waiver_is_not_active() -> None:
    assert is_active(_w(None, status="revoked"), today=TODAY) is False


def test_a_waiver_expiring_today_is_still_active() -> None:
    """Inclusive: an acceptance runs to the end of its last day."""
    assert is_active(_w(None, expires_on=TODAY), today=TODAY) is True


def test_a_waiver_that_expired_yesterday_is_not_active() -> None:
    assert is_active(_w(None, expires_on=TODAY - timedelta(days=1)), today=TODAY) is False


# ── the verdict set that needs covering ──────────────────────────────────────


def test_requires_cover_is_derived_from_the_one_vocabulary() -> None:
    """Derived, not restated -- adding a verdict must not leave coverage behind.

    pass needs no cover; not_applicable and not_tested are excluded from the
    rollup, so they are not findings to accept.
    """
    assert sorted(REQUIRES_COVER) == ["fail", "manual_review_required", "warn"]


# ── the coverage rule ────────────────────────────────────────────────────────


def test_a_whole_check_waiver_covers_every_failing_resource() -> None:
    cov = cover(_findings("fail", "fail"), [_w(None)], today=TODAY)
    assert cov.suppress is True
    assert cov.waived == 2
    assert cov.uncovered == ()


def test_one_uncovered_failing_resource_prevents_suppression() -> None:
    """A partially accepted check is still an unaccepted finding."""
    cov = cover(_findings("fail", "fail"), [_w("res-0")], today=TODAY)
    assert cov.suppress is False
    assert cov.waived == 1
    assert cov.uncovered == ("res-1",)


def test_a_resource_scoped_waiver_cannot_cover_a_resourceless_result() -> None:
    """Spec rule 4. Nothing proves the waived resource was the failing one."""
    cov = cover([], [_w("res-0")], today=TODAY)
    assert cov.suppress is False


def test_a_whole_check_waiver_does_cover_a_resourceless_result() -> None:
    """A manual test records a fail with no resources; only this shape covers it."""
    cov = cover([], [_w(None)], today=TODAY)
    assert cov.suppress is True


def test_passing_and_not_applicable_resources_need_no_cover() -> None:
    cov = cover(
        _verdicts(("res-0", "fail"), ("res-1", "pass"), ("res-2", "not_applicable")),
        [_w("res-0")],
        today=TODAY,
    )
    assert cov.suppress is True
    assert cov.waived == 1


def test_manual_review_required_must_be_covered_too() -> None:
    """It is not a clean verdict; leaving it uncovered must keep the alert."""
    cov = cover(
        _verdicts(("res-0", "fail"), ("res-1", "manual_review_required")),
        [_w("res-0")],
        today=TODAY,
    )
    assert cov.suppress is False
    assert cov.uncovered == ("res-1",)


def test_warn_must_be_covered_too() -> None:
    cov = cover(_verdicts(("res-0", "warn")), [], today=TODAY)
    assert cov.suppress is False
    assert cov.uncovered == ("res-0",)


def test_an_expired_waiver_covers_nothing() -> None:
    cov = cover(_findings("fail"), [_w(None, expires_on=TODAY - timedelta(days=1))], today=TODAY)
    assert cov.suppress is False
    assert cov.waived == 0


def test_a_requested_waiver_covers_nothing() -> None:
    """If asking were enough, anyone could silence a check by asking."""
    cov = cover(_findings("fail"), [_w(None, status="requested")], today=TODAY)
    assert cov.suppress is False


def test_a_revoked_waiver_covers_nothing() -> None:
    cov = cover(_findings("fail"), [_w(None, status="revoked")], today=TODAY)
    assert cov.suppress is False


def test_no_waivers_never_suppresses() -> None:
    assert cover(_findings("fail"), [], today=TODAY).suppress is False


def test_no_failing_resources_does_not_claim_suppression() -> None:
    """An all-passing result is not "suppressed" -- there was nothing to fire."""
    cov = cover(_verdicts(("res-0", "pass")), [_w(None)], today=TODAY)
    assert cov.suppress is False
    assert cov.waived == 0


def test_the_narrowest_waiver_is_attributed_to_a_resource() -> None:
    """The more specific acceptance is the one an auditor should see recorded
    against that resource."""
    whole, specific = _w(None, id=1), _w("res-0", id=2)
    cov = cover(_findings("fail"), [whole, specific], today=TODAY)
    assert cov.by_resource["res-0"] == 2


def test_attribution_is_stable_when_only_a_whole_check_waiver_applies() -> None:
    cov = cover(_findings("fail", "fail"), [_w(None, id=5)], today=TODAY)
    assert cov.by_resource == {"res-0": 5, "res-1": 5}


def test_a_passing_resource_is_never_attributed_to_a_waiver() -> None:
    """Recording an acceptance against a resource that did not fail would
    misstate the evidence."""
    cov = cover(_verdicts(("res-0", "pass"), ("res-1", "fail")), [_w(None, id=5)], today=TODAY)
    assert cov.by_resource == {"res-1": 5}
    assert cov.waived == 1


def test_two_resource_waivers_cover_two_resources() -> None:
    cov = cover(_findings("fail", "fail"), [_w("res-0", id=1), _w("res-1", id=2)], today=TODAY)
    assert cov.suppress is True
    assert cov.by_resource == {"res-0": 1, "res-1": 2}


def test_a_waiver_for_an_absent_resource_covers_nothing() -> None:
    cov = cover(_findings("fail"), [_w("res-99")], today=TODAY)
    assert cov.suppress is False
    assert cov.waived == 0
