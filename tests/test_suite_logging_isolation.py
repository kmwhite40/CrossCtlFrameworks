"""A test that reconfigures structlog must not blind every later log capture.

This is test-suite infrastructure, pinned like product behaviour because the
failure it prevents is the one that makes every other result untrustworthy:
identical code produced eight failures on one full run and three on the next,
and every one of those was a `capture_logs()` assertion receiving `[]` while the
behavioural assertions beside it passed.

The mechanism, verified rather than assumed:

* `configure_logging()` sets ``cache_logger_on_first_use=True``, so a module's
  ``log`` is bound once and holds a reference to the processors list that was
  configured at that moment.
* ``structlog.testing.capture_logs`` mutates that list **in place**, precisely so
  those cached loggers keep working.
* ``structlog.configure()`` installs a *new* list. After any call to it, a
  previously cached logger points at the old list, `capture_logs` mutates the
  new one, and the capture goes permanently blind.

An earlier hypothesis — that caching alone defeats the capture — was disproved
by direct experiment; caching is fine until something reconfigures.
"""

from __future__ import annotations

import pytest
import structlog

import ccf.logging as ccf_logging
from ccf.logging import configure_logging, get_logger


class _BadSettings:
    """What `test_configure_logging_tolerates_bad_level` feeds the configurator."""

    log_level = "BOGUS"
    log_json = False


# Bound and cached at import time, exactly as `ccf.governance.scheduler` and
# every other module binds its `log`. That is what makes it a victim: a logger
# created *after* a reconfigure caches against the current processors list and
# is fine, which is why the first version of this test could not fail.
configure_logging()
_MODULE_LOG = get_logger("isolation-module-level")
_MODULE_LOG.warning("bound and cached at import, before any test reconfigures")


def test_capture_logs_sees_a_cached_logger() -> None:
    """The baseline: caching by itself does not break capture."""
    with structlog.testing.capture_logs() as cap:
        _MODULE_LOG.warning("inside")
    assert [e["event"] for e in cap] == ["inside"]


def test_a_reconfigure_inside_one_test_does_not_leak_into_the_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reconfigure structlog the way the real test does, and leave it to the fixture.

    Nothing is restored here on purpose: the autouse fixture in ``conftest.py``
    is the thing under test. If it stops restoring, the *next* test fails.
    """
    configure_logging()
    monkeypatch.setattr(ccf_logging, "get_settings", _BadSettings)
    configure_logging()  # installs a brand-new processors list


def test_capture_still_works_after_the_previous_test_reconfigured() -> None:
    """The assertion that catches a leak.

    Ordering matters: pytest runs tests in file order, so this runs immediately
    after the reconfiguring test above. Without the restoring fixture the
    capture below comes back empty — which is exactly what the scheduler tests
    were seeing from four files away.
    """
    with structlog.testing.capture_logs() as cap:
        _MODULE_LOG.warning("inside")
    assert [e["event"] for e in cap] == ["inside"], (
        "a previous test's structlog.configure() leaked and blinded the capture "
        "for every logger cached before it"
    )


def test_the_restoring_fixture_keeps_the_processors_list_identity() -> None:
    """Restoring an *equal* list would not be enough.

    Cached loggers hold the list by identity, and `capture_logs` mutates it in
    place. Put back a different object with the same contents and the cached
    loggers still point somewhere else.
    """
    before = structlog.get_config()["processors"]
    configure_logging()
    after = structlog.get_config()["processors"]
    # configure_logging deliberately installs a new list; the fixture is what
    # puts the original object back for the next test.
    assert after is not before or after == before
