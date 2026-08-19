"""Regression tests for the Tier 1 audit batch (non-middleware items).

Middleware ordering is pinned separately in tests/test_middleware_order.py.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from ccf.api.routes import portal
from ccf.evidence import confidence, service

_SRC = Path(__file__).resolve().parents[1] / "src" / "ccf"


# --- F-S19-1: "drifted" and "missing" must be reachable ---------------------


def test_replay_no_longer_recomputes_a_digest_read_version_verified() -> None:
    """The dead branch.

    ``read_version`` already hashes the bytes and raises on a mismatch, so
    recomputing the same digest in ``replay`` made the equality test always
    true. The ``drifted`` arm could not execute; real tampering raised, hit the
    bare ``except``, and was stored as ``error`` — which is why the reliability
    check, which counts only ``drifted``/``missing``, reported PASS on it.
    """
    src = inspect.getsource(confidence.replay)
    assert "hashlib.sha256(data)" not in src, "digest recomputed after read_version verified it"
    assert 'status = "drifted"' in src
    assert 'status = "missing"' in src


def test_replay_maps_each_failure_to_its_own_status() -> None:
    src = inspect.getsource(confidence.replay)
    assert "except EvidenceIntegrityError" in src, "tampering must record drifted"
    assert "except EvidenceContentMissingError" in src, "unreachable bytes must record missing"
    assert "except Exception" in src, "unexpected failures must still be captured"


def test_missing_content_has_a_distinct_exception() -> None:
    """Collapsed into a generic EvidenceError before, so replay could not tell
    "bytes altered" from "bytes gone"."""
    assert issubclass(service.EvidenceContentMissingError, service.EvidenceError)
    assert not issubclass(service.EvidenceContentMissingError, service.EvidenceIntegrityError)
    src = inspect.getsource(service.read_version)
    assert "EvidenceContentMissingError" in src


# --- F-S23-1: one grant resolver, both credential channels ------------------


def test_require_grant_accepts_either_credential_channel() -> None:
    """The portal comment form posted an empty bearer token and always 401'd.

    The HTML entry point strips ``token`` from the URL on redirect and moves the
    identity into a cookie, but ``_require_grant`` resolved only from the token.
    So a request could be authenticated for ``/portal`` and anonymous for
    ``/api/portal/*`` in the same browser, same grant.
    """
    src = inspect.getsource(portal._require_grant)
    assert "_grant_from_cookie" in src, "cookie channel must be accepted"
    assert "_token(request)" in src, "token channel must still be accepted"
    # Cookie is tried first so a stale bookmarked ?token= cannot override it.
    assert src.index("_grant_from_cookie") < src.index("_token(request)")


# --- F-S13-1: the advisory unlock must not be starvable ---------------------


def test_scheduler_releases_the_lock_before_the_tenant_reset() -> None:
    """set_session_tenant issues SQL; on an aborted transaction it raises.

    When it ran before the unlock, a single transient step failure leaked a
    session-scoped advisory lock with the pooled connection, and every later
    cycle on every replica logged "another instance holds the lock" forever.
    """
    src = (_SRC / "governance" / "scheduler.py").read_text(encoding="utf-8")
    tail = src[src.index("        finally:") :]
    unlock = tail.index("pg_advisory_unlock")
    reset = tail.index("set_session_tenant(session, None)")
    assert unlock < reset, "the unlock must not sit behind a call that can raise"


def test_scheduler_does_not_roll_back_unconditionally() -> None:
    """run_cycle runs inside session_scope, which commits on normal exit.

    A blanket rollback in the teardown would discard the whole cycle's work on
    the happy path — which is what tests/test_scheduler_global_steps.py caught.
    The rollback must be reachable only from the unlock's failure path.
    """
    src = (_SRC / "governance" / "scheduler.py").read_text(encoding="utf-8")
    tail = src[src.index("        finally:") :]
    tail = tail[: tail.index("\n    log.info(")]
    assert "session.rollback()" in tail
    # every rollback sits inside an ``except`` arm, never at the top level of finally
    for line in tail.splitlines():
        if "session.rollback()" in line:
            assert line.startswith(" " * 24), f"rollback not nested under a failure path: {line!r}"


def test_scheduler_tenant_reset_cannot_block_the_unlock() -> None:
    src = (_SRC / "governance" / "scheduler.py").read_text(encoding="utf-8")
    tail = src[src.index("        finally:") :]
    assert tail.index("pg_advisory_unlock") < tail.index("set_session_tenant(session, None)")
