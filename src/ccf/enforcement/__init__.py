"""Closed-loop enforcement -- changing an environment, deliberately.

Every other connector in this platform reads. This package writes, and that
difference drives every decision in it: a read-path bug produces a wrong
verdict that review catches, where a write-path bug reconfigures a production
federal system -- possibly one mid-authorization, where an unplanned
configuration change is itself reportable.

So the design is a sequence of refusals. Nothing is written without a write
credential the operator deliberately created, a plan that was built and
persisted first, an approval from someone other than the requester, a resource
count inside a deliberately small blast radius, and the data needed to undo it
captured beforehand. See
``docs/superpowers/specs/2026-09-15-enforcement-design.md``.

Nothing here is automatic. The scheduler applies nothing; there is no
auto-remediate flag.
"""

from __future__ import annotations
