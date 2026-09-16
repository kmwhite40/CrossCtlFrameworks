"""PuppetDB posture checks -- is the fleet managed, and is state being enforced?

Two checks, and the second is the one worth having. Concord can already tell
you what a node's configuration *should* be; PuppetDB can tell you whether the
thing that applies it is actually working.

* **A node whose last Puppet run failed** is a node where declared
  configuration is not being applied. Nothing else in Concord sees that, and it
  is a live CM-2/CM-6 finding.
* **A node that stopped reporting** is unmanaged, whatever its last known state
  said. Silence is not compliance.

Every evaluator here is pure: nodes in, findings out, ``now`` passed in. No
network, no clock, no database -- so each is testable against a recorded
PuppetDB payload, which matters because no Puppet installation is reachable
from the build environment.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from ..types import PostureCheck, ResourceFinding

#: How long a node may go without reporting before it counts as unmanaged.
#: Puppet's default run interval is 30 minutes, so a full day of silence is
#: roughly 48 missed runs -- comfortably past "a transient network problem"
#: without flagging a host that rebooted.
STALE_AFTER_HOURS = 24

#: Run statuses PuppetDB reports, and what each means for enforcement.
#: ``changed`` is a PASS: Puppet converging a drifted node is Puppet working.
_HEALTHY_RUN_STATUSES = frozenset({"unchanged", "changed"})
_FAILED_RUN_STATUSES = frozenset({"failed"})


NODE_REPORTING = PostureCheck(
    key="puppetdb.node.reporting",
    title="Every managed node is still reporting",
    provider="puppetdb",
    resource_type="puppet_node",
    expected=f"every node has reported to PuppetDB within {STALE_AFTER_HOURS} hours",
    control_ids=("CM-8", "CM-2"),
    required_permissions=("PuppetDB query: nodes",),
)

NODE_LAST_RUN_OK = PostureCheck(
    key="puppetdb.node.last_run_succeeded",
    title="No node's most recent configuration run failed",
    provider="puppetdb",
    resource_type="puppet_node",
    expected="no node's most recent Puppet run ended in failure",
    control_ids=("CM-2", "CM-6"),
    required_permissions=("PuppetDB query: nodes",),
)

CHECKS: tuple[PostureCheck, ...] = (NODE_REPORTING, NODE_LAST_RUN_OK)

#: Both checks read the same collection; PuppetDB returns the run status and
#: the report timestamp on the node record, so one query answers both.
_NODES_ENDPOINT = "/pdb/query/v4/nodes"
ENDPOINTS: dict[str, str] = {
    NODE_REPORTING.key: _NODES_ENDPOINT,
    NODE_LAST_RUN_OK.key: _NODES_ENDPOINT,
}


def _node_ref(node: dict[str, Any]) -> str:
    """The node's certname, never empty.

    An unidentified node is still an unmanaged node, so it is reported rather
    than dropped.
    """
    certname = node.get("certname")
    if isinstance(certname, str) and certname:
        return certname
    return "unknown"


def _parse_timestamp(value: Any) -> datetime | None:
    """PuppetDB timestamps are ISO-8601 with a ``Z``; anything else is unusable.

    ``datetime.fromisoformat`` happily accepts an offset-less string and
    returns a **naive** datetime rather than raising -- and subtracting that
    from the timezone-aware ``now`` in :func:`evaluate_node_reporting` raises
    ``TypeError``, which previously escaped this function and took down the
    whole fleet's verdict for one bad node. A parsed-but-naive result is
    exactly as unusable as one that failed to parse, so both return ``None``
    and let the node fall back to ``manual_review_required``.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def evaluate_node_reporting(
    nodes: list[dict[str, Any]],
    *,
    now: datetime,
    threshold_hours: int = STALE_AFTER_HOURS,
) -> list[ResourceFinding]:
    """One finding per node: has it reported recently enough to be managed?

    A node that has **never** reported, or whose timestamp cannot be parsed, is
    ``manual_review_required`` rather than ``pass``. Never having reported is
    not evidence of health, and a ``pass`` there would assert management that
    was never observed.
    """
    findings: list[ResourceFinding] = []
    for node in nodes:
        ref = _node_ref(node)
        reported = _parse_timestamp(node.get("report_timestamp"))
        if reported is None:
            findings.append(
                ResourceFinding(
                    resource_id=ref,
                    resource_type="puppet_node",
                    verdict="manual_review_required",
                    observed=(
                        "node has never reported to PuppetDB, or its timestamp "
                        "is unreadable"
                    ),
                    detail={"report_timestamp": node.get("report_timestamp")},
                )
            )
            continue
        hours = (now - reported).total_seconds() / 3600
        findings.append(
            ResourceFinding(
                resource_id=ref,
                resource_type="puppet_node",
                verdict="pass" if hours <= threshold_hours else "fail",
                observed=f"last reported {hours:.1f} hour(s) ago",
                detail={"report_timestamp": node.get("report_timestamp")},
            )
        )
    return findings


def evaluate_last_run_ok(nodes: list[dict[str, Any]]) -> list[ResourceFinding]:
    """One finding per node: did its most recent Puppet run apply cleanly?

    ``changed`` passes. Puppet correcting a drifted node is Puppet doing its
    job, and treating convergence as a finding would make every well-managed
    fleet look broken. Only ``failed`` fails; an unrecognised or missing status
    is ``manual_review_required``, because a status this build does not
    understand is not one it should call healthy.
    """
    findings: list[ResourceFinding] = []
    for node in nodes:
        ref = _node_ref(node)
        status = node.get("latest_report_status")
        normalized = status.lower() if isinstance(status, str) else None
        if normalized in _FAILED_RUN_STATUSES:
            verdict, observed = (
                "fail",
                "most recent Puppet run failed; declared configuration is not "
                "being applied",
            )
        elif normalized in _HEALTHY_RUN_STATUSES:
            verdict, observed = "pass", f"most recent Puppet run: {normalized}"
        else:
            verdict, observed = (
                "manual_review_required",
                f"unrecognised run status: {status!r}",
            )
        findings.append(
            ResourceFinding(
                resource_id=ref,
                resource_type="puppet_node",
                verdict=verdict,
                observed=observed,
                detail={"latest_report_status": status},
            )
        )
    return findings


#: Check key -> its evaluator, so adding a check is a registry entry.
EVALUATORS: dict[str, Callable[..., list[ResourceFinding]]] = {
    NODE_REPORTING.key: evaluate_node_reporting,
    NODE_LAST_RUN_OK.key: evaluate_last_run_ok,
}
