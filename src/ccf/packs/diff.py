"""What changed in a tenant's declared desired state, between two versions.

A declared posture rule is desired state, so a change to one is a change to
what the tenant asserts about its environment -- reviewable before adoption,
and the answer to "why did this check start failing" afterwards. Shaped like
:mod:`ccf.catalog.diff` (added / removed / changed, keyed) so the two read the
same way.

The guard that matters is :data:`UNKNOWN_BASELINE`. Version rows written before
migration 0069 have no manifest, and treating an absent one as "declared
nothing" would report every current rule as *added* and every prior rule as
*removed* -- fabricating a desired-state change that never happened. An absent
manifest is reported as unknown instead. A manifest that is present but
declares no rules is a real, empty desired state and diffs normally; the
distinction is the whole point.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

#: Reported when either side has no retained manifest, so no comparison is
#: possible and none is invented.
UNKNOWN_BASELINE = "unknown"

#: Reported when both sides were retained and could be compared.
KNOWN_BASELINE = "known"


@dataclass(frozen=True)
class PostureRuleDiff:
    """Desired-state change between two pack versions, by rule key."""

    baseline: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    #: Rule key -> (before, after) for **every** rule in the diff. An added
    #: rule has ``{}`` before, a removed one ``{}`` after. A diff that names a
    #: rule without its definition cannot be reviewed or acted on -- and a
    #: consumer computing what a change affects needs the added and removed
    #: definitions just as much as the changed ones.
    definitions: dict[str, tuple[dict[str, Any], dict[str, Any]]] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline,
            "added": self.added,
            "removed": self.removed,
            "changed": self.changed,
            "has_changes": self.has_changes,
        }


def _posture_rules(manifest: Any) -> dict[str, dict[str, Any]]:
    """Posture rules from a manifest, keyed. Other rule kinds are not desired
    state and are left to whatever owns them."""
    if not isinstance(manifest, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for rule in manifest.get("rules") or []:
        if not isinstance(rule, dict) or rule.get("kind") != "posture":
            continue
        key = rule.get("key")
        definition = rule.get("definition")
        if isinstance(key, str) and key:
            out[key] = definition if isinstance(definition, dict) else {}
    return out


def _canonical(definition: dict[str, Any]) -> str:
    """A stable form, so re-serializing a manifest is not read as drift."""
    return json.dumps(definition, sort_keys=True, separators=(",", ":"))


def diff_posture_rules(old: Any, new: Any) -> PostureRuleDiff:
    """Compare the declared posture rules of two manifests."""
    if not isinstance(old, dict) or not old or not isinstance(new, dict) or not new:
        # No retained manifest on one side: say so rather than fabricating a
        # wholesale addition or removal from missing history.
        return PostureRuleDiff(baseline=UNKNOWN_BASELINE)

    before = _posture_rules(old)
    after = _posture_rules(new)
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed: list[str] = []
    definitions: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for key in sorted(set(before) & set(after)):
        if _canonical(before[key]) != _canonical(after[key]):
            changed.append(key)
            definitions[key] = (before[key], after[key])
    for key in added:
        definitions[key] = ({}, after[key])
    for key in removed:
        definitions[key] = (before[key], {})
    return PostureRuleDiff(
        baseline=KNOWN_BASELINE,
        added=added,
        removed=removed,
        changed=changed,
        definitions=definitions,
    )
