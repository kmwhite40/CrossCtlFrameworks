"""Diff two loaded OSCAL catalog revisions.

Pure functions over :class:`~ccf.catalog.oscal.OscalCatalog` -- no database, no
network -- so the whole diff is unit-testable and safe to run air-gapped.

This is a superset of the currency poller's prose-hash changelog: the
control-set half delegates to :func:`ccf.etl.sources.diff_content_index`, and
the new work is per-control parameter changes and baseline membership shifts,
which a title+prose hash cannot see.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..etl.sources import diff_content_index
from .oscal import OscalCatalog, OscalControl, OscalParam


def _param_fingerprint(p: OscalParam) -> tuple[str, str, tuple[str, ...]]:
    return (p.label, p.guidance, tuple(p.choices))


@dataclass(frozen=True)
class ControlChange:
    """What changed within one control that exists in both revisions."""

    canonical_id: str
    title_changed: bool
    statement_changed: bool
    guidance_changed: bool
    params_added: tuple[str, ...]
    params_removed: tuple[str, ...]
    params_changed: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_id": self.canonical_id,
            "title_changed": self.title_changed,
            "statement_changed": self.statement_changed,
            "guidance_changed": self.guidance_changed,
            "params_added": list(self.params_added),
            "params_removed": list(self.params_removed),
            "params_changed": list(self.params_changed),
        }


@dataclass(frozen=True)
class CatalogDiff:
    """Everything that differs between two revisions of one source."""

    added: tuple[str, ...]
    removed: tuple[str, ...]
    newly_withdrawn: tuple[str, ...]
    un_withdrawn: tuple[str, ...]
    changed: tuple[ControlChange, ...]
    baseline_entered: dict[str, tuple[str, ...]]
    baseline_left: dict[str, tuple[str, ...]]

    def is_empty(self) -> bool:
        return not (
            self.added
            or self.removed
            or self.newly_withdrawn
            or self.un_withdrawn
            or self.changed
            or any(self.baseline_entered.values())
            or any(self.baseline_left.values())
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "added": list(self.added),
            "removed": list(self.removed),
            "newly_withdrawn": list(self.newly_withdrawn),
            "un_withdrawn": list(self.un_withdrawn),
            "changed": [c.to_dict() for c in self.changed],
            "baseline_entered": {k: list(v) for k, v in self.baseline_entered.items()},
            "baseline_left": {k: list(v) for k, v in self.baseline_left.items()},
        }


def _diff_one_control(old: OscalControl, new: OscalControl) -> ControlChange | None:
    """A :class:`ControlChange` when anything moved, else ``None``."""
    old_params = {p.id: _param_fingerprint(p) for p in old.params}
    new_params = {p.id: _param_fingerprint(p) for p in new.params}
    added = tuple(sorted(set(new_params) - set(old_params)))
    removed = tuple(sorted(set(old_params) - set(new_params)))
    changed = tuple(
        sorted(k for k in set(old_params) & set(new_params) if old_params[k] != new_params[k])
    )
    change = ControlChange(
        canonical_id=new.canonical_id,
        title_changed=old.title != new.title,
        statement_changed=old.statement != new.statement,
        guidance_changed=old.guidance != new.guidance,
        params_added=added,
        params_removed=removed,
        params_changed=changed,
    )
    touched = (
        change.title_changed
        or change.statement_changed
        or change.guidance_changed
        or added
        or removed
        or changed
    )
    return change if touched else None


def diff_revisions(old: OscalCatalog, new: OscalCatalog) -> CatalogDiff:
    """Compare two loaded catalogs.

    Control membership is computed with the poller's own index diff so the two
    subsystems can never disagree about what "added" means. Withdrawal is
    tracked as a transition rather than a state, because a control that becomes
    withdrawn still exists in the catalog -- it just stops being claimable.
    """
    # Identity-only index: membership arithmetic, not content comparison.
    membership = diff_content_index(
        {cid: cid for cid in old.controls}, {cid: cid for cid in new.controls}
    )

    both = sorted(set(old.controls) & set(new.controls))
    newly_withdrawn = tuple(
        cid for cid in both if new.controls[cid].withdrawn and not old.controls[cid].withdrawn
    )
    un_withdrawn = tuple(
        cid for cid in both if old.controls[cid].withdrawn and not new.controls[cid].withdrawn
    )

    changes: list[ControlChange] = []
    for cid in both:
        change = _diff_one_control(old.controls[cid], new.controls[cid])
        if change is not None:
            changes.append(change)

    entered: dict[str, tuple[str, ...]] = {}
    left: dict[str, tuple[str, ...]] = {}
    for level in sorted(set(old.baselines) | set(new.baselines)):
        o = old.baselines.get(level, set())
        n = new.baselines.get(level, set())
        entered[level] = tuple(sorted(n - o))
        left[level] = tuple(sorted(o - n))

    return CatalogDiff(
        added=tuple(membership["added"]),
        removed=tuple(membership["removed"]),
        newly_withdrawn=newly_withdrawn,
        un_withdrawn=un_withdrawn,
        changed=tuple(changes),
        baseline_entered=entered,
        baseline_left=left,
    )
