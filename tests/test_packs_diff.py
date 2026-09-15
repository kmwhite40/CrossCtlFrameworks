"""Desired-state diff: what changed in a tenant's declared expectations."""

from __future__ import annotations

import itertools

from sqlalchemy import select

from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_packs import CompliancePackVersion
from ccf.packs.diff import UNKNOWN_BASELINE, diff_posture_rules
from ccf.packs.service import install_pack

_SEQ = itertools.count()


def _rule(key: str, threshold: int) -> dict:
    return {
        "key": key,
        "kind": "posture",
        "definition": {
            "evaluator": "m365.identity.stale_accounts",
            "parameters": {"threshold_days": threshold},
        },
    }


def _manifest(*rules: dict, version: str = "1.0.0") -> dict:
    return {
        "id": "diff-pack",
        "name": "Diff Pack",
        "version": version,
        "schema_version": "1",
        "controls": [{"control_id": "AC-2", "title": "Account Management"}],
        "rules": list(rules),
    }


# ── the pure diff ────────────────────────────────────────────────────────────


def test_an_added_rule_is_reported_as_added() -> None:
    d = diff_posture_rules(_manifest(), _manifest(_rule("a", 60)))
    assert d.added == ["a"]
    assert d.removed == [] and d.changed == []


def test_a_removed_rule_is_reported_as_removed() -> None:
    d = diff_posture_rules(_manifest(_rule("a", 60)), _manifest())
    assert d.removed == ["a"]
    assert d.added == [] and d.changed == []


def test_a_reparameterized_rule_is_reported_as_changed() -> None:
    d = diff_posture_rules(_manifest(_rule("a", 90)), _manifest(_rule("a", 60)))
    assert d.changed == ["a"]
    assert d.added == [] and d.removed == []


def test_an_unchanged_rule_appears_nowhere() -> None:
    d = diff_posture_rules(_manifest(_rule("a", 60)), _manifest(_rule("a", 60)))
    assert (d.added, d.removed, d.changed) == ([], [], [])
    assert not d.has_changes


def test_changed_carries_both_definitions() -> None:
    """A diff that says only "changed" cannot be reviewed."""
    d = diff_posture_rules(_manifest(_rule("a", 90)), _manifest(_rule("a", 60)))
    before, after = d.definitions["a"]
    assert before["parameters"]["threshold_days"] == 90
    assert after["parameters"]["threshold_days"] == 60


def test_non_posture_rules_are_ignored() -> None:
    other = {"key": "m", "kind": "assert", "definition": {"metric": "x"}}
    d = diff_posture_rules(_manifest(), _manifest(other))
    assert (d.added, d.removed, d.changed) == ([], [], [])


def test_results_are_sorted() -> None:
    d = diff_posture_rules(_manifest(), _manifest(_rule("z", 1), _rule("a", 1)))
    assert d.added == ["a", "z"]


def test_key_ordering_inside_a_definition_is_not_a_change() -> None:
    """Re-serializing a manifest must not read as desired-state drift."""
    old = _manifest({"key": "a", "kind": "posture", "definition": {"x": 1, "y": 2}})
    new = _manifest({"key": "a", "kind": "posture", "definition": {"y": 2, "x": 1}})
    assert diff_posture_rules(old, new).changed == []


# ── the missing-history guard ────────────────────────────────────────────────


def test_an_empty_baseline_is_unknown_not_everything_removed() -> None:
    """Version rows written before the manifest was retained have none.

    Reporting "all rules removed" from missing history fabricates deletions
    that never happened -- worse than admitting the gap.
    """
    d = diff_posture_rules({}, _manifest(_rule("a", 60)))
    assert d.baseline == UNKNOWN_BASELINE
    assert d.removed == []
    assert d.added == []
    assert not d.has_changes


def test_an_empty_target_is_also_unknown() -> None:
    d = diff_posture_rules(_manifest(_rule("a", 60)), {})
    assert d.baseline == UNKNOWN_BASELINE
    assert (d.added, d.removed, d.changed) == ([], [], [])


def test_a_manifest_with_no_rules_key_is_a_real_empty_not_unknown() -> None:
    """Distinct from missing history: this manifest genuinely declares none."""
    old = {
        "id": "p",
        "name": "P",
        "version": "1",
        "schema_version": "1",
        "controls": [{"control_id": "AC-2"}],
    }
    d = diff_posture_rules(old, _manifest(_rule("a", 60)))
    assert d.baseline != UNKNOWN_BASELINE
    assert d.added == ["a"]


# ── the manifest is actually retained per version ────────────────────────────


async def test_installing_stores_the_manifest_on_the_version_row() -> None:
    async with session_scope() as session:
        org = Organization(name=f"DiffOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        pack = await install_pack(
            session, org_id=org.id, manifest=_manifest(_rule("a", 60))
        )
        rows = (
            await session.execute(
                select(CompliancePackVersion).where(CompliancePackVersion.pack_id == pack.id)
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].manifest.get("rules")[0]["key"] == "a"


async def test_upgrading_retains_both_versions_manifests() -> None:
    """Without this, "what changed in my desired state" has no answer."""
    async with session_scope() as session:
        org = Organization(name=f"DiffOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        pack = await install_pack(
            session, org_id=org.id, manifest=_manifest(_rule("a", 90), version="1.0.0")
        )
        await install_pack(
            session, org_id=org.id, manifest=_manifest(_rule("a", 60), version="2.0.0")
        )
        rows = (
            await session.execute(
                select(CompliancePackVersion)
                .where(CompliancePackVersion.pack_id == pack.id)
                .order_by(CompliancePackVersion.id)
            )
        ).scalars().all()
        assert [r.version for r in rows] == ["1.0.0", "2.0.0"]
        d = diff_posture_rules(rows[0].manifest, rows[1].manifest)
        assert d.changed == ["a"]
        before, after = d.definitions["a"]
        assert before["parameters"]["threshold_days"] == 90
        assert after["parameters"]["threshold_days"] == 60
