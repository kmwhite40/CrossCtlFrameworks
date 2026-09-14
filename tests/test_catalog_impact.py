"""Adoption impact: what a revision does to my baselines and authored content."""

from __future__ import annotations

import itertools
import json

from ccf.catalog.diff import CatalogDiff, ControlChange
from ccf.catalog.impact import build_adoption_impact
from ccf.catalog.oscal import OscalCatalog, OscalControl
from ccf.db import session_scope
from ccf.models import (
    KSI,
    Control,
    Framework,
    FrameworkMapping,
    Organization,
    SSPControlEntry,
    SSPProject,
    System,
)


def _diff(**kw: object) -> CatalogDiff:
    base: dict[str, object] = {
        "added": (),
        "removed": (),
        "newly_withdrawn": (),
        "un_withdrawn": (),
        "changed": (),
        "baseline_entered": {},
        "baseline_left": {},
    }
    base.update(kw)
    return CatalogDiff(**base)  # type: ignore[arg-type]


def _candidate(*control_ids: str) -> OscalCatalog:
    c = OscalCatalog(version="5.2.0")
    for cid in control_ids:
        c.controls[cid] = OscalControl(
            canonical_id=cid,
            title="T",
            statement="S",
            guidance="G",
            withdrawn=False,
            incorporated_into=[],
            param_ids=[],
            params=[],
        )
    return c


_ORG_SEQ = itertools.count()


async def _project(session, *, baseline: str = "moderate") -> SSPProject:
    # Organization.name is unique and the schema is migrated once per session,
    # so every test needs its own org.
    org = Organization(name=f"Org-{next(_ORG_SEQ)}")
    session.add(org)
    await session.flush()
    session.add(System(organization_id=org.id, name="Sys", baseline=baseline))
    proj = SSPProject(organization_id=org.id, customer_name="Acme")
    session.add(proj)
    await session.flush()
    return proj


async def test_empty_diff_yields_empty_impact() -> None:
    async with session_scope() as session:
        impact = await build_adoption_impact(session, diff=_diff(), candidate=_candidate("AC-1"))
        assert impact.is_empty() is True


async def test_removed_control_orphans_authored_entry() -> None:
    async with session_scope() as session:
        proj = await _project(session)
        session.add(SSPControlEntry(project_id=proj.id, control_id="AC-2", nist_id="AC-2"))
        await session.flush()
        impact = await build_adoption_impact(
            session, diff=_diff(removed=("AC-2",)), candidate=_candidate("AC-1")
        )
        assert impact.is_empty() is False
        entry = next(e for e in impact.orphaned_entries if e["control_id"] == "AC-2")
        assert entry["reason"] == "removed"
        assert entry["organization_id"] is not None


async def test_withdrawn_control_orphans_authored_entry() -> None:
    async with session_scope() as session:
        proj = await _project(session)
        session.add(SSPControlEntry(project_id=proj.id, control_id="AC-3", nist_id="AC-3"))
        await session.flush()
        impact = await build_adoption_impact(
            session, diff=_diff(newly_withdrawn=("AC-3",)), candidate=_candidate("AC-3")
        )
        entry = next(e for e in impact.orphaned_entries if e["control_id"] == "AC-3")
        assert entry["reason"] == "withdrawn"


async def test_statement_change_marks_narrative_stale() -> None:
    change = ControlChange(
        canonical_id="AC-4",
        title_changed=False,
        statement_changed=True,
        guidance_changed=False,
        params_added=(),
        params_removed=(),
        params_changed=(),
    )
    async with session_scope() as session:
        proj = await _project(session)
        session.add(SSPControlEntry(project_id=proj.id, control_id="AC-4", nist_id="AC-4"))
        await session.flush()
        impact = await build_adoption_impact(
            session, diff=_diff(changed=(change,)), candidate=_candidate("AC-4")
        )
        assert any(e["control_id"] == "AC-4" for e in impact.stale_narratives)
        assert impact.param_drift == []


async def test_param_change_reports_drift_not_stale_narrative() -> None:
    change = ControlChange(
        canonical_id="AC-5",
        title_changed=False,
        statement_changed=False,
        guidance_changed=False,
        params_added=(),
        params_removed=(),
        params_changed=("ac-5_prm_1",),
    )
    async with session_scope() as session:
        proj = await _project(session)
        session.add(SSPControlEntry(project_id=proj.id, control_id="AC-5", nist_id="AC-5"))
        await session.flush()
        impact = await build_adoption_impact(
            session, diff=_diff(changed=(change,)), candidate=_candidate("AC-5")
        )
        assert any(e["control_id"] == "AC-5" for e in impact.param_drift)
        assert impact.stale_narratives == []


async def test_baseline_shift_reports_affected_systems() -> None:
    async with session_scope() as session:
        await _project(session, baseline="moderate")
        impact = await build_adoption_impact(
            session,
            diff=_diff(baseline_entered={"moderate": ("AC-9",)}),
            candidate=_candidate("AC-9"),
        )
        assert impact.systems_affected
        assert impact.systems_affected[0]["entering"] == ["AC-9"]
        assert impact.systems_affected[0]["baseline"] == "moderate"


async def test_systems_on_other_baselines_are_not_reported() -> None:
    async with session_scope() as session:
        await _project(session, baseline="low")
        impact = await build_adoption_impact(
            session,
            diff=_diff(baseline_entered={"high": ("AC-9",)}),
            candidate=_candidate("AC-9"),
        )
        assert impact.systems_affected == []


async def test_dangling_mapping_detected_via_reconcile() -> None:
    """A mapping targeting a control the candidate lacks must surface."""
    async with session_scope() as session:
        fw = Framework(code="NIST_800_53_R5", name="NIST 800-53 Rev 5")
        session.add(fw)
        ctl = Control(identifier="AC-1")
        session.add(ctl)
        await session.flush()
        session.add(
            FrameworkMapping(
                control_id=ctl.id,
                framework_id=fw.id,
                column_key="NIST 800-53 Rev 5",
                value="AC-99",
            )
        )
        await session.flush()
        impact = await build_adoption_impact(
            session, diff=_diff(removed=("AC-99",)), candidate=_candidate("AC-1")
        )
        assert any("AC-99" in json.dumps(m) for m in impact.dangling_mappings)


async def test_ksi_referencing_removed_control_is_reported() -> None:
    async with session_scope() as session:
        session.add(
            KSI(
                identifier="KSI-IAM-07",
                category="IAM",
                name="Securely manage account lifecycle",
                nist_refs=["AC-2", "IA-2"],
            )
        )
        await session.flush()
        impact = await build_adoption_impact(
            session, diff=_diff(removed=("IA-2",)), candidate=_candidate("AC-2")
        )
        assert any(k["ksi_key"] == "KSI-IAM-07" for k in impact.ksi_references)


async def test_to_dict_is_json_serialisable() -> None:
    async with session_scope() as session:
        impact = await build_adoption_impact(
            session, diff=_diff(removed=("AC-2",)), candidate=_candidate("AC-1")
        )
        json.dumps(impact.to_dict())  # must not raise
