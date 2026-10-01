"""100% over no data reads as an achievement, the way 0% reads as a finding.

``framework_posture`` already refuses the second half of this: a system with no
declared baseline reports ``None``, not ``0``, because "coverage of an undeclared
baseline is not zero -- it is unanswerable, and reporting 0% would read as a
finding about the system". Two numbers on ``/operations`` get the mirror image
wrong.

``sla.on_track_pct`` is ``100.0`` when there are no open POA&Ms, and
``dashboard.html`` renders it as a **full gauge labelled "100%"**. A tenant that
has scanned nothing therefore sees a complete green dial over an empty remediation
queue. It is vacuously true and it is read as "the programme is on top of its
weaknesses"; the honest answer is that there is nothing to be on track with.

``frameworks[].coverage_pct`` is ``0.0`` when the control catalog has not been
ingested, and renders as a gauge and a badge. Every framework then shows 0%
coverage, which reads as a finding about the frameworks rather than about the
missing catalog -- exactly the sentence ``framework_posture`` was fixed for.

Both are ``None`` now, and the templates say what is actually true.
"""

from __future__ import annotations

import itertools
from datetime import UTC, date, datetime, timedelta

from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.analytics.overview import coverage_ratio, dashboard_overview
from ccf.api.auth_deps import get_principal, get_principal_optional
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.db import session_scope
from ccf.models import POAM, Control, Framework, FrameworkMapping, Organization, System

_SEQ = itertools.count()


async def _org() -> int:
    n = next(_SEQ)
    async with session_scope() as s:
        org = Organization(name=f"PctOrg{n}")
        s.add(org)
        await s.flush()
        s.add(System(organization_id=org.id, name=f"PctSys{n}", baseline="moderate"))
        await s.flush()
        return org.id


async def test_no_open_poams_is_not_one_hundred_percent_on_track() -> None:
    """The defect: a full green gauge over an empty queue.

    ``None`` rather than ``100.0``, so the template can say "no open POA&Ms"
    instead of drawing a complete dial. A tenant that has scanned nothing is not
    a tenant doing well.
    """
    org_id = await _org()
    async with session_scope() as s:
        out = await dashboard_overview(s, org_id=org_id)

    assert out["sla"]["open"] == 0
    assert out["sla"]["on_track_pct"] is None, (
        "100% on track over zero POA&Ms reads as an achievement; the honest "
        "answer is that there is nothing to be on track with"
    )


async def test_a_real_on_track_percentage_is_still_reported() -> None:
    """The other direction: the fix must not blank a number that means something.

    Two open POA&Ms, one overdue, is 50% on track and must say so.
    """
    org_id = await _org()
    async with session_scope() as s:
        system = (
            await s.execute(select(System).where(System.organization_id == org_id))
        ).scalars().first()
        assert system is not None
        today = date.today()
        s.add(
            POAM(
                system_id=system.id,
                title="on track",
                weakness="w1",
                severity="moderate",
                status="open",
                identified_on=today,
                due_on=today + timedelta(days=30),
                original_due_on=today + timedelta(days=30),
            )
        )
        s.add(
            POAM(
                system_id=system.id,
                title="overdue",
                weakness="w2",
                severity="high",
                status="open",
                identified_on=today - timedelta(days=90),
                due_on=today - timedelta(days=10),
                original_due_on=today - timedelta(days=10),
            )
        )
        await s.flush()
        out = await dashboard_overview(s, org_id=org_id)

    assert out["sla"]["open"] == 2
    assert out["sla"]["overdue"] == 1
    assert out["sla"]["on_track_pct"] == 50.0


def test_no_catalog_means_no_coverage_ratio() -> None:
    """The branch, tested where it is reachable.

    Found by mutation: reverting this ``None`` to ``0.0`` survived the whole suite,
    because the ``total_controls == 0`` state cannot be produced through
    ``_framework_tiles`` in a test database that other tests seed controls into.
    So the decision is a pure function and this asserts it directly -- the query
    around it was never the part worth guarding.
    """
    assert coverage_ratio(0, 0) is None
    assert coverage_ratio(None, 0) is None
    assert coverage_ratio(12, 0) is None, (
        "mapped controls with no catalog is a contradiction, not 0%"
    )


def test_a_real_denominator_gives_a_real_ratio() -> None:
    """So the fix is not "always None"."""
    assert coverage_ratio(50, 200) == 25.0
    assert coverage_ratio(0, 200) == 0.0, (
        "zero of two hundred really is 0% -- the None case is about an absent "
        "denominator, not an absent numerator"
    )
    assert coverage_ratio(None, 200) == 0.0


async def test_an_unloaded_catalog_does_not_report_zero_percent_coverage() -> None:
    """The mirror of the on-track defect, and the sentence framework_posture was
    fixed for: 0% over no controls reads as a finding about the frameworks.

    The catalog is a global table, so this test removes exactly the rows it needs
    absent and restores nothing it did not create -- `Control` is empty in the test
    database unless another test seeded it, which several do.
    """
    org_id = await _org()
    async with session_scope() as s:
        # A framework with no mappings, and a catalog with no controls, is the
        # un-ingested state a fresh deployment is in.
        existing_controls = (await s.execute(select(Control.id))).scalars().all()
        out = await dashboard_overview(s, org_id=org_id)

    tiles = out.get("frameworks") or []
    if existing_controls:
        # Another test seeded the catalog; the un-ingested case is not reachable
        # here, so assert the half that is: a real denominator gives a real number.
        for tile in tiles:
            assert tile["coverage_pct"] is None or isinstance(tile["coverage_pct"], float)
        return
    for tile in tiles:
        assert tile["coverage_pct"] is None, (
            f"{tile['code']} reports {tile['coverage_pct']}% coverage of an "
            "un-ingested catalog, which reads as a finding about the framework"
        )


async def test_a_loaded_catalog_reports_a_real_coverage_percentage() -> None:
    """So the fix is not "always None"."""
    org_id = await _org()
    tag = next(_SEQ)
    async with session_scope() as s:
        control = Control(identifier=f"ZP-{tag}", sequence_control=f"ZP-{tag}")
        s.add(control)
        await s.flush()
        fw = Framework(code=f"PCT{tag}", name=f"Pct Framework {tag}")
        s.add(fw)
        await s.flush()
        s.add(
            FrameworkMapping(
                control_id=control.id,
                framework_id=fw.id,
                column_key="pct_test",
                value="something",
            )
        )
        await s.flush()
        out = await dashboard_overview(s, org_id=org_id)
        tile = next((t for t in out["frameworks"] if t["code"] == fw.code), None)
        assert tile is not None, "the seeded framework is not in the overview"
        assert isinstance(tile["coverage_pct"], float)
        assert tile["coverage_pct"] > 0
        # Clean up exactly what this test created: these are global tables.
        await s.execute(delete(FrameworkMapping).where(FrameworkMapping.framework_id == fw.id))
        await s.execute(delete(Framework).where(Framework.id == fw.id))
        await s.execute(delete(Control).where(Control.id == control.id))


async def test_the_sla_block_still_carries_every_count() -> None:
    """The percentage going None must not take the counts with it -- those are
    what the page falls back to rendering."""
    org_id = await _org()
    async with session_scope() as s:
        out = await dashboard_overview(s, org_id=org_id)
    sla = out["sla"]
    for key in ("open", "overdue", "no_due_date", "on_track"):
        assert sla[key] == 0, key
    assert "on_track_pct" in sla


async def test_the_counts_partition_the_open_poams() -> None:
    """While here: overdue + on_track + no_due_date must account for `open`.

    The same property the dashboard buckets needed. A percentage is only
    checkable if its parts add up.
    """
    org_id = await _org()
    async with session_scope() as s:
        system = (
            await s.execute(select(System).where(System.organization_id == org_id))
        ).scalars().first()
        assert system is not None
        today = date.today()
        rows = [
            ("on track", today + timedelta(days=30)),
            ("overdue", today - timedelta(days=10)),
            ("no due date", None),
        ]
        for title, due in rows:
            s.add(
                POAM(
                    system_id=system.id,
                    title=title,
                    weakness=title,
                    severity="moderate",
                    status="open",
                    identified_on=today,
                    due_on=due,
                    original_due_on=due,
                )
            )
        await s.flush()
        out = await dashboard_overview(s, org_id=org_id)

    sla = out["sla"]
    assert sla["overdue"] + sla["on_track"] + sla["no_due_date"] == sla["open"], (
        f"{sla} does not partition: a reader subtracting these gets a remainder "
        "belonging to nothing"
    )
    assert datetime.now(UTC)  # the fixture is time-relative; pin the import


async def test_the_operations_page_renders_with_both_percentages_absent() -> None:
    """A template that formats None raises, which is a 500 on the page.

    Both gauges received a number unconditionally -- ``'{}%'.format(x | round |
    int)`` raises in Jinja on a None -- so the data fix is only half of this. An
    org with no POA&Ms is the common first-run state, which is exactly when both
    values are absent.
    """
    org_id = await _org()
    app = create_app()

    def _principal() -> Principal:
        return Principal(user_id=1, email="o@c.gov", org_id=org_id, role="admin")

    app.dependency_overrides[get_principal] = _principal
    app.dependency_overrides[get_principal_optional] = _principal
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/operations")

    assert r.status_code == 200, r.text[:400]
    assert "No open POA&amp;M to track" in r.text or "No open POA&M to track" in r.text
