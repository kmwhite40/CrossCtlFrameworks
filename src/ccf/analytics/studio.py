"""A safe analytics studio: count a register's records by one or two fields.

Nothing the user types reaches SQL. The user picks a register key and up to
two dimension keys; each key is looked up in :data:`REGISTERS`, a fixed table
mapping keys to SQLAlchemy column objects built here. An unknown key raises
:class:`StudioError` (the page answers 400) -- there is no fallback that
would turn a string into an identifier, and no free-form filter.

Each register carries its own tenant scope, applied in the query itself (not
left to RLS): records with ``organization_id`` filter on it; records without
one scope through a live system (``posture.org_system_subq``), and records
whose ``system_id`` is optional exclude those on a soft-deleted system.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, literal_column, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import FromClause

from ..models import POAM, Risk, System, Task, Vendor
from ..models_evidence import EvidenceObject
from ..models_grc import ControlTest, ControlTestResult
from .posture import org_system_subq

#: Rendered for a NULL group value.
NOT_SET = "(not set)"
MAX_DIMENSIONS = 2


class StudioError(ValueError):
    """An unknown register or dimension, or an invalid combination."""


@dataclass(frozen=True)
class Dimension:
    key: str
    label: str
    column: Any  # a SQLAlchemy column expression, built in this module


@dataclass(frozen=True)
class Register:
    key: str
    label: str
    noun: str
    source: Callable[[], FromClause]
    scope: Callable[[int | None], list[Any]]
    dimensions: tuple[Dimension, ...]

    def dimension(self, key: str) -> Dimension:
        for d in self.dimensions:
            if d.key == key:
                return d
        raise StudioError(f"{key!r} is not a dimension of {self.label}")


def _month(col: Any) -> Any:
    # A literal, not a bind parameter: the same expression appears in SELECT
    # and GROUP BY, and two binds would be two different expressions to
    # Postgres. The format is a constant of this module, never user input.
    return func.to_char(col, literal_column("'YYYY-MM'"))


def _system_optional(col: Any, org_id: int | None) -> Any:
    """A record whose system is optional: none, or one of the org's live ones."""
    return or_(col.is_(None), col.in_(org_system_subq(org_id)))


def _org_eq(col: Any, org_id: int | None) -> list[Any]:
    return [] if org_id is None else [col == org_id]


def _risk_scope(org_id: int | None) -> list[Any]:
    """A risk is the org's if it says so or sits on one of the org's live
    systems (0100: enterprise risks have no system); never one on a
    soft-deleted system."""
    owned = (
        []
        if org_id is None
        else [or_(Risk.organization_id == org_id, Risk.system_id.in_(org_system_subq(org_id)))]
    )
    return [*owned, _system_optional(Risk.system_id, org_id)]


_SYSTEM = Dimension("system", "System", System.name)

REGISTERS: dict[str, Register] = {
    r.key: r
    for r in (
        Register(
            "poams",
            "POA&Ms",
            "POA&M",
            lambda: POAM.__table__.join(System, System.id == POAM.system_id),
            lambda org: [POAM.system_id.in_(org_system_subq(org))],
            (
                Dimension("status", "Status", POAM.status),
                Dimension("severity", "Severity", POAM.severity),
                Dimension("source", "Source", POAM.source),
                Dimension("scanner", "Scanner", POAM.scanner),
                _SYSTEM,
                Dimension("due_month", "Due month", _month(POAM.due_on)),
                Dimension("identified_month", "Identified month", _month(POAM.identified_on)),
            ),
        ),
        Register(
            "risks",
            "Risks",
            "risk",
            lambda: Risk.__table__.outerjoin(System, System.id == Risk.system_id),
            _risk_scope,
            (
                Dimension("register", "Register", Risk.register),
                Dimension("status", "Status", Risk.status),
                Dimension("treatment", "Treatment", Risk.treatment),
                Dimension("category", "Category", Risk.category),
                Dimension("likelihood", "Likelihood (1-5)", Risk.likelihood_score),
                Dimension("impact", "Impact (1-5)", Risk.impact_score),
                _SYSTEM,
            ),
        ),
        Register(
            "test_results",
            "Control test results",
            "test result",
            lambda: ControlTestResult.__table__.join(
                ControlTest, ControlTest.id == ControlTestResult.control_test_id
            ).outerjoin(System, System.id == ControlTest.system_id),
            lambda org: [
                *_org_eq(ControlTest.organization_id, org),
                _system_optional(ControlTest.system_id, org),
            ],
            (
                Dimension("status", "Result", ControlTestResult.status),
                Dimension("method", "Test method", ControlTest.method),
                Dimension("test_source", "Test provenance", ControlTest.source),
                # The test's own primary control, named so: a failure also
                # reaches every control the test declares (posture.evidence),
                # so grouping by this is a count of results, not evidence per
                # control.
                Dimension("control", "Test's primary control", ControlTest.control_id),
                _SYSTEM,
                Dimension("run_month", "Run month", _month(ControlTestResult.run_at)),
            ),
        ),
        Register(
            "evidence",
            "Evidence objects",
            "evidence object",
            lambda: EvidenceObject.__table__.outerjoin(
                System, System.id == EvidenceObject.system_id
            ),
            lambda org: [
                *_org_eq(EvidenceObject.organization_id, org),
                _system_optional(EvidenceObject.system_id, org),
            ],
            (
                Dimension("status", "Review status", EvidenceObject.status),
                Dimension("source_type", "Source type", EvidenceObject.source_type),
                Dimension("framework", "Framework tag", EvidenceObject.framework),
                Dimension("control", "Control tag", EvidenceObject.control_id),
                _SYSTEM,
                Dimension("expires_month", "Expires month", _month(EvidenceObject.expires_on)),
            ),
        ),
        Register(
            "vendors",
            "Vendors",
            "vendor",
            lambda: Vendor.__table__,
            lambda org: _org_eq(Vendor.organization_id, org),
            (
                Dimension("criticality", "Criticality", Vendor.criticality),
                Dimension("status", "Status", Vendor.status),
                Dimension("risk_rating", "Risk rating", Vendor.risk_rating),
                Dimension("service_type", "Service type", Vendor.service_type),
                Dimension("authorization", "Authorization", Vendor.authorization),
            ),
        ),
        Register(
            "tasks",
            "Tasks",
            "task",
            lambda: Task.__table__.outerjoin(System, System.id == Task.system_id),
            lambda org: [
                *_org_eq(Task.organization_id, org),
                _system_optional(Task.system_id, org),
            ],
            (
                Dimension("status", "Status", Task.status),
                Dimension("priority", "Priority", Task.priority),
                Dimension("kind", "Kind", Task.kind),
                Dimension("source", "Source", Task.source),
                _SYSTEM,
                Dimension("due_month", "Due month", _month(Task.due_on)),
            ),
        ),
    )
}


def resolve(register: str, dimensions: list[str]) -> tuple[Register, list[Dimension]]:
    """Keys to allowlisted objects, or :class:`StudioError`."""
    reg = REGISTERS.get(register)
    if reg is None:
        raise StudioError(f"{register!r} is not a register")
    keys = [d for d in dimensions if d]
    if not keys:
        raise StudioError("choose at least one dimension")
    if len(keys) > MAX_DIMENSIONS:
        raise StudioError(f"at most {MAX_DIMENSIONS} dimensions")
    if len(set(keys)) != len(keys):
        raise StudioError("the two dimensions must differ")
    return reg, [reg.dimension(k) for k in keys]


def _label(v: Any) -> str:
    return NOT_SET if v is None or v == "" else str(v)


async def run(
    session: AsyncSession, org_id: int | None, register: str, dimensions: list[str]
) -> dict[str, Any]:
    """Counts of ``register`` grouped by ``dimensions``, scoped to ``org_id``.

    Returns ``rows`` (``values`` tuple, ``n``), ``total`` (the sum of every
    group, which is the number of records in scope) and ``by_first`` (totals
    per first-dimension value, largest first).
    """
    reg, dims = resolve(register, dimensions)
    cols = [d.column.label(f"d{i}") for i, d in enumerate(dims)]
    stmt = (
        select(*cols, func.count().label("n"))
        .select_from(reg.source())
        .where(*reg.scope(org_id))
        .group_by(*[d.column for d in dims])
    )
    raw = (await session.execute(stmt)).all()
    rows = [{"values": tuple(_label(r[i]) for i in range(len(dims))), "n": int(r[-1])} for r in raw]
    rows.sort(key=lambda r: (-r["n"], r["values"]))
    by_first: dict[str, int] = {}
    for r in rows:
        by_first[r["values"][0]] = by_first.get(r["values"][0], 0) + r["n"]
    return {
        "register": reg,
        "dimensions": dims,
        "rows": rows,
        "total": sum(r["n"] for r in rows),
        "by_first": sorted(by_first.items(), key=lambda kv: (-kv[1], kv[0])),
    }


#: The chart's limits: the column macro has four categorical tones, and more
#: than a dozen columns stop being legible. Beyond them, the table is the
#: answer and the page says so.
CHART_MAX_COLUMNS = 12
CHART_MAX_SERIES = 4
_TONES = ("--series-1", "--series-2", "--series-3", "--series-4")


def chart(result: dict[str, Any]) -> dict[str, Any]:
    """Column-chart input for :func:`run`'s result, and what it leaves out.

    One dimension: one series of counts. Two: one stacked series per value of
    the second dimension, when it has at most four values; otherwise the
    chart shows first-dimension totals and ``note`` says the breakdown is in
    the table. The chart never relabels or merges values ("Other"): what it
    cannot show, it omits and names.
    """
    firsts = [k for k, _ in result["by_first"]]
    shown = firsts[:CHART_MAX_COLUMNS]
    notes: list[str] = []
    if len(firsts) > len(shown):
        notes.append(
            f"The chart shows the {len(shown)} largest of {len(firsts)} "
            f"{result['dimensions'][0].label.lower()} values; the table lists all."
        )
    totals = dict(result["by_first"])
    series: list[dict[str, Any]]
    stacked = False
    if len(result["dimensions"]) == 2:
        seconds = sorted({r["values"][1] for r in result["rows"]})
        if len(seconds) <= CHART_MAX_SERIES:
            cell = {r["values"]: r["n"] for r in result["rows"]}
            series = [
                {
                    "name": s,
                    "values": [cell.get((f, s), 0) for f in shown],
                    "tone": _TONES[i],
                }
                for i, s in enumerate(seconds)
            ]
            stacked = True
        else:
            series = [{"name": "Count", "values": [totals[f] for f in shown], "tone": _TONES[0]}]
            notes.append(
                f"{result['dimensions'][1].label} has {len(seconds)} values, more than the "
                f"chart's {CHART_MAX_SERIES} colours; the chart shows totals and the table "
                "has the breakdown."
            )
    else:
        series = [{"name": "Count", "values": [totals[f] for f in shown], "tone": _TONES[0]}]
    return {"labels": shown, "series": series, "stacked": stacked, "notes": notes}
