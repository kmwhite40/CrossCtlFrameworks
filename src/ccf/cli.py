"""Typer CLI entrypoint (`ccf`)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
import uvicorn
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select

from .config import get_settings
from .db import session_scope
from .etl import ingest_workbook
from .logging import configure_logging
from .models import (
    Control,
    Framework,
    FrameworkMapping,
    IngestionRun,
    ScoringControl,
    ScoringStatus,
    SSPControlEntry,
    SSPProject,
    Worksheet,
)
from .scoring.engine import score_system
from .scoring.seed import seed_scoring_controls
from .ssp.generator import generate_ssp_docx
from .ssp.seed import entry_to_dict

app = typer.Typer(help="Concord administration & query CLI", no_args_is_help=True)
console = Console()


@app.callback()
def _setup() -> None:
    configure_logging()


@app.command()
def ingest(
    xlsx: Path = typer.Option(
        None,
        "--xlsx",
        help=(
            "Workbook path (defaults to CCF_WORKBOOK_PATH / "
            "/data/NIST Cross Mappings Rev. 1.1.xlsx)"
        ),
    ),
) -> None:
    """Ingest the NIST Cross Mappings workbook into Postgres."""
    settings = get_settings()
    xlsx = xlsx or settings.workbook_path
    if not xlsx.is_file():
        console.print(f"[red]Workbook not found: {xlsx}[/red]")
        raise typer.Exit(code=2)

    async def _run() -> None:
        async with session_scope() as session:
            run = await ingest_workbook(session, xlsx)
            console.print(
                f"[green]Ingestion {run.status}[/green] — stats: {json.dumps(run.stats, indent=2)}"
            )

    asyncio.run(_run())


@app.command()
def serve(
    host: str = typer.Option(None, "--host"),
    port: int = typer.Option(None, "--port"),
    reload: bool = typer.Option(False, "--reload"),
) -> None:
    """Run the FastAPI web application."""
    settings = get_settings()
    uvicorn.run(
        "ccf.api.main:app",
        host=host or settings.api_host,
        port=port or settings.api_port,
        reload=reload,
    )


@app.command()
def stats() -> None:
    """Print row counts and the most recent ingestion run."""

    async def _run() -> None:
        async with session_scope() as session:
            c = (await session.execute(select(func.count(Control.id)))).scalar_one()
            m = (await session.execute(select(func.count(FrameworkMapping.id)))).scalar_one()
            w = (await session.execute(select(func.count(Worksheet.id)))).scalar_one()
            f = (await session.execute(select(func.count(Framework.id)))).scalar_one()
            last_run = (
                await session.execute(
                    select(IngestionRun).order_by(IngestionRun.id.desc()).limit(1)
                )
            ).scalar_one_or_none()

        t = Table(title="Concord — inventory", show_lines=False)
        t.add_column("Entity")
        t.add_column("Count", justify="right")
        t.add_row("Controls", str(c))
        t.add_row("Framework mappings", str(m))
        t.add_row("Frameworks", str(f))
        t.add_row("Worksheets", str(w))
        console.print(t)
        if last_run:
            console.print(f"Last ingestion: {last_run.started_at}  status={last_run.status}")

    asyncio.run(_run())


@app.command()
def search(
    query: str = typer.Argument(..., help="Full-text search query"),
    limit: int = typer.Option(20, "--limit"),
) -> None:
    """Search controls (FTS) by keyword."""

    async def _run() -> None:
        async with session_scope() as session:
            stmt = (
                select(
                    Control.identifier,
                    Control.control_name,
                    func.ts_rank(
                        Control.search_vector, func.plainto_tsquery("english", query)
                    ).label("rank"),
                )
                .where(Control.search_vector.op("@@")(func.plainto_tsquery("english", query)))
                .order_by(
                    func.ts_rank(
                        Control.search_vector, func.plainto_tsquery("english", query)
                    ).desc()
                )
                .limit(limit)
            )
            rows = (await session.execute(stmt)).all()

        t = Table(title=f"Search: {query}")
        t.add_column("Identifier")
        t.add_column("Name")
        t.add_column("Rank", justify="right")
        for r in rows:
            t.add_row(r.identifier, (r.control_name or "")[:80], f"{r.rank:.3f}")
        console.print(t)

    asyncio.run(_run())


@app.command()
def show(identifier: str) -> None:
    """Print a single control as JSON."""

    async def _run() -> None:
        async with session_scope() as session:
            ctl = (
                await session.execute(select(Control).where(Control.identifier == identifier))
            ).scalar_one_or_none()
            if not ctl:
                console.print(f"[red]Not found: {identifier}[/red]")
                raise typer.Exit(code=1)
            console.print_json(
                json.dumps(
                    {
                        "identifier": ctl.identifier,
                        "control_name": ctl.control_name,
                        "description": ctl.description,
                        "assessment_objective": ctl.assessment_objective,
                        "fisma_low": ctl.fisma_low,
                        "fisma_mod": ctl.fisma_mod,
                        "fisma_high": ctl.fisma_high,
                    }
                )
            )

    asyncio.run(_run())


@app.command(name="scoring-seed")
def scoring_seed(
    source: Path = typer.Option(
        None,
        "--source",
        help="Scoring matrix workbook (.xlsx) or seed.json; defaults to the committed seed.",
    ),
) -> None:
    """Load (or refresh) the CMMC L2 scoring matrix into ccf.scoring_controls."""

    async def _run() -> None:
        async with session_scope() as session:
            result = await seed_scoring_controls(session, source)
        console.print(f"[green]Scoring matrix loaded[/green] — {json.dumps(result)}")

    asyncio.run(_run())


@app.command(name="score")
def score(system_id: int = typer.Argument(..., help="System id to score")) -> None:
    """Print the live SPRS score for a system."""

    async def _run() -> None:
        async with session_scope() as session:
            controls = [
                {"control_id": c.control_id, "domain": c.domain, "point_value": c.point_value}
                for c in (await session.execute(select(ScoringControl))).scalars()
            ]
            states = {
                cid: st
                for cid, st in (
                    await session.execute(
                        select(ScoringControl.control_id, ScoringStatus.state)
                        .join(ScoringStatus, ScoringStatus.scoring_control_id == ScoringControl.id)
                        .where(ScoringStatus.system_id == system_id)
                    )
                ).all()
            }
        summary = score_system(controls, states)
        console.print(
            f"[bold]SPRS score: {summary.score}/110[/bold] "
            f"({summary.percentage}%) - minus {summary.deductions_total} pts, "
            f"SSP present: {summary.ssp_present}"
        )

    asyncio.run(_run())


@app.command(name="ssp-generate")
def ssp_generate(
    project_id: int = typer.Argument(..., help="SSP project id"),
    out: Path = typer.Option("ssp.docx", "--out", help="Output .docx path"),
) -> None:
    """Generate the FedRAMP Appendix A SSP .docx for a saved project."""

    async def _run() -> None:
        async with session_scope() as session:
            proj = (
                await session.execute(select(SSPProject).where(SSPProject.id == project_id))
            ).scalar_one_or_none()
            if proj is None:
                console.print(f"[red]SSP project {project_id} not found[/red]")
                raise typer.Exit(code=1)
            entries = (
                (
                    await session.execute(
                        select(SSPControlEntry)
                        .where(SSPControlEntry.project_id == project_id)
                        .order_by(SSPControlEntry.sort_order)
                    )
                )
                .scalars()
                .all()
            )
            meta = {
                "customer_name": proj.customer_name,
                "system_name": proj.system_name,
                "title": proj.title,
                "version": proj.version,
                "prepared_by": proj.prepared_by,
                "document_date": proj.document_date.strftime("%m/%d/%Y")
                if proj.document_date
                else "",
            }
        data = generate_ssp_docx(meta, [entry_to_dict(e) for e in entries])
        Path(out).write_bytes(data)
        console.print(f"[green]Wrote[/green] {out} ({len(data):,} bytes, {len(entries)} controls)")

    asyncio.run(_run())


if __name__ == "__main__":
    app()
