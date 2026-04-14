"""Typer CLI entrypoint (`ccf`)."""
from __future__ import annotations

import asyncio
import json
import sys
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
from .models import Control, Framework, FrameworkMapping, IngestionRun, Worksheet

app = typer.Typer(help="Concord administration & query CLI", no_args_is_help=True)
console = Console()


@app.callback()
def _setup() -> None:
    configure_logging()


@app.command()
def ingest(
    xlsx: Path = typer.Option(
        None, "--xlsx",
        help="Workbook path (defaults to CCF_WORKBOOK_PATH / /data/NIST Cross Mappings Rev. 1.1.xlsx)",
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
            console.print(f"[green]Ingestion {run.status}[/green] — "
                          f"stats: {json.dumps(run.stats, indent=2)}")

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
                    func.ts_rank(Control.search_vector,
                                 func.plainto_tsquery("english", query)).label("rank"),
                )
                .where(Control.search_vector.op("@@")(
                    func.plainto_tsquery("english", query)
                ))
                .order_by(func.ts_rank(Control.search_vector,
                                       func.plainto_tsquery("english", query)).desc())
                .limit(limit)
            )
            rows = (await session.execute(stmt)).all()

        t = Table(title=f"Search: {query}")
        t.add_column("Identifier"); t.add_column("Name"); t.add_column("Rank", justify="right")
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
                await session.execute(
                    select(Control).where(Control.identifier == identifier)
                )
            ).scalar_one_or_none()
            if not ctl:
                console.print(f"[red]Not found: {identifier}[/red]")
                raise typer.Exit(code=1)
            console.print_json(json.dumps({
                "identifier": ctl.identifier,
                "control_name": ctl.control_name,
                "description": ctl.description,
                "assessment_objective": ctl.assessment_objective,
                "fisma_low": ctl.fisma_low,
                "fisma_mod": ctl.fisma_mod,
                "fisma_high": ctl.fisma_high,
            }))

    asyncio.run(_run())


if __name__ == "__main__":
    app()
