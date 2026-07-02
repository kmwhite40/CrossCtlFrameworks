"""Typer CLI entrypoint (`ccf`)."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer
import uvicorn
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select

from .auth import hash_password, new_api_token
from .config import get_settings
from .db import session_scope
from .etl import ingest_workbook
from .etl.sources import poll as poll_sources
from .etl.sources import seed_sources
from .governance import conmon, digest, insights, scheduler
from .logging import configure_logging
from .models import (
    CatalogSource,
    Control,
    Framework,
    FrameworkMapping,
    IngestionRun,
    Organization,
    ScoringControl,
    ScoringStatus,
    SSPControlEntry,
    SSPProject,
    User,
    Worksheet,
)
from .scoring.engine import score_system
from .scoring.seed import seed_scoring_controls
from .ssp.generator import generate_ssp_docx
from .ssp.seed import entry_to_dict
from .ssp.templates_seed import seed_statement_templates

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


@app.command(name="sources-seed")
def sources_seed() -> None:
    """Register the default authoritative catalog sources (NIST OSCAL, etc.)."""

    async def _run() -> None:
        async with session_scope() as session:
            created = await seed_sources(session)
        console.print(f"[green]Seeded {created} new catalog source(s).[/green]")

    asyncio.run(_run())


@app.command(name="sources-check")
def sources_check(
    key: str = typer.Option(None, "--key", help="Check only this source key"),
    include_disabled: bool = typer.Option(False, "--all", help="Include disabled sources"),
) -> None:
    """Poll authoritative sources and report catalog drift."""

    async def _run() -> None:
        async with session_scope() as session:
            checks = await poll_sources(session, only_key=key, include_disabled=include_disabled)
            # Resolve source keys for display before the session closes.
            src_keys = {
                s.id: s.key for s in (await session.execute(select(CatalogSource))).scalars().all()
            }
            rows = [
                (
                    src_keys.get(c.source_id, str(c.source_id)),
                    c.status,
                    c.detail.get("revision") or "",
                    c.detail.get("counts") or "",
                )
                for c in checks
            ]

        t = Table(title="Concord — catalog drift check", show_lines=False)
        t.add_column("Source")
        t.add_column("Status")
        t.add_column("Revision")
        t.add_column("Changes")
        for src, status, rev, counts in rows:
            color = {"changed": "yellow", "ingested": "green", "error": "red"}.get(status, "white")
            t.add_row(src, f"[{color}]{status}[/{color}]", str(rev), str(counts))
        console.print(t)
        if not rows:
            console.print("[dim]No sources checked. Run `ccf sources-seed` first.[/dim]")

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


@app.command(name="templates-seed")
def templates_seed(
    overwrite: bool = typer.Option(False, "--overwrite", help="Refresh existing template bodies"),
) -> None:
    """Load the canned implementation-statement library into ccf.statement_templates."""

    async def _run() -> None:
        async with session_scope() as session:
            touched = await seed_statement_templates(session, overwrite=overwrite)
        console.print(f"[green]Statement templates loaded[/green] — {touched} touched")

    asyncio.run(_run())


@app.command(name="conmon-scan")
def conmon_scan() -> None:
    """Run a continuous-monitoring scan: open tasks/alerts for unhealthy controls."""

    async def _run() -> None:
        async with session_scope() as session:
            result = await conmon.scan(session, today=datetime.now(UTC).date())
        console.print(f"[green]ConMon scan complete[/green] — {json.dumps(result)}")

    asyncio.run(_run())


@app.command(name="notify-digest")
def notify_digest() -> None:
    """Run the org-level alert digest (ATO expiry, catalog drift, reviews due)."""

    async def _run() -> None:
        async with session_scope() as session:
            counts = await digest.run(session, today=datetime.now(UTC).date())
        console.print(f"[green]Alert digest complete[/green] — {json.dumps(counts)}")

    asyncio.run(_run())


@app.command(name="scheduler")
def scheduler_run() -> None:
    """Run one full automation cycle (catalog poll + ConMon + digest + collection)."""

    async def _run() -> None:
        result = await scheduler.run_cycle()
        console.print("[green]Automation cycle complete[/green]")
        console.print_json(json.dumps(result, default=str))

    asyncio.run(_run())


@app.command(name="data-quality")
def data_quality() -> None:
    """Run GRC data-quality checks (gaps that would undermine an assessment)."""

    async def _run() -> None:
        async with session_scope() as session:
            result = await insights.data_quality(session)
        console.print(
            f"[green]Data quality[/green] — {result['total_issues']} issue(s); "
            f"failing: {', '.join(result['failing_checks']) or 'none'}"
        )

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


@app.command(name="user-create")
def user_create(
    email: str = typer.Argument(..., help="User email (login)"),
    org: str = typer.Option("Default", "--org", help="Organization name (created if missing)"),
    role: str = typer.Option("admin", "--role", help="admin | control_owner | assessor | viewer"),
    password: str = typer.Option(
        ..., "--password", prompt=True, hide_input=True, confirmation_prompt=True
    ),
) -> None:
    """Create (or update) a user with a password + API token for authentication."""

    async def _run() -> None:
        async with session_scope() as session:
            organization = (
                await session.execute(select(Organization).where(Organization.name == org))
            ).scalar_one_or_none()
            if organization is None:
                organization = Organization(name=org)
                session.add(organization)
                await session.flush()
            user = (
                await session.execute(select(User).where(User.email == email))
            ).scalar_one_or_none()
            if user is None:
                user = User(email=email, organization_id=organization.id)
                session.add(user)
            user.role = role
            user.active = True
            user.password_hash = hash_password(password)
            token = new_api_token()
            user.api_token = token
            await session.flush()
        console.print(
            f"[green]User ready[/green] — {email} (org={org}, role={role})\n"
            f"API token: [bold]{token}[/bold]"
        )

    asyncio.run(_run())


@app.command(name="reliability-check")
def reliability_check(
    json_out: bool = typer.Option(False, "--json", help="Emit raw JSON instead of a table"),
) -> None:
    """Run system reliability / operational-readiness checks."""
    from .reliability import run_checks, summarize  # noqa: PLC0415

    async def _run() -> dict[str, Any]:
        async with session_scope() as session:
            return summarize(await run_checks(session))

    summary = asyncio.run(_run())
    if json_out:
        console.print_json(json.dumps(summary, default=str))
    else:
        colors = {"pass": "green", "warn": "yellow", "fail": "red"}
        t = Table(title="Concord — reliability check", show_lines=False)
        t.add_column("Check")
        t.add_column("Status")
        t.add_column("Message")
        for c in summary["checks"]:
            color = colors.get(c["status"], "white")
            t.add_row(c["name"], f"[{color}]{c['status'].upper()}[/{color}]", c["message"])
        console.print(t)
        overall = str(summary["overall"])
        console.print(
            f"Overall: [{colors.get(overall, 'white')}]{overall.upper()}[/] {summary['counts']}"
        )
    if summary["overall"] == "fail":
        raise typer.Exit(code=1)


# --- FedRAMP 20x sub-app ----------------------------------------------------

fedramp20x_app = typer.Typer(help="FedRAMP 20x — KSIs, validation, readiness, package")
app.add_typer(fedramp20x_app, name="fedramp20x")


@fedramp20x_app.command(name="seed-ksi")
def fr20x_seed_ksi(
    path: Path = typer.Option(None, "--path", help="Catalog JSON (defaults to bundled seed)"),
) -> None:
    """Seed / refresh the FedRAMP 20x KSI catalog (idempotent)."""
    from .fedramp20x.catalog import seed_ksis  # noqa: PLC0415

    async def _run() -> None:
        async with session_scope() as session:
            result = await seed_ksis(session, path)
        console.print(f"[green]KSI catalog seeded[/green] — {result}")

    asyncio.run(_run())


@fedramp20x_app.command(name="readiness")
def fr20x_readiness(system_id: int = typer.Option(..., "--system-id")) -> None:
    """Print FedRAMP 20x readiness for a system (no snapshot persisted)."""
    from .fedramp20x.readiness import score_system  # noqa: PLC0415

    async def _run() -> dict[str, object]:
        async with session_scope() as session:
            return await score_system(session, system_id=system_id, persist=False)

    console.print_json(json.dumps(asyncio.run(_run()), default=str))


@fedramp20x_app.command(name="validate")
def fr20x_validate(system_id: int = typer.Option(..., "--system-id")) -> None:
    """Run deterministic KSI validation for a system and persist a snapshot."""
    from .fedramp20x.readiness import score_system  # noqa: PLC0415
    from .fedramp20x.validation import validate_system  # noqa: PLC0415

    async def _run() -> tuple[list[Any], dict[str, Any]]:
        async with session_scope() as session:
            results = await validate_system(session, system_id=system_id)
            score = await score_system(session, system_id=system_id, persist=True)
            return results, score

    results, score = asyncio.run(_run())
    console.print(
        f"[green]Validated {len(results)} KSIs[/green] — "
        f"readiness {score['readiness_pct']}% ({score['status']})"
    )
    console.print_json(json.dumps(results, default=str))


@fedramp20x_app.command(name="export-package")
def fr20x_export(
    system_id: int = typer.Option(..., "--system-id"),
    fmt: str = typer.Option("json", "--format", help="json | markdown | oscal | docx | bundle"),
    out: Path = typer.Option(None, "--out", help="Write to a file instead of stdout"),
) -> None:
    """Export the FedRAMP 20x authorization-package foundation."""
    from .fedramp20x import package as pkg_mod  # noqa: PLC0415

    binary_formats = {"docx", "bundle"}

    async def _run() -> str | bytes:
        async with session_scope() as session:
            pkg = await pkg_mod.build_package(session, system_id=system_id)
        if fmt == "markdown":
            return pkg_mod.render_markdown(pkg)
        if fmt == "oscal":
            return json.dumps(pkg_mod.to_oscal_shaped(pkg), indent=2, default=str)
        if fmt == "docx":
            return pkg_mod.to_docx(pkg)
        if fmt == "bundle":
            return pkg_mod.to_bundle(pkg)
        return json.dumps(pkg, indent=2, default=str)

    data = asyncio.run(_run())
    if fmt in binary_formats and not out:
        console.print(f"[red]--out is required for --format {fmt} (binary output).[/red]")
        raise typer.Exit(code=2)
    if out:
        if isinstance(data, bytes):
            Path(out).write_bytes(data)
        else:
            Path(out).write_text(data, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {out} ({len(data):,} bytes)")
    else:
        console.print(data)


@fedramp20x_app.command(name="list-gaps")
def fr20x_gaps(system_id: int = typer.Option(..., "--system-id")) -> None:
    """List KSIs that are failing, warning, or need manual/assessor review."""
    from .models import KSI, KSIState  # noqa: PLC0415

    async def _run() -> list[dict[str, object]]:
        async with session_scope() as session:
            rows = (
                await session.execute(
                    select(KSI.identifier, KSI.name, KSIState.status)
                    .join(KSIState, KSIState.ksi_id == KSI.id)
                    .where(
                        KSIState.system_id == system_id,
                        KSIState.status.in_(("fail", "warn", "manual_review_required")),
                    )
                    .order_by(KSI.sort_order)
                )
            ).all()
            return [{"ksi": r[0], "name": r[1], "status": r[2]} for r in rows]

    gaps = asyncio.run(_run())
    if not gaps:
        console.print("[green]No open KSI gaps.[/green]")
        return
    t = Table(title=f"FedRAMP 20x KSI gaps — system {system_id}")
    t.add_column("KSI")
    t.add_column("Status")
    t.add_column("Name")
    for g in gaps:
        t.add_row(str(g["ksi"]), str(g["status"]), str(g["name"]))
    console.print(t)


@fedramp20x_app.command(name="dependency-check")
def fr20x_dep_check(system_id: int = typer.Option(..., "--system-id")) -> None:
    """Summarize FedRAMP-authorized vs. non-authorized dependencies for a system."""
    from .models import FedRAMPDependency  # noqa: PLC0415

    async def _run() -> list[FedRAMPDependency]:
        async with session_scope() as session:
            return list(
                (
                    await session.execute(
                        select(FedRAMPDependency).where(FedRAMPDependency.system_id == system_id)
                    )
                )
                .scalars()
                .all()
            )

    deps = asyncio.run(_run())
    if not deps:
        console.print("[yellow]No dependencies recorded for this system.[/yellow]")
        return
    t = Table(title=f"FedRAMP dependencies — system {system_id}")
    t.add_column("Name")
    t.add_column("Provider")
    t.add_column("FedRAMP status")
    t.add_column("Risk")
    for d in deps:
        t.add_row(d.name, d.provider or "", d.fedramp_status, d.dependency_risk or "")
    console.print(t)


@fedramp20x_app.command(name="monitor")
def fr20x_monitor() -> None:
    """Continuous-monitoring sweep: re-validate all 20x systems and report drift."""
    from .fedramp20x.monitoring import scan  # noqa: PLC0415

    async def _run() -> dict[str, Any]:
        async with session_scope() as session:
            return await scan(session)

    out = asyncio.run(_run())
    console.print(
        f"[green]Scanned {out['systems_scanned']} system(s)[/green] — "
        f"{out['drift_events']} with KSI drift"
    )
    console.print_json(json.dumps(out.get("systems", []), default=str))


oscal_app = typer.Typer(help="OSCAL — validate exports against official or structural schema")
app.add_typer(oscal_app, name="oscal")


@oscal_app.command(name="validate")
def oscal_validate(
    path: str = typer.Option(..., "--path", help="Path to an OSCAL JSON document"),
    kind: str = typer.Option("auto", "--kind", help="ssp|component|poam|assessment|auto"),
) -> None:
    """Validate an OSCAL document; exits non-zero when validation fails."""
    from pathlib import Path  # noqa: PLC0415

    from .oscal import validate_document  # noqa: PLC0415

    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]Could not read {path}: {e}[/red]")
        raise typer.Exit(2) from e
    report = validate_document(doc, kind=kind)
    for w in report.warnings:
        console.print(f"[yellow]warning:[/yellow] {w}")
    if report.ok:
        console.print(f"[green]VALID[/green] — {report.kind} ({report.mode} validation)")
        return
    console.print(f"[red]INVALID[/red] — {report.kind} ({report.mode} validation):")
    for err in report.errors:
        console.print(f"  [red]•[/red] {err}")
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
