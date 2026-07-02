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


ai_agents_app = typer.Typer(help="AI agent governance — inventory, risk, approval, kill-switch")
app.add_typer(ai_agents_app, name="ai-agents")


@ai_agents_app.command(name="list")
def ai_agents_list() -> None:
    """List inventoried AI agents."""
    from .models_ai_agents import AiAgent  # noqa: PLC0415

    async def _run() -> list[tuple[int, str, str | None, str]]:
        async with session_scope() as session:
            rows = (await session.execute(select(AiAgent).order_by(AiAgent.name))).scalars().all()
            return [(a.id, a.name, a.risk_rating, a.approval_status) for a in rows]

    for aid, name, rating, status in asyncio.run(_run()):
        console.print(f"[cyan]#{aid}[/cyan] {name} — risk {rating or '?'}, {status}")


@ai_agents_app.command(name="create")
def ai_agents_create(
    name: str = typer.Option(..., "--name"),
    autonomy: str = typer.Option("low", "--autonomy"),
    production: bool = typer.Option(False, "--production/--no-production"),
) -> None:
    """Inventory a new AI agent (scores risk on creation)."""
    from .ai_governance import risk_assess  # noqa: PLC0415
    from .models_ai_agents import AiAgent  # noqa: PLC0415

    async def _run() -> tuple[int, str]:
        async with session_scope() as session:
            agent = AiAgent(name=name, autonomy_level=autonomy, production_access=production)
            session.add(agent)
            await session.flush()
            a = await risk_assess(session, agent, actor="cli")
            await session.commit()
            return agent.id, a.rating

    aid, rating = asyncio.run(_run())
    console.print(f"[green]agent #{aid}[/green] created — risk {rating}")


@ai_agents_app.command(name="risk-assess")
def ai_agents_risk_assess(agent_id: int = typer.Option(..., "--agent-id")) -> None:
    """Re-score an agent's risk."""
    from .ai_governance import risk_assess  # noqa: PLC0415
    from .models_ai_agents import AiAgent  # noqa: PLC0415

    async def _run() -> str:
        async with session_scope() as session:
            agent = await session.get(AiAgent, agent_id)
            if agent is None:
                return "not_found"
            a = await risk_assess(session, agent, actor="cli")
            await session.commit()
            return f"{a.score} ({a.rating})"

    out = asyncio.run(_run())
    if out == "not_found":
        console.print("[red]Agent not found.[/red]")
        raise typer.Exit(1)
    console.print(f"Risk: [cyan]{out}[/cyan]")


@ai_agents_app.command(name="approve")
def ai_agents_approve(agent_id: int = typer.Option(..., "--agent-id")) -> None:
    """Approve an AI agent."""
    _ai_agent_decision(agent_id, "approved", None)


@ai_agents_app.command(name="kill-switch")
def ai_agents_kill_switch(
    agent_id: int = typer.Option(..., "--agent-id"),
    reason: str = typer.Option("", "--reason"),
) -> None:
    """Engage an AI agent's kill-switch."""
    from .ai_governance import engage_kill_switch  # noqa: PLC0415
    from .models_ai_agents import AiAgent  # noqa: PLC0415

    async def _run() -> str:
        async with session_scope() as session:
            agent = await session.get(AiAgent, agent_id)
            if agent is None:
                return "not_found"
            await engage_kill_switch(session, agent, reason=reason or None, actor="cli")
            await session.commit()
            return agent.kill_switch_status

    out = asyncio.run(_run())
    if out == "not_found":
        console.print("[red]Agent not found.[/red]")
        raise typer.Exit(1)
    console.print(f"Kill-switch: [red]{out}[/red]")


def _ai_agent_decision(agent_id: int, decision: str, note: str | None) -> None:
    from .ai_governance import review_agent  # noqa: PLC0415
    from .models_ai_agents import AiAgent  # noqa: PLC0415

    async def _run() -> str:
        async with session_scope() as session:
            agent = await session.get(AiAgent, agent_id)
            if agent is None:
                return "not_found"
            await review_agent(session, agent, decision=decision, reviewer="cli", note=note)
            await session.commit()
            return agent.approval_status

    out = asyncio.run(_run())
    if out == "not_found":
        console.print("[red]Agent not found.[/red]")
        raise typer.Exit(1)
    console.print(f"Agent {agent_id}: [green]{out}[/green]")


ai_actions_app = typer.Typer(help="Typed AI GRC actions — list, run, review, approve/reject")
app.add_typer(ai_actions_app, name="ai-actions")


@ai_actions_app.command(name="list")
def ai_actions_list() -> None:
    """List the registered typed AI actions."""
    from .ai_actions import ACTIONS  # noqa: PLC0415

    for a in ACTIONS.values():
        mut = f" → {a.allowed_mutation}" if a.allowed_mutation else ""
        console.print(f"[cyan]{a.key}[/cyan] — {a.title}{mut}")


@ai_actions_app.command(name="run")
def ai_actions_run(
    action_key: str = typer.Argument(...),
    entity_type: str = typer.Option(..., "--entity-type"),
    entity_id: str = typer.Option(..., "--entity-id"),
) -> None:
    """Run a typed AI action against an entity (deterministic stub)."""
    from .ai_actions import run_action, service  # noqa: PLC0415

    async def _run() -> tuple[int, str]:
        async with session_scope() as session:
            try:
                r = await run_action(
                    session, action_key=action_key, entity_type=entity_type,
                    entity_id=entity_id, org_id=None, actor="cli",
                )
            except service.AiActionError as e:
                await session.commit()
                return -1, str(e)
            await session.commit()
            return r.id, r.status

    rid, status = asyncio.run(_run())
    if rid < 0:
        console.print(f"[red]{status}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]run #{rid}[/green] — status {status}")


@ai_actions_app.command(name="review-queue")
def ai_actions_review_queue() -> None:
    """List AI action runs awaiting human review."""
    from .models_ai_actions import AiActionRun  # noqa: PLC0415

    async def _run() -> list[tuple[int, str, str]]:
        async with session_scope() as session:
            rows = (
                await session.execute(
                    select(AiActionRun).where(AiActionRun.status == "pending_review")
                )
            ).scalars().all()
            return [(r.id, r.action_key, f"{r.entity_type}:{r.entity_id}") for r in rows]

    for rid, key, target in asyncio.run(_run()):
        console.print(f"[cyan]#{rid}[/cyan] {key} → {target}")


@ai_actions_app.command(name="approve")
def ai_actions_approve(run_id: int = typer.Option(..., "--run-id")) -> None:
    """Approve an AI action run (applies its declared mutation)."""
    _ai_decision(run_id, approve=True, reason=None)


@ai_actions_app.command(name="reject")
def ai_actions_reject(
    run_id: int = typer.Option(..., "--run-id"),
    reason: str = typer.Option("", "--reason"),
) -> None:
    """Reject an AI action run (record preserved)."""
    _ai_decision(run_id, approve=False, reason=reason or None)


def _ai_decision(run_id: int, *, approve: bool, reason: str | None) -> None:
    from .ai_actions import service  # noqa: PLC0415
    from .models_ai_actions import AiActionRun  # noqa: PLC0415

    async def _run() -> str:
        async with session_scope() as session:
            run = await session.get(AiActionRun, run_id)
            if run is None:
                return "not_found"
            try:
                if approve:
                    await service.approve_run(session, run, reviewer="cli")
                else:
                    await service.reject_run(session, run, reviewer="cli", note=reason)
            except service.AiActionError as e:
                await session.commit()
                return f"blocked: {e}"
            await session.commit()
            return run.status

    status = asyncio.run(_run())
    if status == "not_found":
        console.print("[red]Run not found.[/red]")
        raise typer.Exit(1)
    console.print(f"Run {run_id}: [cyan]{status}[/cyan]")


package_app = typer.Typer(help="Authorization packages — list, diff, replay")
app.add_typer(package_app, name="package")


@package_app.command(name="list")
def package_list() -> None:
    """List persisted authorization packages."""
    from .models_packages import AuthorizationPackage  # noqa: PLC0415

    async def _run() -> list[tuple[int, str, float | None, int]]:
        async with session_scope() as session:
            rows = (
                await session.execute(
                    select(AuthorizationPackage).order_by(AuthorizationPackage.id.desc())
                )
            ).scalars().all()
            return [(p.id, p.label, p.readiness_pct, p.fact_count) for p in rows]

    for pid, label, pct, facts in asyncio.run(_run()):
        console.print(f"[cyan]#{pid}[/cyan] {label} — readiness {pct}%, {facts} facts")


@package_app.command(name="diff")
def package_diff(
    from_id: int = typer.Option(..., "--from", help="From package id"),
    to_id: int = typer.Option(..., "--to", help="To package id"),
) -> None:
    """Diff two persisted authorization packages."""
    from .packages import diff_packages  # noqa: PLC0415

    async def _run() -> dict[str, Any]:
        async with session_scope() as session:
            diff = await diff_packages(session, org_id=None, from_id=from_id, to_id=to_id)
            await session.commit()
            return diff.summary

    s = asyncio.run(_run())
    console.print(
        f"[green]+{s['added']}[/green] / [red]-{s['removed']}[/red] / "
        f"[yellow]~{s['changed']}[/yellow] fact changes"
    )


@package_app.command(name="replay")
def package_replay(
    package: int = typer.Option(..., "--package", help="Package id"),
) -> None:
    """Replay a package's facts against the live DB and report drift."""
    from .models_packages import AuthorizationPackage  # noqa: PLC0415
    from .packages import replay_package  # noqa: PLC0415

    async def _run() -> str:
        async with session_scope() as session:
            pkg = await session.get(AuthorizationPackage, package)
            if pkg is None:
                return "not_found"
            run = await replay_package(session, org_id=None, package=pkg)
            await session.commit()
            return run.status

    status = asyncio.run(_run())
    if status == "not_found":
        console.print("[red]Package not found.[/red]")
        raise typer.Exit(1)
    console.print(f"Replay result: [cyan]{status}[/cyan]")


@fedramp20x_app.command(name="delta")
def fr20x_delta(
    system_id: int = typer.Option(..., "--system-id"),
    since: str = typer.Option("", "--since", help="ISO date; compare to the package on/before it"),
) -> None:
    """Print an assessor-facing authorization delta memo for a system."""
    import contextlib  # noqa: PLC0415
    from datetime import date as _date  # noqa: PLC0415

    from .packages import delta_memo  # noqa: PLC0415

    since_date = None
    if since:
        with contextlib.suppress(ValueError):
            since_date = _date.fromisoformat(since)

    async def _run() -> str:
        async with session_scope() as session:
            memo = await delta_memo(
                session, org_id=None, system_id=system_id, since=since_date
            )
            await session.commit()
            return memo.body

    console.print(asyncio.run(_run()))


self_assess_app = typer.Typer(help="Concord-on-Concord — self-assess the platform")
app.add_typer(self_assess_app, name="self-assess")


@self_assess_app.command(name="init")
def self_assess_init() -> None:
    """Seed the Concord Platform system + self-assurance pack."""
    from .self_assurance import init_self_assurance  # noqa: PLC0415

    async def _run() -> dict[str, Any]:
        async with session_scope() as session:
            out = await init_self_assurance(session, actor="cli")
            await session.commit()
            return out

    out = asyncio.run(_run())
    console.print(
        f"[green]initialized[/green] — system {out['system_id']}, {out['controls']} controls"
    )


@self_assess_app.command(name="run")
def self_assess_run() -> None:
    """Run Concord's self-assessment (reliability checks → self-controls)."""
    from .self_assurance import run_self_assessment  # noqa: PLC0415

    async def _run() -> tuple[float, int, int]:
        async with session_scope() as session:
            r = await run_self_assessment(session, actor="cli")
            await session.commit()
            return r.readiness_pct, r.checks_passed, r.checks_total

    pct, passed, total = asyncio.run(_run())
    console.print(f"[green]self-assurance readiness {pct}%[/green] — {passed}/{total} checks pass")


@self_assess_app.command(name="status")
def self_assess_status() -> None:
    """Show the latest self-assurance status."""
    from .self_assurance import status  # noqa: PLC0415

    async def _run() -> dict[str, Any]:
        async with session_scope() as session:
            return await status(session)

    out = asyncio.run(_run())
    if not out.get("initialized"):
        console.print("[yellow]Not initialized — run `ccf self-assess init`.[/yellow]")
        return
    console.print(f"Readiness: [cyan]{out['readiness_pct']}%[/cyan]")
    for cid, st in (out.get("control_status") or {}).items():
        console.print(f"  {cid}: {st}")


@self_assess_app.command(name="export-package")
def self_assess_export() -> None:
    """Export Concord's own authorization package."""
    from .self_assurance import export_package  # noqa: PLC0415

    async def _run() -> dict[str, Any]:
        async with session_scope() as session:
            out = await export_package(session, actor="cli")
            await session.commit()
            return out

    out = asyncio.run(_run())
    console.print(
        f"[green]package #{out['package_id']}[/green] — "
        f"readiness {out['readiness_pct']}%, {out['fact_count']} facts"
    )


packs_app = typer.Typer(help="Compliance packs — validate, install, coverage, test")
app.add_typer(packs_app, name="packs")


@packs_app.command(name="list")
def packs_list() -> None:
    """List available (bundled) and installed compliance packs."""
    from .models_packs import CompliancePack  # noqa: PLC0415
    from .packs import list_available  # noqa: PLC0415

    async def _installed() -> list[tuple[str, str]]:
        async with session_scope() as session:
            rows = (await session.execute(select(CompliancePack))).scalars().all()
            return [(p.pack_key, p.version) for p in rows]

    console.print("[bold]Available:[/bold]")
    for p in list_available():
        console.print(f"  [cyan]{p['id']}[/cyan] v{p['version']} — {p['controls']} controls")
    console.print("[bold]Installed:[/bold]")
    for key, version in asyncio.run(_installed()):
        console.print(f"  [green]{key}[/green] v{version}")


@packs_app.command(name="validate")
def packs_validate(path: str = typer.Argument(...)) -> None:
    """Validate a pack manifest (path or pack id)."""
    from .packs import load_pack, validate_manifest  # noqa: PLC0415

    try:
        manifest = load_pack(path)
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(2) from e
    errors = validate_manifest(manifest)
    if errors:
        console.print("[red]INVALID[/red]:")
        for err in errors:
            console.print(f"  [red]•[/red] {err}")
        raise typer.Exit(1)
    console.print(f"[green]VALID[/green] — {manifest['id']} v{manifest.get('version')}")


@packs_app.command(name="install")
def packs_install(path_or_name: str = typer.Argument(...)) -> None:
    """Install a compliance pack (bundled id or path)."""
    from .packs import install_pack, load_pack, service  # noqa: PLC0415

    async def _run() -> str:
        async with session_scope() as session:
            try:
                manifest = load_pack(path_or_name)
                pack = await install_pack(
                    session, org_id=None, manifest=manifest, source=path_or_name, actor="cli"
                )
            except FileNotFoundError as e:
                return f"not_found: {e}"
            except service.PackError as e:
                return f"invalid: {e}"
            await session.commit()
            return f"{pack.pack_key} v{pack.version}"

    out = asyncio.run(_run())
    if out.startswith(("not_found", "invalid")):
        console.print(f"[red]{out}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]installed[/green] {out}")


@packs_app.command(name="coverage")
def packs_coverage(
    pack_id: str = typer.Argument(...),
    system_id: int = typer.Option(..., "--system-id"),
) -> None:
    """Show a pack's control coverage for a system."""
    from .models_packs import CompliancePack  # noqa: PLC0415
    from .packs import coverage  # noqa: PLC0415

    async def _run() -> dict[str, Any] | None:
        async with session_scope() as session:
            pack = (
                await session.execute(
                    select(CompliancePack).where(CompliancePack.pack_key == pack_id)
                )
            ).scalars().first()
            if pack is None:
                return None
            return await coverage(session, pack=pack, system_id=system_id)

    out = asyncio.run(_run())
    if out is None:
        console.print("[red]Pack not installed.[/red]")
        raise typer.Exit(1)
    console.print(
        f"[cyan]{out['pack_key']}[/cyan] on system {system_id}: "
        f"{out['coverage_pct']}% ({out['covered']}/{out['total_controls']})"
    )


@packs_app.command(name="test")
def packs_test(pack_id: str = typer.Argument(...)) -> None:
    """Run a pack's conformance tests."""
    from .models_packs import CompliancePack  # noqa: PLC0415
    from .packs import run_tests  # noqa: PLC0415

    async def _run() -> list[tuple[str, str]] | None:
        async with session_scope() as session:
            pack = (
                await session.execute(
                    select(CompliancePack).where(CompliancePack.pack_key == pack_id)
                )
            ).scalars().first()
            if pack is None:
                return None
            results = await run_tests(session, pack)
            await session.commit()
            return [(r.test_key, r.status) for r in results]

    out = asyncio.run(_run())
    if out is None:
        console.print("[red]Pack not installed.[/red]")
        raise typer.Exit(1)
    for key, status in out:
        color = "green" if status == "pass" else "red"
        console.print(f"  [{color}]{status}[/{color}] {key}")


evidence_app = typer.Typer(help="Evidence repository — confidence scoring + replay")
app.add_typer(evidence_app, name="evidence")


@evidence_app.command(name="score")
def evidence_score() -> None:
    """Score confidence for every evidence object."""
    from .evidence import confidence  # noqa: PLC0415

    async def _run() -> dict[str, Any]:
        async with session_scope() as session:
            n = await confidence.score_all(session)
            summary = await confidence.confidence_summary(session)
            await session.commit()
            return {"scored": n, **summary}

    out = asyncio.run(_run())
    console.print(
        f"[green]Scored {out['scored']} object(s)[/green] — "
        f"avg confidence {out['evidence_confidence_pct']}%, "
        f"reproducible {out['reproducible_validation_pct']}%"
    )


@evidence_app.command(name="replay")
def evidence_replay(
    evidence_id: int = typer.Option(..., "--evidence-id"),
) -> None:
    """Attempt to reproduce one evidence object's content (digest replay)."""
    from .evidence import confidence  # noqa: PLC0415
    from .models_evidence import EvidenceObject  # noqa: PLC0415

    async def _run() -> str:
        async with session_scope() as session:
            obj = await session.get(EvidenceObject, evidence_id)
            if obj is None:
                return "not_found"
            run = await confidence.replay(session, obj)
            await session.commit()
            return run.status

    status = asyncio.run(_run())
    if status == "not_found":
        console.print("[red]Evidence object not found.[/red]")
        raise typer.Exit(1)
    console.print(f"Replay result: [cyan]{status}[/cyan]")


assurance_app = typer.Typer(help="Assurance graph — build + query the authorization digital twin")
app.add_typer(assurance_app, name="assurance")


@assurance_app.command(name="graph-rebuild")
def assurance_graph_rebuild() -> None:
    """Rebuild the assurance graph for every organization."""
    from .assurance import rebuild  # noqa: PLC0415

    async def _run() -> list[dict[str, Any]]:
        async with session_scope() as session:
            out = await rebuild(session)
            await session.commit()
            return out

    out = asyncio.run(_run())
    for row in out:
        console.print(
            f"[green]org {row['organization_id']}[/green]: "
            f"{row['nodes']} nodes, {row['edges']} edges ({row['status']})"
        )
    if not out:
        console.print("[yellow]No organizations to build.[/yellow]")


@assurance_app.command(name="impact")
def assurance_impact(
    entity_type: str = typer.Option(..., "--entity-type", help="e.g. evidence, vendor, connector"),
    entity_id: str = typer.Option(..., "--entity-id"),
) -> None:
    """Show the blast radius of an entity in the assurance graph."""
    from .assurance import impact_for  # noqa: PLC0415

    async def _run() -> dict[str, Any]:
        async with session_scope() as session:
            return await impact_for(
                session, org_id=None, entity_type=entity_type, entity_id=entity_id
            )

    out = asyncio.run(_run())
    if out["root"] is None:
        console.print("[yellow]Entity not present in the graph — run graph-rebuild first.[/yellow]")
        raise typer.Exit(1)
    console.print(
        f"[green]{out['root']['label']}[/green] impacts {out['affected_count']} node(s):"
    )
    for etype, items in out["affected"].items():
        console.print(f"  {etype}: {len(items)}")


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
