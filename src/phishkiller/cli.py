"""PhishKiller CLI — built with Typer.

Entry point registered in pyproject.toml as `phishkiller` console script.

Commands:
    phishkiller submit <url|file>            Submit a kit URL or local file for analysis
    phishkiller submit --batch f.txt         Bulk submit URLs from a file
    phishkiller watch <kit_id>               Watch analysis progress until completion
    phishkiller status <kit_id>              Check analysis status
    phishkiller kits list                    List kits with filters
    phishkiller kits get <kit_id>            Get kit details
    phishkiller kits similar <kit_id>        Find similar kits by TLSH
    phishkiller iocs search <query>          Search IOCs
    phishkiller iocs list                    List IOCs with filters
    phishkiller iocs stats                   IOC statistics
    phishkiller feeds ingest                 Trigger feed ingestion
    phishkiller feeds status                 Feed processing status
    phishkiller campaigns list               List campaigns
    phishkiller campaigns get <id>           Campaign details with linked kits/actors
    phishkiller campaigns create             Create a campaign
    phishkiller campaigns add-kits <id>      Add kits to a campaign
    phishkiller investigations list          List investigations
    phishkiller investigations get <id>      Investigation details
    phishkiller investigations tree <id>     Parent-child kit tree view
    phishkiller investigations create <url>  Start a new investigation
    phishkiller actors list                  List threat actors
    phishkiller actors get <id>              Actor details
    phishkiller actors search <query>        Search actors
    phishkiller analyze <kit_id>             Re-run analysis on a kit
    phishkiller health                       Check service health
    phishkiller worker recover               Recover stuck kits
"""

import time
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from rich.tree import Tree as RichTree

app = typer.Typer(
    name="phishkiller",
    help="PhishKiller — Phishing kit tracking and analysis platform",
    no_args_is_help=True,
)

kits_app = typer.Typer(help="Kit management commands", no_args_is_help=True)
iocs_app = typer.Typer(help="IOC query commands", no_args_is_help=True)
worker_app = typer.Typer(help="Worker management commands", no_args_is_help=True)
actors_app = typer.Typer(help="Actor/threat group commands", no_args_is_help=True)
campaigns_app = typer.Typer(help="Campaign management commands", no_args_is_help=True)
investigations_app = typer.Typer(help="Investigation management commands", no_args_is_help=True)

app.add_typer(kits_app, name="kits")
app.add_typer(iocs_app, name="iocs")
app.add_typer(worker_app, name="worker")
app.add_typer(actors_app, name="actors")
app.add_typer(campaigns_app, name="campaigns")
app.add_typer(investigations_app, name="investigations")

console = Console()

API_BASE = "http://localhost:8000/api/v1"


def _api(method: str, path: str, **kwargs) -> dict | list | None:
    """Make an API call and handle errors."""
    try:
        with httpx.Client(timeout=30) as client:
            response = getattr(client, method)(f"{API_BASE}{path}", **kwargs)
            response.raise_for_status()
            if response.status_code == 204:
                return None
            return response.json()
    except httpx.ConnectError:
        console.print("[red]Error: Cannot connect to API at {API_BASE}[/red]")
        console.print("Is the server running? Start with: uvicorn phishkiller.main:app")
        raise typer.Exit(1) from None
    except httpx.HTTPStatusError as e:
        console.print(f"[red]API Error {e.response.status_code}:[/red] {e.response.text}")
        raise typer.Exit(1) from None


# ─── Top-Level Commands ──────────────────────────────────────────────


@app.command()
def submit(
    target: str = typer.Argument(None, help="URL or local file path of phishing kit"),
    source: str = typer.Option("manual", "--source", "-s", help="Source feed name"),
    batch: str = typer.Option(
        None, "--batch", "-b", help="File containing one URL per line (bulk submit)"
    ),
):
    """Submit a phishing kit for analysis.

    Accepts a URL, a local file path, or --batch for bulk URL submission.

    Examples:
        phishkiller submit https://example.com/kit.zip
        phishkiller submit ./suspicious-kit.zip --source ir-42
        phishkiller submit --batch urls.txt
    """
    if batch:
        # Bulk URL mode
        batch_path = Path(batch)
        if not batch_path.exists():
            console.print(f"[red]File not found:[/red] {batch}")
            raise typer.Exit(1)
        urls = [
            line.strip()
            for line in batch_path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not urls:
            console.print("[yellow]No URLs found in file[/yellow]")
            raise typer.Exit(1)
        if len(urls) > 500:
            console.print(f"[red]Too many URLs ({len(urls)}). Maximum is 500 per batch.[/red]")
            raise typer.Exit(1)

        data = _api("post", "/kits/bulk", json={"urls": urls, "source_feed": source})
        console.print(
            f"[green]+[/green] Bulk submit: "
            f"[bold]{data['submitted']}[/bold] submitted, "
            f"[yellow]{data['skipped_duplicate']}[/yellow] duplicates skipped"
        )
        table = Table(title="Results")
        table.add_column("URL", max_width=255)
        table.add_column("Kit ID", max_width=255)
        table.add_column("Status")
        for r in data["results"]:
            status_str = "[yellow]duplicate[/yellow]" if r["duplicate"] else "[green]queued[/green]"
            table.add_row(r["url"], str(r["kit_id"]), status_str)
        console.print(table)
        return

    if not target:
        console.print("[red]Error:[/red] Provide a URL, file path, or use --batch")
        raise typer.Exit(1)

    # Check if target is a local file
    target_path = Path(target)
    if target_path.exists() and target_path.is_file():
        # File upload mode
        with open(target_path, "rb") as f:
            try:
                with httpx.Client(timeout=60) as client:
                    response = client.post(
                        f"{API_BASE}/kits/upload",
                        files={"file": (target_path.name, f)},
                        data={"source_feed": source},
                    )
                    response.raise_for_status()
                    data = response.json()
            except httpx.ConnectError:
                console.print(f"[red]Error: Cannot connect to API at {API_BASE}[/red]")
                raise typer.Exit(1) from None
            except httpx.HTTPStatusError as e:
                console.print(
                    f"[red]API Error {e.response.status_code}:[/red] {e.response.text}"
                )
                raise typer.Exit(1) from None
        console.print(f"[green]+[/green] File uploaded: [bold]{data['kit_id']}[/bold]")
        console.print(f"  Task ID: {data['task_id']}")
        console.print(f"  Watch progress: phishkiller watch {data['kit_id']}")
        return

    # URL mode (default)
    data = _api("post", "/kits", json={"url": target, "source_feed": source})
    if data.get("duplicate"):
        console.print(f"[yellow]≡[/yellow] Duplicate — existing kit: [bold]{data['kit_id']}[/bold]")
        console.print(f"  Check status: phishkiller status {data['kit_id']}")
    else:
        console.print(f"[green]+[/green] Kit submitted: [bold]{data['kit_id']}[/bold]")
        console.print(f"  Task ID: {data['task_id']}")
        console.print(f"  Watch progress: phishkiller watch {data['kit_id']}")


@app.command()
def status(
    kit_id: str = typer.Argument(..., help="Kit UUID"),
):
    """Check the analysis status of a kit."""
    data = _api("get", f"/kits/{kit_id}")

    table = Table(title=f"Kit {kit_id[:8]}…", show_header=False, padding=(0, 2))
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")

    table.add_row("Status", _status_badge(data["status"]))
    table.add_row("URL", data["source_url"])
    table.add_row("SHA256", data.get("sha256") or "—")
    table.add_row("TLSH", data.get("tlsh") or "—")
    table.add_row("File Size", f"{data.get('file_size') or 0:,} bytes")
    table.add_row("Created", data["created_at"])

    if data.get("parent_kit_id"):
        table.add_row("Parent Kit", str(data["parent_kit_id"]))
    if data.get("investigation_id"):
        table.add_row("Investigation", str(data["investigation_id"]))
    if data.get("chain_depth"):
        table.add_row("Chain Depth", str(data["chain_depth"]))
    if data.get("discovery_method"):
        table.add_row("Discovery", data["discovery_method"])

    if data.get("error_message"):
        table.add_row("Error", f"[red]{data['error_message']}[/red]")

    console.print(table)

    # Show child kits
    child_kits = data.get("child_kits", [])
    if child_kits:
        console.print(f"\n[bold]Child Kits ({len(child_kits)}):[/bold]")
        child_table = Table()
        child_table.add_column("ID", style="dim", max_width=255)
        child_table.add_column("Status")
        child_table.add_column("URL", max_width=255)
        for child in child_kits:
            child_table.add_row(
                str(child["id"]),
                _status_badge(child["status"]),
                child["source_url"],
            )
        console.print(child_table)

    # Show campaigns
    campaigns = data.get("campaigns", [])
    if campaigns:
        console.print(f"\n[bold]Campaigns ({len(campaigns)}):[/bold]")
        camp_table = Table()
        camp_table.add_column("ID", style="dim", max_width=255)
        camp_table.add_column("Name", style="bold")
        camp_table.add_column("Brand")
        for camp in campaigns:
            camp_table.add_row(
                str(camp["id"]),
                camp["name"],
                camp.get("target_brand") or "—",
            )
        console.print(camp_table)

    # Show indicators summary
    indicators = data.get("indicators", [])
    if indicators:
        console.print(f"\n[bold]Indicators ({len(indicators)}):[/bold]")
        for ioc in indicators[:10]:
            console.print(
                f"  [{ioc['type']}] {ioc['value']} "
                f"(confidence: {ioc['confidence']})"
            )
        if len(indicators) > 10:
            console.print(f"  … and {len(indicators) - 10} more")


@app.command()
def health():
    """Check API and service health."""
    data = _api("get", "/health")
    overall = data["status"]
    color = "green" if overall == "ok" else "yellow"
    console.print(f"Overall: [{color}]{overall}[/{color}]")
    for svc, info in data.get("services", {}).items():
        svc_color = "green" if info["status"] == "ok" else "red"
        detail = f" — {info['detail']}" if info.get("detail") else ""
        console.print(f"  {svc}: [{svc_color}]{info['status']}[/{svc_color}]{detail}")


@app.command()
def analyze(
    kit_id: str = typer.Argument(..., help="Kit UUID to re-analyze"),
):
    """Re-run the full analysis pipeline on an existing kit."""
    data = _api("post", f"/kits/{kit_id}/reanalyze")
    console.print(f"[green]+[/green] Analysis re-triggered for {kit_id[:8]}…")
    console.print(f"  Task ID: {data['task_id']}")


@app.command()
def watch(
    kit_id: str = typer.Argument(..., help="Kit UUID to watch"),
    timeout: int = typer.Option(600, "--timeout", "-t", help="Timeout in seconds"),
    interval: int = typer.Option(3, "--interval", "-i", help="Poll interval in seconds"),
):
    """Watch a kit's analysis progress until completion."""
    terminal_states = {"analyzed", "failed"}
    start = time.time()

    with Live(Spinner("dots", text=f"Watching kit {kit_id[:8]}…"), console=console) as live:
        while time.time() - start < timeout:
            try:
                data = _api("get", f"/kits/{kit_id}")
            except SystemExit:
                return

            kit_status = data["status"]
            live.update(
                Spinner("dots", text=f"Kit {kit_id[:8]}… [{kit_status}]")
            )

            if kit_status in terminal_states:
                live.stop()
                if kit_status == "analyzed":
                    ioc_count = len(data.get("indicators", []))
                    yara_count = len([
                        r for r in data.get("analysis_results", [])
                        if r.get("analysis_type") == "yara_scan"
                    ])
                    console.print(
                        f"[green]✓[/green] Kit {kit_id[:8]}… analyzed — "
                        f"{ioc_count} IOCs, {yara_count} YARA results"
                    )
                else:
                    error = data.get("error_message") or "unknown"
                    console.print(
                        f"[red]✗[/red] Kit {kit_id[:8]}… failed: {error}"
                    )
                # Print full status
                status(kit_id)
                return

            time.sleep(interval)

    console.print(f"[yellow]⏱[/yellow] Timeout after {timeout}s — kit still {kit_status}")
    console.print(f"  Check later: phishkiller status {kit_id}")


# ─── Kits Sub-Commands ───────────────────────────────────────────────


@kits_app.command("list")
def kits_list(
    status_filter: str = typer.Option(None, "--status", help="Filter by status"),
    source: str = typer.Option(None, "--source", help="Filter by source feed"),
    limit: int = typer.Option(20, "--limit", "-n", help="Number of results"),
):
    """List phishing kits."""
    params = {"limit": limit}
    if status_filter:
        params["status_filter"] = status_filter
    if source:
        params["source_feed"] = source
    data = _api("get", "/kits", params=params)

    table = Table(title=f"Phishing Kits ({data['total']} total)")
    table.add_column("ID", style="dim", max_width=255)
    table.add_column("Status")
    table.add_column("SHA256", max_width=255)
    table.add_column("Size")
    table.add_column("Source URL", max_width=255)

    for kit in data["items"]:
        table.add_row(
            str(kit["id"]),
            _status_badge(kit["status"]),
            kit.get("sha256") or "—",
            f"{kit.get('file_size') or 0:,}",
            kit["source_url"],
        )
    console.print(table)


@kits_app.command("get")
def kits_get(kit_id: str = typer.Argument(..., help="Kit UUID")):
    """Get detailed kit information."""
    status(kit_id)  # Reuses the status command


@kits_app.command("similar")
def kits_similar(
    kit_id: str = typer.Argument(..., help="Kit UUID"),
    threshold: int = typer.Option(100, "--threshold", "-t", help="TLSH distance threshold"),
):
    """Find kits similar to the given kit by TLSH fuzzy hash."""
    data = _api("get", f"/kits/{kit_id}/similar", params={"threshold": threshold})

    if not data:
        console.print("[yellow]No similar kits found.[/yellow]")
        return

    table = Table(title=f"Similar Kits (threshold={threshold})")
    table.add_column("ID", max_width=255)
    table.add_column("Distance", justify="right")
    table.add_column("SHA256", max_width=255)
    table.add_column("URL", max_width=255)

    for item in data:
        table.add_row(
            str(item["id"]),
            str(item["distance"]),
            item.get("sha256") or "—",
            item["source_url"],
        )
    console.print(table)


@kits_app.command("delete")
def kits_delete(
    kit_id: str = typer.Argument(..., help="Kit UUID to delete"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Delete a kit and all associated data."""
    if not confirm:
        typer.confirm(f"Delete kit {kit_id}?", abort=True)
    _api("delete", f"/kits/{kit_id}")
    console.print(f"[green]+[/green] Kit {kit_id[:8]}… deleted")


# ─── IOCs Sub-Commands ───────────────────────────────────────────────


@iocs_app.command("list")
def iocs_list(
    type_filter: str = typer.Option(None, "--type", "-t", help="IOC type filter"),
    limit: int = typer.Option(20, "--limit", "-n", help="Number of results"),
):
    """List indicators of compromise."""
    params = {"limit": limit}
    if type_filter:
        params["type_filter"] = type_filter
    data = _api("get", "/indicators", params=params)

    table = Table(title=f"Indicators ({data['total']} total)")
    table.add_column("Type", style="bold")
    table.add_column("Value", max_width=255)
    table.add_column("Conf", justify="right")
    table.add_column("Kit", max_width=255)

    for ioc in data["items"]:
        table.add_row(
            ioc["type"],
            ioc["value"],
            str(ioc["confidence"]),
            str(ioc["kit_id"]),
        )
    console.print(table)


@iocs_app.command("search")
def iocs_search(
    query: str = typer.Argument(..., help="Search term"),
    type_filter: str = typer.Option(None, "--type", "-t", help="IOC type filter"),
    limit: int = typer.Option(20, "--limit", "-n", help="Number of results"),
):
    """Search indicators of compromise by value."""
    params = {"q": query, "limit": limit}
    if type_filter:
        params["type_filter"] = type_filter
    data = _api("get", "/indicators/search", params=params)

    table = Table(title=f"Search: '{query}' ({data['total']} results)")
    table.add_column("Type", style="bold")
    table.add_column("Value", max_width=255)
    table.add_column("Conf", justify="right")
    table.add_column("Kit", max_width=255)

    for ioc in data["items"]:
        table.add_row(
            ioc["type"],
            ioc["value"],
            str(ioc["confidence"]),
            str(ioc["kit_id"]),
        )
    console.print(table)


@iocs_app.command("stats")
def iocs_stats():
    """Show IOC statistics by type."""
    data = _api("get", "/indicators/stats")

    table = Table(title="IOC Statistics")
    table.add_column("Type", style="bold")
    table.add_column("Count", justify="right")

    total = 0
    for stat in data:
        table.add_row(stat["type"], f"{stat['count']:,}")
        total += stat["count"]
    table.add_row("[bold]Total[/bold]", f"[bold]{total:,}[/bold]")

    console.print(table)


# ─── Worker Sub-Commands ────────────────────────────────────────────


@worker_app.command("recover")
def worker_recover(
    timeout: int = typer.Option(
        30, "--timeout", "-t", help="Minutes a kit must be stuck before recovery"
    ),
):
    """Recover kits stuck in transient states (DOWNLOADING/ANALYZING/DOWNLOADED)."""
    from phishkiller.tasks.recovery import recover_stuck_kits

    result = recover_stuck_kits.delay(timeout_minutes=timeout)
    console.print(f"[green]+[/green] Recovery task dispatched (task_id={result.id})")
    console.print(f"  Timeout: {timeout} minutes")
    console.print("  Check worker logs for recovery details.")


@worker_app.command("reset")
def worker_reset():
    """Purge all queues, clean DB analysis data, and re-dispatch all non-failed kits."""
    typer.confirm(
        "This will purge ALL queued messages, delete all indicators/analysis_results, "
        "and re-run every non-failed kit through the full analysis chain. Continue?",
        abort=True,
    )
    from phishkiller.tasks.recovery import full_reset_and_redispatch

    result = full_reset_and_redispatch.delay()
    console.print(f"[green]+[/green] Full reset task dispatched (task_id={result.id})")
    console.print("  Monitor progress: docker compose logs -f worker")


# ─── Actors Sub-Commands ───────────────────────────────────────────


@actors_app.command("list")
def actors_list(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of results"),
):
    """List auto-correlated threat actors."""
    from sqlalchemy import func, select

    from phishkiller.database import get_sync_db
    from phishkiller.models.actor import Actor
    from phishkiller.models.indicator import Indicator

    db = get_sync_db()
    try:
        # Get actors with kit count via indicators
        actors = db.execute(
            select(
                Actor,
                func.count(func.distinct(Indicator.kit_id)).label("kit_count"),
                func.count(Indicator.id).label("ioc_count"),
            )
            .outerjoin(Indicator, Indicator.actor_id == Actor.id)
            .group_by(Actor.id)
            .order_by(func.count(func.distinct(Indicator.kit_id)).desc())
            .limit(limit)
        ).all()

        if not actors:
            console.print(
                "[yellow]No actors found yet. Actors are auto-created during analysis.[/yellow]"
            )
            return

        table = Table(title=f"Threat Actors ({len(actors)} shown)")
        table.add_column("ID", style="dim", max_width=255)
        table.add_column("Name", style="bold")
        table.add_column("Kits", justify="right")
        table.add_column("IOCs", justify="right")
        table.add_column("Emails", max_width=255)
        table.add_column("First Seen")
        table.add_column("Last Seen")

        for actor, kit_count, ioc_count in actors:
            emails = ", ".join(actor.email_addresses) if actor.email_addresses else "—"
            table.add_row(
                str(actor.id),
                actor.name,
                str(kit_count),
                str(ioc_count),
                emails,
                actor.first_seen or "—",
                actor.last_seen or "—",
            )
        console.print(table)
    finally:
        db.close()


@actors_app.command("get")
def actors_get(
    actor_id: str = typer.Argument(..., help="Actor UUID"),
):
    """Show detailed actor information with linked kits and IOCs."""
    import uuid as uuid_mod

    from sqlalchemy import select

    from phishkiller.database import get_sync_db
    from phishkiller.models.actor import Actor
    from phishkiller.models.indicator import Indicator
    from phishkiller.models.kit import Kit

    db = get_sync_db()
    try:
        actor = db.query(Actor).filter(Actor.id == uuid_mod.UUID(actor_id)).first()
        if not actor:
            console.print(f"[red]Actor {actor_id} not found[/red]")
            raise typer.Exit(1)

        table = Table(title=f"Actor: {actor.name}", show_header=False, padding=(0, 2))
        table.add_column("Field", style="bold cyan")
        table.add_column("Value")

        table.add_row("ID", str(actor.id))
        table.add_row("Name", actor.name)
        table.add_row("Description", actor.description or "—")
        table.add_row("First Seen", actor.first_seen or "—")
        table.add_row("Last Seen", actor.last_seen or "—")
        table.add_row("Emails", ", ".join(actor.email_addresses) if actor.email_addresses else "—")
        tg = ", ".join(actor.telegram_handles) if actor.telegram_handles else "—"
        table.add_row("Telegram", tg)
        console.print(table)

        # Show linked kits
        linked_kits = db.execute(
            select(Kit.id, Kit.source_url, Kit.status, Kit.sha256)
            .join(Indicator, Indicator.kit_id == Kit.id)
            .where(Indicator.actor_id == actor.id)
            .distinct()
            .limit(20)
        ).all()

        if linked_kits:
            console.print(f"\n[bold]Linked Kits ({len(linked_kits)}):[/bold]")
            kit_table = Table()
            kit_table.add_column("Kit ID", max_width=255)
            kit_table.add_column("Status")
            kit_table.add_column("SHA256", max_width=255)
            kit_table.add_column("URL", max_width=255)
            for kid, url, st, sha in linked_kits:
                kit_table.add_row(str(kid), _status_badge(st.value), sha or "—", url)
            console.print(kit_table)

        # Show linked IOCs
        linked_iocs = db.scalars(
            select(Indicator)
            .where(Indicator.actor_id == actor.id)
            .limit(20)
        ).all()

        if linked_iocs:
            console.print(f"\n[bold]Linked IOCs ({len(linked_iocs)}):[/bold]")
            ioc_table = Table()
            ioc_table.add_column("Type", style="bold")
            ioc_table.add_column("Value", max_width=255)
            ioc_table.add_column("Conf", justify="right")
            for ioc in linked_iocs:
                ioc_table.add_row(ioc.type.value, ioc.value, str(ioc.confidence))
            console.print(ioc_table)

    finally:
        db.close()


@actors_app.command("search")
def actors_search(
    query: str = typer.Argument(..., help="Search by name, email, or handle"),
    limit: int = typer.Option(20, "--limit", "-n", help="Number of results"),
):
    """Search actors by name, email address, or Telegram handle."""
    from sqlalchemy import or_

    from phishkiller.database import get_sync_db
    from phishkiller.models.actor import Actor

    db = get_sync_db()
    try:
        actors = db.query(Actor).filter(
            or_(
                Actor.name.ilike(f"%{query}%"),
                Actor.email_addresses.any(query),
                Actor.telegram_handles.any(query),
            )
        ).limit(limit).all()

        if not actors:
            console.print(f"[yellow]No actors matching '{query}'[/yellow]")
            return

        table = Table(title=f"Actor Search: '{query}' ({len(actors)} results)")
        table.add_column("ID", style="dim", max_width=255)
        table.add_column("Name", style="bold")
        table.add_column("Emails", max_width=255)
        table.add_column("First Seen")

        for actor in actors:
            emails = ", ".join(actor.email_addresses) if actor.email_addresses else "—"
            table.add_row(
                str(actor.id),
                actor.name,
                emails,
                actor.first_seen or "—",
            )
        console.print(table)
    finally:
        db.close()


# ─── Campaign Commands ────────────────────────────────────────────────


@campaigns_app.command("list")
def campaigns_list(
    brand: str = typer.Option(None, "--brand", "-b", help="Filter by target brand"),
    limit: int = typer.Option(20, "--limit", "-n", help="Number of results"),
):
    """List campaigns."""
    params = {"limit": limit}
    if brand:
        params["target_brand"] = brand
    data = _api("get", "/campaigns", params=params)

    table = Table(title=f"Campaigns ({data['total']} total)")
    table.add_column("ID", style="dim", max_width=255)
    table.add_column("Name", style="bold")
    table.add_column("Brand")
    table.add_column("Start")
    table.add_column("End")
    table.add_column("Created")

    for camp in data["items"]:
        table.add_row(
            str(camp["id"]),
            camp["name"],
            camp.get("target_brand") or "—",
            camp.get("start_date") or "—",
            camp.get("end_date") or "—",
            camp["created_at"],
        )
    console.print(table)


@campaigns_app.command("get")
def campaigns_get(
    campaign_id: str = typer.Argument(..., help="Campaign UUID"),
):
    """Show campaign details with linked kits and actors."""
    data = _api("get", f"/campaigns/{campaign_id}")

    table = Table(title=f"Campaign: {data['name']}", show_header=False, padding=(0, 2))
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")

    table.add_row("ID", str(data["id"]))
    table.add_row("Name", data["name"])
    table.add_row("Brand", data.get("target_brand") or "—")
    table.add_row("Description", data.get("description") or "—")
    table.add_row("Start", data.get("start_date") or "—")
    table.add_row("End", data.get("end_date") or "—")
    table.add_row("Created", data["created_at"])
    console.print(table)

    kits = data.get("kits", [])
    if kits:
        console.print(f"\n[bold]Linked Kits ({len(kits)}):[/bold]")
        kit_table = Table()
        kit_table.add_column("ID", style="dim", max_width=255)
        kit_table.add_column("Status")
        kit_table.add_column("SHA256", max_width=255)
        kit_table.add_column("URL", max_width=255)
        for kit in kits:
            kit_table.add_row(
                str(kit["id"]),
                _status_badge(kit["status"]),
                kit.get("sha256") or "—",
                kit["source_url"],
            )
        console.print(kit_table)

    actors = data.get("actors", [])
    if actors:
        console.print(f"\n[bold]Linked Actors ({len(actors)}):[/bold]")
        actor_table = Table()
        actor_table.add_column("ID", style="dim", max_width=255)
        actor_table.add_column("Name", style="bold")
        for actor in actors:
            actor_table.add_row(str(actor["id"]), actor["name"])
        console.print(actor_table)


@campaigns_app.command("create")
def campaigns_create(
    name: str = typer.Option(..., "--name", help="Campaign name"),
    brand: str = typer.Option(None, "--brand", "-b", help="Target brand"),
    description: str = typer.Option(None, "--desc", "-d", help="Description"),
):
    """Create a new campaign."""
    payload = {"name": name}
    if brand:
        payload["target_brand"] = brand
    if description:
        payload["description"] = description
    data = _api("post", "/campaigns", json=payload)
    console.print(f"[green]+[/green] Campaign created: [bold]{data['id']}[/bold]")
    console.print(f"  Name: {data['name']}")


@campaigns_app.command("add-kits")
def campaigns_add_kits(
    campaign_id: str = typer.Argument(..., help="Campaign UUID"),
    kit_ids: Annotated[list[str], typer.Argument(help="Kit UUIDs to add")] = ...,
):
    """Add kits to a campaign."""
    data = _api("post", f"/campaigns/{campaign_id}/kits", json={"kit_ids": kit_ids})
    console.print(f"[green]+[/green] Added {data['added']} kit(s) to campaign {campaign_id}")


# ─── Investigation Commands ───────────────────────────────────────────


@investigations_app.command("list")
def investigations_list(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of results"),
):
    """List investigations."""
    data = _api("get", "/investigations", params={"limit": limit})

    table = Table(title=f"Investigations ({data['total']} total)")
    table.add_column("ID", style="dim", max_width=255)
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Max Depth", justify="right")
    table.add_column("Kits", justify="right")
    table.add_column("Depth Reached", justify="right")
    table.add_column("Created")

    for inv in data["items"]:
        table.add_row(
            str(inv["id"]),
            inv.get("name") or "—",
            _status_badge(inv["status"]),
            str(inv["max_depth"]),
            str(inv["total_kits"]),
            str(inv["total_depth_reached"]),
            inv["created_at"],
        )
    console.print(table)


@investigations_app.command("get")
def investigations_get(
    investigation_id: str = typer.Argument(..., help="Investigation UUID"),
):
    """Show investigation details."""
    data = _api("get", f"/investigations/{investigation_id}")

    table = Table(
        title=f"Investigation: {data.get('name') or investigation_id}",
        show_header=False,
        padding=(0, 2),
    )
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")

    table.add_row("ID", str(data["id"]))
    table.add_row("Name", data.get("name") or "—")
    table.add_row("Status", _status_badge(data["status"]))
    table.add_row("Max Depth", str(data["max_depth"]))
    table.add_row("Total Kits", str(data["total_kits"]))
    table.add_row("Depth Reached", str(data["total_depth_reached"]))
    table.add_row("Created", data["created_at"])

    root_kit = data.get("root_kit")
    if root_kit:
        table.add_row("Root Kit", f"{root_kit['id']}  {root_kit['source_url']}")
    console.print(table)


@investigations_app.command("tree")
def investigations_tree(
    investigation_id: str = typer.Argument(..., help="Investigation UUID"),
):
    """Show the kit parent-child tree for an investigation."""
    nodes = _api("get", f"/investigations/{investigation_id}/tree")
    if not nodes:
        console.print("[yellow]No kits in this investigation[/yellow]")
        return

    tree = RichTree(f"[bold]Investigation {investigation_id}[/bold]")
    for node in nodes:
        _render_tree_node(tree, node)
    console.print(tree)


def _render_tree_node(parent: RichTree, node: dict):
    """Recursively render an investigation tree node."""
    kit = node["kit"]
    label = f"{kit['id']}  {_status_badge(kit['status'])}  {kit['source_url']}"
    discovery = node.get("discovery_method")
    if discovery:
        label += f"  [dim]({discovery})[/dim]"
    branch = parent.add(label)
    for child in node.get("children", []):
        _render_tree_node(branch, child)


@investigations_app.command("create")
def investigations_create(
    url: str = typer.Argument(..., help="URL to investigate"),
    max_depth: int = typer.Option(3, "--depth", "-d", help="Max crawl depth"),
):
    """Start a new investigation from a URL."""
    data = _api("post", "/investigations", json={"url": url, "max_depth": max_depth})
    inv_id = data["investigation_id"]
    console.print(f"[green]+[/green] Investigation started: [bold]{inv_id}[/bold]")
    console.print(f"  Root Kit: {data['kit_id']}")
    console.print(f"  Task ID: {data['task_id']}")
    console.print(f"  Watch progress: phishkiller watch {data['kit_id']}")


# ─── Helpers ─────────────────────────────────────────────────────────


def _status_badge(status_str: str) -> str:
    """Color-coded status badge."""
    colors = {
        "pending": "yellow",
        "downloading": "blue",
        "downloaded": "cyan",
        "analyzing": "blue",
        "analyzed": "green",
        "failed": "red",
    }
    color = colors.get(status_str, "white")
    return f"[{color}]{status_str}[/{color}]"


if __name__ == "__main__":
    app()
