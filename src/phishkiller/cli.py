"""PhishKiller CLI — built with Typer.

Entry point registered in pyproject.toml as `phishkiller` console script.

Commands:
    phishkiller submit <url>           Submit a kit URL for analysis
    phishkiller status <kit_id>        Check analysis status
    phishkiller kits list              List kits with filters
    phishkiller kits get <kit_id>      Get kit details
    phishkiller kits similar <kit_id>  Find similar kits by TLSH
    phishkiller iocs search <query>    Search IOCs
    phishkiller iocs list              List IOCs with filters
    phishkiller iocs stats             IOC statistics
    phishkiller feeds ingest           Trigger feed ingestion
    phishkiller feeds status           Feed processing status
    phishkiller analyze <kit_id>       Re-run analysis on a kit
    phishkiller health                 Check service health
"""

import json
import sys

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="phishkiller",
    help="PhishKiller — Phishing kit tracking and analysis platform",
    no_args_is_help=True,
)

kits_app = typer.Typer(help="Kit management commands", no_args_is_help=True)
iocs_app = typer.Typer(help="IOC query commands", no_args_is_help=True)
feeds_app = typer.Typer(help="Feed management commands", no_args_is_help=True)

app.add_typer(kits_app, name="kits")
app.add_typer(iocs_app, name="iocs")
app.add_typer(feeds_app, name="feeds")

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
        raise typer.Exit(1)
    except httpx.HTTPStatusError as e:
        console.print(f"[red]API Error {e.response.status_code}:[/red] {e.response.text}")
        raise typer.Exit(1)


# ─── Top-Level Commands ──────────────────────────────────────────────


@app.command()
def submit(
    url: str = typer.Argument(..., help="URL of phishing kit to download and analyze"),
    source: str = typer.Option("manual", "--source", "-s", help="Source feed name"),
):
    """Submit a phishing kit URL for download and analysis."""
    data = _api("post", "/kits", json={"url": url, "source_feed": source})
    console.print(f"[green]+[/green] Kit submitted: [bold]{data['kit_id']}[/bold]")
    console.print(f"  Task ID: {data['task_id']}")
    console.print(f"  Track status: phishkiller status {data['kit_id']}")


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
    table.add_row("URL", data["source_url"][:80])
    table.add_row("SHA256", data.get("sha256") or "—")
    table.add_row("TLSH", data.get("tlsh") or "—")
    table.add_row("File Size", f"{data.get('file_size') or 0:,} bytes")
    table.add_row("Created", data["created_at"])

    if data.get("error_message"):
        table.add_row("Error", f"[red]{data['error_message']}[/red]")

    console.print(table)

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
    table.add_column("ID", style="dim", max_width=12)
    table.add_column("Status")
    table.add_column("SHA256", max_width=20)
    table.add_column("Size")
    table.add_column("Source URL", max_width=50)

    for kit in data["items"]:
        table.add_row(
            str(kit["id"])[:12] + "…",
            _status_badge(kit["status"]),
            (kit.get("sha256") or "—")[:20],
            f"{kit.get('file_size') or 0:,}",
            kit["source_url"][:50],
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
    table.add_column("ID", max_width=12)
    table.add_column("Distance", justify="right")
    table.add_column("SHA256", max_width=20)
    table.add_column("URL", max_width=50)

    for item in data:
        table.add_row(
            str(item["id"])[:12] + "…",
            str(item["distance"]),
            (item.get("sha256") or "—")[:20],
            item["source_url"][:50],
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
    table.add_column("Value", max_width=60)
    table.add_column("Conf", justify="right")
    table.add_column("Kit", max_width=12)

    for ioc in data["items"]:
        table.add_row(
            ioc["type"],
            ioc["value"][:60],
            str(ioc["confidence"]),
            str(ioc["kit_id"])[:12] + "…",
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
    table.add_column("Value", max_width=60)
    table.add_column("Conf", justify="right")
    table.add_column("Kit", max_width=12)

    for ioc in data["items"]:
        table.add_row(
            ioc["type"],
            ioc["value"][:60],
            str(ioc["confidence"]),
            str(ioc["kit_id"])[:12] + "…",
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


# ─── Feeds Sub-Commands ──────────────────────────────────────────────


@feeds_app.command("ingest")
def feeds_ingest(
    source: str = typer.Option(
        "all", "--source", "-s",
        help="Feed source (phishtank, urlhaus, openphish, all)",
    ),
):
    """Trigger feed ingestion manually."""
    data = _api("post", "/feeds/ingest", json={"source": source})
    console.print(f"[green]+[/green] {data['message']}")
    for tid in data.get("task_ids", []):
        console.print(f"  Task: {tid}")


@feeds_app.command("status")
def feeds_status():
    """Show feed processing statistics."""
    data = _api("get", "/feeds/stats")

    table = Table(title="Feed Statistics")
    table.add_column("Source", style="bold")
    table.add_column("Total", justify="right")
    table.add_column("Processed", justify="right")
    table.add_column("Pending", justify="right")

    for stat in data:
        table.add_row(
            stat["source"],
            f"{stat['total']:,}",
            f"{stat['processed']:,}",
            f"{stat['unprocessed']:,}",
        )
    console.print(table)


@feeds_app.command("entries")
def feeds_entries(
    source: str = typer.Option(None, "--source", "-s", help="Filter by source"),
    processed: bool = typer.Option(None, "--processed/--unprocessed", help="Filter by processed state"),
    limit: int = typer.Option(20, "--limit", "-n", help="Number of results"),
):
    """List feed entries."""
    params = {"limit": limit}
    if source:
        params["source"] = source
    if processed is not None:
        params["processed"] = processed
    data = _api("get", "/feeds/entries", params=params)

    table = Table(title=f"Feed Entries ({data['total']} total)")
    table.add_column("Source", style="bold", max_width=12)
    table.add_column("URL", max_width=60)
    table.add_column("Processed")
    table.add_column("Created")

    for entry in data["items"]:
        table.add_row(
            entry["source"],
            entry["url"][:60],
            "Y" if entry["is_processed"] else "N",
            entry["created_at"][:19],
        )
    console.print(table)


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
