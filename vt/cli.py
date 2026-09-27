import typer
from rich.console import Console

app = typer.Typer(help="VulnTriage-RAG CLI")
console = Console()

ingest_app = typer.Typer(help="Ingest advisory data sources")
app.add_typer(ingest_app, name="ingest")


@app.callback()
def main() -> None:
    """VulnTriage-RAG CLI."""


@app.command("db-init")
def db_init() -> None:
    """Apply sql/schema.sql to the configured database."""
    from vt.db import init_schema

    init_schema()
    console.print("[green]Schema applied.[/green]")


@ingest_app.command("osv")
def ingest_osv_cmd(limit: int | None = typer.Option(None, "--limit")) -> None:
    """Download and upsert OSV (PyPI) advisories into the database."""
    from vt.ingest.osv import ingest_osv

    n = ingest_osv(limit=limit)
    console.print(f"[green]Upserted {n} advisories.[/green]")


if __name__ == "__main__":
    app()
