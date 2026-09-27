import typer
from rich.console import Console

app = typer.Typer(help="VulnTriage-RAG CLI")
console = Console()


@app.command("db-init")
def db_init() -> None:
    """Apply sql/schema.sql to the configured database."""
    from vt.db import init_schema

    init_schema()
    console.print("[green]Schema applied.[/green]")


if __name__ == "__main__":
    app()
