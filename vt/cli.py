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


@ingest_app.command("kev")
def ingest_kev_cmd() -> None:
    """Download and upsert the CISA KEV catalog into the database."""
    from vt.ingest.kev import ingest_kev

    n = ingest_kev()
    console.print(f"[green]Upserted {n} KEV entries.[/green]")


@ingest_app.command("epss")
def ingest_epss_cmd() -> None:
    """Fetch and upsert FIRST EPSS scores for all known CVEs."""
    from vt.ingest.epss import ingest_epss

    n = ingest_epss()
    console.print(f"[green]Upserted {n} EPSS rows.[/green]")


@app.command("index")
def index_cmd() -> None:
    """Embed advisory chunks and rebuild the BM25 index."""
    from vt.chunking import chunk_advisory
    from vt.embed import build_embedding_input, embed_texts
    from vt.bm25_index import build_bm25, save_bm25
    from vt.db import get_conn
    from vt.models import Advisory
    from pathlib import Path

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, package, aliases, cve_ids, group_id, summary, details, "
                "cvss_vector, cvss_score, cwe_ids, fixed_versions, affected, refs, "
                "published, modified FROM advisories"
            )
            rows = cur.fetchall()

        all_chunks = []
        for row in rows:
            adv = Advisory(
                id=row[0], package=row[1], aliases=row[2], cve_ids=row[3],
                group_id=row[4], summary=row[5], details=row[6], cvss_vector=row[7],
                cvss_score=row[8], cwe_ids=row[9], fixed_versions=row[10],
                # psycopg3 auto-deserializes jsonb columns to Python
                # lists/dicts already, so no json.loads() here.
                affected=row[11] if row[11] else [],
                refs=row[12] if row[12] else [],
                published=row[13], modified=row[14],
            )
            all_chunks.extend(chunk_advisory(adv))

        console.print(f"Embedding {len(all_chunks)} chunks...")
        texts = [build_embedding_input(c.header, c.content, is_query=False) for c in all_chunks]
        vectors = embed_texts(texts)

        with conn.cursor() as cur:
            insert_sql = """
                INSERT INTO chunks (id, advisory_id, kind, header, content, embedding)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET embedding = EXCLUDED.embedding,
                    header = EXCLUDED.header, content = EXCLUDED.content
            """
            rows_to_insert = [
                (c.id, c.advisory_id, c.kind, c.header, c.content, vec.tolist())
                for c, vec in zip(all_chunks, vectors)
            ]
            for i in range(0, len(rows_to_insert), 500):
                cur.executemany(insert_sql, rows_to_insert[i : i + 500])

        bm25 = build_bm25([f"{c.header}\n{c.content}" for c in all_chunks])
        save_bm25(bm25, [c.id for c in all_chunks], Path("data/bm25.pkl"))

    console.print(f"[green]Indexed {len(all_chunks)} chunks (embeddings + BM25).[/green]")


if __name__ == "__main__":
    app()
