from contextlib import contextmanager

import psycopg
from pgvector.psycopg import register_vector

from vt.config import settings


@contextmanager
def get_conn():
    conn = psycopg.connect(settings.database_url, autocommit=True)
    try:
        try:
            register_vector(conn)
        except psycopg.ProgrammingError:
            # The `vector` extension may not exist yet (e.g. on a fresh
            # database before init_schema() has run `CREATE EXTENSION
            # vector`). The connection is still usable without it.
            pass
        yield conn
    finally:
        conn.close()


def init_schema() -> None:
    from pathlib import Path

    schema_sql = Path(__file__).resolve().parent.parent / "sql" / "schema.sql"
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(schema_sql.read_text())
