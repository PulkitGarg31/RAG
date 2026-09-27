from vt.models import Chunk

_UPSERT_SQL = """
    INSERT INTO chunks (id, advisory_id, kind, header, content, embedding)
    VALUES (%s, %s, %s, %s, %s, %s)
    ON CONFLICT (id) DO UPDATE SET embedding = EXCLUDED.embedding,
        kind = EXCLUDED.kind, header = EXCLUDED.header, content = EXCLUDED.content
"""


def write_chunks(conn, chunks: list[Chunk], vectors) -> int:
    """Make the chunks table match this indexing run: delete chunk ids it no longer produces
    (e.g. details pieces that disappeared after re-chunking), then upsert the rest."""
    ids = [c.id for c in chunks]
    rows = [
        (c.id, c.advisory_id, c.kind, c.header, c.content, vec.tolist())
        for c, vec in zip(chunks, vectors)
    ]
    with conn.cursor() as cur:
        cur.execute("DELETE FROM chunks WHERE NOT (id = ANY(%s))", (ids,))
        for i in range(0, len(rows), 500):
            cur.executemany(_UPSERT_SQL, rows[i : i + 500])
    return len(rows)
