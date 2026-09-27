from dataclasses import dataclass
from typing import Callable

from pgvector import Vector

from vt.embed import embed_query
from vt.retrieval.base import Hit


@dataclass
class DenseRetriever:
    get_conn: Callable

    def search(self, query: str, k: int = 10, advisory_filter: set[str] | None = None) -> list[Hit]:
        # Wrap in pgvector's Vector so psycopg binds this parameter as the `vector`
        # type (required for the <=> operator); a bare Python list gets bound as a
        # numeric array and Postgres rejects `vector <=> real[]`.
        vec = Vector(list(embed_query(query)))
        if advisory_filter is None:
            sql = (
                "SELECT id, advisory_id, 1 - (embedding <=> %s) AS score, content FROM chunks "
                "ORDER BY embedding <=> %s LIMIT %s"
            )
            params: list = [vec, vec, k]
        else:
            # Filter first, then rank exactly. If the planner used the HNSW index here it would
            # return only hnsw.ef_search (40) global neighbours *before* the WHERE clause, which
            # a filter to a few advisories can reduce to zero rows.
            sql = (
                "WITH candidates AS MATERIALIZED ("
                "SELECT id, advisory_id, content, embedding FROM chunks WHERE advisory_id = ANY(%s)) "
                "SELECT id, advisory_id, 1 - (embedding <=> %s) AS score, content FROM candidates "
                "ORDER BY embedding <=> %s LIMIT %s"
            )
            params = [list(advisory_filter), vec, vec, k]

        conn = self.get_conn()
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [Hit(chunk_id=r[0], advisory_id=r[1], score=float(r[2]), text=r[3]) for r in rows]
