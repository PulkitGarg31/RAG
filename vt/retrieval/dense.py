from dataclasses import dataclass
from typing import Callable

from vt.embed import embed_query
from vt.retrieval.base import Hit


@dataclass
class DenseRetriever:
    get_conn: Callable

    def search(self, query: str, k: int = 10, advisory_filter: set[str] | None = None) -> list[Hit]:
        vec = list(embed_query(query))
        sql = "SELECT id, advisory_id, 1 - (embedding <=> %s) AS score, content FROM chunks"
        params: list = [vec]
        if advisory_filter is not None:
            sql += " WHERE advisory_id = ANY(%s)"
            params.append(list(advisory_filter))
        sql += " ORDER BY embedding <=> %s LIMIT %s"
        params.extend([vec, k])

        conn = self.get_conn()
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [Hit(chunk_id=r[0], advisory_id=r[1], score=float(r[2]), text=r[3]) for r in rows]
