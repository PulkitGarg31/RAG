"""One place that builds the retrievers against the live index.

The BM25 index, chunk metadata and alias groups are loaded once and cached until
data/bm25.pkl changes (i.e. until the next `vt index`), instead of on every request.
"""
from dataclasses import dataclass
from pathlib import Path

from vt.bm25_index import load_bm25
from vt.retrieval.bm25 import BM25Retriever
from vt.retrieval.dense import DenseRetriever
from vt.retrieval.hybrid import HybridRetriever
from vt.retrieval.rerank import RerankedRetriever

BM25_PATH = Path("data/bm25.pkl")

_cache: dict[str, tuple] = {}


@dataclass(frozen=True)
class CorpusSnapshot:
    bm25: object
    chunk_ids: list[str]
    advisory_ids: dict[str, str]
    texts: dict[str, str]
    group_of: dict[str, str]


@dataclass
class Retrievers:
    bm25: BM25Retriever
    dense: DenseRetriever
    hybrid: HybridRetriever
    reranked: RerankedRetriever
    group_of: dict[str, str]

    def by_name(self) -> dict:
        return {"bm25": self.bm25, "dense": self.dense, "hybrid": self.hybrid, "hybrid_rerank": self.reranked}


def load_snapshot(conn, path: Path = BM25_PATH) -> CorpusSnapshot | None:
    if not path.exists():
        return None
    key = (str(path.resolve()), path.stat().st_mtime_ns)
    cached = _cache.get("snapshot")
    if cached is not None and cached[0] == key:
        return cached[1]

    bm25, chunk_ids = load_bm25(path)
    with conn.cursor() as cur:
        cur.execute("SELECT id, advisory_id, content FROM chunks WHERE id = ANY(%s)", (chunk_ids,))
        rows = cur.fetchall()
    with conn.cursor() as cur:
        cur.execute("SELECT id, group_id FROM advisories")
        group_of = {r[0]: (r[1] or r[0]) for r in cur.fetchall()}

    snapshot = CorpusSnapshot(
        bm25=bm25,
        chunk_ids=chunk_ids,
        advisory_ids={r[0]: r[1] for r in rows},
        texts={r[0]: r[2] for r in rows},
        group_of=group_of,
    )
    _cache["snapshot"] = (key, snapshot)
    return snapshot


def build_retrievers(conn) -> Retrievers | None:
    """All four retrievers bound to an already-open connection; None if `vt index` hasn't run."""
    snap = load_snapshot(conn)
    if snap is None:
        return None
    bm25 = BM25Retriever(bm25=snap.bm25, chunk_ids=snap.chunk_ids, advisory_ids=snap.advisory_ids, texts=snap.texts)
    dense = DenseRetriever(get_conn=lambda: conn)
    hybrid = HybridRetriever(bm25_retriever=bm25, dense_retriever=dense)
    return Retrievers(bm25=bm25, dense=dense, hybrid=hybrid, reranked=RerankedRetriever(hybrid=hybrid), group_of=snap.group_of)
