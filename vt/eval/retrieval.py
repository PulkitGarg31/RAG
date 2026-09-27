import time

from vt.eval.metrics import hit_at_k, reciprocal_rank


def evaluate_setup(retriever, queries: list[dict], group_of: dict[str, str], k: int = 10) -> dict:
    hits_at = {1: 0, 5: 0, 10: 0}
    reciprocal_ranks = []
    latencies_ms = []

    for q in queries:
        start = time.perf_counter()
        results = retriever.search(q["query"], k=k)
        latencies_ms.append((time.perf_counter() - start) * 1000)

        seen = set()
        ranked_groups = []
        for hit in results:
            g = group_of.get(hit.advisory_id, hit.advisory_id)
            if g not in seen:
                seen.add(g)
                ranked_groups.append(g)

        gold = q["gold_group"]
        for cutoff in (1, 5, 10):
            if hit_at_k(ranked_groups, gold, cutoff):
                hits_at[cutoff] += 1
        reciprocal_ranks.append(reciprocal_rank(ranked_groups, gold, cutoff=10))

    n = len(queries) or 1
    latencies_ms.sort()
    p50 = latencies_ms[len(latencies_ms) // 2] if latencies_ms else 0.0

    return {
        "recall@1": hits_at[1] / n, "recall@5": hits_at[5] / n, "recall@10": hits_at[10] / n,
        "mrr@10": sum(reciprocal_ranks) / n, "p50_ms": p50,
    }


def run_full_eval(queries: list[dict]) -> list[dict]:
    """Build all four retrievers against the live index and evaluate each. Dev-run only (needs Postgres + bm25.pkl)."""
    from pathlib import Path

    from vt.bm25_index import load_bm25
    from vt.db import get_conn
    from vt.retrieval.bm25 import BM25Retriever
    from vt.retrieval.dense import DenseRetriever
    from vt.retrieval.hybrid import HybridRetriever
    from vt.retrieval.rerank import RerankedRetriever

    bm25, chunk_ids = load_bm25(Path("data/bm25.pkl"))
    rows = []
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, advisory_id, content FROM chunks WHERE id = ANY(%s)", (chunk_ids,))
            chunk_rows = {r[0]: r for r in cur.fetchall()}
        advisory_ids = {cid: chunk_rows[cid][1] for cid in chunk_ids if cid in chunk_rows}
        texts = {cid: chunk_rows[cid][2] for cid in chunk_ids if cid in chunk_rows}

        with conn.cursor() as cur:
            cur.execute("SELECT id, group_id FROM advisories")
            group_of = {r[0]: (r[1] or r[0]) for r in cur.fetchall()}

        bm25_retriever = BM25Retriever(bm25=bm25, chunk_ids=chunk_ids, advisory_ids=advisory_ids, texts=texts)
        dense_retriever = DenseRetriever(get_conn=lambda: conn)
        hybrid = HybridRetriever(bm25_retriever=bm25_retriever, dense_retriever=dense_retriever)
        reranked = RerankedRetriever(hybrid=hybrid)

        for name, retriever in [
            ("BM25", bm25_retriever), ("Dense (bge-small)", dense_retriever),
            ("Hybrid (RRF)", hybrid), ("Hybrid + cross-encoder", reranked),
        ]:
            result = evaluate_setup(retriever, queries, group_of)
            rows.append({"setup": name, **result})

    return rows
