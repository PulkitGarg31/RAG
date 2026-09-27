import time

from vt.eval.metrics import hit_at_k, reciprocal_rank


def evaluate_setup(retriever, queries: list[dict], group_of: dict[str, str], k: int = 10, fetch_k: int = 50) -> dict:
    """Recall@{1,5,10} and MRR@10 over the top-k distinct advisory *groups* per query.

    fetch_k chunks are retrieved and deduped to alias groups before ranking, because each
    advisory contributes several chunks. The gold group is resolved from the query's
    advisory_id at eval time (stored gold_group is only a fallback), so re-ingesting can't
    silently break labels; queries whose advisory left the corpus are skipped and counted.
    """
    hits_at = {1: 0, 5: 0, 10: 0}
    reciprocal_ranks: list[float] = []
    latencies_ms: list[float] = []
    skipped = 0

    for q in queries:
        adv_id = q.get("advisory_id")
        if adv_id is not None:
            if adv_id not in group_of:
                skipped += 1
                continue
            gold = group_of[adv_id]
        else:
            gold = q["gold_group"]

        start = time.perf_counter()
        results = retriever.search(q["query"], k=fetch_k)
        latencies_ms.append((time.perf_counter() - start) * 1000)

        seen: set[str] = set()
        ranked_groups: list[str] = []
        for hit in results:
            g = group_of.get(hit.advisory_id, hit.advisory_id)
            if g not in seen:
                seen.add(g)
                ranked_groups.append(g)
        ranked_groups = ranked_groups[:k]

        for cutoff in (1, 5, 10):
            if hit_at_k(ranked_groups, gold, cutoff):
                hits_at[cutoff] += 1
        reciprocal_ranks.append(reciprocal_rank(ranked_groups, gold, cutoff=10))

    n = len(reciprocal_ranks) or 1
    latencies_ms.sort()
    p50 = latencies_ms[len(latencies_ms) // 2] if latencies_ms else 0.0
    return {
        "recall@1": hits_at[1] / n, "recall@5": hits_at[5] / n, "recall@10": hits_at[10] / n,
        "mrr@10": sum(reciprocal_ranks) / n, "p50_ms": p50,
        "queries": len(reciprocal_ranks), "skipped": skipped,
    }


def run_full_eval(queries: list[dict]) -> list[dict]:
    """Build all four retrievers against the live index and evaluate each. Dev-run only (needs Postgres + bm25.pkl)."""
    from vt.db import get_conn
    from vt.retrieval.factory import build_retrievers

    rows = []
    with get_conn() as conn:
        retrievers = build_retrievers(conn)
        if retrievers is None:
            raise RuntimeError("No BM25 index found; run `vt index` first.")
        for name, retriever in [
            ("BM25", retrievers.bm25), ("Dense (bge-small)", retrievers.dense),
            ("Hybrid (RRF)", retrievers.hybrid), ("Hybrid + cross-encoder", retrievers.reranked),
        ]:
            rows.append({"setup": name, **evaluate_setup(retriever, queries, retrievers.group_of)})
    return rows
