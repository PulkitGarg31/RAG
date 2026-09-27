from dataclasses import dataclass

from vt.retrieval.base import Hit


def reciprocal_rank_fusion(ranked_lists: list[list[str]], k: int = 60) -> dict[str, float]:
    """score(d) = sum over lists of 1 / (k + rank(d)), rank is 1-indexed."""
    scores: dict[str, float] = {}
    for ranked in ranked_lists:
        for rank, doc_id in enumerate(ranked, start=1):
            scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank)
    return scores


@dataclass
class HybridRetriever:
    bm25_retriever: object
    dense_retriever: object
    rrf_k: int = 60
    fanout: int = 50

    def search(self, query: str, k: int = 10, advisory_filter=None) -> list[Hit]:
        fanout = max(self.fanout, k)
        bm25_hits = self.bm25_retriever.search(query, k=fanout, advisory_filter=advisory_filter)
        dense_hits = self.dense_retriever.search(query, k=fanout, advisory_filter=advisory_filter)

        by_id = {h.chunk_id: h for h in [*bm25_hits, *dense_hits]}
        fused = reciprocal_rank_fusion(
            [[h.chunk_id for h in bm25_hits], [h.chunk_id for h in dense_hits]], k=self.rrf_k
        )
        ranked_ids = sorted(fused, key=fused.get, reverse=True)[:k]
        return [
            Hit(chunk_id=cid, advisory_id=by_id[cid].advisory_id, score=fused[cid], text=by_id[cid].text)
            for cid in ranked_ids
        ]
