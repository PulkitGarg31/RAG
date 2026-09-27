from dataclasses import dataclass
from functools import lru_cache

from vt.config import settings
from vt.retrieval.base import Hit


@lru_cache(maxsize=1)
def _cross_encoder():
    from sentence_transformers import CrossEncoder

    return CrossEncoder(settings.rerank_model)


@dataclass
class RerankedRetriever:
    hybrid: object
    cross_encoder: object = None
    hybrid_k: int = 30

    def search(self, query: str, k: int = 10, advisory_filter=None) -> list[Hit]:
        candidates = self.hybrid.search(query, k=self.hybrid_k, advisory_filter=advisory_filter)
        if not candidates:
            return []
        model = self.cross_encoder or _cross_encoder()
        scores = model.predict([(query, h.text) for h in candidates])
        rescored = [
            Hit(chunk_id=h.chunk_id, advisory_id=h.advisory_id, score=float(s), text=h.text)
            for h, s in zip(candidates, scores)
        ]
        return sorted(rescored, key=lambda h: h.score, reverse=True)[:k]
