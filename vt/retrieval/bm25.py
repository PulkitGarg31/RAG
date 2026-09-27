from dataclasses import dataclass

import numpy as np

from vt.bm25_index import tokenize
from vt.retrieval.base import Hit


@dataclass
class BM25Retriever:
    bm25: object
    chunk_ids: list[str]
    advisory_ids: dict[str, str]
    texts: dict[str, str]

    def search(self, query: str, k: int = 10, advisory_filter: set[str] | None = None) -> list[Hit]:
        scores = self.bm25.get_scores(tokenize(query))
        order = np.argsort(scores)[::-1]
        hits: list[Hit] = []
        for idx in order:
            cid = self.chunk_ids[idx]
            adv_id = self.advisory_ids.get(cid)
            if adv_id is None:  # bm25.pkl is older than the chunks table
                continue
            if advisory_filter is not None and adv_id not in advisory_filter:
                continue
            hits.append(Hit(chunk_id=cid, advisory_id=adv_id, score=float(scores[idx]), text=self.texts[cid]))
            if len(hits) >= k:
                break
        return hits
