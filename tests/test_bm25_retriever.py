from vt.retrieval.bm25 import BM25Retriever
from vt.bm25_index import build_bm25


def _retriever():
    chunk_ids = ["c1", "c2", "c3"]
    advisory_ids = {"c1": "ADV-1", "c2": "ADV-2", "c3": "ADV-2"}
    texts = {
        "c1": "yaml load arbitrary code execution vulnerability",
        "c2": "pillow image parsing buffer overflow",
        "c3": "pillow buffer overflow crash on crafted image",
    }
    bm25 = build_bm25([texts[cid] for cid in chunk_ids])
    return BM25Retriever(bm25=bm25, chunk_ids=chunk_ids, advisory_ids=advisory_ids, texts=texts), chunk_ids


def test_bm25_retriever_returns_hits_ranked_by_relevance():
    retriever, _ = _retriever()
    hits = retriever.search("yaml code execution", k=2)
    assert hits[0].chunk_id == "c1"


def test_bm25_retriever_respects_advisory_filter():
    retriever, _ = _retriever()
    hits = retriever.search("buffer overflow", k=3, advisory_filter={"ADV-2"})
    assert all(h.advisory_id == "ADV-2" for h in hits)
    assert len(hits) == 2
