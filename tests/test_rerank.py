from unittest.mock import MagicMock

from vt.retrieval.base import Hit
from vt.retrieval.rerank import RerankedRetriever


def test_reranked_retriever_reorders_by_cross_encoder_score():
    hybrid_hits = [
        Hit(chunk_id="c1", advisory_id="A1", score=0.1, text="unrelated text"),
        Hit(chunk_id="c2", advisory_id="A2", score=0.05, text="yaml load rce exact match"),
    ]
    fake_hybrid = MagicMock()
    fake_hybrid.search.return_value = hybrid_hits

    fake_cross_encoder = MagicMock()
    # cross-encoder scores c2 higher than its hybrid rank suggested
    fake_cross_encoder.predict.return_value = [0.1, 0.9]

    retriever = RerankedRetriever(hybrid=fake_hybrid, cross_encoder=fake_cross_encoder, hybrid_k=30)
    hits = retriever.search("yaml load rce", k=2)

    assert hits[0].chunk_id == "c2"
    fake_hybrid.search.assert_called_once_with("yaml load rce", k=30, advisory_filter=None)
