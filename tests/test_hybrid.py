from unittest.mock import MagicMock

from vt.retrieval.hybrid import HybridRetriever


def test_hybrid_fanout_grows_with_k():
    bm25, dense = MagicMock(), MagicMock()
    bm25.search.return_value = []
    dense.search.return_value = []
    HybridRetriever(bm25_retriever=bm25, dense_retriever=dense, fanout=50).search("q", k=80)
    bm25.search.assert_called_once_with("q", k=80, advisory_filter=None)
    dense.search.assert_called_once_with("q", k=80, advisory_filter=None)
