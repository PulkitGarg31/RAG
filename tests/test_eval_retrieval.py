from unittest.mock import MagicMock

from vt.eval.retrieval import evaluate_setup
from vt.retrieval.base import Hit


def test_evaluate_setup_computes_recall_and_mrr():
    fake_retriever = MagicMock()
    fake_retriever.search.side_effect = [
        [Hit(chunk_id="c1", advisory_id="A1", score=1.0, text="")],  # query 1: gold at rank 1
        [Hit(chunk_id="c2", advisory_id="A2", score=1.0, text="")],  # query 2: gold not retrieved
    ]
    group_of = {"A1": "G1", "A2": "G2"}
    queries = [
        {"query": "q1", "gold_group": "G1"},
        {"query": "q2", "gold_group": "G-MISSING"},
    ]

    result = evaluate_setup(fake_retriever, queries, group_of, k=10)

    assert result["recall@1"] == 0.5
    assert result["mrr@10"] == 0.5
    assert result["p50_ms"] >= 0.0
