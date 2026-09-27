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


def test_recall_is_over_distinct_advisory_groups_not_chunks():
    hits = [Hit(chunk_id=f"{g}{i}", advisory_id=g, score=1.0, text="") for g in "ABC" for i in range(4)]
    hits.append(Hit(chunk_id="D0", advisory_id="D", score=1.0, text=""))  # 13th chunk, 4th advisory
    retriever = MagicMock()
    retriever.search.side_effect = lambda query, k: hits[:k]

    result = evaluate_setup(retriever, [{"query": "q", "advisory_id": "D"}], {g: g for g in "ABCD"}, k=10)

    assert result["recall@5"] == 1.0
    assert result["mrr@10"] == 0.25


def test_gold_group_comes_from_the_querys_advisory_at_eval_time():
    retriever = MagicMock()
    retriever.search.return_value = [Hit(chunk_id="c1", advisory_id="PYSEC-1", score=1.0, text="")]
    group_of = {"PYSEC-1": "CVE-1", "GHSA-1": "CVE-1"}

    result = evaluate_setup(
        retriever, [{"query": "q", "advisory_id": "GHSA-1", "gold_group": "STALE-ROOT"}], group_of, k=10
    )

    assert result["recall@1"] == 1.0


def test_queries_whose_advisory_left_the_corpus_are_skipped():
    retriever = MagicMock()
    retriever.search.return_value = []

    result = evaluate_setup(
        retriever, [{"query": "q", "advisory_id": "GONE"}, {"query": "q2", "gold_group": "G"}], {"A": "A"}, k=10
    )

    assert result["queries"] == 1
    assert result["skipped"] == 1
