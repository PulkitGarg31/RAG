from unittest.mock import MagicMock

from vt.retrieval.dense import DenseRetriever


def test_dense_retriever_builds_filtered_query(monkeypatch):
    fake_conn = MagicMock()
    fake_cursor = fake_conn.cursor.return_value.__enter__.return_value
    fake_cursor.fetchall.return_value = [
        ("c1", "ADV-1", 0.9, "some text"),
        ("c2", "ADV-2", 0.8, "other text"),
    ]
    monkeypatch.setattr("vt.retrieval.dense.embed_query", lambda q: [0.1] * 384)

    retriever = DenseRetriever(get_conn=lambda: fake_conn)
    hits = retriever.search("query", k=2, advisory_filter={"ADV-1", "ADV-2"})

    assert len(hits) == 2
    executed_sql = fake_cursor.execute.call_args[0][0]
    assert "WHERE advisory_id = ANY" in executed_sql
    assert hits[0].chunk_id == "c1"


def test_dense_retriever_omits_filter_clause_when_none(monkeypatch):
    fake_conn = MagicMock()
    fake_cursor = fake_conn.cursor.return_value.__enter__.return_value
    fake_cursor.fetchall.return_value = []
    monkeypatch.setattr("vt.retrieval.dense.embed_query", lambda q: [0.1] * 384)

    retriever = DenseRetriever(get_conn=lambda: fake_conn)
    retriever.search("query", k=5)

    executed_sql = fake_cursor.execute.call_args[0][0]
    assert "WHERE advisory_id = ANY" not in executed_sql


def test_dense_retriever_filters_before_ranking(monkeypatch):
    fake_conn = MagicMock()
    fake_cursor = fake_conn.cursor.return_value.__enter__.return_value
    fake_cursor.fetchall.return_value = []
    monkeypatch.setattr("vt.retrieval.dense.embed_query", lambda q: [0.1] * 384)

    DenseRetriever(get_conn=lambda: fake_conn).search("q", k=3, advisory_filter={"ADV-1"})

    sql, params = fake_cursor.execute.call_args[0]
    assert "AS MATERIALIZED" in sql
    assert sql.index("WHERE advisory_id = ANY") < sql.index("ORDER BY")
    assert params[0] == ["ADV-1"]
    assert params[-1] == 3
