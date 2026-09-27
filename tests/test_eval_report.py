from vt.eval.report import render_markdown_table


def test_render_markdown_table_has_header_and_rows():
    rows = [
        {"setup": "BM25", "recall@1": 0.10, "recall@5": 0.30, "recall@10": 0.40, "mrr@10": 0.20, "p50_ms": 5.0},
    ]
    md = render_markdown_table(rows)
    assert "| Setup |" in md
    assert "| BM25 | 0.100 | 0.300 | 0.400 | 0.200 | 5.0 |" in md
