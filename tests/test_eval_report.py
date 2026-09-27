from vt.eval.report import render_markdown_table, write_report


def test_render_markdown_table_has_header_and_rows():
    rows = [
        {"setup": "BM25", "recall@1": 0.10, "recall@5": 0.30, "recall@10": 0.40, "mrr@10": 0.20, "p50_ms": 5.0},
    ]
    md = render_markdown_table(rows)
    assert "| Setup |" in md
    assert "| BM25 | 0.100 | 0.300 | 0.400 | 0.200 | 5.0 |" in md


def test_write_report_includes_note(tmp_path):
    rows = [{"setup": "BM25", "recall@1": 0.1, "recall@5": 0.3, "recall@10": 0.4, "mrr@10": 0.2, "p50_ms": 5.0}]
    write_report(rows, tmp_path / "eval.md", note="53 queries evaluated.")
    text = (tmp_path / "eval.md").read_text(encoding="utf-8")
    assert "53 queries evaluated." in text
    assert "| BM25 |" in text
