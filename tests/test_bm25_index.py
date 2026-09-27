from pathlib import Path

from vt.bm25_index import build_bm25, save_bm25, load_bm25, tokenize


def test_tokenize_lowercases_and_splits():
    assert tokenize("Jinja2 Sandbox Escape!") == ["jinja2", "sandbox", "escape"]


def test_tokenize_keeps_cve_ids_intact():
    tokens = tokenize("Fixes CVE-2019-10906 in jinja2")
    assert "cve-2019-10906" in tokens


def test_build_bm25_ranks_relevant_doc_higher():
    # A third, unrelated filler doc avoids the degenerate BM25 case where a
    # term's document frequency equals exactly half the corpus size (df=1 of
    # N=2), which makes Okapi's idf formula evaluate to exactly 0 for every
    # query term and collapses both scores to 0.0 regardless of relevance.
    chunk_ids = ["a", "b", "c"]
    texts = [
        "yaml load arbitrary code execution",
        "unrelated pillow image crash",
        "sql injection in login form",
    ]
    bm25 = build_bm25(texts)
    scores = bm25.get_scores(tokenize("yaml code execution"))
    assert scores[0] > scores[1]


def test_save_and_load_roundtrip(tmp_path: Path):
    chunk_ids = ["a", "b"]
    texts = ["yaml load arbitrary code execution", "unrelated pillow image crash"]
    bm25 = build_bm25(texts)
    path = tmp_path / "bm25.pkl"
    save_bm25(bm25, chunk_ids, path)
    loaded_bm25, loaded_ids = load_bm25(path)
    assert loaded_ids == chunk_ids
    assert loaded_bm25.get_scores(tokenize("yaml")).tolist() == bm25.get_scores(tokenize("yaml")).tolist()
