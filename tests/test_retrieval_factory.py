import os
from unittest.mock import MagicMock

from vt.bm25_index import build_bm25, save_bm25
from vt.retrieval import factory
from vt.retrieval.factory import load_snapshot

_CHUNK_ROWS = [("c1", "A1", "yaml code"), ("c2", "A2", "pillow crash"), ("c3", "A3", "third doc")]
_GROUP_ROWS = [("A1", "G1"), ("A2", None), ("A3", "G3")]


def test_snapshot_is_cached_until_bm25_file_changes(tmp_path):
    path = tmp_path / "bm25.pkl"
    save_bm25(build_bm25(["yaml code", "pillow crash", "third doc"]), ["c1", "c2", "c3"], path)
    conn = MagicMock()
    cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchall.side_effect = [_CHUNK_ROWS, _GROUP_ROWS, _CHUNK_ROWS, _GROUP_ROWS]
    factory._cache.clear()

    first = load_snapshot(conn, path)
    second = load_snapshot(conn, path)
    assert first is second
    assert cur.execute.call_count == 2
    assert first.group_of == {"A1": "G1", "A2": "A2", "A3": "G3"}
    assert first.advisory_ids["c2"] == "A2"

    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    third = load_snapshot(conn, path)
    assert third is not first
    assert cur.execute.call_count == 4


def test_snapshot_is_none_without_an_index(tmp_path):
    factory._cache.clear()
    assert load_snapshot(MagicMock(), tmp_path / "missing.pkl") is None
