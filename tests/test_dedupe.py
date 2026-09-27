from vt.retrieval.base import Hit
from vt.retrieval.dedupe import dedupe_to_advisory


def test_dedupe_keeps_best_ranked_chunk_per_advisory():
    hits = [
        Hit(chunk_id="c1", advisory_id="ADV-1", score=0.9, text="a"),
        Hit(chunk_id="c2", advisory_id="ADV-1", score=0.5, text="b"),  # same advisory, lower score
        Hit(chunk_id="c3", advisory_id="ADV-2", score=0.8, text="c"),
    ]
    deduped = dedupe_to_advisory(hits)
    assert [h.advisory_id for h in deduped] == ["ADV-1", "ADV-2"]
    assert next(h for h in deduped if h.advisory_id == "ADV-1").chunk_id == "c1"


def test_dedupe_handles_empty_and_single_hit_lists():
    assert dedupe_to_advisory([]) == []

    single = [Hit(chunk_id="c1", advisory_id="ADV-1", score=0.5, text="a")]
    assert dedupe_to_advisory(single) == single


def test_dedupe_collapses_alias_group_members():
    hits = [
        Hit(chunk_id="c1", advisory_id="GHSA-a", score=0.9, text="a"),
        Hit(chunk_id="c2", advisory_id="PYSEC-a", score=0.8, text="b"),
        Hit(chunk_id="c3", advisory_id="GHSA-b", score=0.7, text="c"),
    ]
    group_of = {"GHSA-a": "CVE-1", "PYSEC-a": "CVE-1", "GHSA-b": "GHSA-b"}
    assert [h.chunk_id for h in dedupe_to_advisory(hits, group_of)] == ["c1", "c3"]
