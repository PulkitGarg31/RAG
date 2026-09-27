from vt.retrieval.hybrid import reciprocal_rank_fusion


def test_rrf_hand_computed_two_lists():
    # list A ranks: d1(1), d2(2), d3(3)
    # list B ranks: d2(1), d3(2), d1(3)
    list_a = ["d1", "d2", "d3"]
    list_b = ["d2", "d3", "d1"]
    scores = reciprocal_rank_fusion([list_a, list_b], k=60)

    expected_d1 = 1 / (60 + 1) + 1 / (60 + 3)
    expected_d2 = 1 / (60 + 2) + 1 / (60 + 1)
    expected_d3 = 1 / (60 + 3) + 1 / (60 + 2)

    assert abs(scores["d1"] - expected_d1) < 1e-9
    assert abs(scores["d2"] - expected_d2) < 1e-9
    assert abs(scores["d3"] - expected_d3) < 1e-9
    # d2 appears at rank 1 in list B and rank 2 in list A -> highest fused score
    assert max(scores, key=scores.get) == "d2"


def test_rrf_document_only_in_one_list():
    scores = reciprocal_rank_fusion([["only_a"], ["d2", "d3"]], k=60)
    assert scores["only_a"] == 1 / 61
    assert set(scores) == {"only_a", "d2", "d3"}
