from vt.eval.metrics import hit_at_k, reciprocal_rank


def test_hit_at_k_true_when_gold_in_top_k():
    ranked = ["g2", "g1", "g3"]
    assert hit_at_k(ranked, gold_group="g1", k=2) is True


def test_hit_at_k_false_when_gold_outside_top_k():
    ranked = ["g2", "g3", "g1"]
    assert hit_at_k(ranked, gold_group="g1", k=2) is False


def test_reciprocal_rank_of_first_position():
    assert reciprocal_rank(["g1", "g2"], gold_group="g1", cutoff=10) == 1.0


def test_reciprocal_rank_of_third_position():
    assert abs(reciprocal_rank(["g2", "g3", "g1"], gold_group="g1", cutoff=10) - 1 / 3) < 1e-9


def test_reciprocal_rank_zero_when_not_found_within_cutoff():
    assert reciprocal_rank(["g2", "g3"], gold_group="g1", cutoff=10) == 0.0
