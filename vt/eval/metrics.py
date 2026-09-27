def hit_at_k(ranked_groups: list[str], gold_group: str, k: int) -> bool:
    return gold_group in ranked_groups[:k]


def reciprocal_rank(ranked_groups: list[str], gold_group: str, cutoff: int) -> float:
    for i, g in enumerate(ranked_groups[:cutoff], start=1):
        if g == gold_group:
            return 1.0 / i
    return 0.0
