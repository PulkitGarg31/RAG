from vt.retrieval.base import Hit


def dedupe_to_advisory(hits: list[Hit]) -> list[Hit]:
    """Keep only the best-scoring hit per advisory_id, preserving descending score order."""
    best: dict[str, Hit] = {}
    for h in hits:
        cur = best.get(h.advisory_id)
        if cur is None or h.score > cur.score:
            best[h.advisory_id] = h
    return sorted(best.values(), key=lambda h: h.score, reverse=True)
