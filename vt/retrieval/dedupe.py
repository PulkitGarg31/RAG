from vt.retrieval.base import Hit


def dedupe_to_advisory(hits: list[Hit], group_of: dict[str, str] | None = None) -> list[Hit]:
    """Keep the best-scoring hit per alias group (per advisory_id when group_of isn't given),
    in descending score order."""
    group_of = group_of or {}
    best: dict[str, Hit] = {}
    for h in hits:
        key = group_of.get(h.advisory_id, h.advisory_id)
        cur = best.get(key)
        if cur is None or h.score > cur.score:
            best[key] = h
    return sorted(best.values(), key=lambda h: h.score, reverse=True)
