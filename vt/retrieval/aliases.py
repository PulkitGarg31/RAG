from vt.models import Advisory


class _UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def build_alias_groups(advisories: list[Advisory]) -> dict[str, str]:
    """Return {advisory_id: group_id}. Advisories sharing any alias (or id-as-alias) share a group.

    group_id is the lexicographically smallest member (advisory id or alias) of the group, so it
    doesn't depend on ingest order or on which mirror records happen to be ingested.
    """
    uf = _UnionFind()
    for adv in advisories:
        uf.find(adv.id)
        for key in adv.aliases:
            uf.union(adv.id, key)
    smallest: dict[str, str] = {}
    for member in list(uf.parent):
        root = uf.find(member)
        if root not in smallest or member < smallest[root]:
            smallest[root] = member
    return {adv.id: smallest[uf.find(adv.id)] for adv in advisories}
