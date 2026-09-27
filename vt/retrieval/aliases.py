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
    """Return {advisory_id: group_id}. Advisories sharing any alias (or id-as-alias) share a group."""
    uf = _UnionFind()
    for adv in advisories:
        keys = [adv.id, *adv.aliases]
        uf.find(adv.id)
        for key in keys[1:]:
            uf.union(adv.id, key)
    return {adv.id: uf.find(adv.id) for adv in advisories}
