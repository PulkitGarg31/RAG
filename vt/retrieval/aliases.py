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
    # Normalize: within one advisory's own alias set, union everything to adv.id first,
    # then a second pass unions across advisories that reference each other's ids.
    for adv in advisories:
        for other in advisories:
            if other.id == adv.id:
                continue
            shared = (set(adv.aliases) | {adv.id}) & (set(other.aliases) | {other.id})
            if shared:
                uf.union(adv.id, other.id)
    return {adv.id: uf.find(adv.id) for adv in advisories}
