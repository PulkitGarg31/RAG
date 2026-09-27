from vt.retrieval.aliases import build_alias_groups
from vt.models import Advisory


def test_pysec_and_ghsa_sharing_cve_end_in_one_group():
    a = Advisory(id="GHSA-462w-v97r-4m45", package="jinja2", aliases=["CVE-2019-10906"])
    b = Advisory(
        id="PYSEC-2019-217",
        package="jinja2",
        aliases=["CVE-2019-10906", "GHSA-462w-v97r-4m45"],
    )
    groups = build_alias_groups([a, b])
    assert groups[a.id] == groups[b.id]


def test_unrelated_advisories_get_different_groups():
    a = Advisory(id="GHSA-aaaa", package="foo", aliases=["CVE-2020-0001"])
    b = Advisory(id="GHSA-bbbb", package="bar", aliases=["CVE-2020-0002"])
    groups = build_alias_groups([a, b])
    assert groups[a.id] != groups[b.id]


def test_group_id_is_smallest_member_regardless_of_order():
    a = Advisory(id="GHSA-462w-v97r-4m45", package="jinja2", aliases=["CVE-2019-10906"])
    b = Advisory(id="PYSEC-2019-217", package="jinja2", aliases=["CVE-2019-10906", "GHSA-462w-v97r-4m45"])
    assert build_alias_groups([a, b])[a.id] == "CVE-2019-10906"
    assert build_alias_groups([b, a])[b.id] == "CVE-2019-10906"


def test_group_id_is_stable_when_a_mirror_is_not_ingested():
    a = Advisory(id="GHSA-462w-v97r-4m45", package="jinja2", aliases=["CVE-2019-10906"])
    b = Advisory(id="PYSEC-2019-217", package="jinja2", aliases=["CVE-2019-10906", "GHSA-462w-v97r-4m45"])
    assert build_alias_groups([a])[a.id] == build_alias_groups([a, b])[a.id]
    assert build_alias_groups([b])[b.id] == build_alias_groups([a, b])[b.id]


def test_advisory_without_aliases_is_its_own_group():
    a = Advisory(id="GHSA-solo", package="x", aliases=[])
    assert build_alias_groups([a]) == {"GHSA-solo": "GHSA-solo"}
