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
