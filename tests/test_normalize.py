from vt.normalize import normalize_package


def test_normalize_lowercases():
    assert normalize_package("PyYAML") == "pyyaml"


def test_normalize_collapses_separators():
    assert normalize_package("zope.interface") == "zope-interface"
    assert normalize_package("zope_interface") == "zope-interface"
    assert normalize_package("zope--interface") == "zope-interface"
