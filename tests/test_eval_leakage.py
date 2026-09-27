from vt.eval.leakage import question_leaks_identifiers


def test_leaks_when_package_name_present():
    assert question_leaks_identifiers(
        "The jinja2 template engine allows sandbox escape", package="jinja2", ids=["GHSA-1", "CVE-1"]
    )


def test_leaks_when_advisory_id_present():
    assert question_leaks_identifiers(
        "See GHSA-1 for details", package="jinja2", ids=["GHSA-1"]
    )


def test_no_leak_for_clean_question():
    assert not question_leaks_identifiers(
        "template rendering in a Python web templating library allows sandbox escape",
        package="jinja2", ids=["GHSA-1", "CVE-2019-10906"],
    )


def test_leak_check_is_case_insensitive():
    assert question_leaks_identifiers("Uses JINJA2 under the hood", package="jinja2", ids=[])
