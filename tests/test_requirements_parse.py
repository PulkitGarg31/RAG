from vt.scanner.requirements import parse_requirements, ParsedLine


def test_parses_simple_pin():
    result = parse_requirements("jinja2==2.10\n")
    assert result == [ParsedLine(package="jinja2", version="2.10", skipped_reason=None)]


def test_strips_comments():
    result = parse_requirements("jinja2==2.10  # pinned for security\n# full line comment\n")
    assert len(result) == 1
    assert result[0].package == "jinja2"


def test_strips_extras():
    result = parse_requirements("requests[security]==2.19.0\n")
    assert result[0].package == "requests"
    assert result[0].version == "2.19.0"


def test_strips_environment_markers():
    result = parse_requirements('pywin32==300 ; sys_platform == "win32"\n')
    assert result[0].package == "pywin32"
    assert result[0].version == "300"


def test_normalizes_package_name():
    result = parse_requirements("PyYAML==5.3\n")
    assert result[0].package == "pyyaml"


def test_unpinned_line_is_skipped_not_guessed():
    result = parse_requirements("requests>=2.0\n")
    assert result[0].skipped_reason == "not pinned"
    assert result[0].version is None


def test_blank_lines_ignored():
    result = parse_requirements("jinja2==2.10\n\n\npyyaml==5.3\n")
    assert len(result) == 2


def test_demo_fixture_parses_eight_pins():
    from pathlib import Path

    text = (Path(__file__).parent / "fixtures" / "requirements_demo.txt").read_text()
    result = parse_requirements(text)
    assert len(result) == 8
    assert all(r.skipped_reason is None for r in result)


def test_parses_local_version_identifier():
    result = parse_requirements("foo==1.0.0+local\n")
    assert result[0].version == "1.0.0+local"
