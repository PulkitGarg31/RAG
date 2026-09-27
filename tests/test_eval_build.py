from unittest.mock import MagicMock

from vt.eval.build import generate_query_for_advisory
from vt.models import Advisory


def test_returns_first_question_when_clean():
    adv = Advisory(id="GHSA-1", package="jinja2", cve_ids=["CVE-1"], details="sandbox escape bug")
    provider = MagicMock()
    provider.complete_json.return_value = '{"question": "template engine allows code execution via crafted input"}'

    q = generate_query_for_advisory(adv, provider)
    assert q == "template engine allows code execution via crafted input"
    assert provider.complete_json.call_count == 1


def test_regenerates_once_when_first_attempt_leaks():
    adv = Advisory(id="GHSA-1", package="jinja2", cve_ids=["CVE-1"], details="sandbox escape bug")
    provider = MagicMock()
    provider.complete_json.side_effect = [
        '{"question": "jinja2 has a sandbox escape"}',  # leaks package name
        '{"question": "a Python templating library has a sandbox escape"}',  # clean
    ]

    q = generate_query_for_advisory(adv, provider)
    assert q == "a Python templating library has a sandbox escape"
    assert provider.complete_json.call_count == 2


def test_returns_none_when_still_leaking_after_regenerate():
    adv = Advisory(id="GHSA-1", package="jinja2", cve_ids=["CVE-1"], details="sandbox escape bug")
    provider = MagicMock()
    provider.complete_json.return_value = '{"question": "jinja2 has a sandbox escape"}'

    q = generate_query_for_advisory(adv, provider)
    assert q is None
    assert provider.complete_json.call_count == 2
