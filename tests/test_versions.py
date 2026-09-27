import pytest

from vt.models import Advisory
from vt.scanner.versions import min_safe_version, safe_parse


def _adv(fixed_versions: list[str]) -> Advisory:
    return Advisory(id="ADV", package="pkg", fixed_versions=fixed_versions)


def test_single_advisory_single_fix():
    assert min_safe_version("1.0.0", [_adv(["1.2.0"])]) == "1.2.0"


def test_two_advisories_needing_different_fixes_takes_max():
    advisories = [_adv(["1.2.0"]), _adv(["1.5.0"])]
    assert min_safe_version("1.0.0", advisories) == "1.5.0"


def test_advisory_with_no_fix_above_installed_returns_none():
    # only fix is below the installed version -> effectively "no fix available" going forward
    assert min_safe_version("2.0.0", [_adv(["1.5.0"])]) is None


def test_no_advisories_returns_none():
    assert min_safe_version("1.0.0", []) is None


def test_picks_earliest_fix_above_installed_per_advisory():
    # two branches both fix this one advisory: 3.2.19 (old branch) and 4.1.0 (new branch)
    assert min_safe_version("3.0.0", [_adv(["3.2.19", "4.1.0"])]) == "3.2.19"


def test_safe_parse_handles_prerelease():
    assert safe_parse("2.0.0rc1") is not None


def test_safe_parse_handles_invalid_version_returns_none():
    assert safe_parse("not-a-version-!!!") is None


def test_min_safe_version_skips_invalid_fixed_versions():
    adv = _adv(["not-a-version", "1.3.0"])
    assert min_safe_version("1.0.0", [adv]) == "1.3.0"


def test_multi_branch_advisory_combined_with_second_advisory():
    # A has two independent fix branches (1.1.0, 2.0.0); B only fixed by 1.5.0.
    # A's earliest applicable fix (1.1.0) and B's (1.5.0) combine via max -> 1.5.0,
    # which is >= both advisories' relevant fixed_versions thresholds.
    advisories = [_adv(["1.1.0", "2.0.0"]), _adv(["1.5.0"])]
    assert min_safe_version("1.0.0", advisories) == "1.5.0"
