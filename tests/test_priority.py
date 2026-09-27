from vt.scanner.priority import compute_priority


def test_kev_beats_everything():
    assert compute_priority(cvss_score=1.0, epss=0.0, epss_percentile=0.0, in_kev=True) == "P0"


def test_epss_at_threshold_is_p1():
    assert compute_priority(cvss_score=None, epss=0.10, epss_percentile=None, in_kev=False) == "P1"


def test_epss_just_below_threshold_is_not_p1():
    assert compute_priority(cvss_score=None, epss=0.099, epss_percentile=None, in_kev=False) == "P3"


def test_cvss_at_9_is_p1():
    assert compute_priority(cvss_score=9.0, epss=None, epss_percentile=None, in_kev=False) == "P1"


def test_cvss_at_7_is_p2():
    assert compute_priority(cvss_score=7.0, epss=None, epss_percentile=None, in_kev=False) == "P2"


def test_cvss_just_below_7_is_p3():
    assert compute_priority(cvss_score=6.99, epss=None, epss_percentile=None, in_kev=False) == "P3"


def test_epss_percentile_at_90_is_p2():
    assert compute_priority(cvss_score=None, epss=0.01, epss_percentile=0.90, in_kev=False) == "P2"


def test_missing_all_data_is_p3():
    assert compute_priority(cvss_score=None, epss=None, epss_percentile=None, in_kev=False) == "P3"


def test_p1_beats_p2_when_both_match():
    # CVSS 9.5 matches both P1 (>=9.0) and P2 (>=7.0) rules -> first match (P1) wins
    assert compute_priority(cvss_score=9.5, epss=None, epss_percentile=None, in_kev=False) == "P1"
