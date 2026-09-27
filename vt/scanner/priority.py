from vt.config import settings


def compute_priority(
    cvss_score: float | None,
    epss: float | None,
    epss_percentile: float | None,
    in_kev: bool,
) -> str:
    """First matching rule wins (spec section 7.3). Thresholds live in config, not here."""
    if in_kev:
        return "P0"

    if (epss is not None and epss >= settings.epss_p1_threshold) or (
        cvss_score is not None and cvss_score >= settings.cvss_p1_threshold
    ):
        return "P1"

    if (cvss_score is not None and cvss_score >= settings.cvss_p2_threshold) or (
        epss_percentile is not None and epss_percentile >= settings.epss_percentile_p2_threshold
    ):
        return "P2"

    return "P3"
