import re


def normalize_package(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of -_. collapse to a single '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()
