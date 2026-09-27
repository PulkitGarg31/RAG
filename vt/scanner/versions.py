from packaging.version import InvalidVersion, Version

from vt.models import Advisory


def safe_parse(version_str: str) -> Version | None:
    try:
        return Version(version_str)
    except InvalidVersion:
        return None


def min_safe_version(installed: str, advisories: list[Advisory]) -> str | None:
    """Smallest version >= installed that fixes EVERY advisory affecting this package."""
    inst = Version(installed)
    needed: list[Version] = []
    for adv in advisories:
        fixes = sorted(
            v for v in (safe_parse(fv) for fv in adv.fixed_versions) if v is not None and v > inst
        )
        if not fixes:
            return None
        needed.append(fixes[0])
    return str(max(needed)) if needed else None
