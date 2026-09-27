import re
from dataclasses import dataclass

from vt.normalize import normalize_package

_PIN_RE = re.compile(
    r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+]+)"
)
_UNPINNED_NAME_RE = re.compile(r"^([A-Za-z0-9_.\-]+)")


@dataclass(frozen=True)
class ParsedLine:
    package: str
    version: str | None
    skipped_reason: str | None


def _strip_comment_and_marker(line: str) -> str:
    line = line.split("#", 1)[0]
    line = line.split(";", 1)[0]
    return line.strip()


def parse_requirements(text: str) -> list[ParsedLine]:
    results: list[ParsedLine] = []
    for raw_line in text.splitlines():
        line = _strip_comment_and_marker(raw_line)
        if not line:
            continue

        pin_match = _PIN_RE.match(line)
        if pin_match:
            name, _extras, version = pin_match.groups()
            results.append(ParsedLine(package=normalize_package(name), version=version, skipped_reason=None))
            continue

        name_match = _UNPINNED_NAME_RE.match(line)
        if name_match:
            results.append(
                ParsedLine(package=normalize_package(name_match.group(1)), version=None, skipped_reason="not pinned")
            )
    return results
