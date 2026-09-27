import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from vt.normalize import normalize_package

# The version must be followed by whitespace or end of line. This lookahead keeps
# wildcard pins like `pkg==2.*` unpinned while still allowing trailing ` \`
# continuations and `--hash=...` options after the version.
_PIN_RE = re.compile(
    r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)(?=\s|$)"
)
_UNPINNED_NAME_RE = re.compile(r"^([A-Za-z0-9_.\-]+)")

# pip options that change what gets installed but that we can't follow, so they are
# reported as skipped. All other option lines (--hash continuations, --index-url,
# --find-links, ...) don't name a package and are ignored.
_UNSUPPORTED_PIP_OPTIONS = frozenset(
    {"-r", "--requirement", "-c", "--constraint", "-e", "--editable"}
)


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
    for raw_line in text.lstrip(chr(0xFEFF)).splitlines():
        line = _strip_comment_and_marker(raw_line)
        if not line:
            continue

        if line.startswith("-"):
            option = line.split()[0].split("=", 1)[0]
            if option in _UNSUPPORTED_PIP_OPTIONS:
                results.append(
                    ParsedLine(package=line, version=None, skipped_reason="unsupported pip option (not scanned)")
                )
            continue

        pin_match = _PIN_RE.match(line)
        if pin_match:
            name, _extras, version = pin_match.groups()
            try:
                Version(version)
            except InvalidVersion:
                results.append(ParsedLine(package=normalize_package(name), version=None, skipped_reason="invalid version"))
                continue
            results.append(ParsedLine(package=normalize_package(name), version=version, skipped_reason=None))
            continue

        name_match = _UNPINNED_NAME_RE.match(line)
        if name_match:
            results.append(
                ParsedLine(package=normalize_package(name_match.group(1)), version=None, skipped_reason="not pinned")
            )
    return results
