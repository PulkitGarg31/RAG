import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from vt.normalize import normalize_package

# The version must be followed by whitespace, a line-continuation backslash, or end
# of line. This lookahead keeps wildcard pins like `pkg==2.*` unpinned while still
# allowing trailing `\` continuations (with or without a space) and `--hash=...`
# options after the version.
_PIN_RE = re.compile(
    r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)(?=\s|\\|$)"
)
_UNPINNED_NAME_RE = re.compile(r"^([A-Za-z0-9_.\-]+)")

_BOM = chr(0xFEFF)

# pip options that change what gets installed but that we can't follow, so they are
# reported as skipped. All other option lines (--hash continuations, --index-url,
# --find-links, ...) don't name a package and are ignored.
_UNSUPPORTED_PIP_OPTIONS = frozenset(
    {"-r", "--requirement", "-c", "--constraint", "-e", "--editable"}
)
# pip also accepts these short options with the value attached: `-rbase.txt`, `-e.`.
_ATTACHED_SHORT_OPTIONS = frozenset({"-r", "-c", "-e"})


@dataclass(frozen=True)
class ParsedLine:
    package: str
    version: str | None
    skipped_reason: str | None


def _strip_comment_and_marker(line: str) -> str:
    """Drop comments and environment markers, plus surrounding whitespace and BOMs
    (a BOM can start any line when files are concatenated; str.strip keeps it)."""
    line = line.split("#", 1)[0]
    line = line.split(";", 1)[0]
    return line.strip().strip(_BOM).strip()


def _is_unsupported_option(line: str) -> bool:
    """True for an option line that pulls in requirements we can't follow: -r/-c/-e and
    their long forms (with a space or `=`), including attached short forms like `-rbase.txt`.
    A `--` option never matches the short-form check because its first two chars are `--`."""
    option = line.split()[0].split("=", 1)[0]
    return option in _UNSUPPORTED_PIP_OPTIONS or line[:2] in _ATTACHED_SHORT_OPTIONS


def parse_requirements(text: str) -> list[ParsedLine]:
    results: list[ParsedLine] = []
    for raw_line in text.splitlines():
        line = _strip_comment_and_marker(raw_line)
        if not line:
            continue

        if line.startswith("-"):
            if _is_unsupported_option(line):
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
