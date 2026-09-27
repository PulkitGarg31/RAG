from vt.models import Advisory, Chunk

_MAX_DETAIL_CHARS = 1200
_TARGET_PIECE_CHARS = 800


def _header(adv: Advisory, kind: str) -> str:
    cve_part = ", ".join(adv.cve_ids) or "no-CVE"
    cwe_part = ",".join(adv.cwe_ids) or "-"
    return f"[PyPI:{adv.package}] [{adv.id}] [{cve_part}] [CWE:{cwe_part}] [{kind}]"


def _split_details(details: str) -> list[str]:
    if len(details) <= _MAX_DETAIL_CHARS:
        return [details]
    paragraphs = [p for p in details.split("\n\n") if p.strip()]
    pieces: list[str] = []
    current: list[str] = []
    current_len = 0
    for para in paragraphs:
        current.append(para)
        current_len += len(para)
        if current_len >= _TARGET_PIECE_CHARS:
            pieces.append("\n\n".join(current))
            current = [para]  # 1-paragraph overlap: carry the last paragraph forward
            current_len = len(para)
    if current and (not pieces or "\n\n".join(current) != pieces[-1]):
        pieces.append("\n\n".join(current))
    return pieces or [details]


def _render_affected(adv: Advisory) -> str:
    parts = []
    for entry in adv.affected:
        for r in entry.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            introduced = None
            for event in r.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event and introduced is not None:
                    parts.append(f"introduced {introduced}, fixed {event['fixed']}")
                    introduced = None
    return "Affected: " + ("; ".join(parts) if parts else "no known fix")


def _render_refs(adv: Advisory) -> str:
    lines = []
    for ref in adv.refs:
        if ref["type"] == "FIX":
            lines.append(f"Fix commit: {ref['url']}")
        elif ref["type"] == "ADVISORY":
            lines.append(f"Advisory: {ref['url']}")
    return " ; ".join(lines) if lines else "No fix/advisory references."


def chunk_advisory(adv: Advisory) -> list[Chunk]:
    chunks: list[Chunk] = []

    chunks.append(
        Chunk(id=f"{adv.id}#summary#0", advisory_id=adv.id, kind="summary",
              header=_header(adv, "summary"), content=adv.summary or "")
    )

    for i, piece in enumerate(_split_details(adv.details or "")):
        chunks.append(
            Chunk(id=f"{adv.id}#details#{i}", advisory_id=adv.id, kind="details",
                  header=_header(adv, "details"), content=piece)
        )

    chunks.append(
        Chunk(id=f"{adv.id}#affected#0", advisory_id=adv.id, kind="affected",
              header=_header(adv, "affected"), content=_render_affected(adv))
    )

    chunks.append(
        Chunk(id=f"{adv.id}#refs#0", advisory_id=adv.id, kind="refs",
              header=_header(adv, "refs"), content=_render_refs(adv))
    )

    return chunks
