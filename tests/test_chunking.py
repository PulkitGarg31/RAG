from vt.chunking import chunk_advisory
from vt.models import Advisory


def _adv(**overrides) -> Advisory:
    base = dict(
        id="GHSA-462w-v97r-4m45",
        package="jinja2",
        cve_ids=["CVE-2019-10906"],
        cwe_ids=["CWE-94"],
        summary="Jinja2 sandbox escape via format method",
        details="short details",
        affected=[
            {
                "package": {"name": "Jinja2", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.11.3"}],
                    }
                ],
            }
        ],
        refs=[
            {"type": "FIX", "url": "https://example.com/commit/abc"},
            {"type": "ADVISORY", "url": "https://example.com/advisory"},
            {"type": "WEB", "url": "https://example.com/blog"},
        ],
    )
    base.update(overrides)
    return Advisory(**base)


def test_header_format():
    chunks = chunk_advisory(_adv())
    summary_chunk = next(c for c in chunks if c.kind == "summary")
    assert summary_chunk.header == (
        "[PyPI:jinja2] [GHSA-462w-v97r-4m45] [CVE-2019-10906] [CWE:CWE-94] [summary]"
    )


def test_header_no_cve_no_cwe():
    chunks = chunk_advisory(_adv(cve_ids=[], cwe_ids=[]))
    summary_chunk = next(c for c in chunks if c.kind == "summary")
    assert "[no-CVE]" in summary_chunk.header
    assert "[CWE:-]" in summary_chunk.header


def test_four_chunk_kinds_present():
    kinds = {c.kind for c in chunk_advisory(_adv())}
    assert kinds == {"summary", "details", "affected", "refs"}


def test_affected_chunk_renders_ranges():
    chunks = chunk_advisory(_adv())
    affected_chunk = next(c for c in chunks if c.kind == "affected")
    assert "introduced 0, fixed 2.11.3" in affected_chunk.content


def test_refs_chunk_only_fix_and_advisory():
    chunks = chunk_advisory(_adv())
    refs_chunk = next(c for c in chunks if c.kind == "refs")
    assert "example.com/commit/abc" in refs_chunk.content
    assert "example.com/advisory" in refs_chunk.content
    assert "example.com/blog" not in refs_chunk.content


def test_long_details_split_into_multiple_chunks_with_overlap():
    paragraph = "Paragraph sentence text. " * 20  # ~500 chars per paragraph
    details = "\n\n".join([paragraph] * 4)  # ~2000 chars total
    chunks = chunk_advisory(_adv(details=details))
    detail_chunks = [c for c in chunks if c.kind == "details"]
    assert len(detail_chunks) > 1
    # overlap: the last paragraph of chunk N appears at the start of chunk N+1
    assert detail_chunks[0].content.strip().split("\n\n")[-1] in detail_chunks[1].content


def test_chunk_ids_are_unique_and_prefixed():
    chunks = chunk_advisory(_adv())
    ids = [c.id for c in chunks]
    assert len(ids) == len(set(ids))
    assert all(cid.startswith("GHSA-462w-v97r-4m45#") for cid in ids)


def test_split_details_does_not_repeat_last_paragraph_as_its_own_chunk():
    details = "a" * 700 + "\n\n" + "b" * 600
    detail_chunks = [c for c in chunk_advisory(_adv(details=details)) if c.kind == "details"]
    assert len(detail_chunks) == 1
    assert detail_chunks[0].content == details


def test_every_later_details_chunk_adds_a_new_paragraph():
    paragraph = "Paragraph sentence text. " * 20
    details = "\n\n".join(f"{i} {paragraph}" for i in range(5))
    detail_chunks = [c for c in chunk_advisory(_adv(details=details)) if c.kind == "details"]
    for prev, cur in zip(detail_chunks, detail_chunks[1:]):
        prev_paras = set(prev.content.split("\n\n"))
        assert any(p not in prev_paras for p in cur.content.split("\n\n"))
