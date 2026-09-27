import json
from pathlib import Path

from vt.ingest.epss import parse_epss_response, chunk_cves

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_epss_response():
    data = json.loads((FIXTURES / "epss_small.json").read_text())
    entries = parse_epss_response(data)
    assert len(entries) == 2
    e = next(e for e in entries if e.cve_id == "CVE-2019-10906")
    assert abs(e.epss - 0.01234) < 1e-6
    assert abs(e.percentile - 0.71230) < 1e-6


def test_chunk_cves_respects_batch_size():
    cves = [f"CVE-2020-{i:04d}" for i in range(250)]
    batches = list(chunk_cves(cves, size=100))
    assert len(batches) == 3
    assert len(batches[0]) == 100
    assert len(batches[2]) == 50
