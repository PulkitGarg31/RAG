import json
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import respx

from vt.ingest.epss import epss_for, parse_epss_response, chunk_cves

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


@respx.mock
def test_epss_for_fetches_and_caches_missing_cves():
    conn = MagicMock()
    cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchall.return_value = [("CVE-1", 0.1, 0.5, "2026-09-27")]
    respx.get(host="api.first.org", path="/data/v1/epss").mock(return_value=httpx.Response(
        200, json={"data": [{"cve": "CVE-2", "epss": "0.3", "percentile": "0.9", "date": "2026-09-27"}]}
    ))

    out = epss_for(conn, ["CVE-1", "CVE-2"])

    assert out["CVE-1"].epss == 0.1
    assert out["CVE-2"].epss == 0.3
    cur.executemany.assert_called_once()


@respx.mock
def test_epss_for_falls_back_to_cache_when_first_is_down():
    conn = MagicMock()
    cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchall.return_value = [("CVE-1", 0.1, 0.5, "2026-09-27")]
    respx.get(host="api.first.org", path="/data/v1/epss").mock(return_value=httpx.Response(503))

    out = epss_for(conn, ["CVE-1", "CVE-2"])

    assert set(out) == {"CVE-1"}
