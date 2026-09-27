import json
from pathlib import Path

from vt.ingest.kev import parse_kev_feed

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_kev_feed():
    data = json.loads((FIXTURES / "kev_small.json").read_text())
    entries = parse_kev_feed(data)
    assert len(entries) == 1
    e = entries[0]
    assert e.cve_id == "CVE-2019-10906"
    assert e.vendor == "Pallets"
    assert str(e.date_added) == "2024-01-15"
