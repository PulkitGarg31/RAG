import httpx
import respx
from fastapi.testclient import TestClient

from vt.api import app


@respx.mock
def test_scan_endpoint_returns_sorted_findings(monkeypatch):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-1"}]}]})
    )

    class FakeCursor:
        def __init__(self):
            self.last_sql = ""

        def execute(self, sql, params=None):
            self.last_sql = sql

        def fetchall(self):
            if "FROM advisories WHERE id = ANY" in self.last_sql:
                return [("GHSA-1", "jinja2", [], ["CVE-1"], "CVE-1", [], ["2.11.3"], 9.8)]
            if "FROM kev" in self.last_sql:
                return []
            return []

        def fetchone(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeConn:
        def cursor(self):
            return FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("vt.scanner.scan.get_conn", lambda: FakeConn())
    monkeypatch.setattr("vt.scanner.scan.epss_for", lambda conn, cves: {})

    client = TestClient(app)
    resp = client.post("/scan?use_llm=false", json={"requirements": "jinja2==2.10\n"})

    assert resp.status_code == 200
    body = resp.json()
    assert "scan_id" in body
    assert body["findings"][0]["package"] == "jinja2"
    # use_llm=false is required here: FakeConn only stubs the scanner's queries
    # (vt.scanner.scan.get_conn); fill_verdicts (Task 12) opens its own real
    # get_conn/BM25/Ollama and is exercised separately by the Task 12 dev-run.


def test_health_endpoint():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert "db" in resp.json()


def test_advisory_endpoint_reduces_multi_cve_kev_epss_correctly(monkeypatch):
    class FakeCursor:
        def __init__(self):
            self.last_sql = ""

        def execute(self, sql, params=None):
            self.last_sql = sql

        def fetchall(self):
            if "FROM kev" in self.last_sql:
                return [("2024-01-01",)]
            if "FROM epss" in self.last_sql:
                return [(0.01, 0.25), (0.05, 0.85)]
            return []

        def fetchone(self):
            if "FROM advisories WHERE id" in self.last_sql:
                return ("GHSA-multi", "pkg", ["CVE-1", "CVE-2"], "summary", 8.0)
            return None

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeConn:
        def cursor(self):
            return FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("vt.api.get_conn", lambda: FakeConn())

    client = TestClient(app)
    resp = client.get("/advisory/GHSA-multi")

    assert resp.status_code == 200
    body = resp.json()
    assert body["epss"] == 0.05
    assert body["epss_percentile"] == 0.85


@respx.mock
def test_scan_fetches_advisories_missing_from_local_corpus(monkeypatch):
    respx.post("https://api.osv.dev/v1/querybatch").mock(side_effect=[
        httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-remote"}]}]}),  # the scan
        httpx.Response(200, json={"results": [{"vulns": []}]}),                        # verification
    ])
    record = {
        "id": "GHSA-remote", "aliases": ["CVE-2099-0001"], "summary": "s", "details": "d",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.11.3"}]}]}],
        "references": [],
    }
    respx.get("https://api.osv.dev/v1/vulns/GHSA-remote").mock(return_value=httpx.Response(200, json=record))
    upserts = []

    class FakeCursor:
        def execute(self, sql, params=None):
            pass

        def executemany(self, sql, rows):
            upserts.extend(rows)

        def fetchall(self):
            return []  # nothing local, no KEV hits

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeConn:
        def cursor(self):
            return FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("vt.scanner.scan.get_conn", lambda: FakeConn())
    monkeypatch.setattr("vt.scanner.scan.epss_for", lambda conn, cves: {})

    body = TestClient(app).post("/scan?use_llm=false", json={"requirements": "jinja2==2.10\n"}).json()

    assert [f["advisory_id"] for f in body["findings"]] == ["GHSA-remote"]
    assert body["findings"][0]["min_safe_version"] == "2.11.3"
    assert body["findings"][0]["verified"] is True
    assert [row[0] for row in upserts] == ["GHSA-remote"]
