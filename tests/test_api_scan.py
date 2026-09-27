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
                return [("GHSA-1", "jinja2", ["CVE-1"], ["2.11.3"], 9.8)]
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
