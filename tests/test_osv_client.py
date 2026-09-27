import httpx
import respx

from vt.scanner.osv_client import fetch_vulns, query_batch


@respx.mock
def test_query_batch_maps_results_back_by_index():
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "GHSA-1"}]},
                    {"vulns": []},
                ]
            },
        )
    )
    result = query_batch([("jinja2", "2.10"), ("requests", "2.19.0")])
    assert result == [["GHSA-1"], []]


@respx.mock
def test_query_batch_chunks_at_1000(monkeypatch):
    calls = []

    def responder(request):
        import json

        body = json.loads(request.content)
        calls.append(len(body["queries"]))
        return httpx.Response(200, json={"results": [{"vulns": []}] * len(body["queries"])})

    respx.post("https://api.osv.dev/v1/querybatch").mock(side_effect=responder)
    pkgs = [(f"pkg{i}", "1.0.0") for i in range(1500)]
    result = query_batch(pkgs)
    assert calls == [1000, 500]
    assert len(result) == 1500


@respx.mock
def test_fetch_vulns_skips_ids_that_fail():
    respx.get("https://api.osv.dev/v1/vulns/GHSA-ok").mock(return_value=httpx.Response(200, json={"id": "GHSA-ok"}))
    respx.get("https://api.osv.dev/v1/vulns/GHSA-404").mock(return_value=httpx.Response(404))
    assert fetch_vulns(["GHSA-ok", "GHSA-404"]) == {"GHSA-ok": {"id": "GHSA-ok"}}
