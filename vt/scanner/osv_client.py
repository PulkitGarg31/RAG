import httpx

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"


def query_batch(pkg_versions: list[tuple[str, str]], batch_size: int = 1000) -> list[list[str]]:
    """For each (package, version), return the list of OSV vuln ids affecting it, same order as input."""
    all_ids: list[list[str]] = []
    with httpx.Client(timeout=30) as client:
        for i in range(0, len(pkg_versions), batch_size):
            batch = pkg_versions[i : i + batch_size]
            queries = [
                {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
                for name, version in batch
            ]
            r = client.post(OSV_QUERYBATCH_URL, json={"queries": queries})
            r.raise_for_status()
            results = r.json().get("results", [])
            assert len(results) == len(batch), (
                f"OSV querybatch returned {len(results)} results for {len(batch)} queries; "
                "response order no longer matches request order"
            )
            all_ids.extend([v.get("id") for v in item.get("vulns", [])] for item in results)
    return all_ids


def fetch_vulns(vuln_ids: list[str]) -> dict[str, dict]:
    """Full OSV records by id; ids that fail (404, network error) are left out."""
    records: dict[str, dict] = {}
    with httpx.Client(timeout=30) as client:
        for vid in vuln_ids:
            try:
                r = client.get(OSV_VULN_URL.format(vid))
                r.raise_for_status()
                records[vid] = r.json()
            except (httpx.HTTPError, ValueError):
                continue
    return records
