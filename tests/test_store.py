import json
from pathlib import Path

from vt.store import ScanStore
from vt.models import Finding


def test_save_and_get_roundtrip(tmp_path: Path):
    store = ScanStore(data_dir=tmp_path)
    findings = [
        Finding(package="jinja2", installed="2.10", advisory_id="GHSA-1", cve_ids=[],
                priority="P2", min_safe_version="3.1.4", verified=True, kev=False, epss=None)
    ]
    scan_id = store.save(findings, skipped=[])
    result = store.get(scan_id)
    assert result is not None
    assert result["findings"][0]["package"] == "jinja2"


def test_get_missing_scan_returns_none(tmp_path: Path):
    store = ScanStore(data_dir=tmp_path)
    assert store.get("does-not-exist") is None


def test_save_writes_json_file(tmp_path: Path):
    store = ScanStore(data_dir=tmp_path)
    scan_id = store.save([], skipped=[])
    assert (tmp_path / f"{scan_id}.json").exists()


def test_get_falls_back_to_disk_when_not_in_memory(tmp_path: Path):
    store = ScanStore(data_dir=tmp_path)
    scan_id = store.save([], skipped=[])
    # simulate a fresh process: new store instance, same data dir
    store2 = ScanStore(data_dir=tmp_path)
    assert store2.get(scan_id) is not None
