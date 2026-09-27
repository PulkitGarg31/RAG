import json
import uuid
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


def test_get_rejects_ids_that_save_could_not_have_produced(tmp_path: Path, monkeypatch):
    outside = tmp_path / "secret.json"
    outside.write_text('{"findings": [], "skipped": []}')
    store = ScanStore(data_dir=tmp_path / "scans")
    assert store.get("../secret") is None
    assert store.get(str(tmp_path / "secret")) is None
    assert store.get("ABCDEF123456") is None
    assert store.get("abc") is None
    # Pin the id so it contains letters: an all-digit id would upper-case to itself.
    monkeypatch.setattr(uuid, "uuid4", lambda: uuid.UUID("abcdef12-3456-4789-8abc-def012345678"))
    saved_id = store.save([], skipped=[])
    assert saved_id == "abcdef123456"
    # On a case-insensitive filesystem (NTFS) the upper-cased path finds the saved file.
    assert store.get(saved_id.upper()) is None
