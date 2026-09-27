import json
import re
import uuid
from dataclasses import asdict
from pathlib import Path

from vt.models import Finding

_SCAN_ID_RE = re.compile(r"[0-9a-f]{12}")


class ScanStore:
    def __init__(self, data_dir: Path | str = Path("data/scans")):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._memory: dict[str, dict] = {}

    def save(self, findings: list[Finding], skipped: list[dict]) -> str:
        scan_id = uuid.uuid4().hex[:12]
        record = {"scan_id": scan_id, "findings": [asdict(f) for f in findings], "skipped": skipped}
        self._memory[scan_id] = record
        (self.data_dir / f"{scan_id}.json").write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
        return scan_id

    def get(self, scan_id: str) -> dict | None:
        if not isinstance(scan_id, str) or not _SCAN_ID_RE.fullmatch(scan_id):
            return None
        if scan_id in self._memory:
            return self._memory[scan_id]
        path = self.data_dir / f"{scan_id}.json"
        if path.exists():
            record = json.loads(path.read_text(encoding="utf-8"))
            self._memory[scan_id] = record
            return record
        return None


_default_store: ScanStore | None = None


def default_store() -> ScanStore:
    global _default_store
    if _default_store is None:
        _default_store = ScanStore()
    return _default_store
