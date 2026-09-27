import logging
import re
import zipfile
from pathlib import Path

import httpx
from cvss import CVSS3, CVSS4

from vt.models import Advisory
from vt.normalize import normalize_package

logger = logging.getLogger(__name__)

OSV_ALL_ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"


def _cvss(severity: list[dict]) -> tuple[str | None, float | None]:
    """(vector, base_score), preferring CVSS v3 and falling back to v4."""
    for kind, parser in (("CVSS_V3", CVSS3), ("CVSS_V4", CVSS4)):
        for entry in severity:
            if entry.get("type") != kind:
                continue
            try:
                return entry["score"], float(parser(entry["score"]).base_score)
            except Exception:
                continue
    return None, None


def fixed_versions_for_package(affected: list[dict], package: str) -> list[str]:
    """Every ECOSYSTEM `fixed` event for one (normalized) package, in order, deduplicated."""
    fixed: list[str] = []
    for entry in affected:
        if normalize_package(entry.get("package", {}).get("name", "")) != package:
            continue
        for r in entry.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            for event in r.get("events", []):
                if "fixed" in event and event["fixed"] not in fixed:
                    fixed.append(event["fixed"])
    return fixed


def parse_osv_record(record: dict) -> Advisory | None:
    """Parse one OSV JSON record into an Advisory, or None if withdrawn or not PyPI-affected."""
    if record.get("withdrawn"):
        return None

    pypi_affected = [
        a
        for a in record.get("affected", [])
        if a.get("package", {}).get("ecosystem") == "PyPI"
    ]
    if not pypi_affected:
        return None

    distinct = {normalize_package(a["package"]["name"]) for a in pypi_affected}
    if len(distinct) > 1:
        logger.warning(
            "OSV record %s lists %d PyPI-affected packages; storing under the first (%s)",
            record.get("id"), len(distinct), pypi_affected[0]["package"]["name"],
        )

    package = normalize_package(pypi_affected[0]["package"]["name"])

    aliases = record.get("aliases", [])
    cve_ids = [a for a in aliases if a.startswith("CVE-")]
    if record["id"].startswith("CVE-") and record["id"] not in cve_ids:
        cve_ids.append(record["id"])

    fixed_versions = fixed_versions_for_package(pypi_affected, package)

    refs = [
        {"type": r["type"], "url": r["url"]}
        for r in record.get("references", [])
        if r.get("type") in ("FIX", "ADVISORY", "WEB", "PACKAGE")
    ]

    cvss_vector, cvss_score = _cvss(record.get("severity", []))

    return Advisory(
        id=record["id"],
        package=package,
        aliases=aliases,
        cve_ids=cve_ids,
        summary=record.get("summary", "") or "",
        details=record.get("details", "") or "",
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        cwe_ids=record.get("database_specific", {}).get("cwe_ids", []) or [],
        fixed_versions=fixed_versions,
        affected=pypi_affected,
        refs=refs,
        published=record.get("published"),
        modified=record.get("modified"),
    )


def _is_complete_zip(path: Path) -> bool:
    """A truncated download has no central directory, so ZipFile() raises."""
    try:
        with zipfile.ZipFile(path) as zf:
            zf.namelist()
        return True
    except (zipfile.BadZipFile, OSError):
        return False


def download_all_zip(dest: Path, force: bool = False) -> Path:
    import time

    dest.parent.mkdir(parents=True, exist_ok=True)
    fresh = dest.exists() and (time.time() - dest.stat().st_mtime) < 86400
    if fresh and not force and _is_complete_zip(dest):
        return dest
    tmp = dest.with_name(dest.name + ".part")
    with httpx.stream("GET", OSV_ALL_ZIP_URL, follow_redirects=True, timeout=120) as r:
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in r.iter_bytes():
                f.write(chunk)
    if not _is_complete_zip(tmp):
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"Downloaded OSV archive is incomplete: {OSV_ALL_ZIP_URL}")
    tmp.replace(dest)
    return dest


def iter_osv_records(zip_path: Path, limit: int | None = None):
    import json

    count = 0
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            if limit is not None and count >= limit:
                return
            with zf.open(name) as f:
                yield json.loads(f.read())
            count += 1


def upsert_advisories(conn, advisories: list[Advisory]) -> int:
    from vt.retrieval.aliases import build_alias_groups

    groups = build_alias_groups(advisories)
    sql = """
        INSERT INTO advisories
            (id, aliases, cve_ids, package, group_id, summary, details,
             cvss_vector, cvss_score, cwe_ids, fixed_versions, affected, refs,
             published, modified)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (id) DO UPDATE SET
            aliases = EXCLUDED.aliases,
            cve_ids = EXCLUDED.cve_ids,
            package = EXCLUDED.package,
            group_id = EXCLUDED.group_id,
            summary = EXCLUDED.summary,
            details = EXCLUDED.details,
            cvss_vector = EXCLUDED.cvss_vector,
            cvss_score = EXCLUDED.cvss_score,
            cwe_ids = EXCLUDED.cwe_ids,
            fixed_versions = EXCLUDED.fixed_versions,
            affected = EXCLUDED.affected,
            refs = EXCLUDED.refs,
            published = EXCLUDED.published,
            modified = EXCLUDED.modified
    """
    import json as jsonlib

    rows = [
        (
            a.id, a.aliases, a.cve_ids, a.package, groups.get(a.id),
            a.summary, a.details, a.cvss_vector, a.cvss_score, a.cwe_ids,
            a.fixed_versions, jsonlib.dumps(a.affected), jsonlib.dumps(a.refs),
            a.published, a.modified,
        )
        for a in advisories
    ]
    with conn.cursor() as cur:
        for i in range(0, len(rows), 1000):
            cur.executemany(sql, rows[i : i + 1000])
    return len(rows)


def ingest_osv(limit: int | None = None, force_download: bool = False) -> int:
    from vt.db import get_conn

    zip_path = download_all_zip(Path("data/raw/osv_pypi_all.zip"), force=force_download)
    advisories = []
    for record in iter_osv_records(zip_path, limit=limit):
        adv = parse_osv_record(record)
        if adv is not None:
            advisories.append(adv)
    with get_conn() as conn:
        n = upsert_advisories(conn, advisories)
    return n
