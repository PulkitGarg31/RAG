import logging
import time
from collections.abc import Iterator

import httpx

from vt.models import EpssEntry

logger = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"


def parse_epss_response(data: dict) -> list[EpssEntry]:
    return [
        EpssEntry(
            cve_id=row["cve"],
            epss=float(row["epss"]),
            percentile=float(row["percentile"]),
            score_date=row["date"],
        )
        for row in data.get("data", [])
    ]


def chunk_cves(cves: list[str], size: int = 100) -> Iterator[list[str]]:
    for i in range(0, len(cves), size):
        yield cves[i : i + size]


def fetch_epss(cves: list[str]) -> list[EpssEntry]:
    r = httpx.get(EPSS_URL, params={"cve": ",".join(cves)}, timeout=30)
    r.raise_for_status()
    return parse_epss_response(r.json())


def upsert_epss(conn, entries: list[EpssEntry]) -> int:
    sql = """
        INSERT INTO epss (cve_id, epss, percentile, score_date)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (cve_id) DO UPDATE SET
            epss = EXCLUDED.epss, percentile = EXCLUDED.percentile,
            score_date = EXCLUDED.score_date, fetched_at = now()
    """
    rows = [(e.cve_id, e.epss, e.percentile, e.score_date) for e in entries]
    with conn.cursor() as cur:
        cur.executemany(sql, rows)
    return len(rows)


def distinct_cves(conn) -> list[str]:
    with conn.cursor() as cur:
        cur.execute("SELECT DISTINCT unnest(cve_ids) FROM advisories")
        return [row[0] for row in cur.fetchall()]


def ingest_epss(sleep_seconds: float = 0.3) -> int:
    from vt.db import get_conn

    with get_conn() as conn:
        cves = distinct_cves(conn)
        total = 0
        for batch in chunk_cves(cves, size=100):
            entries = fetch_epss(batch)
            total += upsert_epss(conn, entries)
            time.sleep(sleep_seconds)
    return total


def epss_for(conn, cves: list[str]) -> dict[str, EpssEntry]:
    """Per-scan EPSS lookup. Reads the cache; CVEs not cached yet are fetched from FIRST in
    batches of 100 and stored, so a scan never waits on a full `vt ingest epss` refresh.
    If FIRST is unreachable the scan proceeds with whatever is cached."""
    if not cves:
        return {}
    with conn.cursor() as cur:
        cur.execute(
            "SELECT cve_id, epss, percentile, score_date FROM epss WHERE cve_id = ANY(%s)",
            (cves,),
        )
        found = {
            row[0]: EpssEntry(cve_id=row[0], epss=row[1], percentile=row[2], score_date=row[3])
            for row in cur.fetchall()
        }
    missing = [c for c in cves if c not in found]
    if missing:
        try:
            fetched = [e for batch in chunk_cves(missing, size=100) for e in fetch_epss(batch)]
        except httpx.HTTPError:
            logger.warning("EPSS fetch failed for %d CVEs; using cached scores only", len(missing))
            fetched = []
        if fetched:
            upsert_epss(conn, fetched)
            found.update({e.cve_id: e for e in fetched})
    return found
