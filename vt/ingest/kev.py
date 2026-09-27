import httpx

from vt.models import KevEntry

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse_kev_feed(data: dict) -> list[KevEntry]:
    return [
        KevEntry(
            cve_id=v["cveID"],
            vendor=v.get("vendorProject"),
            product=v.get("product"),
            date_added=v.get("dateAdded"),
            due_date=v.get("dueDate"),
            ransomware=v.get("knownRansomwareCampaignUse"),
            notes=v.get("notes") or None,
        )
        for v in data.get("vulnerabilities", [])
    ]


def fetch_kev_feed() -> dict:
    r = httpx.get(KEV_URL, timeout=30, follow_redirects=True)
    r.raise_for_status()
    return r.json()


def upsert_kev(conn, entries: list[KevEntry]) -> int:
    sql = """
        INSERT INTO kev (cve_id, vendor, product, date_added, due_date, ransomware, notes)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (cve_id) DO UPDATE SET
            vendor = EXCLUDED.vendor, product = EXCLUDED.product,
            date_added = EXCLUDED.date_added, due_date = EXCLUDED.due_date,
            ransomware = EXCLUDED.ransomware, notes = EXCLUDED.notes
    """
    rows = [(e.cve_id, e.vendor, e.product, e.date_added, e.due_date, e.ransomware, e.notes) for e in entries]
    with conn.cursor() as cur:
        cur.executemany(sql, rows)
    return len(rows)


def ingest_kev() -> int:
    from vt.db import get_conn

    entries = parse_kev_feed(fetch_kev_feed())
    with get_conn() as conn:
        return upsert_kev(conn, entries)
