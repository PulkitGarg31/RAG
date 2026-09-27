import os

import pytest

from vt.db import get_conn


@pytest.mark.skipif(os.environ.get("CI") == "true", reason="requires a live Postgres")
def test_can_connect_and_see_tables():
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
        )
        tables = {row[0] for row in cur.fetchall()}
    assert {"advisories", "chunks", "kev", "epss"} <= tables
