from unittest.mock import MagicMock

import numpy as np

from vt.indexing import write_chunks
from vt.models import Chunk


def test_write_chunks_deletes_stale_ids_then_upserts():
    conn = MagicMock()
    cur = conn.cursor.return_value.__enter__.return_value
    chunks = [
        Chunk(id="A#summary#0", advisory_id="A", kind="summary", header="h", content="c"),
        Chunk(id="A#details#0", advisory_id="A", kind="details", header="h", content="d"),
    ]

    n = write_chunks(conn, chunks, np.zeros((2, 3)))

    assert n == 2
    delete_sql, delete_params = cur.execute.call_args_list[0][0]
    assert delete_sql.startswith("DELETE FROM chunks")
    assert delete_params == (["A#summary#0", "A#details#0"],)
    assert cur.executemany.call_count == 1
