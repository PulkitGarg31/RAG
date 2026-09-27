"""
Retrievers take `get_conn: Callable[[], Connection]` — a zero-arg callable that
returns an ALREADY-OPEN psycopg connection. Callers open the connection once
(e.g. `with get_conn() as conn:`) and pass `lambda: conn`, not `vt.db.get_conn`
itself (which would open/close a fresh connection per call).
"""
