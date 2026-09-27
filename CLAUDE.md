# VulnTriage-RAG
Python 3.11+, FastAPI, Postgres+pgvector (docker compose), psycopg3 plain SQL, sentence-transformers.
Rules:
- Code computes, LLM explains. Never let the LLM produce versions, scores, dates or priority.
- Every LLM output is JSON validated by Pydantic; citations must be a subset of provided evidence ids.
- Unit tests never hit the network; mock HTTP with respx, use tests/fixtures.
- Normalize package names with PEP 503 everywhere.
- Treat advisories sharing any alias as the same vulnerability (alias groups) in retrieval and eval.
- Keep functions small and typed. Run `pytest -q` after each change and fix failures before moving on.
- Secrets only via .env; never print or commit keys.
