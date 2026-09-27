import json
import random
from pathlib import Path

from vt.eval.leakage import question_leaks_identifiers
from vt.models import Advisory

QUERY_GEN_PROMPT = (
    'Write ONE developer question (a single sentence) describing this vulnerability WITHOUT '
    "naming the package, advisory id, or CVE. Focus on the kind of bug and its impact. "
    'Return JSON only: {"question": str}'
)


def generate_query_for_advisory(advisory: Advisory, provider, max_attempts: int = 2) -> str | None:
    ids = [advisory.id, *advisory.cve_ids]
    dossier = f"Summary: {advisory.summary}\nDetails: {advisory.details}"
    for _ in range(max_attempts):
        raw = provider.complete_json(QUERY_GEN_PROMPT, dossier)
        try:
            question = json.loads(raw)["question"]
        except (json.JSONDecodeError, KeyError):
            continue
        if not question_leaks_identifiers(question, advisory.package, ids):
            return question
    return None


def sample_advisories(conn, n: int = 150, seed: int = 42) -> list[Advisory]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, package, group_id, cve_ids, summary, details FROM advisories "
            "WHERE length(details) > 200 AND cardinality(cve_ids) > 0"
        )
        rows = cur.fetchall()
    rng = random.Random(seed)
    rng.shuffle(rows)
    chosen = rows[:n]
    return [
        Advisory(id=r[0], package=r[1], group_id=r[2], cve_ids=r[3], summary=r[4], details=r[5])
        for r in chosen
    ]


def build_eval_set(n: int = 150, seed: int = 42, out_path: Path = Path("data/eval/queries.jsonl")) -> int:
    from vt.db import get_conn
    from vt.llm.provider import get_provider

    provider = get_provider()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with get_conn() as conn, open(out_path, "w") as f:
        for adv in sample_advisories(conn, n=n, seed=seed):
            question = generate_query_for_advisory(adv, provider)
            if question is None:
                continue
            f.write(json.dumps({
                "qid": f"gen-{written}", "query": question,
                "gold_group": adv.group_id or adv.id, "advisory_id": adv.id,
            }) + "\n")
            written += 1
    return written
