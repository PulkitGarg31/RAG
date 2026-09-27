_COLUMNS = ["setup", "recall@1", "recall@5", "recall@10", "mrr@10", "p50_ms"]
_HEADERS = ["Setup", "Recall@1", "Recall@5", "Recall@10", "MRR@10", "p50 ms"]


def render_markdown_table(rows: list[dict]) -> str:
    lines = ["| " + " | ".join(_HEADERS) + " |", "|" + "|".join(["---"] * len(_HEADERS)) + "|"]
    for row in rows:
        cells = [str(row["setup"])]
        for col in _COLUMNS[1:-1]:
            cells.append(f"{row[col]:.3f}")
        cells.append(f"{row['p50_ms']:.1f}")
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def write_report(rows: list[dict], path) -> None:
    from pathlib import Path

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("# Retrieval evaluation\n\n" + render_markdown_table(rows) + "\n")
