import pickle
import re
from pathlib import Path

from rank_bm25 import BM25Okapi

_TOKEN_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def build_bm25(texts: list[str]) -> BM25Okapi:
    return BM25Okapi([tokenize(t) for t in texts])


def save_bm25(bm25: BM25Okapi, chunk_ids: list[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump({"chunk_ids": chunk_ids, "bm25": bm25}, f)


def load_bm25(path: Path) -> tuple[BM25Okapi, list[str]]:
    with open(path, "rb") as f:
        data = pickle.load(f)
    return data["bm25"], data["chunk_ids"]
