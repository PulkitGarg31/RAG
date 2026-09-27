from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Hit:
    chunk_id: str
    advisory_id: str
    score: float
    text: str


class Retriever(Protocol):
    def search(
        self, query: str, k: int = 10, advisory_filter: set[str] | None = None
    ) -> list[Hit]: ...
