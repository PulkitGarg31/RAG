from functools import lru_cache

from vt.config import settings

QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "


def build_embedding_input(header: str, content: str, is_query: bool) -> str:
    if is_query:
        return QUERY_INSTRUCTION + content
    return f"{header}\n{content}"


@lru_cache(maxsize=1)
def _model():
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(settings.embed_model)


def embed_texts(texts: list[str], batch_size: int = 64):
    return _model().encode(
        texts, batch_size=batch_size, normalize_embeddings=True, show_progress_bar=False
    )


def embed_query(text: str):
    return embed_texts([build_embedding_input("", text, is_query=True)])[0]
