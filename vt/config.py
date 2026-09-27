from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql://vt:vt@localhost:5432/vulntriage"
    llm_provider: str = "ollama"
    ollama_model: str = "llama3.2:3b"
    ollama_timeout: float = 120.0
    gemini_api_key: str = ""
    embed_model: str = "BAAI/bge-small-en-v1.5"
    rerank_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"

    # Priority policy (spec section 7.3) — kept configurable, not hardcoded in logic.
    epss_p1_threshold: float = 0.10
    cvss_p1_threshold: float = 9.0
    cvss_p2_threshold: float = 7.0
    epss_percentile_p2_threshold: float = 0.90


settings = Settings()
