from typing import Protocol

from vt.config import settings


class LLMProvider(Protocol):
    def complete_json(self, system: str, user: str) -> str: ...


class ProviderError(Exception):
    """The LLM call itself failed: unreachable server, timeout, SDK error, or no text back."""


def complete_json_checked(provider: LLMProvider, system: str, user: str) -> str:
    try:
        raw = provider.complete_json(system, user)
    except Exception as e:
        raise ProviderError(f"{type(e).__name__}: {e}") from e
    if not isinstance(raw, str):
        raise ProviderError(f"provider returned {type(raw).__name__}, not text")
    return raw


class OllamaProvider:
    def complete_json(self, system: str, user: str) -> str:
        import ollama

        client = ollama.Client(timeout=settings.ollama_timeout)
        response = client.chat(
            model=settings.ollama_model,
            format="json",
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response["message"]["content"]


class GeminiProvider:
    def complete_json(self, system: str, user: str) -> str:
        from google import genai

        client = genai.Client(api_key=settings.gemini_api_key)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=f"{system}\n\n{user}",
            config={"response_mime_type": "application/json"},
        )
        return response.text


def get_provider() -> LLMProvider:
    if settings.llm_provider == "gemini":
        return GeminiProvider()
    return OllamaProvider()
