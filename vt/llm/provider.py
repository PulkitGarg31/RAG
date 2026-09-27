from typing import Protocol

from vt.config import settings


class LLMProvider(Protocol):
    def complete_json(self, system: str, user: str) -> str: ...


class OllamaProvider:
    def complete_json(self, system: str, user: str) -> str:
        import ollama

        response = ollama.chat(
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
