import json
import re
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError, field_validator


def normalize_citation(citation: str) -> str:
    """Models often copy an evidence id together with the square brackets it's printed in
    ("[GHSA-x#summary#0]"); strip those so the subset check compares bare ids."""
    return citation.strip().strip("[]").strip()


class VerdictOutput(BaseModel):
    summary: str
    rationale: str
    citations: list[str]

    @field_validator("citations", mode="before")
    @classmethod
    def normalize(cls, v: list[str]) -> list[str]:
        if not isinstance(v, list):
            return v
        seen: set[str] = set()
        normalized: list[str] = []
        for c in v:
            if not isinstance(c, str):
                normalized.append(c)  # let Pydantic reject the non-string item
                continue
            nc = normalize_citation(c)
            if nc and nc not in seen:
                seen.add(nc)
                normalized.append(nc)
        return normalized

    @field_validator("citations")
    @classmethod
    def non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("citations must be non-empty")
        return v


@dataclass
class ValidationResult:
    ok: bool
    verdict: VerdictOutput | None
    error: str | None
    stage: str


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)

# Any value json.loads can return.
JsonValue = dict | list | str | int | float | bool | None


def extract_json(raw: object) -> JsonValue:
    """Parse the JSON value in an LLM response, tolerating prose around a JSON object.
    Returns None when raw is not a string or holds no parseable JSON (a JSON `null`
    also comes back as None)."""
    if not isinstance(raw, str):
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = _JSON_OBJECT_RE.search(raw)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None


def validate_verdict(raw: str | None, evidence_ids: set[str]) -> ValidationResult:
    data = extract_json(raw)
    if not isinstance(data, dict):
        return ValidationResult(ok=False, verdict=None, error="response was not a JSON object", stage="json")

    try:
        verdict = VerdictOutput.model_validate(data)
    except ValidationError as e:
        return ValidationResult(ok=False, verdict=None, error=str(e), stage="schema")

    unknown = [c for c in verdict.citations if c not in evidence_ids]
    if unknown:
        return ValidationResult(
            ok=False, verdict=None, error=f"citations not in evidence: {unknown}", stage="citations"
        )

    return ValidationResult(ok=True, verdict=verdict, error=None, stage="ok")
