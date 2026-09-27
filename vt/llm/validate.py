import json
import re
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError, field_validator


class VerdictOutput(BaseModel):
    summary: str
    rationale: str
    citations: list[str]

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


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json(raw: str) -> dict | None:
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


def validate_verdict(raw: str, evidence_ids: set[str]) -> ValidationResult:
    data = _extract_json(raw)
    if data is None:
        return ValidationResult(ok=False, verdict=None, error="response was not valid JSON")

    try:
        verdict = VerdictOutput.model_validate(data)
    except ValidationError as e:
        return ValidationResult(ok=False, verdict=None, error=str(e))

    unknown = [c for c in verdict.citations if c not in evidence_ids]
    if unknown:
        return ValidationResult(
            ok=False, verdict=None, error=f"citations not in evidence: {unknown}"
        )

    return ValidationResult(ok=True, verdict=verdict, error=None)
