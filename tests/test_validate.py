from vt.llm.validate import validate_verdict


def test_valid_json_with_known_citations_passes():
    raw = '{"summary": "s", "rationale": "r", "citations": ["GHSA-1", "FACT:pkg"]}'
    result = validate_verdict(raw, evidence_ids={"GHSA-1", "FACT:pkg"})
    assert result.ok
    assert result.verdict.citations == ["GHSA-1", "FACT:pkg"]


def test_unknown_citation_rejected():
    raw = '{"summary": "s", "rationale": "r", "citations": ["MADE-UP-ID"]}'
    result = validate_verdict(raw, evidence_ids={"GHSA-1"})
    assert not result.ok
    assert "MADE-UP-ID" in result.error


def test_empty_citations_rejected():
    raw = '{"summary": "s", "rationale": "r", "citations": []}'
    result = validate_verdict(raw, evidence_ids={"GHSA-1"})
    assert not result.ok


def test_malformed_json_rejected():
    result = validate_verdict("not json at all", evidence_ids={"GHSA-1"})
    assert not result.ok
    assert result.verdict is None


def test_prose_around_json_is_extracted():
    raw = 'Sure, here is the JSON:\n{"summary": "s", "rationale": "r", "citations": ["GHSA-1"]}\nHope that helps!'
    result = validate_verdict(raw, evidence_ids={"GHSA-1"})
    assert result.ok


def test_none_response_is_rejected_not_crashing():
    result = validate_verdict(None, evidence_ids={"GHSA-1"})
    assert not result.ok
    assert result.verdict is None


def test_non_object_json_is_rejected():
    result = validate_verdict('["a", "b"]', evidence_ids={"GHSA-1"})
    assert not result.ok


def test_validation_stage_distinguishes_bad_json_schema_and_citations():
    assert validate_verdict("nope", {"GHSA-1"}).stage == "json"
    assert validate_verdict('{"summary": "s"}', {"GHSA-1"}).stage == "schema"
    assert validate_verdict('{"summary": "s", "rationale": "r", "citations": ["X"]}', {"GHSA-1"}).stage == "citations"
    assert validate_verdict('{"summary": "s", "rationale": "r", "citations": ["GHSA-1"]}', {"GHSA-1"}).stage == "ok"
