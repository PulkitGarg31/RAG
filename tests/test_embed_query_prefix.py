from vt.embed import build_embedding_input, QUERY_INSTRUCTION


def test_document_input_is_header_plus_content():
    text = build_embedding_input(header="[H]", content="body", is_query=False)
    assert text == "[H]\nbody"


def test_query_input_gets_bge_instruction_prefix():
    text = build_embedding_input(header="", content="yaml load rce", is_query=True)
    assert text == QUERY_INSTRUCTION + "yaml load rce"
