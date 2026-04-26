from app.services.http_snippets import extract_http_snippets


def test_extracts_request_and_response_blocks():
    notes = """GET /index HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain

hi"""
    snippets = extract_http_snippets(notes)
    assert len(snippets) == 2
    assert snippets[0]["type"] == "request"
    assert "GET /index HTTP/1.1" in snippets[0]["text"]
    assert snippets[1]["type"] == "response"
    assert "HTTP/1.1 200 OK" in snippets[1]["text"]


def test_snippet_truncation_and_limit():
    notes = "\n".join(["GET / HTTP/1.1", "Host: ex", ""] * 10)
    snippets = extract_http_snippets(notes, max_snippets=1, max_chars=10)
    assert len(snippets) == 1
    assert snippets[0]["text"].endswith("...")
