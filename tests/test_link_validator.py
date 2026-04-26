from app.services import link_validator


def test_extract_urls_dedupes_and_strips():
    text = "See https://example.com/test, and https://example.com/test."
    urls = link_validator.extract_urls(text)
    assert urls == ["https://example.com/test"]


def test_extract_identifier_urls():
    text = "CVE-2021-1234 CWE-79 A1:2021"
    urls = link_validator.extract_identifier_urls(text)
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-1234" in urls
    assert "https://cwe.mitre.org/data/definitions/79.html" in urls
    assert any("owasp.org" in u for u in urls)


def test_identifier_to_url_variants():
    assert link_validator.identifier_to_url("CVE-2022-0001")
    assert link_validator.identifier_to_url("CWE-89")
    assert link_validator.identifier_to_url("A10:2021")
    assert link_validator.identifier_to_url("A1")
    assert link_validator.identifier_to_url("A1:2017")
    assert link_validator.identifier_to_url("NOPE") is None


def test_get_valid_urls_allows_canonical_on_error(monkeypatch):
    def fake_validate(url: str) -> str:
        return "error"

    monkeypatch.setattr(link_validator, "validate_url", fake_validate)
    urls = ["https://nvd.nist.gov/vuln/detail/CVE-2021-1234", "https://example.com/a"]
    valid = link_validator.get_valid_urls(urls)
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-1234" in valid
    assert "https://example.com/a" not in valid


def test_validate_url_rejects_non_http():
    assert link_validator.validate_url("ftp://example.com") == "invalid"


def test_validate_url_caches_results(monkeypatch):
    """Validation results are cached; repeated URLs skip the fetch."""
    fetch_count = 0

    class MockClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def get(self, url):
            nonlocal fetch_count
            fetch_count += 1
            from httpx import Response
            return Response(200, text="OK content")

    import httpx
    monkeypatch.setattr(httpx, "Client", MockClient)

    link_validator._validation_cache.clear()
    assert link_validator.validate_url("https://cwe.mitre.org/data/definitions/79.html") == "valid"
    assert fetch_count == 1

    assert link_validator.validate_url("https://cwe.mitre.org/data/definitions/79.html") == "valid"
    assert fetch_count == 1


def test_validate_url_evicts_when_full(monkeypatch):
    """When cache hits MAX_CACHE_SIZE, oldest entries are evicted (FIFO)."""
    fetch_count = 0

    class MockClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def get(self, url):
            nonlocal fetch_count
            fetch_count += 1
            from httpx import Response
            return Response(200, text="OK content")

    import httpx
    monkeypatch.setattr(httpx, "Client", MockClient)

    link_validator._validation_cache.clear()
    original_max = link_validator.MAX_CACHE_SIZE
    link_validator.MAX_CACHE_SIZE = 3

    try:
        link_validator.validate_url("https://example.com/1")
        link_validator.validate_url("https://example.com/2")
        link_validator.validate_url("https://example.com/3")
        assert len(link_validator._validation_cache) == 3

        link_validator.validate_url("https://example.com/4")
        assert len(link_validator._validation_cache) == 3
        assert "https://example.com/1" not in link_validator._validation_cache
        assert "https://example.com/4" in link_validator._validation_cache

        link_validator.validate_url("https://example.com/1")
        assert fetch_count == 5
    finally:
        link_validator.MAX_CACHE_SIZE = original_max
