"""SSRF guard: validate_outbound_url and the places it is enforced."""
import socket

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

import app.config as config
from app.main import app
from app.services import llm
from app.validation import OutboundUrlError, validate_outbound_url

client = TestClient(app)

PUBLIC_IP = "93.184.216.34"


def _fake_resolver(table):
    """Build an app.validation._resolve_host stand-in that answers from a host->ips table."""
    def _resolve(host, port):
        if host not in table:
            raise socket.gaierror(8, "nodename nor servname provided")
        return list(table[host])
    return _resolve


@pytest.fixture
def dns(monkeypatch):
    table = {
        "public.example": [PUBLIC_IP],
        "localhost": ["127.0.0.1"],
        "internal.example": ["10.0.0.5"],
        "mixed.example": [PUBLIC_IP, "127.0.0.1"],
    }
    monkeypatch.setattr("app.validation._resolve_host", _fake_resolver(table))
    return table


class TestValidateOutboundUrl:
    def test_public_https_host_allowed(self, dns):
        assert validate_outbound_url("https://public.example/v1") == "https://public.example/v1"

    @pytest.mark.parametrize("url", [
        "http://127.0.0.1:11434",
        "http://localhost:11434",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://[::1]/",
        "http://[::ffff:10.0.0.5]/",
        "http://0.0.0.0/",
        "http://internal.example/",
        "http://mixed.example/",
    ])
    def test_private_or_internal_blocked(self, dns, url):
        with pytest.raises(OutboundUrlError, match="private or internal"):
            validate_outbound_url(url)

    @pytest.mark.parametrize("url,msg", [
        ("ftp://public.example/", "http:// or https://"),
        ("file:///etc/passwd", "http:// or https://"),
        ("http://user:pw@public.example/", "embedded credentials"),
        ("http:///nohost", "include a host"),
        ("", "required"),
        (None, "required"),
        ("http://does-not-resolve.example/", "could not be resolved"),
    ])
    def test_malformed_rejected(self, dns, url, msg):
        with pytest.raises(OutboundUrlError, match=msg):
            validate_outbound_url(url)

    def test_allow_private_bypasses_address_check_only(self, dns):
        assert validate_outbound_url("http://localhost:11434", allow_private=True)
        with pytest.raises(OutboundUrlError):
            validate_outbound_url("ftp://localhost", allow_private=True)

    def test_too_long_rejected(self, dns):
        with pytest.raises(OutboundUrlError, match="characters or less"):
            validate_outbound_url("https://public.example/" + "a" * 3000)


class TestEnsureSafeBaseUrl:
    def test_none_and_builtin_defaults_trusted(self, dns, monkeypatch):
        monkeypatch.setattr(config.settings, "allow_private_llm_urls", False)
        llm.ensure_safe_base_url(None)
        llm.ensure_safe_base_url("")
        llm.ensure_safe_base_url(llm.DEFAULT_OLLAMA_BASE_URL)
        llm.ensure_safe_base_url(llm.DEFAULT_OLLAMA_BASE_URL + "/")
        for preset in llm.PROVIDER_PRESETS.values():
            llm.ensure_safe_base_url(preset["base_url"])

    def test_private_override_blocked_without_flag(self, dns, monkeypatch):
        monkeypatch.setattr(config.settings, "allow_private_llm_urls", False)
        with pytest.raises(OutboundUrlError):
            llm.ensure_safe_base_url("http://192.168.1.50:11434")

    def test_private_override_allowed_with_flag(self, dns, monkeypatch):
        monkeypatch.setattr(config.settings, "allow_private_llm_urls", True)
        llm.ensure_safe_base_url("http://192.168.1.50:11434")

    def test_resolve_provider_enforces_guard(self, dns, monkeypatch):
        monkeypatch.setattr(config.settings, "allow_private_llm_urls", False)
        with pytest.raises(OutboundUrlError):
            llm._resolve_provider("openai_compatible", "http://169.254.169.254/", "k")

    def test_list_ollama_models_enforces_guard(self, dns, monkeypatch):
        monkeypatch.setattr(config.settings, "allow_private_llm_urls", False)
        with patch("app.services.llm.httpx.get") as mock_get:
            with pytest.raises(OutboundUrlError):
                llm.list_ollama_models(base_url_override="http://10.0.0.5:11434")
        mock_get.assert_not_called()


class TestProviderEndpoints:
    def test_private_base_url_returns_400_and_does_not_fetch(self, dns, monkeypatch):
        monkeypatch.setattr(config.settings, "allow_private_llm_urls", False)
        with patch("httpx.get") as mock_get:  # providers.py imports httpx lazily inside the helper
            r = client.get("/api/providers/models?provider=openai&base_url=http://169.254.169.254/latest")
        assert r.status_code == 400
        assert "private or internal" in r.json()["detail"]
        mock_get.assert_not_called()

    def test_private_base_url_vision_returns_400(self, dns, monkeypatch):
        monkeypatch.setattr(config.settings, "allow_private_llm_urls", False)
        r = client.get("/api/providers/vision-models?provider=ollama&base_url=http://127.0.0.1:11434")
        assert r.status_code == 400

    def test_default_ollama_base_url_still_works(self, dns, monkeypatch):
        monkeypatch.setattr(config.settings, "allow_private_llm_urls", False)
        with patch("app.api.providers.list_ollama_models", return_value=["llama3"]):
            r = client.get("/api/providers/models?provider=ollama&base_url=http://localhost:11434")
        assert r.status_code == 200
        assert r.json()["models"] == ["llama3"]

    def test_try_list_models_guards_direct_call(self, dns, monkeypatch):
        from app.api.providers import _try_list_models_via_api
        monkeypatch.setattr(config.settings, "allow_private_llm_urls", False)
        with pytest.raises(OutboundUrlError):
            _try_list_models_via_api("openai", "http://10.0.0.5/v1", api_key="k")


class TestJiraClient:
    def test_private_url_rejected(self, dns, monkeypatch):
        from app.services.jira import JiraClient
        monkeypatch.setattr(config.settings, "allow_private_jira_urls", False)
        with pytest.raises(OutboundUrlError):
            JiraClient(url="http://10.0.0.9:8080", email="a@b.c", api_token="t")

    def test_private_url_allowed_with_flag(self, dns, monkeypatch):
        from app.services.jira import JiraClient
        monkeypatch.setattr(config.settings, "allow_private_jira_urls", True)
        c = JiraClient(url="http://10.0.0.9:8080/", email="a@b.c", api_token="t")
        assert c.url == "http://10.0.0.9:8080"

    def test_public_url_accepted(self, dns, monkeypatch):
        from app.services.jira import JiraClient
        monkeypatch.setattr(config.settings, "allow_private_jira_urls", False)
        JiraClient(url="https://public.example", email="a@b.c", api_token="t")

    def test_get_jira_client_returns_none_for_private_url(self, dns, monkeypatch):
        import json
        from app.services.jira import get_jira_client
        monkeypatch.setattr(config.settings, "allow_private_jira_urls", False)
        cfg = json.dumps({"url": "http://127.0.0.1:8080", "email": "a@b.c", "api_token": "t"})
        assert get_jira_client(cfg) is None


class TestConnectorPayload:
    """Saving or testing a connector with a private URL is refused up front (422)."""

    def _payload(self, url):
        from app.api.admin import ConnectorPayload
        return ConnectorPayload(type="jira", name="Jira", config={"url": url, "email": "a@b.c", "api_token": "t"})

    def test_private_connector_url_rejected_at_validation(self, dns, monkeypatch):
        from pydantic import ValidationError
        monkeypatch.setattr(config.settings, "allow_private_jira_urls", False)
        with pytest.raises(ValidationError, match="private or internal"):
            self._payload("http://10.0.0.9:8080")

    def test_private_connector_url_allowed_with_flag(self, dns, monkeypatch):
        monkeypatch.setattr(config.settings, "allow_private_jira_urls", True)
        assert self._payload("http://10.0.0.9:8080").config["url"] == "http://10.0.0.9:8080"

    def test_public_connector_url_accepted(self, dns, monkeypatch):
        monkeypatch.setattr(config.settings, "allow_private_jira_urls", False)
        assert self._payload("https://public.example").config["url"] == "https://public.example"

    def test_create_connector_endpoint_returns_422(self, dns, monkeypatch):
        monkeypatch.setattr(config.settings, "allow_private_jira_urls", False)
        r = client.post("/api/admin/connectors", json={
            "type": "jira", "name": "Jira",
            "config": {"url": "http://169.254.169.254", "email": "a@b.c", "api_token": "t"},
        })
        assert r.status_code == 422, r.text
        assert "private or internal" in r.text
