from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_provider_models_ollama_with_base_url():
    with patch("app.api.providers.list_ollama_models") as mock_list:
        mock_list.return_value = ["model-a", "model-b"]
        r = client.get("/api/providers/models?provider=ollama&base_url=http://localhost:11434")
    assert r.status_code == 200
    data = r.json()
    assert data["provider"] == "ollama"
    assert data["models"] == ["model-a", "model-b"]
    mock_list.assert_called_once_with(base_url_override="http://localhost:11434")


@patch("app.api.providers._try_list_models_via_api", return_value=None)
def test_provider_models_openai_returns_models(mock_try_list):
    """OpenAI provider returns well-known model list; no real API call in tests."""
    r = client.get("/api/providers/models?provider=openai")
    assert r.status_code == 200
    data = r.json()
    assert data["provider"] == "openai"
    assert len(data["models"]) > 0, "OpenAI models list must not be empty for dropdown"
    assert "gpt-4o-mini" in data["models"]
    assert "gpt-4o" in data["models"]
    mock_try_list.assert_called_once()


@patch("app.api.providers._try_list_models_via_api", return_value=None)
def test_provider_models_openai_compatible_returns_models(mock_try_list):
    """OpenAI-compatible provider returns same chat models as openai so dropdown works; no real API call."""
    r = client.get("/api/providers/models?provider=openai_compatible")
    assert r.status_code == 200
    data = r.json()
    assert data["provider"] == "openai_compatible"
    assert len(data["models"]) > 0
    assert "gpt-4o-mini" in data["models"]
    mock_try_list.assert_called_once()


def test_provider_models_unknown_provider():
    r = client.get("/api/providers/models?provider=custom")
    assert r.status_code == 200
    data = r.json()
    assert data["provider"] == "custom"
    assert data["models"] == []


@patch("app.api.providers._try_list_models_via_api", return_value=["deepseek-chat"])
def test_provider_models_uses_user_stored_key_for_api_listing(mock_try_list):
    """Regression: provider model listing must pass per-user stored key to API probe."""
    from app.api.providers import provider_models
    from app.db.models import User

    class _Adapter:
        def get_user_openai_api_key(self, _user_id):
            return "sk-user-deepseek"
        def get_user_provider_api_key(self, _user_id, provider):
            return "sk-user-deepseek" if provider == "deepseek" else None

    user = User(id="u1", email="u@example.com", provider="local", ai_key_provider="deepseek")
    data = provider_models(
        provider="deepseek",
        base_url="https://api.deepseek.com/v1",
        user=user,
        adapter=_Adapter(),
    )
    assert data["provider"] == "deepseek"
    assert data["models"] == ["deepseek-chat"]
    mock_try_list.assert_called_once()
    kwargs = mock_try_list.call_args.kwargs
    assert kwargs.get("api_key") == "sk-user-deepseek"
