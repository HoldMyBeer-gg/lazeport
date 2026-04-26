"""Tests for app.services.llm."""
import importlib
import re
from unittest.mock import patch
import pytest

import app.config
import app.services.llm as llm_module


def _reload_config_and_llm():
    importlib.reload(app.config)
    importlib.reload(llm_module)


class TestGetModel:
    def test_model_override_wins(self, monkeypatch):
        _reload_config_and_llm()
        assert llm_module.get_model(provider_override="openai", model_override="custom-model") == "custom-model"

    def test_openai_model_default(self, monkeypatch):
        _reload_config_and_llm()
        assert llm_module.get_model(provider_override="openai") == "gpt-4o-mini"

    def test_ollama_model_defaults_to_first_available(self, monkeypatch):
        _reload_config_and_llm()
        monkeypatch.setattr(llm_module, "list_ollama_models", lambda *_args, **_kwargs: ["m1", "m2"])
        assert llm_module.get_model(provider_override="ollama") == "m1"

    def test_openai_compatible_requires_model(self, monkeypatch):
        _reload_config_and_llm()
        with pytest.raises(ValueError, match="Model is required"):
            llm_module.get_model(provider_override="openai_compatible")


class TestIsLlmAvailable:
    def test_ollama_always_available(self, monkeypatch):
        _reload_config_and_llm()
        assert llm_module.is_llm_available(provider_override="ollama") is True

    def test_openai_compatible_always_available(self, monkeypatch):
        _reload_config_and_llm()
        assert llm_module.is_llm_available(provider_override="openai_compatible") is True

    def test_openai_requires_key(self, monkeypatch):
        _reload_config_and_llm()
        assert llm_module.is_llm_available(provider_override="openai") is False

    def test_openai_with_key_available(self, monkeypatch):
        _reload_config_and_llm()
        assert llm_module.is_llm_available(provider_override="openai", api_key_override="sk-test") is True


class TestGetClient:
    def test_ollama_returns_client(self, monkeypatch):
        _reload_config_and_llm()
        client = llm_module.get_client(provider_override="ollama")
        assert client is not None

    def test_unknown_provider_raises(self, monkeypatch):
        _reload_config_and_llm()
        with pytest.raises(ValueError, match="Unknown LLM_PROVIDER"):
            llm_module.get_client(provider_override="unknown_provider")

    def test_openai_returns_client(self, monkeypatch):
        _reload_config_and_llm()
        client = llm_module.get_client(provider_override="openai", api_key_override="sk-test")
        assert client is not None


def test_list_ollama_models_handles_error(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("down")

    monkeypatch.setattr(llm_module.httpx, "get", boom)
    models = llm_module.list_ollama_models(base_url_override="http://localhost:11434")
    assert models == []


class TestResolveProviderOverrides:
    def test_provider_override_openai_uses_openai_base_url(self, monkeypatch):
        _reload_config_and_llm()
        provider, base_url, _ = llm_module._resolve_provider(
            provider_override="openai",
            base_url_override=None,
            api_key_override=None,
        )
        assert provider == "openai"
        assert "11434" not in base_url
        assert "openai.com" in base_url or "api.openai.com" in base_url

    def test_provider_override_openai_with_explicit_base_url_uses_it(self, monkeypatch):
        _reload_config_and_llm()
        provider, base_url, _ = llm_module._resolve_provider(
            provider_override="openai",
            base_url_override="https://api.openai.com/v1",
            api_key_override=None,
        )
        assert provider == "openai"
        assert base_url.rstrip("/") == "https://api.openai.com/v1"
        assert "11434" not in base_url

    def test_openai_compatible_requires_base_url(self, monkeypatch):
        _reload_config_and_llm()
        with pytest.raises(ValueError, match="base_url is required"):
            llm_module._resolve_provider(
                provider_override="openai_compatible",
                base_url_override=None,
                api_key_override=None,
            )

    def test_chat_completion_with_openai_override_does_not_call_ollama(self, monkeypatch):
        _reload_config_and_llm()
        from unittest.mock import patch
        with patch("app.services.llm._llm_client") as mock_factory:
            mock_factory.return_value.chat.completions.create.return_value = type(
                "R", (), {"choices": [type("C", (), {"message": type("M", (), {"content": "ok"})()})()]}
            )()
            llm_module.chat_completion(
                [{"role": "user", "content": "hi"}],
                provider_override="openai",
                base_url_override="https://api.openai.com/v1",
                api_key_override="sk-test",
                model_override="gpt-4o-mini",
            )
            mock_factory.assert_called_once()
            call_kwargs = mock_factory.call_args[1]
            assert call_kwargs["base_url"].rstrip("/") == "https://api.openai.com/v1"
            assert "11434" not in call_kwargs["base_url"]
            assert call_kwargs["api_key"] == "sk-test"


class TestChatCompletion:
    def test_ollama_calls_client(self, monkeypatch):
        _reload_config_and_llm()
        from unittest.mock import patch
        with patch("app.services.llm._llm_client") as mock_client:
            monkeypatch.setattr(llm_module, "list_ollama_models", lambda *_args, **_kwargs: ["llama3.2"])
            mock_client.return_value.chat.completions.create.return_value = type(
                "R", (), {"choices": [type("C", (), {"message": type("M", (), {"content": "hello"})()})()]}
            )()
            result = llm_module.chat_completion(
                [{"role": "user", "content": "hi"}],
                provider_override="ollama",
                base_url_override="http://localhost:11434",
            )
            assert result == "hello"

    def test_unknown_provider_raises(self, monkeypatch):
        _reload_config_and_llm()
        with pytest.raises(ValueError, match="Unknown LLM_PROVIDER"):
            llm_module.chat_completion([{"role": "user", "content": "hi"}], provider_override="fake")

    def test_openai_calls_client(self, monkeypatch):
        _reload_config_and_llm()
        from unittest.mock import patch
        with patch("app.services.llm._llm_client") as mock_client:
            mock_client.return_value.chat.completions.create.return_value = type(
                "R", (), {"choices": [type("C", (), {"message": type("M", (), {"content": "openai reply"})()})()]}
            )()
            result = llm_module.chat_completion(
                [{"role": "user", "content": "hi"}],
                provider_override="openai",
                model_override="gpt-4o-mini",
                api_key_override="sk-test",
            )
            assert result == "openai reply"


class TestResolveTimeout:
    def test_cloud_provider_default(self):
        _reload_config_and_llm()
        assert llm_module._resolve_timeout("openai") == 60.0

    def test_local_provider_default(self):
        _reload_config_and_llm()
        assert llm_module._resolve_timeout("ollama") == 300.0
        assert llm_module._resolve_timeout("openai_compatible") == 300.0
        assert llm_module._resolve_timeout("custom") == 300.0

    def test_override_wins_for_cloud(self):
        _reload_config_and_llm()
        assert llm_module._resolve_timeout("openai", timeout_override=120.0) == 120.0

    def test_override_wins_for_local(self):
        _reload_config_and_llm()
        assert llm_module._resolve_timeout("ollama", timeout_override=500.0) == 500.0

    def test_zero_override_uses_default(self):
        _reload_config_and_llm()
        assert llm_module._resolve_timeout("openai", timeout_override=0) == 60.0

    def test_negative_override_uses_default(self):
        _reload_config_and_llm()
        assert llm_module._resolve_timeout("ollama", timeout_override=-5) == 300.0

    def test_none_override_uses_default(self):
        _reload_config_and_llm()
        assert llm_module._resolve_timeout("openai", timeout_override=None) == 60.0

    def test_named_preset_uses_cloud_default(self):
        _reload_config_and_llm()
        for provider in ["anthropic", "gemini", "groq", "together", "deepseek", "mistral"]:
            assert llm_module._resolve_timeout(provider) == 60.0


class TestFilterSamplingParams:
    def test_empty_params_returns_empty(self):
        _reload_config_and_llm()
        sdk, extra = llm_module._filter_sampling_params("openai", {})
        assert sdk == {}
        assert extra is None

    def test_none_params_returns_empty(self):
        _reload_config_and_llm()
        sdk, extra = llm_module._filter_sampling_params("openai", None)
        assert sdk == {}
        assert extra is None

    def test_openai_keeps_supported_params(self):
        _reload_config_and_llm()
        params = {"temperature": 0.5, "top_p": 0.9, "frequency_penalty": 0.3, "presence_penalty": 0.1}
        sdk, extra = llm_module._filter_sampling_params("openai", params)
        assert sdk == params
        assert extra is None

    def test_openai_drops_unsupported_params(self):
        _reload_config_and_llm()
        params = {"temperature": 0.5, "top_k": 40, "min_p": 0.1, "repeat_penalty": 1.5}
        sdk, extra = llm_module._filter_sampling_params("openai", params)
        assert sdk == {"temperature": 0.5}
        assert extra is None

    def test_anthropic_only_temperature_and_top_p(self):
        _reload_config_and_llm()
        params = {"temperature": 0.7, "top_p": 0.8, "frequency_penalty": 0.5}
        sdk, extra = llm_module._filter_sampling_params("anthropic", params)
        assert sdk == {"temperature": 0.7, "top_p": 0.8}
        assert extra is None

    def test_ollama_sdk_and_extra_body(self):
        _reload_config_and_llm()
        params = {
            "temperature": 0.3, "top_p": 0.9, "frequency_penalty": 0.2,
            "top_k": 40, "min_p": 0.05, "repeat_penalty": 1.1,
        }
        sdk, extra = llm_module._filter_sampling_params("ollama", params)
        assert sdk == {"temperature": 0.3, "top_p": 0.9, "frequency_penalty": 0.2}
        assert extra == {"options": {"top_k": 40, "min_p": 0.05, "repeat_penalty": 1.1}}

    def test_ollama_without_native_params_no_extra_body(self):
        _reload_config_and_llm()
        params = {"temperature": 0.5}
        sdk, extra = llm_module._filter_sampling_params("ollama", params)
        assert sdk == {"temperature": 0.5}
        assert extra is None

    def test_none_values_are_stripped(self):
        _reload_config_and_llm()
        params = {"temperature": 0.5, "top_p": None, "frequency_penalty": None}
        sdk, extra = llm_module._filter_sampling_params("openai", params)
        assert sdk == {"temperature": 0.5}

    def test_unknown_provider_falls_back_to_temp_and_top_p(self):
        _reload_config_and_llm()
        params = {"temperature": 0.8, "top_p": 0.7, "frequency_penalty": 1.0}
        sdk, extra = llm_module._filter_sampling_params("some_future_provider", params)
        assert sdk == {"temperature": 0.8, "top_p": 0.7}
        assert extra is None

    def test_max_tokens_passes_through_for_openai(self):
        _reload_config_and_llm()
        params = {"max_tokens": 600}
        sdk, extra = llm_module._filter_sampling_params("openai", params)
        assert sdk == {"max_tokens": 600}
        assert extra is None

    def test_max_tokens_passes_through_for_ollama(self):
        _reload_config_and_llm()
        params = {"max_tokens": 600, "top_k": 40}
        sdk, extra = llm_module._filter_sampling_params("ollama", params)
        assert sdk == {"max_tokens": 600}
        assert extra == {"options": {"top_k": 40}}

    def test_max_tokens_passes_through_for_all_providers(self):
        _reload_config_and_llm()
        for provider in ["openai", "anthropic", "gemini", "groq", "together", "deepseek",
                         "mistral", "ollama", "openai_compatible", "custom"]:
            sdk, _ = llm_module._filter_sampling_params(provider, {"max_tokens": 600})
            assert "max_tokens" in sdk, f"max_tokens not passed through for provider: {provider}"

    def test_non_ollama_provider_ignores_native_params(self):
        _reload_config_and_llm()
        params = {"top_k": 40, "min_p": 0.1, "repeat_penalty": 1.5}
        sdk, extra = llm_module._filter_sampling_params("deepseek", params)
        assert sdk == {}
        assert extra is None

    def test_ollama_num_ctx_and_num_predict_route_to_options(self):
        _reload_config_and_llm()
        params = {"temperature": 0.15, "top_k": 40, "num_ctx": 16384, "num_predict": 2048}
        sdk, extra = llm_module._filter_sampling_params("ollama", params)
        assert sdk == {"temperature": 0.15}
        assert extra == {"options": {"top_k": 40, "num_ctx": 16384, "num_predict": 2048}}

    def test_non_ollama_provider_ignores_num_ctx(self):
        _reload_config_and_llm()
        params = {"temperature": 0.5, "num_ctx": 16384, "num_predict": 2048}
        sdk, extra = llm_module._filter_sampling_params("openai", params)
        assert sdk == {"temperature": 0.5}
        assert extra is None


class TestSamplingParamsPassthrough:
    def test_chat_completion_passes_sampling_params_to_create(self, monkeypatch):
        _reload_config_and_llm()
        from unittest.mock import patch, call
        monkeypatch.setattr(llm_module, "list_ollama_models", lambda *_a, **_k: ["m1"])
        with patch("app.services.llm._llm_client") as mock_factory:
            mock_factory.return_value.chat.completions.create.return_value = type(
                "R", (), {"choices": [type("C", (), {"message": type("M", (), {"content": "ok"})()})()],
                          "usage": None}
            )()
            llm_module.chat_completion(
                [{"role": "user", "content": "hi"}],
                provider_override="openai",
                model_override="gpt-4o-mini",
                api_key_override="sk-test",
                sampling_params={"temperature": 0.9, "top_p": 0.8, "frequency_penalty": 0.5},
            )
            create_call = mock_factory.return_value.chat.completions.create.call_args
            assert create_call[1]["temperature"] == 0.9
            assert create_call[1]["top_p"] == 0.8
            assert create_call[1]["frequency_penalty"] == 0.5

    def test_chat_completion_ollama_passes_extra_body(self, monkeypatch):
        _reload_config_and_llm()
        from unittest.mock import patch
        monkeypatch.setattr(llm_module, "list_ollama_models", lambda *_a, **_k: ["m1"])
        with patch("app.services.llm._llm_client") as mock_factory:
            mock_factory.return_value.chat.completions.create.return_value = type(
                "R", (), {"choices": [type("C", (), {"message": type("M", (), {"content": "ok"})()})()],
                          "usage": None}
            )()
            llm_module.chat_completion(
                [{"role": "user", "content": "hi"}],
                provider_override="ollama",
                sampling_params={"temperature": 0.4, "top_k": 50, "repeat_penalty": 1.2},
            )
            create_call = mock_factory.return_value.chat.completions.create.call_args
            assert create_call[1]["temperature"] == 0.4
            assert create_call[1]["extra_body"] == {"options": {"top_k": 50, "repeat_penalty": 1.2}}

    def test_chat_completion_without_sampling_params_uses_default_temp(self, monkeypatch):
        _reload_config_and_llm()
        from unittest.mock import patch
        with patch("app.services.llm._llm_client") as mock_factory:
            mock_factory.return_value.chat.completions.create.return_value = type(
                "R", (), {"choices": [type("C", (), {"message": type("M", (), {"content": "ok"})()})()],
                          "usage": None}
            )()
            llm_module.chat_completion(
                [{"role": "user", "content": "hi"}],
                provider_override="openai",
                model_override="gpt-4o-mini",
                api_key_override="sk-test",
            )
            create_call = mock_factory.return_value.chat.completions.create.call_args
            assert create_call[1]["temperature"] == 0.3
            assert "extra_body" not in create_call[1]

    def test_sampling_temperature_overrides_function_default(self, monkeypatch):
        _reload_config_and_llm()
        from unittest.mock import patch
        with patch("app.services.llm._llm_client") as mock_factory:
            mock_factory.return_value.chat.completions.create.return_value = type(
                "R", (), {"choices": [type("C", (), {"message": type("M", (), {"content": "ok"})()})()],
                          "usage": None}
            )()
            llm_module.chat_completion(
                [{"role": "user", "content": "hi"}],
                provider_override="openai",
                model_override="gpt-4o-mini",
                api_key_override="sk-test",
                temperature=0.5,
                sampling_params={"temperature": 1.0},
            )
            create_call = mock_factory.return_value.chat.completions.create.call_args
            assert create_call[1]["temperature"] == 1.0


class TestTimeoutPassthrough:
    def test_get_client_passes_timeout_override(self, monkeypatch):
        _reload_config_and_llm()
        from unittest.mock import patch
        with patch("app.services.llm._llm_client") as mock_factory:
            mock_factory.return_value = "client"
            llm_module.get_client(
                provider_override="ollama",
                timeout_override=180.0,
            )
            call_kwargs = mock_factory.call_args[1]
            assert call_kwargs["timeout"] == 180.0

    def test_chat_completion_passes_timeout_override(self, monkeypatch):
        _reload_config_and_llm()
        from unittest.mock import patch
        monkeypatch.setattr(llm_module, "list_ollama_models", lambda *_a, **_k: ["m1"])
        with patch("app.services.llm._llm_client") as mock_factory:
            mock_factory.return_value.chat.completions.create.return_value = type(
                "R", (), {"choices": [type("C", (), {"message": type("M", (), {"content": "ok"})()})()]}
            )()
            llm_module.chat_completion(
                [{"role": "user", "content": "hi"}],
                provider_override="ollama",
                timeout_override=420.0,
            )
            call_kwargs = mock_factory.call_args[1]
            assert call_kwargs["timeout"] == 420.0

    def test_cloud_default_timeout_without_override(self, monkeypatch):
        _reload_config_and_llm()
        from unittest.mock import patch
        with patch("app.services.llm._llm_client") as mock_factory:
            mock_factory.return_value.chat.completions.create.return_value = type(
                "R", (), {"choices": [type("C", (), {"message": type("M", (), {"content": "ok"})()})()]}
            )()
            llm_module.chat_completion(
                [{"role": "user", "content": "hi"}],
                provider_override="openai",
                model_override="gpt-4o-mini",
                api_key_override="sk-test",
            )
            call_kwargs = mock_factory.call_args[1]
            assert call_kwargs["timeout"] == 60.0


class TestResolveLlmSettings:
    """Tests for _resolve_llm_settings in organizations.py."""

    def test_flat_legacy_gets_default_extra_instructions(self):
        from app.api.organizations import _resolve_llm_settings
        from app.api.generate import DEFAULT_EXTRA_INSTRUCTIONS
        raw = {"provider": "ollama", "model": "llama3", "base_url": "http://host:11434"}
        result = _resolve_llm_settings(raw)
        assert result["provider"] == "ollama"
        assert result["model"] == "llama3"
        assert result["extra_instructions"] == DEFAULT_EXTRA_INSTRUCTIONS

    def test_empty_dict_gets_default_extra_instructions(self):
        from app.api.organizations import _resolve_llm_settings
        from app.api.generate import DEFAULT_EXTRA_INSTRUCTIONS
        result = _resolve_llm_settings({})
        assert result["extra_instructions"] == DEFAULT_EXTRA_INSTRUCTIONS

    def test_active_provider_resolved_from_providers_dict(self):
        from app.api.organizations import _resolve_llm_settings
        raw = {
            "provider": "ollama",
            "extra_instructions": "Be concise.",
            "providers": {
                "ollama": {
                    "model": "qwen3.5:32b",
                    "base_url": "http://192.168.1.100:11434",
                    "timeout": 300,
                    "sampling_params": {"temperature": 1.0},
                },
                "openai": {
                    "model": "gpt-4o-mini",
                    "timeout": 60,
                },
            },
        }
        result = _resolve_llm_settings(raw)
        assert result["provider"] == "ollama"
        assert result["model"] == "qwen3.5:32b"
        assert result["base_url"] == "http://192.168.1.100:11434"
        assert result["timeout"] == 300
        assert result["extra_instructions"] == "Be concise."
        assert result["sampling_params"] == {"temperature": 1.0}
        assert "providers" not in result

    def test_missing_active_provider_returns_raw_with_default(self):
        from app.api.organizations import _resolve_llm_settings
        from app.api.generate import DEFAULT_EXTRA_INSTRUCTIONS
        raw = {
            "provider": "anthropic",
            "providers": {"ollama": {"model": "llama3"}},
        }
        result = _resolve_llm_settings(raw)
        assert result["provider"] == "anthropic"
        assert result["extra_instructions"] == DEFAULT_EXTRA_INSTRUCTIONS

    def test_no_provider_field_returns_raw_with_default(self):
        from app.api.organizations import _resolve_llm_settings
        from app.api.generate import DEFAULT_EXTRA_INSTRUCTIONS
        raw = {"providers": {"ollama": {"model": "llama3"}}}
        result = _resolve_llm_settings(raw)
        assert result["extra_instructions"] == DEFAULT_EXTRA_INSTRUCTIONS

    def test_none_values_stripped_but_default_ei_applied(self):
        from app.api.organizations import _resolve_llm_settings
        from app.api.generate import DEFAULT_EXTRA_INSTRUCTIONS
        raw = {
            "provider": "openai",
            "extra_instructions": None,
            "providers": {
                "openai": {"model": "gpt-4o", "base_url": None, "timeout": 60},
            },
        }
        result = _resolve_llm_settings(raw)
        assert "base_url" not in result
        assert result["model"] == "gpt-4o"
        assert result["timeout"] == 60
        assert result["extra_instructions"] == DEFAULT_EXTRA_INSTRUCTIONS

    def test_custom_extra_instructions_preserved(self):
        from app.api.organizations import _resolve_llm_settings
        raw = {
            "provider": "openai",
            "extra_instructions": "Always use British English.",
            "providers": {
                "openai": {"model": "gpt-4o", "timeout": 60},
            },
        }
        result = _resolve_llm_settings(raw)
        assert result["extra_instructions"] == "Always use British English."

    def test_empty_string_extra_instructions_not_replaced(self):
        """If admin explicitly cleared instructions, respect that."""
        from app.api.organizations import _resolve_llm_settings
        raw = {
            "provider": "ollama",
            "extra_instructions": "",
            "providers": {
                "ollama": {"model": "llama3"},
            },
        }
        result = _resolve_llm_settings(raw)
        assert result["extra_instructions"] == ""


class TestValidateCwe:
    def test_valid_cwe_format_passes(self):
        from app.services.field_extraction import validate_cwe
        assert validate_cwe("CWE-79") == "CWE-79"
        assert validate_cwe("CWE-89") == "CWE-89"
        assert validate_cwe("CWE-99999") == "CWE-99999"

    def test_no_digits_returns_none(self):
        from app.services.field_extraction import validate_cwe
        assert validate_cwe("CWE-") is None
        assert validate_cwe("not-a-cwe") is None


class TestPromptCweOwaspInference:
    """Verify that prompts encourage CWE/OWASP inference and restrict only CVSS."""

    def test_structurer_system_prompt_encourages_cwe_owasp(self):
        from app.services.structurer import _call_llm
        import inspect
        source = inspect.getsource(_call_llm)
        assert "suggest the most specific applicable CWE ID" in source
        assert "suggest the applicable OWASP Top 10 2021 category" in source
        assert "do NOT infer CVSS" in source or "only include if explicitly present" in source

    def test_evidence_structurer_prompt_encourages_cwe_owasp(self):
        from app.services.evidence_structurer import structure_from_evidence
        import inspect
        source = inspect.getsource(structure_from_evidence)
        assert "suggest the most specific applicable CWE ID" in source
        assert "suggest the applicable OWASP Top 10 2021 category" in source

    def test_prompts_no_longer_block_cwe_owasp_inference(self):
        from app.services.structurer import _call_llm
        from app.services.evidence_structurer import structure_from_evidence
        import inspect
        structurer_src = inspect.getsource(_call_llm)
        evidence_src = inspect.getsource(structure_from_evidence)
        for src in [structurer_src, evidence_src]:
            assert "do NOT infer" not in src or "do NOT infer CVSS" in src or "do not infer CVSS" in src
