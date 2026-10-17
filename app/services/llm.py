"""
LLM provider abstraction: OpenAI, Ollama, or any OpenAI-compatible API.

UI request values + DB-stored key are the source of truth for provider, model,
base URL, and API key. This module does not fall back to env configuration for
those fields.
"""
import logging
import math
from typing import Dict, List

import httpx

from app.validation import validate_outbound_url

log = logging.getLogger(__name__)


# ── Provider presets ──────────────────────────────────────────────────────────
# Maps provider slug -> { base_url, label, key_label }
# All of these speak the OpenAI chat completions format.
PROVIDER_PRESETS: Dict[str, Dict[str, str]] = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "label": "OpenAI",
        "key_label": "OpenAI API Key",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1/",
        "label": "Anthropic",
        "key_label": "Anthropic API Key",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "label": "Google Gemini",
        "key_label": "Gemini API Key",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "label": "Groq",
        "key_label": "Groq API Key",
    },
    "together": {
        "base_url": "https://api.together.xyz/v1",
        "label": "Together AI",
        "key_label": "Together API Key",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "label": "DeepSeek",
        "key_label": "DeepSeek API Key",
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "label": "Mistral",
        "key_label": "Mistral API Key",
    },
}

# Providers that are always available (local / catch-all)
_ALWAYS_PROVIDERS = {"ollama", "openai_compatible", "custom"}

# Full set of valid provider slugs (used for request validation)
ALLOWED_PROVIDERS: set[str] = set(PROVIDER_PRESETS.keys()) | _ALWAYS_PROVIDERS

DEFAULT_PROVIDER = "openai"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"


def ensure_safe_base_url(base_url_override: str | None) -> None:
    """
    SSRF guard for user-supplied LLM base URLs.

    The built-in Ollama default and the provider presets are trusted. Any other
    value must pass ``validate_outbound_url``; private/loopback hosts are only
    accepted when ``ALLOW_PRIVATE_LLM_URLS`` is enabled. Raises
    ``app.validation.OutboundUrlError`` on rejection.
    """
    if not base_url_override:
        return
    normalized = str(base_url_override).strip().rstrip("/")
    trusted = {DEFAULT_OLLAMA_BASE_URL.rstrip("/")} | {
        preset["base_url"].rstrip("/") for preset in PROVIDER_PRESETS.values()
    }
    if normalized in trusted:
        return
    from app.config import settings  # call-time import: tests reload app.config
    validate_outbound_url(
        normalized,
        allow_private=settings.allow_private_llm_urls,
        purpose="LLM base URL",
    )
DEFAULT_MODELS: Dict[str, str] = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-sonnet-4-20250514",
    "gemini": "gemini-2.0-flash",
    "groq": "llama-3.3-70b-versatile",
    "together": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "deepseek": "deepseek-chat",
    "mistral": "mistral-large-latest",
}


def _stringify_message_content(content) -> str:
    """Normalize message content to a plain string for token estimation."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                # OpenAI-style multimodal content blocks
                if item.get("type") == "text":
                    parts.append(str(item.get("text") or ""))
                elif item.get("type") == "image_url":
                    image_url = item.get("image_url") or {}
                    if isinstance(image_url, dict):
                        parts.append(str(image_url.get("url") or ""))
                    else:
                        parts.append(str(image_url))
                else:
                    parts.append(str(item))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    if isinstance(content, dict):
        return str(content)
    return str(content)


def _estimate_prompt_tokens(messages: List[Dict[str, str]]) -> int:
    """
    Fast approximate prompt token estimate.
    Heuristic: ~4 chars/token + small per-message overhead.
    """
    if not messages:
        return 0
    total_chars = 0
    for msg in messages:
        total_chars += len(str(msg.get("role") or ""))
        total_chars += len(_stringify_message_content(msg.get("content")))
    # include protocol overhead per message
    overhead = 4 * len(messages)
    return max(1, math.ceil(total_chars / 4) + overhead)


def _llm_client(base_url: str, api_key: str, timeout: float = 60.0):
    from openai import OpenAI
    import httpx
    from app.config import settings
    # Providers like Ollama don't need a real API key but the SDK requires one
    effective_key = api_key or settings.llm_dummy_api_key  # noqa: S105
    return OpenAI(
        api_key=effective_key,
        base_url=base_url,
        timeout=timeout,
        max_retries=1,  # Fail faster instead of long retries
        http_client=httpx.Client(timeout=timeout)
    )


def _resolve_provider(provider_override: str | None, base_url_override: str | None, api_key_override: str | None):
    """Resolve provider, base_url, and api_key from request/UI overrides and presets."""
    ensure_safe_base_url(base_url_override)
    provider = (provider_override or DEFAULT_PROVIDER).lower()

    if provider == "ollama":
        base_url = (base_url_override or DEFAULT_OLLAMA_BASE_URL).rstrip("/")
        base_url = f"{base_url}/v1"
        api_key = "ollama"
        return provider, base_url, api_key

    # Named presets: use preset base_url when no override given.
    if provider in PROVIDER_PRESETS:
        preset = PROVIDER_PRESETS[provider]
        base_url = (base_url_override or preset["base_url"]).rstrip("/")
        api_key = (api_key_override or "").strip()
        return provider, base_url, api_key

    # openai_compatible / custom: require explicit base_url from UI.
    if provider in ("openai_compatible", "custom"):
        base_url = (base_url_override or "").rstrip("/")
        if not base_url:
            raise ValueError("base_url is required for openai_compatible/custom providers.")
        api_key = (api_key_override or "").strip()
        return provider, base_url, api_key

    raise ValueError(
        f"Unknown LLM_PROVIDER={provider}. "
        f"Use one of: {', '.join(sorted(ALLOWED_PROVIDERS))}."
    )


DEFAULT_TIMEOUT_CLOUD = 60.0
DEFAULT_TIMEOUT_LOCAL = 300.0

# ── Provider-aware sampling param filtering ──────────────────────────────────
PROVIDER_SUPPORTED_PARAMS: dict[str, set[str]] = {
    "openai":            {"temperature", "top_p", "frequency_penalty", "presence_penalty", "max_tokens"},
    "anthropic":         {"temperature", "top_p", "max_tokens"},
    "gemini":            {"temperature", "top_p", "max_tokens"},
    "groq":              {"temperature", "top_p", "frequency_penalty", "presence_penalty", "max_tokens"},
    "together":          {"temperature", "top_p", "frequency_penalty", "presence_penalty", "max_tokens"},
    "deepseek":          {"temperature", "top_p", "frequency_penalty", "presence_penalty", "max_tokens"},
    "mistral":           {"temperature", "top_p", "max_tokens"},
    "ollama":            {"temperature", "top_p", "frequency_penalty", "presence_penalty",
                          "top_k", "min_p", "repeat_penalty", "max_tokens",
                          "num_ctx", "num_predict"},
    "openai_compatible": {"temperature", "top_p", "frequency_penalty", "presence_penalty", "max_tokens"},
    "custom":            {"temperature", "top_p", "frequency_penalty", "presence_penalty", "max_tokens"},
}

OPENAI_SDK_PARAMS = {"temperature", "top_p", "frequency_penalty", "presence_penalty", "max_tokens"}
OLLAMA_OPTION_PARAMS = {"top_k", "min_p", "repeat_penalty", "num_ctx", "num_predict"}


def _filter_sampling_params(
    provider: str, params: dict
) -> tuple[dict, dict | None]:
    """
    Filter user-provided sampling params to only those the provider supports.

    Returns (sdk_kwargs, extra_body_or_none):
    - sdk_kwargs: params safe to pass as named args to create()
    - extra_body_or_none: for Ollama, params passed via {"options": {...}}
    """
    if not params:
        return {}, None

    allowed = PROVIDER_SUPPORTED_PARAMS.get(provider, {"temperature", "top_p"})
    filtered = {k: v for k, v in params.items() if k in allowed and v is not None}

    sdk_kwargs = {k: v for k, v in filtered.items() if k in OPENAI_SDK_PARAMS}
    native = {k: v for k, v in filtered.items() if k in OLLAMA_OPTION_PARAMS}

    extra_body = None
    if native and provider == "ollama":
        extra_body = {"options": native}

    return sdk_kwargs, extra_body

def _resolve_timeout(provider: str, timeout_override: float | None = None) -> float:
    """Resolve timeout: use UI override if set, otherwise provider-appropriate default."""
    if timeout_override is not None and timeout_override > 0:
        return float(timeout_override)
    if provider in ("ollama", "openai_compatible", "custom"):
        return DEFAULT_TIMEOUT_LOCAL
    return DEFAULT_TIMEOUT_CLOUD


def get_client(
    provider_override: str | None = None,
    base_url_override: str | None = None,
    api_key_override: str | None = None,
    timeout_override: float | None = None,
):
    """
    Return an OpenAI-compatible chat client for the configured provider.
    The client must support: client.chat.completions.create(model=..., messages=..., temperature=...).
    api_key_override: optional per-user OpenAI key (e.g. from profile); used for openai/openai_compatible.
    timeout_override: optional per-request timeout in seconds (from UI settings).
    """
    _provider, base_url, api_key = _resolve_provider(provider_override, base_url_override, api_key_override)
    timeout = _resolve_timeout(_provider, timeout_override)
    return _llm_client(base_url=base_url, api_key=api_key, timeout=timeout)


def get_model(
    provider_override: str | None = None,
    model_override: str | None = None,
    base_url_override: str | None = None,
) -> str:
    """Return model name from UI override or provider defaults."""
    if model_override:
        return model_override

    provider = (provider_override or DEFAULT_PROVIDER).lower()
    if provider == "ollama":
        models = list_ollama_models(base_url_override=base_url_override)
        if models:
            return models[0]
        raise ValueError("No Ollama models available. Select a model in UI or start Ollama with a model.")

    if provider in DEFAULT_MODELS:
        return DEFAULT_MODELS[provider]
    if provider in ("openai_compatible", "custom"):
        raise ValueError("Model is required for openai_compatible/custom providers.")
    raise ValueError(
        f"Unknown LLM_PROVIDER={provider}. "
        f"Use one of: {', '.join(sorted(ALLOWED_PROVIDERS))}."
    )


def chat_completion(
    messages: List[Dict[str, str]],
    temperature: float = 0.3,
    provider_override: str | None = None,
    model_override: str | None = None,
    base_url_override: str | None = None,
    api_key_override: str | None = None,
    timeout_override: float | None = None,
    sampling_params: dict | None = None,
) -> str:
    """
    Single entry point for chat completion across all providers.
    Returns the assistant message content.
    api_key_override: optional per-user OpenAI key (from profile).
    timeout_override: optional per-request timeout in seconds (from UI settings).
    sampling_params: optional dict of sampling overrides (temperature, top_p, etc.).
        When sampling_params includes 'temperature', it overrides the function's
        temperature argument. Provider-unsupported params are silently dropped.
    """
    provider, base_url, api_key = _resolve_provider(
        provider_override, base_url_override, api_key_override
    )
    timeout = _resolve_timeout(provider, timeout_override)
    client = _llm_client(base_url=base_url, api_key=api_key, timeout=timeout)
    model = get_model(
        provider_override=provider,
        model_override=model_override,
        base_url_override=base_url,
    )
    estimated_prompt_tokens = _estimate_prompt_tokens(messages)
    log.info(
        "LLM completion request: provider=%s model=%s estimated_prompt_tokens=%d messages=%d",
        provider,
        model,
        estimated_prompt_tokens,
        len(messages),
    )

    create_kwargs: dict = {"model": model, "messages": messages}

    if sampling_params:
        sdk_kwargs, extra_body = _filter_sampling_params(provider, sampling_params)
        create_kwargs["temperature"] = sdk_kwargs.pop("temperature", temperature)
        create_kwargs.update(sdk_kwargs)
        if extra_body:
            create_kwargs["extra_body"] = extra_body
    else:
        create_kwargs["temperature"] = temperature

    response = client.chat.completions.create(**create_kwargs)
    usage = getattr(response, "usage", None)
    prompt_tokens = getattr(usage, "prompt_tokens", None) if usage is not None else None
    if prompt_tokens is not None:
        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
        # Safe: Only logging metadata (provider name, model name, token count), not API keys or secrets
        log.info(
            "LLM completion response: provider=%s model=%s prompt_tokens=%s",
            provider,
            model,
            prompt_tokens,
        )
    return (response.choices[0].message.content or "").strip()


def is_llm_available(
    provider_override: str | None = None,
    api_key_override: str | None = None,
) -> bool:
    """True if the configured provider can be used (Ollama/openai_compatible need no key; keyed providers need an API key)."""
    provider = (provider_override or DEFAULT_PROVIDER).lower()
    if provider in ("ollama", "openai_compatible", "custom"):
        return True  # local servers / catch-all typically don't require a key
    # All named presets (including openai) require an API key
    return bool(api_key_override and api_key_override.strip())


def vision_completion(
    prompt: str,
    image_base64: str,
    image_mime_type: str = "image/png",
    temperature: float = 0.1,
    provider_override: str | None = None,
    model_override: str | None = None,
    base_url_override: str | None = None,
    api_key_override: str | None = None,
    timeout_override: float | None = None,
    sampling_params: dict | None = None,
) -> str:
    """
    Vision completion: analyze an image with a text prompt.
    Returns the assistant message content.
    Supports OpenAI vision models (gpt-4o, gpt-4o-mini, gpt-4-vision-preview)
    and Ollama vision models (llava, llava-phi3, bakllava, etc.).
    Low temperature (0.1) for accurate text extraction.
    """
    provider, base_url, api_key = _resolve_provider(
        provider_override, base_url_override, api_key_override
    )

    log.info(
        "Vision completion: provider=%s, model_override=%s, base_url=%s",
        provider,
        model_override,
        base_url,
    )

    if provider == "ollama":
        model = model_override or "llava"
    else:
        model = model_override or "gpt-4o-mini"

    log.info("Using %s: base_url=%s, model=%s", provider, base_url, model)

    timeout = _resolve_timeout(provider, timeout_override)
    client = _llm_client(base_url=base_url, api_key=api_key, timeout=timeout)

    # Build message with image content and strict system prompt
    messages = [
        {
            "role": "system",
            "content": (
                "You are a security evidence analyst reviewing screenshots for pentest reports. "
                "If the image contains readable text, extract it verbatim — preserving URLs, headers, payloads, error messages, and code exactly as shown. "
                "If the image contains little or no readable text, describe only what is literally visible in 1–2 concise sentences — "
                "do not invent security context, URLs, or details that are not clearly present in the image. "
                "Use [unclear] only for specific characters or words you genuinely cannot read — never as the entire response."
            )
        },
        {
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:{image_mime_type};base64,{image_base64}"
                    }
                }
            ]
        }
    ]
    estimated_prompt_tokens = _estimate_prompt_tokens(messages)
    log.info(
        "LLM vision completion request: provider=%s model=%s estimated_prompt_tokens=%d messages=%d",
        provider,
        model,
        estimated_prompt_tokens,
        len(messages),
    )

    # Log image size for debugging
    image_size_kb = len(image_base64) / 1024
    log.info("Image size: %.1f KB (base64)", image_size_kb)

    if image_size_kb > 5000:  # Warn if > 5MB
        log.warning("Large image detected (%.1f KB). This may cause timeouts.", image_size_kb)

    try:
        log.info("Calling vision API...")
        create_kwargs: dict = {"model": model, "messages": messages}
        if sampling_params:
            sdk_kwargs, extra_body = _filter_sampling_params(provider, sampling_params)
            create_kwargs["temperature"] = sdk_kwargs.pop("temperature", temperature)
            create_kwargs.update(sdk_kwargs)
            if extra_body:
                create_kwargs["extra_body"] = extra_body
        else:
            create_kwargs["temperature"] = temperature
        response = client.chat.completions.create(**create_kwargs)
        usage = getattr(response, "usage", None)
        prompt_tokens = getattr(usage, "prompt_tokens", None) if usage is not None else None
        if prompt_tokens is not None:
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            # Safe: Only logging metadata (provider name, model name, token count), not API keys or secrets
            log.info(
                "LLM vision completion response: provider=%s model=%s prompt_tokens=%s",
                provider,
                model,
                prompt_tokens,
            )
        result = (response.choices[0].message.content or "").strip()
        log.info("Vision API returned %d characters", len(result))
        return result
    except Exception as e:
        log.error("Vision API error: %s", str(e), exc_info=True)
        raise


def list_ollama_models(base_url_override: str | None = None) -> list[str]:
    import json
    ensure_safe_base_url(base_url_override)
    base_url = (base_url_override or DEFAULT_OLLAMA_BASE_URL).rstrip("/")
    url = f"{base_url}/api/tags"
    try:
        resp = httpx.get(url, timeout=3.0)
        resp.raise_for_status()
        data = resp.json()
        models = data.get("models") or []
        return sorted({m.get("name") for m in models if m.get("name")})
    except (httpx.HTTPError, httpx.RequestError, json.JSONDecodeError) as e:
        log.debug("Could not fetch Ollama models from %s: %s", url, e)
        return []
    except Exception as e:
        log.debug("Could not fetch Ollama models from %s: %s", url, e)
        return []
