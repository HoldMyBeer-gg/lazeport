from __future__ import annotations

import logging

from fastapi import APIRouter, Query, Depends

from app.db import get_adapter
from app.db.adapter import StorageAdapter
from app.db.models import User
from app.services.llm import list_ollama_models, PROVIDER_PRESETS
from app.services.auth import get_current_user


log = logging.getLogger(__name__)
router = APIRouter()

# Vision model name substrings (Ollama)
_VISION_SUBSTRINGS = ("llava", "bakllava", "vision")

# Well-known model lists for providers whose /models endpoint may not be public
_WELL_KNOWN_MODELS: dict[str, list[str]] = {
    "openai": ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-4.1-mini", "gpt-4.1", "o3-mini"],
    "anthropic": ["claude-sonnet-4-20250514", "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-opus-20240229"],
    "gemini": ["gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-pro", "gemini-1.5-flash"],
    "groq": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768", "gemma2-9b-it"],
    "together": ["meta-llama/Llama-3.3-70B-Instruct-Turbo", "meta-llama/Llama-3.1-8B-Instruct-Turbo", "mistralai/Mixtral-8x7B-Instruct-v0.1"],
    "deepseek": ["deepseek-chat", "deepseek-reasoner"],
    "mistral": ["mistral-large-latest", "mistral-small-latest", "open-mistral-nemo"],
}

_WELL_KNOWN_VISION: dict[str, list[str]] = {
    "openai": ["gpt-4o", "gpt-4o-mini"],
    "anthropic": ["claude-sonnet-4-20250514", "claude-3-5-sonnet-20241022", "claude-3-opus-20240229"],
    "gemini": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
    "groq": ["llama-3.2-90b-vision-preview", "llama-3.2-11b-vision-preview"],
    "together": [],
    "deepseek": [],
    "mistral": ["mistral-large-latest"],
}


def _try_list_models_via_api(provider: str, base_url: str | None, api_key: str | None = None) -> list[str] | None:
    """Attempt to list models from a provider's /models endpoint. Returns None on failure."""
    import httpx

    preset = PROVIDER_PRESETS.get(provider)
    if not preset:
        return None

    url = (base_url or preset["base_url"]).rstrip("/") + "/models"
    api_key = (api_key or "").strip()

    try:
        resp = httpx.get(
            url,
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            timeout=5.0,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        # OpenAI-style response: { "data": [ { "id": "model-name" }, ... ] }
        models_data = data.get("data") or data.get("models") or []
        if isinstance(models_data, list):
            ids = []
            for m in models_data:
                if isinstance(m, dict):
                    ids.append(m.get("id") or m.get("name", ""))
                elif isinstance(m, str):
                    ids.append(m)
            return sorted([i for i in ids if i])
    except Exception as e:
        log.debug("Failed to list models from %s: %s", url, e)
    return None


@router.get("/providers")
def list_providers(
    user: User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Return which LLM providers are available."""
    if getattr(adapter, "get_user_provider_api_key", None):
        user_openai_key = adapter.get_user_provider_api_key(user.id, "openai")
    else:
        user_openai_key = (
            adapter.get_user_openai_api_key(user.id) if getattr(adapter, "get_user_openai_api_key", None) else None
        )
    openai_available = bool(user_openai_key)
    return {
        "openai": openai_available,
        "ollama": True,
        "openai_compatible": True,
    }


@router.get("/providers/models")
def provider_models(
    provider: str = Query("ollama"),
    base_url: str | None = None,
    user: User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List available models for a provider. Requires authentication."""
    provider = (provider or "").lower()

    if provider == "ollama":
        return {"provider": "ollama", "models": list_ollama_models(base_url_override=base_url)}

    # For named presets, try the API first then fall back to well-known list
    if provider in PROVIDER_PRESETS or provider in ("openai", "openai_compatible"):
        if getattr(adapter, "get_user_provider_api_key", None):
            effective_key = adapter.get_user_provider_api_key(user.id, provider)
        else:
            # Legacy single-key fallback is OpenAI-only.
            effective_key = (
                adapter.get_user_openai_api_key(user.id)
                if provider == "openai" and getattr(adapter, "get_user_openai_api_key", None)
                else None
            )
        api_models = _try_list_models_via_api(provider, base_url, api_key=effective_key)
        if api_models:
            return {"provider": provider, "models": api_models}
        # Fall back to well-known (openai_compatible uses same list as openai)
        fallback_key = "openai" if provider == "openai_compatible" else provider
        return {"provider": provider, "models": list(_WELL_KNOWN_MODELS.get(fallback_key, []))}

    return {"provider": provider, "models": []}


@router.get("/providers/vision-models")
def provider_vision_models(
    provider: str = Query(""),
    base_url: str | None = None,
    _user: User = Depends(get_current_user),
):
    """List vision-capable models for a provider. Requires authentication."""
    provider = (provider or "").lower()

    if not provider or provider in ("openai", "openai_compatible"):
        return {"provider": "openai", "models": _WELL_KNOWN_VISION.get("openai", ["gpt-4o", "gpt-4o-mini"])}

    if provider == "ollama":
        all_models = list_ollama_models(base_url_override=base_url)
        vision = [m for m in all_models if any(s in m.lower() for s in _VISION_SUBSTRINGS)]
        return {"provider": "ollama", "models": vision}

    # For other named presets, return well-known vision models
    return {"provider": provider, "models": list(_WELL_KNOWN_VISION.get(provider, []))}
