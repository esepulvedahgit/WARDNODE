"""Selección del proveedor LLM activo según AppConfig, con fallback.

Si el proveedor configurado no tiene API key, se recorre el orden fijo
openrouter → anthropic → openai → deepseek → gemini y se usa el primero con
key. Sin keys, retorna None y el SOC funciona solo con heurísticas (sin IA).
"""

from app.encryption import EncryptionNotConfigured
from app.models import AppConfig
from app.soc.llm.base import LLMProvider
from app.soc.llm.providers import (
    AnthropicProvider,
    DeepSeekProvider,
    GeminiProvider,
    OpenAIProvider,
    OpenRouterProvider,
)

DEFAULT_MODELS = {
    "openrouter": "anthropic/claude-sonnet-4.5",
    "anthropic": "claude-sonnet-4-5",
    "openai": "gpt-4o-mini",
    "deepseek": "deepseek-chat",
    "gemini": "gemini-2.0-flash",
}

_PROVIDER_KEYS = {
    "openrouter": "soc_openrouter_api_key",
    "anthropic": "soc_anthropic_api_key",
    "openai": "soc_openai_api_key",
    "deepseek": "soc_deepseek_api_key",
    "gemini": "soc_gemini_api_key",
}

_PROVIDER_CLASSES = {
    "openrouter": OpenRouterProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "deepseek": DeepSeekProvider,
    "gemini": GeminiProvider,
}

_FALLBACK_ORDER = ["openrouter", "anthropic", "openai", "deepseek", "gemini"]


def _key_for(provider: str) -> str | None:
    try:
        return AppConfig.get_secret(_PROVIDER_KEYS[provider])
    except EncryptionNotConfigured:
        return None


def get_provider() -> LLMProvider | None:
    active = AppConfig.get("soc_llm_provider") or "openrouter"
    if active not in _PROVIDER_CLASSES:
        active = "openrouter"

    candidates = [active] + [p for p in _FALLBACK_ORDER if p != active]
    for name in candidates:
        api_key = _key_for(name)
        if api_key:
            model = ""
            if name == active:
                model = AppConfig.get("soc_llm_model") or ""
            model = model or DEFAULT_MODELS[name]
            return _PROVIDER_CLASSES[name](api_key=api_key, model=model)
    return None
