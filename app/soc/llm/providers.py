"""Adaptadores LLM vía httpx puro (sin SDKs).

Los cinco proveedores comparten timeout, max_tokens y temperature. El contrato
JSON de salida se impone por prompt; schema.normalize_llm_output absorbe
cualquier desviación. Los mensajes de error jamás incluyen la API key.
"""

import json as _json
import re

import httpx

from app.soc.llm.base import LLMError, LLMProvider

_TIMEOUT = httpx.Timeout(60.0, connect=10.0)
_MAX_TOKENS = 4096   # incrementado de 2048: respuestas JSON completas evitan truncación
_TEMPERATURE = 0.2

# Límite de tamaño de respuesta (M-1): un proveedor/MITM no puede devolver GB y
# agotar la RAM del worker. 2 MB es más que suficiente para 2048 tokens de salida.
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _post_json(url: str, headers: dict, body: dict, provider_name: str) -> dict:
    try:
        with httpx.stream("POST", url, headers=headers, json=body, timeout=_TIMEOUT) as resp:
            resp.raise_for_status()
            total, chunks = 0, []
            for chunk in resp.iter_bytes():
                total += len(chunk)
                if total > _MAX_RESPONSE_BYTES:
                    raise LLMError(
                        f"{provider_name}: respuesta excede tamaño máximo"
                    )
                chunks.append(chunk)
        return _json.loads(b"".join(chunks))
    except LLMError:
        raise
    except httpx.TimeoutException as exc:
        raise LLMError(f"{provider_name}: timeout ({type(exc).__name__})") from exc
    except httpx.HTTPStatusError as exc:
        raise LLMError(
            f"{provider_name}: HTTP {exc.response.status_code}"
        ) from exc
    except httpx.HTTPError as exc:
        raise LLMError(f"{provider_name}: error de red ({type(exc).__name__})") from exc
    except (_json.JSONDecodeError, ValueError) as exc:
        raise LLMError(f"{provider_name}: respuesta no-JSON") from exc


class OpenRouterProvider(LLMProvider):
    name = "openrouter"
    _URL = "https://openrouter.ai/api/v1/chat/completions"

    def chat(self, system: str, user: str, *, json_mode: bool = True) -> tuple[str, int, int]:  # noqa: ARG002
        data = _post_json(
            self._URL,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "X-Title": "WardNode SOC",
            },
            body={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "max_tokens": _MAX_TOKENS,
                "temperature": _TEMPERATURE,
            },
            provider_name=self.name,
        )
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"{self.name}: estructura de respuesta inesperada") from exc
        usage = data.get("usage") or {}
        return text, usage.get("prompt_tokens") or 0, usage.get("completion_tokens") or 0


class OpenAIProvider(LLMProvider):
    name = "openai"
    _URL = "https://api.openai.com/v1/chat/completions"

    def chat(self, system: str, user: str, *, json_mode: bool = True) -> tuple[str, int, int]:
        body: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": _MAX_TOKENS,
            "temperature": _TEMPERATURE,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        data = _post_json(
            self._URL,
            headers={"Authorization": f"Bearer {self.api_key}"},
            body=body,
            provider_name=self.name,
        )
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"{self.name}: estructura de respuesta inesperada") from exc
        usage = data.get("usage") or {}
        return text, usage.get("prompt_tokens") or 0, usage.get("completion_tokens") or 0


class AnthropicProvider(LLMProvider):
    name = "anthropic"
    _URL = "https://api.anthropic.com/v1/messages"

    def chat(self, system: str, user: str, *, json_mode: bool = True) -> tuple[str, int, int]:  # noqa: ARG002
        data = _post_json(
            self._URL,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            body={
                "model": self.model,
                "system": system,
                "messages": [{"role": "user", "content": user}],
                "max_tokens": _MAX_TOKENS,
                "temperature": _TEMPERATURE,
            },
            provider_name=self.name,
        )
        try:
            text = data["content"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"{self.name}: estructura de respuesta inesperada") from exc
        usage = data.get("usage") or {}
        return text, usage.get("input_tokens") or 0, usage.get("output_tokens") or 0


class DeepSeekProvider(OpenAIProvider):
    """DeepSeek expone una API OpenAI-compatible (incl. response_format json_object).

    Hereda íntegro OpenAIProvider.chat: mismo body, mismo parsing choices[0],
    mismo _post_json con cap de 2 MB y errores sin key.
    """

    name = "deepseek"
    _URL = "https://api.deepseek.com/v1/chat/completions"


# SEGURIDAD: el nombre del modelo va en el PATH de la URL de Gemini
# → validar con esta regex antes de construir la URL para evitar path traversal
# y SSRF (ej. "../evil", "m?key=x", "m:batchGenerate"). NO relajar sin revisar
# GeminiProvider.chat y el campo de modelo en config.html.
_GEMINI_MODEL_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,119}$")


class GeminiProvider(LLMProvider):
    """Google Gemini vía API nativa generateContent.

    Auth: header x-goog-api-key (nunca en query string para evitar filtración
    en logs/URLs). La respuesta usa el contrato nativo de Gemini
    (candidates[0].content.parts[0].text + usageMetadata), distinto al
    contrato OpenAI-compat. Reutiliza _post_json → cap 2 MB + errores sin key.
    """

    name = "gemini"
    _BASE = "https://generativelanguage.googleapis.com/v1beta/models"

    def chat(self, system: str, user: str, *, json_mode: bool = True) -> tuple[str, int, int]:
        # Validar modelo antes de insertarlo en el path de la URL.
        if not _GEMINI_MODEL_RE.match(self.model or ""):
            raise LLMError(f"{self.name}: nombre de modelo inválido")
        url = f"{self._BASE}/{self.model}:generateContent"
        gen_config: dict = {
            "temperature": _TEMPERATURE,
            "maxOutputTokens": _MAX_TOKENS,
        }
        if json_mode:
            # Fuerza JSON puro para analyze_incident; omitir en prosa libre
            # (ej. generate_llm_summary) para no envolver la narrativa en un
            # objeto {"summary": "..."} que el caller no espera.
            gen_config["responseMimeType"] = "application/json"
        data = _post_json(
            url,
            # Key en header, nunca en query string (evita filtración en logs).
            headers={"x-goog-api-key": self.api_key},
            body={
                "system_instruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": gen_config,
            },
            provider_name=self.name,
        )
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"{self.name}: estructura de respuesta inesperada") from exc
        usage = data.get("usageMetadata") or {}
        return (
            text,
            usage.get("promptTokenCount") or 0,
            usage.get("candidatesTokenCount") or 0,
        )
