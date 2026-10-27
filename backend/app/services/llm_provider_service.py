import os
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List

from app.core.config import settings


def _enabled_tools() -> List[str]:
    return [t.strip() for t in settings.ENABLED_TOOLS.split(",") if t.strip()]


def get_llm_settings() -> Dict[str, Any]:
    """
    Read-only view of the LLM provider configuration sourced entirely from
    environment variables (Railway/Render/etc.). The OpenRouter API key is
    never persisted to a database or surfaced through any HTTP endpoint.
    """
    return {
        "openrouter_api_key": settings.OPENROUTER_API_KEY,
        "primary_model": settings.PRIMARY_MODEL,
        "fallback_model": settings.FALLBACK_MODEL,
        "remediation_model": settings.REMEDIATION_MODEL,
        "use_local_fine_tuned": settings.USE_LOCAL_FINE_TUNED,
        "local_model_endpoint": settings.LOCAL_MODEL_ENDPOINT,
        "enabled_tools": _enabled_tools(),
    }


class LLMProviderService:

    @staticmethod
    def get_remediation_api_key() -> str:
        return settings.REMEDIATION_OPENROUTER_API_KEY

    @staticmethod
    def get_settings() -> Dict[str, Any]:
        return get_llm_settings()

    @classmethod
    def validate_openrouter(cls) -> Dict[str, Any]:
        """Validate the configured OpenRouter credential without generating text."""
        api_key = get_llm_settings().get("openrouter_api_key")
        if not api_key:
            return {"configured": False, "reachable": False, "detail": "OPENROUTER_API_KEY is not set."}
        request = urllib.request.Request(
            "https://openrouter.ai/api/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return {
                    "configured": True,
                    "reachable": response.status == 200,
                    "model": get_llm_settings()["primary_model"],
                }
        except urllib.error.HTTPError as error:
            return {"configured": True, "reachable": False, "detail": f"OpenRouter returned HTTP {error.code}."}
        except Exception as error:
            return {"configured": True, "reachable": False, "detail": str(error)}

    @classmethod
    def call_llm(cls, prompt: str, system_prompt: Optional[str] = None, json_mode: bool = True, api_key_override: Optional[str] = None, allow_fallback: bool = True, model_override: Optional[str] = None) -> str:
        cfg = get_llm_settings()

        # 1. Local fine-tuned model endpoint option
        if cfg.get("use_local_fine_tuned") and cfg.get("local_model_endpoint"):
            try:
                return cls._call_openai_compatible(
                    endpoint=cfg["local_model_endpoint"],
                    api_key="local",
                    model="local-fine-tuned",
                    prompt=prompt,
                    system_prompt=system_prompt,
                    json_mode=json_mode
                )
            except Exception as e:
                print(f"[LLMProviderService] Local model failed: {e}. Falling back to OpenRouter Primary...")

        # 2. OpenRouter Primary Model
        api_key = api_key_override or cfg.get("openrouter_api_key") or os.getenv("OPENROUTER_API_KEY", "")
        primary_model = model_override or cfg.get("primary_model", "qwen/qwen-2.5-coder-32b-instruct")

        if not api_key:
            raise RuntimeError("No OpenRouter API key configured. Set OPENROUTER_API_KEY environment variable.")

        try:
            return cls._call_openrouter(
                api_key=api_key,
                model=primary_model,
                prompt=prompt,
                system_prompt=system_prompt,
                json_mode=json_mode
            )
        except Exception as e:
            if not allow_fallback:
                raise RuntimeError(f"Primary OpenRouter model ({primary_model}) failed: {e}") from e
            print(f"[LLMProviderService] Primary OpenRouter model ({primary_model}) failed: {e}. Trying fallback...")

            # 3. Fallback Model (DeepSeek R1)
            fallback_model = cfg.get("fallback_model", "deepseek/deepseek-r1")
            try:
                return cls._call_openrouter(
                    api_key=api_key,
                    model=fallback_model,
                    prompt=prompt,
                    system_prompt=system_prompt,
                    json_mode=json_mode
                )
            except Exception as fallback_err:
                raise RuntimeError(f"All LLM providers failed. Primary: {e}, Fallback: {fallback_err}")

    @classmethod
    def _call_openrouter(cls, api_key: str, model: str, prompt: str, system_prompt: Optional[str], json_mode: bool) -> str:
        url = "https://openrouter.ai/api/v1/chat/completions"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 12000,
        }

        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://sentinelai.local",
            "X-Title": "SentinelAI Scanner"
        }

        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        # Hosted remediation models can take several minutes to produce a
        # complete patch; the caller controls the overall request deadline.
        with urllib.request.urlopen(req, timeout=600) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices") if isinstance(data, dict) else None
            if not isinstance(choices, list) or not choices:
                raise RuntimeError(f"OpenRouter response contained no choices: {str(data)[:500]}")
            message = choices[0].get("message") or {}
            content = message.get("content")
            if not isinstance(content, str) or not content.strip():
                raise RuntimeError("OpenRouter returned an empty message content; no remediation JSON was produced")
            return content

    @classmethod
    def _call_openai_compatible(cls, endpoint: str, api_key: str, model: str, prompt: str, system_prompt: Optional[str], json_mode: bool) -> str:
        url = f"{endpoint.rstrip('/')}/chat/completions"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.2
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=150) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
