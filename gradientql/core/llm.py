"""LLM client for OpenRouter, with response caching and a circuit breaker."""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any

from langchain_openai import ChatOpenAI

_circuit_state: dict[str, Any] = {
    "is_open": False,
    "failure_count": 0,
    "last_failure": 0,
    "fallback_active": False,
}

_CIRCUIT_THRESHOLD = 3
_CIRCUIT_TIMEOUT = 60


def configure_circuit(settings: dict[str, Any]) -> None:
    """Set the circuit-breaker threshold/timeout from settings.llm.circuit_breaker."""
    global _CIRCUIT_THRESHOLD, _CIRCUIT_TIMEOUT
    cfg = settings.get("llm", {}).get("circuit_breaker", {}) or {}
    _CIRCUIT_THRESHOLD = int(cfg.get("threshold", 3))
    _CIRCUIT_TIMEOUT = int(cfg.get("cooldown", 60))


def reset_circuit() -> None:
    global _circuit_state
    _circuit_state = {
        "is_open": False,
        "failure_count": 0,
        "last_failure": 0,
        "fallback_active": False,
    }


def _record_failure() -> None:
    global _circuit_state
    _circuit_state["failure_count"] += 1
    _circuit_state["last_failure"] = time.time()
    
    if _circuit_state["failure_count"] >= _CIRCUIT_THRESHOLD:
        _circuit_state["is_open"] = True
        _circuit_state["fallback_active"] = True
        print(f"[CIRCUIT BREAKER] OPENED after {_CIRCUIT_THRESHOLD} failures. Fallback mode active.")


def _record_success() -> None:
    global _circuit_state
    if not _circuit_state["is_open"]:
        _circuit_state["failure_count"] = max(0, _circuit_state["failure_count"] - 1)


def _should_attempt_reset() -> bool:
    """Report whether a call may proceed, half-opening the circuit on timeout.

    True when the circuit is closed, or when it is open but the cooldown has
    elapsed, in which case the circuit is reset to closed as a side effect.
    """
    if not _circuit_state["is_open"]:
        return True
    elapsed = time.time() - _circuit_state["last_failure"]
    if elapsed > _CIRCUIT_TIMEOUT:
        print(f"[CIRCUIT BREAKER] Attempting reset after {elapsed:.0f}s...")
        _circuit_state["is_open"] = False
        _circuit_state["failure_count"] = 0
        return True
    return False


_llm_cache: dict[str, ChatOpenAI] = {}

_response_memo_cache: dict[str, Any] = {}

_cache_settings: dict[str, Any] = {"memoize_responses": False}


def configure_cache(settings: dict[str, Any]) -> None:
    """Set module-level response-memo config from settings.llm.cache."""
    global _cache_settings
    cache_cfg = settings.get("llm", {}).get("cache", {}) or {}
    _cache_settings = {
        "memoize_responses": bool(cache_cfg.get("memoize_responses", False)),
    }


def _memoize_enabled() -> bool:
    return bool(_cache_settings.get("memoize_responses", False))


def _compute_memo_key(messages: Any, model: str) -> str:
    """Return a stable SHA-256 cache key for a prompt across message shapes.

    Normalizes str, dict, and message-object inputs to a canonical
    role/content form so equivalent prompts hash identically for a model.
    """
    serializable: list[dict[str, str]] = []
    if isinstance(messages, str):
        serializable.append({"role": "user", "content": messages})
    elif isinstance(messages, (list, tuple)):
        for m in messages:
            if isinstance(m, str):
                serializable.append({"role": "user", "content": m})
            elif isinstance(m, dict):
                serializable.append({
                    "role": str(m.get("role", "user")),
                    "content": str(m.get("content", "")),
                })
            elif hasattr(m, "content"):
                serializable.append({
                    "role": str(getattr(m, "type", "user")),
                    "content": str(m.content),
                })
    else:
        serializable.append({"role": "user", "content": str(messages)})

    blob = json.dumps(serializable, sort_keys=True, default=str) + f"::{model}"
    return hashlib.sha256(blob.encode("utf-8", errors="ignore")).hexdigest()


def clear_response_memo_cache() -> None:
    _response_memo_cache.clear()


def _get_base_llm(settings: dict[str, Any], model_key: str, default_model: str,
                  temperature: float, max_tokens: int) -> ChatOpenAI:
    llm_cfg = settings.get("llm", {})
    api_key = llm_cfg.get("api_key") or os.environ.get(
        llm_cfg.get("api_key_env", "OPENROUTER_API_KEY"), ""
    )

    model_name = llm_cfg.get(model_key, default_model)
    base_url = llm_cfg.get("base_url", "https://openrouter.ai/api/v1")

    provider_routing = llm_cfg.get("provider_routing")
    if not isinstance(provider_routing, dict):
        provider_routing = None

    routing_key = json.dumps(provider_routing, sort_keys=True) if provider_routing else ""
    cache_key = f"{model_name}:{temperature}:{max_tokens}:{base_url}:pr={routing_key}"
    if cache_key in _llm_cache:
        return _llm_cache[cache_key]

    extra_body: dict[str, Any] = {}
    if provider_routing:
        extra_body["provider"] = provider_routing
    extra_kwargs: dict[str, Any] = {"extra_body": extra_body} if extra_body else {}

    llm = ChatOpenAI(
        model=model_name,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=llm_cfg.get("timeout", 120),
        max_retries=llm_cfg.get("max_retries", 2),
        **extra_kwargs,
    )
    response_format = llm_cfg.get("response_format", {"type": "json_object"})
    if response_format:
        if not isinstance(response_format, dict):
            response_format = {"type": "json_object"}
        llm = llm.bind(response_format=response_format)
    _llm_cache[cache_key] = llm
    return llm


def clear_llm_cache() -> None:
    _llm_cache.clear()


def get_attacker_llm(settings: dict[str, Any]) -> ChatOpenAI:
    llm_cfg = settings.get("llm", {})
    max_tokens = int(llm_cfg.get("attacker_max_tokens", 16384))
    temperature = float(llm_cfg.get("temperature", 0.7))
    return _get_base_llm(
        settings,
        model_key="attacker_model",
        default_model="anthropic/claude-opus-4.7",
        temperature=temperature,
        max_tokens=max_tokens,
    )


def verify_key(settings: dict[str, Any]) -> tuple[bool, str]:
    """Confirm the configured API key authenticates, via a minimal probe call.

    Returns (ok, message). ok is False only when no key is set or the provider
    clearly rejects the key; any other probe failure (rate-limit, network, model
    quirk) returns ok so a valid key is never blocked over a probe hiccup.
    """
    llm_cfg = settings.get("llm", {})
    key = (llm_cfg.get("api_key") or os.environ.get(
        llm_cfg.get("api_key_env", "OPENROUTER_API_KEY"), "")).strip()
    if not key:
        return False, "No API key set. Put it in config/api_key.local or the OPENROUTER_API_KEY env var."
    try:
        probe = ChatOpenAI(
            model=llm_cfg.get("attacker_model", "anthropic/claude-opus-4.7"),
            api_key=key,
            base_url=llm_cfg.get("base_url", "https://openrouter.ai/api/v1"),
            temperature=0,
            max_tokens=16,
            timeout=min(int(llm_cfg.get("timeout", 120)), 20),
            max_retries=0,
        )
        probe.invoke("ping")
        return True, "ok"
    except Exception as e:  # noqa: BLE001
        low = str(e).lower()
        auth_markers = ("401", "unauthor", "invalid api key", "invalid_api_key", "no auth credentials",
                        "authentication", "user not found", "invalid token", "incorrect api key")
        if any(m in low for m in auth_markers):
            return False, "API key rejected by the provider. Check the key is valid and funded."
        return True, "ok"


def invoke_with_circuit_breaker(llm: Any, messages: list, **kwargs) -> Any:
    """Invoke the LLM through the circuit breaker and response memo cache.

    Re-raises on rate-limit errors so the caller can back off, and updates
    circuit state on each success or failure.

    Returns:
        The LLM result, or None if the circuit is open or the call failed.
    """
    if _circuit_state["is_open"]:
        if not _should_attempt_reset():
            print(f"[CIRCUIT BREAKER] Circuit OPEN - skipping LLM call ({_circuit_state['failure_count']} failures)")
            return None

    memo_key = None
    if _memoize_enabled():
        model_name = getattr(llm, "model_name", None) or getattr(llm, "model", "unknown")
        memo_key = _compute_memo_key(messages, str(model_name))
        if memo_key in _response_memo_cache:
            return _response_memo_cache[memo_key]

    try:
        result = llm.invoke(messages, **kwargs)
        _record_success()
        if memo_key is not None and result is not None:
            _response_memo_cache[memo_key] = result
        return result

    except Exception as e:
        error_str = str(e).lower()
        if "rate limit" in error_str or "429" in error_str:
            raise
        is_timeout = "timeout" in error_str or "timeout" in type(e).__name__.lower()
        _record_failure()
        if is_timeout:
            print(f"[CIRCUIT BREAKER] LLM call timed out (native timeout): {e}")
        else:
            print(f"[CIRCUIT BREAKER] LLM call failed: {e}")
        return None


def get_circuit_breaker_status() -> dict[str, Any]:
    now = time.time()
    return {
        "is_open": _circuit_state["is_open"],
        "failure_count": _circuit_state["failure_count"],
        "fallback_active": _circuit_state["fallback_active"],
        "last_failure_age_seconds": now - _circuit_state["last_failure"] if _circuit_state["last_failure"] else None,
        "threshold": _CIRCUIT_THRESHOLD,
        "timeout": _CIRCUIT_TIMEOUT,
    }
