"""Tests for LLM response memoization (F2) and native-timeout circuit breaker (F7)."""

import pytest

import gradientql.core.llm as llm


class FakeResp:
    def __init__(self, content):
        self.content = content


class FakeLLM:
    """Minimal stand-in for ChatOpenAI: counts invokes, optionally raises."""

    def __init__(self, content="ok", raises=None):
        self.model_name = "test/model"
        self.calls = 0
        self._content = content
        self._raises = raises

    def invoke(self, messages, **kwargs):
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return FakeResp(self._content)


@pytest.fixture(autouse=True)
def _reset():
    llm.reset_circuit()
    llm.clear_response_memo_cache()
    llm.configure_cache({})  # default: memoization off
    llm.configure_circuit({})  # default: threshold 3 / cooldown 60
    yield
    llm.reset_circuit()
    llm.clear_response_memo_cache()
    llm.configure_cache({})
    llm.configure_circuit({})


def test_memoization_hit_when_enabled():
    llm.configure_cache({"llm": {"cache": {"memoize_responses": True}}})
    fake = FakeLLM(content="A")
    r1 = llm.invoke_with_circuit_breaker(fake, "same prompt")
    r2 = llm.invoke_with_circuit_breaker(fake, "same prompt")
    assert r1 is r2  # cached object returned
    assert fake.calls == 1  # second call served from memo


def test_memoization_off_by_default():
    fake = FakeLLM(content="A")
    llm.invoke_with_circuit_breaker(fake, "same prompt")
    llm.invoke_with_circuit_breaker(fake, "same prompt")
    assert fake.calls == 2  # no caching


def test_memoization_distinct_prompts():
    llm.configure_cache({"llm": {"cache": {"memoize_responses": True}}})
    fake = FakeLLM(content="A")
    llm.invoke_with_circuit_breaker(fake, "prompt one")
    llm.invoke_with_circuit_breaker(fake, "prompt two")
    assert fake.calls == 2


def test_clear_memo_forces_recall():
    llm.configure_cache({"llm": {"cache": {"memoize_responses": True}}})
    fake = FakeLLM(content="A")
    llm.invoke_with_circuit_breaker(fake, "p")
    llm.clear_response_memo_cache()
    llm.invoke_with_circuit_breaker(fake, "p")
    assert fake.calls == 2


def test_circuit_opens_after_timeouts():
    fake = FakeLLM(raises=Exception("Request timeout exceeded"))
    for _ in range(3):
        assert llm.invoke_with_circuit_breaker(fake, "p") is None
    status = llm.get_circuit_breaker_status()
    assert status["is_open"] is True
    # Once open, further calls are skipped without invoking the LLM.
    before = fake.calls
    assert llm.invoke_with_circuit_breaker(fake, "p") is None
    assert fake.calls == before


def test_configure_circuit_override_lowers_threshold():
    assert llm._CIRCUIT_THRESHOLD == 3  # default before override
    llm.configure_circuit({"llm": {"circuit_breaker": {"threshold": 2, "cooldown": 5}}})
    assert llm._CIRCUIT_THRESHOLD == 2
    assert llm._CIRCUIT_TIMEOUT == 5
    fake = FakeLLM(raises=Exception("Request timeout exceeded"))
    for _ in range(2):
        assert llm.invoke_with_circuit_breaker(fake, "p") is None
    # Breaker opens at the overridden threshold of 2, not the default 3.
    assert llm.get_circuit_breaker_status()["is_open"] is True


def test_rate_limit_is_reraised_not_counted():
    fake = FakeLLM(raises=Exception("HTTP 429 rate limit"))
    with pytest.raises(Exception):
        llm.invoke_with_circuit_breaker(fake, "p")
    # Rate limits must NOT count toward opening the circuit.
    assert llm.get_circuit_breaker_status()["failure_count"] == 0


def test_success_returns_result_directly():
    fake = FakeLLM(content="hello")
    result = llm.invoke_with_circuit_breaker(fake, "p")
    assert isinstance(result, FakeResp)
    assert result.content == "hello"
    assert fake.calls == 1


# --- response_format config gate (F1) ---

def _base_settings():
    return {"llm": {"api_key": "test", "attacker_model": "test/model"}}


def test_response_format_bound_by_default():
    llm.clear_llm_cache()
    built = llm.get_attacker_llm(_base_settings())
    # Default on: a RunnableBinding carrying response_format kwargs.
    assert built.kwargs.get("response_format") == {"type": "json_object"}


def test_response_format_disabled_when_falsy():
    llm.clear_llm_cache()
    settings = _base_settings()
    settings["llm"]["response_format"] = None
    built = llm.get_attacker_llm(settings)
    # Disabled: plain ChatOpenAI with no bound response_format.
    assert "response_format" not in getattr(built, "kwargs", {})


def test_response_format_custom_dict_bound():
    llm.clear_llm_cache()
    settings = _base_settings()
    settings["llm"]["response_format"] = {"type": "json_schema", "json_schema": {}}
    built = llm.get_attacker_llm(settings)
    assert built.kwargs.get("response_format") == {"type": "json_schema", "json_schema": {}}
