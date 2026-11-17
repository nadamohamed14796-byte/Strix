"""Tests for model-aware token budgets."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import SimpleNamespace

from strix.config import ContextSettings, load_settings
from strix.llm import context_budget


if TYPE_CHECKING:
    import pytest


def test_context_window_known_model() -> None:
    # gpt-4o is mapped by LiteLLM at 128k input tokens.
    assert context_budget.context_window("gpt-4o") == 128_000


def test_context_window_strips_provider_prefix() -> None:
    assert context_budget.context_window("openai/gpt-4o") == 128_000


def test_context_window_chatgpt_prefix_skips_provider_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        context_budget,
        "load_settings",
        lambda: SimpleNamespace(
            context=ContextSettings(), llm=SimpleNamespace(api_base=None)
        ),
    )
    context_budget._model_info.cache_clear()
    calls: list[str] = []

    def _model_info(model: str) -> dict[str, int]:
        calls.append(model)
        return {"max_input_tokens": 1_050_000, "max_output_tokens": 128_000}

    monkeypatch.setattr("strix.llm.context_budget.litellm.get_model_info", _model_info)
    try:
        assert context_budget.context_window("chatgpt/gpt-5.6-luna") == 1_050_000
        assert calls == ["gpt-5.6-luna"]
    finally:
        context_budget._model_info.cache_clear()


def test_custom_endpoint_context_window_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        context_budget,
        "_model_info",
        lambda _model: {"max_input_tokens": 180_000, "max_output_tokens": 4_096},
    )
    monkeypatch.setattr(
        context_budget,
        "load_settings",
        lambda: SimpleNamespace(
            context=SimpleNamespace(
                fallback_context_tokens=160_000, max_context_tokens=160_000
            ),
            llm=SimpleNamespace(api_base="https://inference.dahl.global/v1"),
        ),
    )
    assert context_budget.context_window("openai/deepseek-ai/DeepSeek-V4-Flash-0731") == 160_000


def test_context_settings_use_safe_fallback_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_CONTEXT_FALLBACK_TOKENS", raising=False)
    assert ContextSettings().fallback_context_tokens == 160_000


def test_context_window_unmapped_uses_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    context_budget._model_info.cache_clear()

    def _raise(_model: str) -> dict[str, int]:
        raise ValueError("This model isn't mapped yet.")

    monkeypatch.setattr("strix.llm.context_budget.litellm.get_model_info", _raise)
    expected = load_settings().context.fallback_context_tokens
    assert context_budget.context_window("totally-made-up-model") == expected
    context_budget._model_info.cache_clear()


def test_count_tokens_fallback_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(**_kwargs: object) -> int:
        raise RuntimeError("no tokenizer")

    monkeypatch.setattr("strix.llm.context_budget.litellm.token_counter", _raise)
    # Falls back to UTF-8 byte length (upper bound on tokens).
    assert context_budget.count_tokens("weird-model", "x" * 400) == 400
    assert context_budget.count_tokens("weird-model", "😀" * 10) == 40


def test_count_tokens_empty_is_zero() -> None:
    assert context_budget.count_tokens("gpt-4o", "") == 0
