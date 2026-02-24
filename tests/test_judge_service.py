from __future__ import annotations

import pytest

from src.api.services.judge import (
    JudgeConfigurationError,
    ProviderJudgeNotReadyError,
    compute_agreement,
    get_judge_service,
)


def test_compute_agreement_overall_and_clean() -> None:
    comparisons = [
        {"human_label": "yes", "judge_label": "yes", "is_clean": True},
        {"human_label": "no", "judge_label": "yes", "is_clean": False},
        {"human_label": "partially", "judge_label": "partially", "is_clean": True},
    ]
    overall, clean = compute_agreement(comparisons)
    assert overall == pytest.approx(2 / 3)
    assert clean == pytest.approx(1.0)


def test_compute_agreement_without_clean_subset() -> None:
    comparisons = [{"human_label": "yes", "judge_label": "yes", "is_clean": False}]
    overall, clean = compute_agreement(comparisons)
    assert overall == pytest.approx(1.0)
    assert clean is None


def test_deterministic_answer_eval_shape() -> None:
    judge = get_judge_service(mode="deterministic", model="gpt-4.1-mini", prompt_version="v1")
    result = judge.evaluate_answer_case(
        input_text="What is Acme policy?",
        expected_output="Acme uses hybrid policy.",
        acceptable_sources="HR Policy 2026",
    )
    assert result["generated"]
    assert result["answer_correct"] in {"yes", "partially", "no"}
    assert result["source_correct"] in {"yes", "partially", "no"}
    assert result["response_quality"] in {"good", "average", "not_good"}
    assert "execution" in result["reasoning"].lower()


def test_deterministic_criteria_eval_shape() -> None:
    judge = get_judge_service(mode="deterministic")
    result = judge.evaluate_criteria_case(
        input_text="Draft summary",
        criteria=[{"id": "accuracy"}, {"id": "format"}],
    )
    assert isinstance(result["criteria_results"], list)
    assert isinstance(result["dimension_scores"], dict)
    assert result["overall_score"] in {"good", "average", "not_good"}


def test_provider_mode_requires_openai_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("JUDGE_PROVIDER", "openai")
    with pytest.raises(JudgeConfigurationError):
        get_judge_service(mode="provider")


def test_provider_mode_unknown_provider_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JUDGE_PROVIDER", "anthropic")
    judge = get_judge_service(mode="provider")
    with pytest.raises(ProviderJudgeNotReadyError):
        judge.evaluate_answer_case("q", "a", "s")
