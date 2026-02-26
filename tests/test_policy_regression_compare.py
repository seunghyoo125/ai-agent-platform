from datetime import datetime, timezone
from uuid import uuid4

from src.api.main import _is_value_regression, _summary_from_row


def test_is_value_regression_for_answer_scores():
    assert _is_value_regression("answer_correct", "yes", "partially") is True
    assert _is_value_regression("answer_correct", "partially", "yes") is False
    assert _is_value_regression("source_correct", "no", "partially") is False


def test_is_value_regression_for_quality_scores():
    assert _is_value_regression("response_quality", "good", "average") is True
    assert _is_value_regression("response_quality", "average", "good") is False
    assert _is_value_regression("response_quality", "not_good", "not_good") is False


def test_summary_from_row_handles_zero_total():
    now = datetime.now(timezone.utc)
    row = (
        uuid4(),
        "completed",
        now,
        now,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    summary = _summary_from_row(row)
    assert summary.total_results == 0
    assert summary.answer_yes_rate == 0.0
    assert summary.source_yes_rate == 0.0
    assert summary.quality_good_rate == 0.0
