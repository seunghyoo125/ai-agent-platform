from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional

ScoreLabel = Literal["yes", "partial", "no"]


@dataclass
class Tags:
    capability: str
    difficulty: str
    test_type: str
    behavior: List[str]


@dataclass
class GoldenCase:
    id: str
    prompt: str
    expected: Optional[str]
    sources: List[str]
    tags: Tags


@dataclass
class RubricScores:
    answer_correct: ScoreLabel
    sources_correct: ScoreLabel
    response_appropriate: ScoreLabel


@dataclass
class CaseResult:
    id: str
    prompt: str
    expected: Optional[str]
    sources: List[str]
    tags: Dict[str, Any]
    generated: str
    rubric: Dict[str, ScoreLabel]
    overall: str

