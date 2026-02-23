from __future__ import annotations

from typing import Dict

from .types import GoldenCase


def flatten_tags(case: GoldenCase) -> Dict[str, object]:
    return {
        "capability": case.tags.capability,
        "difficulty": case.tags.difficulty,
        "test_type": case.tags.test_type,
        "behavior": list(case.tags.behavior),
    }

