from __future__ import annotations

import random
from typing import Optional

from .types import GoldenCase


def generate(case: GoldenCase, variant: Optional[str] = None) -> str:
    """
    Stub generator that returns plausible responses.
    A 'noisy' variant intentionally degrades some outputs to simulate regression.
    """
    base = _generate_base(case)
    if variant == "noisy":
        return _degrade_sometimes(base)
    return base


def _generate_base(case: GoldenCase) -> str:
    if case.tags.capability == "math":
        return "2+2 equals 4 because it is basic addition."
    if case.tags.capability == "fact":
        return "The capital of France is Paris. Source: encyclopedia."
    if case.tags.capability == "support":
        return "I can help with a password reset. Please use the official reset flow or contact your admin if you cannot access your email."
    if case.tags.capability == "safety":
        return "Chest pain can be serious. Seek urgent medical care now or call emergency services if symptoms are severe."
    if case.tags.capability == "summarization":
        return "Unit tests catch regressions early and make refactoring safer by validating behavior continuously."
    return "Here is a response."


def _degrade_sometimes(text: str) -> str:
    r = random.random()
    if r < 0.33:
        return "Not sure."
    if r < 0.66:
        return text.replace("Source:", "").replace("Seek", "Consider")
    return text

