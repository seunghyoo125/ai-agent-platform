from __future__ import annotations

from dataclasses import dataclass
import json
import os
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib import error, request

import certifi

@dataclass
class JudgeContext:
    mode: str = "deterministic"
    prompt_version: Optional[str] = None
    model: Optional[str] = None


class JudgeServiceError(Exception):
    pass


class JudgeConfigurationError(JudgeServiceError):
    pass


class ProviderJudgeNotReadyError(JudgeServiceError):
    pass


class ProviderJudgeRuntimeError(JudgeServiceError):
    pass


class JudgeService:
    def __init__(self, context: JudgeContext) -> None:
        self.context = context

    def evaluate_answer_case(
        self,
        input_text: str,
        expected_output: Optional[str],
        acceptable_sources: Optional[str],
    ) -> Dict[str, Any]:
        base = (expected_output or "").strip()
        if not base:
            base = f"Draft response for: {input_text}"
        if acceptable_sources and acceptable_sources.strip():
            generated = f"{base} Source: {acceptable_sources.strip()}."
        else:
            generated = base

        generated_lower = generated.lower()
        expected = (expected_output or "").strip()
        source_hint = (acceptable_sources or "").strip()

        if expected:
            if expected.lower() in generated_lower:
                answer_correct = "yes"
            elif any(tok in generated_lower for tok in expected.lower().split()[:3]):
                answer_correct = "partially"
            else:
                answer_correct = "no"
        else:
            answer_correct = "partially"

        if source_hint:
            if source_hint.lower() in generated_lower and "source" in generated_lower:
                source_correct = "yes"
            elif "source" in generated_lower:
                source_correct = "partially"
            else:
                source_correct = "no"
        else:
            source_correct = "partially"

        text_len = len(generated.strip())
        if text_len == 0:
            response_quality = "not_good"
        elif text_len < 40:
            response_quality = "average"
        else:
            response_quality = "good"

        return {
            "generated": generated,
            "answer_correct": answer_correct,
            "source_correct": source_correct,
            "response_quality": response_quality,
            "reasoning": f"{self.context.mode} baseline execution.",
        }

    def evaluate_criteria_case(self, input_text: str, criteria: Any) -> Dict[str, Any]:
        items: List[Dict[str, Any]] = []
        if isinstance(criteria, list):
            for idx, c in enumerate(criteria):
                if isinstance(c, dict):
                    cid = str(c.get("id") or c.get("criterionId") or f"criterion_{idx + 1}")
                else:
                    cid = f"criterion_{idx + 1}"
                items.append({"criterionId": cid, "score": "good", "evidence": "System baseline execution."})
        elif isinstance(criteria, dict):
            for key in criteria.keys():
                items.append({"criterionId": str(key), "score": "good", "evidence": "System baseline execution."})
        else:
            items.append({"criterionId": "criterion_1", "score": "good", "evidence": "System baseline execution."})

        dimension_scores = {item["criterionId"]: item["score"] for item in items}
        return {
            "generated": f"Criteria-evaluated response for: {input_text}",
            "criteria_results": items,
            "dimension_scores": dimension_scores,
            "overall_score": "good",
            "reasoning": f"{self.context.mode} baseline execution.",
        }


class ProviderJudgeService(JudgeService):
    def __init__(self, context: JudgeContext, provider: str) -> None:
        super().__init__(context=context)
        self.provider = provider

    @staticmethod
    def _ssl_context() -> ssl.SSLContext:
        # Use certifi CA bundle to avoid platform-specific trust-store issues.
        return ssl.create_default_context(cafile=certifi.where())

    def _openai_json_judge(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise JudgeConfigurationError("OPENAI_API_KEY is required for OpenAI provider mode.")

        api_base = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
        model = self.context.model or os.getenv("JUDGE_MODEL", "gpt-4.1-mini")
        url = f"{api_base.rstrip('/')}/chat/completions"
        payload = {
            "model": model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }
        req = request.Request(
            url=url,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            data=json.dumps(payload).encode("utf-8"),
        )
        try:
            with request.urlopen(req, timeout=60, context=self._ssl_context()) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            raise ProviderJudgeRuntimeError(f"OpenAI HTTP {exc.code}: {raw}") from exc
        except Exception as exc:
            raise ProviderJudgeRuntimeError(f"OpenAI request failed: {exc}") from exc

        try:
            content = body["choices"][0]["message"]["content"]
            if isinstance(content, list):
                content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("JSON response is not an object.")
            return data
        except Exception as exc:
            raise ProviderJudgeRuntimeError(f"Failed to parse OpenAI JSON response: {exc}") from exc

    def evaluate_answer_case(
        self,
        input_text: str,
        expected_output: Optional[str],
        acceptable_sources: Optional[str],
    ) -> Dict[str, Any]:
        if self.provider != "openai":
            raise ProviderJudgeNotReadyError(
                f"Provider judge mode is configured ({self.provider}) but only openai is currently implemented."
            )

        system_prompt = (
            "You are an evaluation judge. Return strict JSON with keys: "
            "generated, answer_correct, source_correct, response_quality, reasoning. "
            "Allowed values: answer_correct/source_correct in [yes, partially, no], "
            "response_quality in [good, average, not_good]."
        )
        user_prompt = (
            f"Input:\n{input_text}\n\n"
            f"Expected output:\n{(expected_output or '').strip()}\n\n"
            f"Acceptable sources:\n{(acceptable_sources or '').strip()}\n\n"
            "Generate a concise response and score it."
        )
        data = self._openai_json_judge(system_prompt, user_prompt)
        return {
            "generated": str(data.get("generated", "")),
            "answer_correct": str(data.get("answer_correct", "partially")),
            "source_correct": str(data.get("source_correct", "partially")),
            "response_quality": str(data.get("response_quality", "average")),
            "reasoning": str(data.get("reasoning", "Provider judge execution.")),
        }

    def evaluate_criteria_case(self, input_text: str, criteria: Any) -> Dict[str, Any]:
        if self.provider != "openai":
            raise ProviderJudgeNotReadyError(
                f"Provider judge mode is configured ({self.provider}) but only openai is currently implemented."
            )

        system_prompt = (
            "You are an evaluation judge. Return strict JSON with keys: "
            "generated, criteria_results, dimension_scores, overall_score, reasoning. "
            "criteria_results must be an array of {criterionId, score, evidence}. "
            "Use score values in [good, average, not_good]."
        )
        user_prompt = (
            f"Input:\n{input_text}\n\n"
            f"Criteria JSON:\n{json.dumps(criteria, ensure_ascii=True)}\n\n"
            "Generate a concise response and evaluate each criterion."
        )
        data = self._openai_json_judge(system_prompt, user_prompt)
        criteria_results = data.get("criteria_results")
        if not isinstance(criteria_results, list):
            criteria_results = [{"criterionId": "criterion_1", "score": "average", "evidence": "Fallback."}]
        dimension_scores = data.get("dimension_scores")
        if not isinstance(dimension_scores, dict):
            dimension_scores = {str(x.get("criterionId", "criterion_1")): str(x.get("score", "average")) for x in criteria_results if isinstance(x, dict)}

        return {
            "generated": str(data.get("generated", f"Criteria-evaluated response for: {input_text}")),
            "criteria_results": criteria_results,
            "dimension_scores": dimension_scores,
            "overall_score": str(data.get("overall_score", "average")),
            "reasoning": str(data.get("reasoning", "Provider judge execution.")),
        }


def compute_agreement(comparisons: List[Dict[str, Any]]) -> Tuple[float, Optional[float]]:
    total = len(comparisons)
    matched = sum(1 for c in comparisons if c.get("human_label") == c.get("judge_label"))
    overall = matched / total if total else 0.0

    clean_cases = [c for c in comparisons if bool(c.get("is_clean"))]
    if not clean_cases:
        return overall, None
    clean_matched = sum(1 for c in clean_cases if c.get("human_label") == c.get("judge_label"))
    clean = clean_matched / len(clean_cases)
    return overall, clean


def get_judge_service(
    mode: str = "deterministic",
    prompt_version: Optional[str] = None,
    model: Optional[str] = None,
) -> JudgeService:
    context = JudgeContext(mode=mode, prompt_version=prompt_version, model=model)
    if mode == "deterministic":
        return JudgeService(context=context)
    if mode == "provider":
        provider = os.getenv("JUDGE_PROVIDER", "openai")
        if provider == "openai" and not os.getenv("OPENAI_API_KEY"):
            raise JudgeConfigurationError("OPENAI_API_KEY is required when judge_mode=provider and JUDGE_PROVIDER=openai.")
        return ProviderJudgeService(context=context, provider=provider)
    raise JudgeConfigurationError(f"Unsupported judge mode: {mode}")
