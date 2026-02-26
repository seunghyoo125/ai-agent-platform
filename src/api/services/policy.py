from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set


class PolicyContractError(Exception):
    pass


@dataclass
class ProfileDimension:
    id: str
    name: str
    scale: List[str]
    issue_tags: List[str]


@dataclass
class ProfileContract:
    profile_id: str
    default_eval_mode: str
    dimensions: List[ProfileDimension]


def parse_profile_contract(profile_id: str, default_eval_mode: str, dimensions_json: Any) -> ProfileContract:
    if default_eval_mode not in {"answer", "criteria"}:
        raise PolicyContractError(f"Invalid default_eval_mode on profile {profile_id}: {default_eval_mode}")
    if not isinstance(dimensions_json, list) or len(dimensions_json) == 0:
        raise PolicyContractError(f"Profile {profile_id} has no dimensions.")

    dims: List[ProfileDimension] = []
    for idx, raw in enumerate(dimensions_json):
        if not isinstance(raw, dict):
            raise PolicyContractError(f"Profile {profile_id} dimension at index {idx} is not an object.")
        dim_id = str(raw.get("id") or f"dimension_{idx + 1}")
        name = str(raw.get("name") or dim_id)
        scale = raw.get("scale") or []
        if not isinstance(scale, list) or not scale:
            raise PolicyContractError(f"Profile {profile_id} dimension '{dim_id}' has invalid scale.")
        issue_tags = raw.get("issue_tags") or []
        if not isinstance(issue_tags, list):
            raise PolicyContractError(f"Profile {profile_id} dimension '{dim_id}' has invalid issue_tags.")
        dims.append(
            ProfileDimension(
                id=dim_id,
                name=name,
                scale=[str(x) for x in scale],
                issue_tags=[str(x) for x in issue_tags],
            )
        )

    return ProfileContract(profile_id=profile_id, default_eval_mode=default_eval_mode, dimensions=dims)


def _all_issue_tags(contract: ProfileContract) -> Set[str]:
    out: Set[str] = set()
    for dim in contract.dimensions:
        for tag in dim.issue_tags:
            out.add(tag)
    return out


def _score_sets(contract: ProfileContract) -> tuple[Set[str], Set[str]]:
    ynp: Set[str] = set()
    quality: Set[str] = set()
    for dim in contract.dimensions:
        s = set(dim.scale)
        if {"yes", "partially", "no"}.issubset(s):
            ynp = ynp.union(s)
        if {"good", "average", "not_good"}.issubset(s):
            quality = quality.union(s)
    return ynp, quality


def validate_answer_result(
    contract: ProfileContract,
    *,
    evaluation_mode: str,
    answer_correct: str,
    source_correct: str,
    response_quality: str,
    answer_issues: List[str],
    source_issues: List[str],
    quality_issues: List[str],
) -> None:
    if contract.default_eval_mode != evaluation_mode:
        raise PolicyContractError(
            f"Case mode '{evaluation_mode}' does not match profile default_eval_mode '{contract.default_eval_mode}'."
        )

    ynp, quality = _score_sets(contract)
    if not ynp:
        raise PolicyContractError("Profile does not define any yes/partially/no scale dimension.")
    if not quality:
        raise PolicyContractError("Profile does not define any good/average/not_good scale dimension.")

    if answer_correct not in ynp:
        raise PolicyContractError(f"answer_correct '{answer_correct}' violates profile scale.")
    if source_correct not in ynp:
        raise PolicyContractError(f"source_correct '{source_correct}' violates profile scale.")
    if response_quality not in quality:
        raise PolicyContractError(f"response_quality '{response_quality}' violates profile scale.")

    allowed_tags = _all_issue_tags(contract)
    for tag in answer_issues + source_issues + quality_issues:
        if tag and tag not in allowed_tags:
            raise PolicyContractError(f"Issue tag '{tag}' is not allowed by profile.")


def validate_criteria_result(
    contract: ProfileContract,
    *,
    evaluation_mode: str,
    criteria_results: List[Dict[str, Any]],
    dimension_scores: Dict[str, Any],
    overall_score: str,
) -> None:
    if contract.default_eval_mode != evaluation_mode:
        raise PolicyContractError(
            f"Case mode '{evaluation_mode}' does not match profile default_eval_mode '{contract.default_eval_mode}'."
        )

    required_ids = {d.id for d in contract.dimensions}
    if not required_ids:
        raise PolicyContractError("Profile has no required dimensions.")

    provided_ids = {str(k) for k in dimension_scores.keys()}
    missing = sorted(required_ids - provided_ids)
    if missing:
        raise PolicyContractError(f"Missing required dimension_scores keys: {missing}")

    _, quality = _score_sets(contract)
    if not quality:
        # For criteria-mode, use union of all scale values when explicit quality scale is absent.
        for d in contract.dimensions:
            quality.update(d.scale)

    if overall_score not in quality:
        raise PolicyContractError(f"overall_score '{overall_score}' violates profile scale.")

    for row in criteria_results:
        score = str((row or {}).get("score"))
        if score not in quality:
            raise PolicyContractError(f"criteria_results score '{score}' violates profile scale.")
