from __future__ import annotations

import argparse
import json
import os
import uuid
from typing import List

from .artifacts import summarize_case_overall, utc_now_iso, write_json
from .generator_stub import generate
from .rubric import overall_label, score_case
from .taxonomy import flatten_tags
from .types import GoldenCase, Tags


def load_golden_set(path: str) -> List[GoldenCase]:
    cases: List[GoldenCase] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            tags_obj = obj["tags"]
            tags = Tags(
                capability=tags_obj["capability"],
                difficulty=tags_obj["difficulty"],
                test_type=tags_obj["test_type"],
                behavior=list(tags_obj.get("behavior", [])),
            )
            cases.append(
                GoldenCase(
                    id=obj["id"],
                    prompt=obj["prompt"],
                    expected=obj.get("expected"),
                    sources=list(obj.get("sources", [])),
                    tags=tags,
                )
            )
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(description="Run evaluation over a golden set and write a run artifact.")
    parser.add_argument("--golden", required=True, help="Path to golden set JSONL")
    parser.add_argument("--out", required=True, help="Path to output run artifact JSON")
    parser.add_argument("--run-name", default="run", help="Friendly run name")
    parser.add_argument("--variant", default="", help="Variant name, e.g. prompt_v2 or model_x")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    run_id = str(uuid.uuid4())
    cases = load_golden_set(args.golden)

    case_results = []
    for case in cases:
        generated = generate(case, variant=args.variant or None)
        scores = score_case(case, generated)
        overall = overall_label(scores)
        case_results.append(
            {
                "id": case.id,
                "prompt": case.prompt,
                "expected": case.expected,
                "sources": case.sources,
                "tags": flatten_tags(case),
                "generated": generated,
                "rubric": scores,
                "overall": overall,
            }
        )

    artifact = {
        "run_id": run_id,
        "run_name": args.run_name,
        "created_at": utc_now_iso(),
        "golden_set_path": args.golden,
        "variant": args.variant,
        "summary": summarize_case_overall(case_results),
        "cases": case_results,
    }

    write_json(args.out, artifact)
    print(f"Wrote run artifact: {args.out}")
    print(f"Summary: {artifact['summary']}")


if __name__ == "__main__":
    main()

