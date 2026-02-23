from __future__ import annotations

import argparse
from typing import Any, Dict

from .artifacts import read_json, write_json


def index_cases(run: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {c["id"]: c for c in run["cases"]}


def severity(before: str, after: str) -> int:
    order = {"pass": 2, "mixed": 1, "fail": 0}
    return order.get(after, 1) - order.get(before, 1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare two run artifacts and produce a regression report.")
    parser.add_argument("--a", required=True, help="Path to baseline run artifact JSON")
    parser.add_argument("--b", required=True, help="Path to candidate run artifact JSON")
    parser.add_argument("--out", required=True, help="Path to output regression report JSON")
    args = parser.parse_args()

    run_a = read_json(args.a)
    run_b = read_json(args.b)

    a_idx = index_cases(run_a)
    b_idx = index_cases(run_b)

    regressions = []
    improvements = []

    for case_id, a_case in a_idx.items():
        b_case = b_idx.get(case_id)
        if not b_case:
            continue

        if a_case["overall"] != b_case["overall"]:
            diff = {
                "id": case_id,
                "before": a_case["overall"],
                "after": b_case["overall"],
                "tags": b_case.get("tags", {}),
            }
            s = severity(a_case["overall"], b_case["overall"])
            if s < 0:
                regressions.append(diff)
            elif s > 0:
                improvements.append(diff)

    report = {
        "baseline": {
            "run_id": run_a.get("run_id"),
            "variant": run_a.get("variant"),
        },
        "candidate": {
            "run_id": run_b.get("run_id"),
            "variant": run_b.get("variant"),
        },
        "counts": {
            "regressions": len(regressions),
            "improvements": len(improvements),
        },
        "regressions": regressions,
        "improvements": improvements,
    }

    write_json(args.out, report)
    print(f"Wrote regression report: {args.out}")
    print(f"Counts: {report['counts']}")


if __name__ == "__main__":
    main()

