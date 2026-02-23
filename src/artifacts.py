from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def summarize_case_overall(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(cases)
    dist = {"pass": 0, "mixed": 0, "fail": 0}
    for c in cases:
        dist[c["overall"]] = dist.get(c["overall"], 0) + 1

    pass_rate_strict = (dist["pass"] / total) if total else 0.0
    pass_rate_lenient = ((total - dist["fail"]) / total) if total else 0.0

    return {
        "total": total,
        "score_distribution": dist,
        "pass_rate_strict": pass_rate_strict,
        "pass_rate_lenient": pass_rate_lenient,
    }

