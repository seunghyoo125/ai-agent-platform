# CI Queue-Aware Quality Gate

Script:

- `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`

Purpose:

- Validate async run path + queue health in CI.
- Enforce regression and delta gates before merge.

Checks performed:

1. API health
2. Agent listing by org
3. Queue precheck (`/api/system/queue/stats`)
4. Dead-letter baseline count (`/api/system/queue/jobs/failed`)
5. Create + enqueue baseline run (`/start`) and poll to completion
6. Create + enqueue candidate run (`/start`) and poll to completion
7. Compare baseline vs candidate (`/api/eval/compare`) and enforce:
   - `regression_count <= ALLOWED_REGRESSIONS`
   - `answer/source/quality` deltas above minimum thresholds
8. Promotion safety gate (`/run-registry/promote-candidate`) requiring clean compare evidence
9. Dead-letter postcheck (must not increase)
10. Queue postcheck + validation envelope contract
11. Admin queue idempotency contract:
   - missing `Idempotency-Key` on bulk replay must fail with `VALIDATION_ERROR`
   - same call with `Idempotency-Key` in dry-run mode must succeed
12. Admin stale-reap dry-run contract:
   - missing `Idempotency-Key` on stale reap must fail with `VALIDATION_ERROR`
   - same call with `Idempotency-Key` in dry-run mode must succeed
13. Admin prune dry-run contract:
   - missing `Idempotency-Key` on prune must fail with `VALIDATION_ERROR`
   - same call with `Idempotency-Key` in dry-run mode must succeed
14. Queue maintenance policy contract:
   - `GET /api/system/queue/maintenance-policy?org_id=...` returns `ok=true` and matching `org_id`
15. Queue maintenance runner contract:
   - missing `Idempotency-Key` on maintenance run must fail with `VALIDATION_ERROR`
   - same call with `Idempotency-Key` in dry-run mode must succeed and return matching `org_id`
16. Queue maintenance history contract:
   - list endpoint returns at least one run item after maintenance execution
   - detail endpoint resolves the returned `run_id`
17. Queue maintenance metrics contract:
   - `GET /api/system/queue/maintenance/metrics?org_id=...&window_days=30` returns `ok=true`
   - response includes matching `org_id`, expected `window_days`, and non-negative `total_runs`
18. Queue maintenance stale-run reap contract:
   - missing `Idempotency-Key` on stale maintenance reap must fail with `VALIDATION_ERROR`
   - same call with `Idempotency-Key` in dry-run mode must succeed and return matching `org_id`
19. Queue maintenance schedule-trigger dedupe contract:
   - first trigger call executes (`executed=true`, `deduped=false`)
   - second trigger call in same window returns deduped response (`executed=false`, `deduped=true`)
20. Queue maintenance schedule summary contract:
   - `GET /api/system/queue/maintenance/schedule-summary` returns `ok=true`
   - response includes matching `org_id`, expected `schedule_name`, and non-zero trigger/dedupe counts after trigger checks
21. Queue maintenance schedule anomaly notify contract:
   - missing `Idempotency-Key` on notify endpoint must fail with `VALIDATION_ERROR`
   - same call with `Idempotency-Key` and `dry_run=true` must succeed
22. Queue maintenance schedule alert delivery contract:
   - `GET /api/system/queue/maintenance/schedule-alert-delivery` returns `ok=true`
   - response includes matching `org_id`, expected `schedule_name`, and non-zero notify event count after notify check
23. Eval run list contract:
   - `GET /api/eval/runs?org_id=...` returns `ok=true`
   - response includes non-empty `items` and consistent `count/total_count`
24. Agent/org health rollup contracts:
   - `GET /api/agents/{agent_id}/score-trend` returns `ok=true` with matching `agent_id`
   - `GET /api/agents/{agent_id}/health` returns `ok=true` with matching `agent_id` and `org_id`
   - `GET /api/orgs/{org_id}/portfolio-health` returns `ok=true` with matching `org_id`
25. Eval run artifacts contract:
   - `GET /api/eval/runs/{run_id}/artifacts` returns `ok=true`
   - response includes matching `run_id` and consistent `count/total_count`
26. Human review workflow contract:
   - `GET /api/eval/runs/{run_id}/review-queue` returns `ok=true` with matching `run_id`
   - `PATCH /api/eval/runs/{run_id}/results/{result_id}/review` accepts decision payload and returns review status fields
27. Calibration gate status contract:
   - `GET /api/agents/{agent_id}/calibration-gate-status` returns `ok=true`
   - response includes matching `agent_id` and string `status`
28. Golden set quality gate status contract:
   - `GET /api/golden-sets/{golden_set_id}/quality-gate-status` returns `ok=true`
   - response includes matching `golden_set_id` and string `status`
29. Gate definitions + agent gate bindings contract:
   - `GET /api/gate-definitions?org_id=...` returns `ok=true`
   - `GET /api/agents/{agent_id}/gate-bindings` returns `ok=true` with matching `agent_id`
30. Evaluator definitions + agent evaluator bindings contract:
   - `GET /api/evaluator-definitions?org_id=...` returns `ok=true`
   - `GET /api/agents/{agent_id}/evaluator-bindings` returns `ok=true` with matching `agent_id`
31. Run type definitions + agent run type bindings contract:
   - `GET /api/run-type-definitions?org_id=...` returns `ok=true`
   - `GET /api/agents/{agent_id}/run-type-bindings` returns `ok=true` with matching `agent_id`
32. Agent contract preflight status contract:
   - `GET /api/agents/{agent_id}/contract-status?run_type=...&entrypoint=...&golden_set_id=...` returns `ok=true`
   - response includes matching `agent_id`, string `status`, and string `resolved_handler_key`

Required env vars:

- `BASE_URL`
- `API_KEY`
- `ORG_ID`
- `AGENT_ID`
- `GOLDEN_SET_ID`

Optional env vars:

- `API_PREFIX` (default `/api/v1`)
- `ADMIN_API_KEY` (default `API_KEY`)
- `QUEUE_MAX_RUNNING` (default `0`)
- `ALLOWED_REGRESSIONS` (default `0`)
- `MIN_ANSWER_DELTA` (default `0`)
- `MIN_SOURCE_DELTA` (default `0`)
- `MIN_QUALITY_DELTA` (default `0`)
- `POLL_MAX_ATTEMPTS` (default `90`)
- `POLL_SLEEP_SECONDS` (default `2`)
