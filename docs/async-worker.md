# Async Eval Worker

Queue-backed async eval execution worker.

Worker module:

- `/Users/seungyoo/Desktop/ai-agent-platform/src/api/worker.py`

Queue table migration:

- `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224120000_tier12_eval_run_queue.sql`
- `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224200000_tier20_eval_run_cancelled_status.sql`
- `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224203000_tier23_eval_run_jobs_status_transition_guard.sql`

Run worker:

```bash
set -a; source .env; set +a
python3 -m src.api.worker
```

Optional env:

- `EVAL_WORKER_ID` (default: `worker-<pid>`)
- `EVAL_WORKER_POLL_SECONDS` (default: `2.0`)
- `EVAL_WORKER_RETRY_BASE_SECONDS` (default: `15`)
- `EVAL_WORKER_MAX_RETRY_DELAY_SECONDS` (default: `900`)
- `EVAL_WORKER_HEARTBEAT_SECONDS` (default: `5.0`)
- `EVAL_WORKER_STALE_HEARTBEAT_SECONDS` (default: `60`)
- `EVAL_WORKER_REAP_INTERVAL_SECONDS` (default: `10.0`)
- `EVAL_WORKER_NOTIFY_DRAIN_SECONDS` (default: `5.0`)
- `EVAL_WORKER_MAX_RUNTIME_SECONDS` (default: `900`)
- `EVAL_WORKER_MAX_CONCURRENCY_GLOBAL` (default: `0` = unlimited)
- `EVAL_WORKER_MAX_CONCURRENCY_PER_ORG` (default: `0` = unlimited)

Queue API flow:

1. Create run: `POST /api/eval/runs`
2. Enqueue run: `POST /api/eval/runs/{run_id}/start`
   - Response includes `enqueued=true|false`:
     - `true`: new queue job created
     - `false`: existing queued/running job reused (idempotent dedupe)
3. Worker executes queued job and updates run status/results
   - If execute returns `status=cancelled`, queue job is finalized as `cancelled`
   - Cooperative cancellation checks run before execution and between cases
   - Claim guardrails enforce optional running concurrency caps:
     - global running cap
     - per-org running cap
   - Fair scheduling favors orgs with fewer running jobs:
     - choose next org by `running_org asc`, then oldest queued run
     - within org, choose oldest queued run first
   - run state transitions are guarded (`pending -> running -> completed|failed|cancelled`)
   - rerun flows reopen terminal runs to `pending` before enqueue/execute
   - queue job status transitions are DB-guarded:
     - `queued -> running|cancelled`
     - `running -> succeeded|failed|cancelled|queued`
     - `failed -> queued`
4. Inspect progress/events: `GET /api/eval/runs/{run_id}/events`
5. Optional cancel: `POST /api/eval/runs/{run_id}/cancel`
6. Optional manual notification drain: `POST /api/system/notifications/outbox/drain`
7. Optional outbox ops:
   - list/filter: `GET /api/system/notifications/outbox`
   - dead-letter summary: `GET /api/system/notifications/outbox/dead-letter-summary`
   - retry one item: `POST /api/system/notifications/outbox/{outbox_id}/retry`
8. Optional queue ops:
   - stale reap (admin): `POST /api/system/queue/jobs/reap-stale`
   - terminal prune (admin): `POST /api/system/queue/jobs/prune`
   - maintenance runner (admin): `POST /api/system/queue/maintenance/run`
   - maintenance stale-run reap (admin): `POST /api/system/queue/maintenance/reap-stale-runs`
   - maintenance scheduler trigger (admin): `POST /api/system/queue/maintenance/schedule-trigger`
   - maintenance scheduler summary (admin): `GET /api/system/queue/maintenance/schedule-summary`
   - maintenance scheduler anomaly notify (admin): `POST /api/system/queue/maintenance/schedule-summary/notify`
   - maintenance scheduler alert delivery status (admin): `GET /api/system/queue/maintenance/schedule-alert-delivery`
   - maintenance history:
     - list: `GET /api/system/queue/maintenance/runs`
     - detail: `GET /api/system/queue/maintenance/runs/{run_id}`
   - maintenance metrics:
     - `GET /api/system/queue/maintenance/metrics`
