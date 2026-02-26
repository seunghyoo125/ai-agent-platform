# API v1 (Foundations)

Base response envelope:

```json
{ "ok": true, "data": { } }
```

```json
{ "ok": false, "error": { "code": "SOME_CODE", "message": "..." } }
```

Validation failures (`422`) also follow the same envelope:

```json
{
  "ok": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed.",
    "details": []
  }
}
```

Auth header:

```text
Authorization: Bearer <api_key>
```

Base API paths:
- Canonical: `/api/v1/*`
- Legacy (backward-compatible): `/api/*`
- Both return `X-API-Version: v1`.
- Legacy `/api/*` responses also return `Deprecation: true`.

OpenAPI docs:
- Schema: `/openapi.json`
- Swagger UI: `/docs`
- ReDoc: `/redoc`
- Operations are grouped by domain tags and API endpoints are documented with bearer auth (`BearerAuth`).
- Operation IDs follow a deterministic convention:
  - `<http_method>_<resource_path>`
  - Example: `post_eval_runs`, `get_agents_by_agent_id_latest`

Generated client baselines:
- Python: `/Users/seungyoo/Desktop/ai-agent-platform/sdk/python/greenlight_client.py`
- TypeScript: `/Users/seungyoo/Desktop/ai-agent-platform/sdk/typescript/greenlightClient.ts`
- Usage examples: `/Users/seungyoo/Desktop/ai-agent-platform/docs/sdk-usage.md`
- Regenerate from current OpenAPI schema:
  - `PYTHONPATH=. /Users/seungyoo/Desktop/ai-agent-platform/scripts/generate_clients.py`
- Generated typing scope:
  - request models are typed from OpenAPI component schemas
  - method `body` arguments use typed request models when available
  - response envelopes are typed from OpenAPI response schema refs
- generated SDK includes `*_all` paginator helpers for list endpoints with `data.items`
  - configurable `page_size/pageSize` and `max_pages/maxPages`
- generated SDK request layer includes retry/backoff for transient failures:
  - retries on `429` and `5xx` responses
  - retries on transient network errors
  - Python constructor: `max_retries`, `backoff_base_seconds`
  - TypeScript constructor: `maxRetries`, `backoffBaseMs`
- per-request override support:
  - Python method args: `timeout`, `max_retries`, `backoff_base_seconds`
  - TypeScript method args: `requestOptions` with `{ timeoutMs, maxRetries, backoffBaseMs }`
- structured SDK errors:
  - Python raises `GreenlightApiError` with: `status_code`, `code`, `message`, `request_id`, `details`
  - TypeScript throws `GreenlightApiError` with: `statusCode`, `code`, `message`, `requestId`, `details`
  - request-id correlation is preserved across retries; retry-exhausted network/timeouts carry the last seen request id when available
- SDK logging hooks (safe-by-default payload, no auth/header/body content):
  - Python client-level logger: `logger: Callable[[dict], None]`
  - Python per-request override: method arg `logger=...`
  - TypeScript client-level logger: constructor `logger?: RequestLogger`
  - TypeScript per-request override: `requestOptions.logger`
  - Event fields include: `event`, `method`, `path`, `statusCode`, `durationMs`, `attempt`, `requestId`, `errorCode`, `hasBody`, `queryKeys`

Role model (API key role):
- `viewer`: read-only endpoints
- `member`: viewer + operational writes (runs, results workflows, patterns, SLO policy)
- `admin`: member + system/admin operations (API key management, system audit logs, launch decisions)

Forbidden response:
- HTTP `403`
- error code: `FORBIDDEN`
- details include:
  - `required_role`
  - `actual_role`

Request correlation:

- API returns `X-Request-Id` response header on all requests.
- You can pass your own `X-Request-Id` request header; otherwise server generates one.
- Activity feed metadata stores `request_id` for traceability.
- Mutating API calls are also written to internal `api_audit_logs` with request path/status/latency/error code.

Idempotency (mutating endpoints):

- For `POST|PATCH|PUT|DELETE` under `/api/*` or `/api/v1/*`, send optional header:
  - `Idempotency-Key: <client-generated-unique-key>`
- If same key is replayed with identical payload, API returns the original stored response.
- If same key is reused with different payload, API returns `409`:
  - `IDEMPOTENCY_KEY_REUSED`
- If identical request is still processing, API returns `409`:
  - `IDEMPOTENCY_IN_PROGRESS`

Server env:

- `DATABASE_URL` or `SUPABASE_DB_URL`
- Optional webhook notifications:
  - `NOTIFY_WEBHOOK_URL` (destination URL)
  - `NOTIFY_WEBHOOK_EVENTS` (comma-separated event types; empty = all)
  - `NOTIFY_WEBHOOK_SECRET` (optional; enables signed webhook headers)
  - `NOTIFY_WEBHOOK_FORMAT` (`json` or `slack`; default auto-detect by URL)
  - `NOTIFY_WEBHOOK_SIGNATURE_TOLERANCE_SECONDS` (default `300`, recommended receiver replay window)

Webhook signing (when `NOTIFY_WEBHOOK_SECRET` is set):

- `X-Greenlight-Timestamp: <unix-seconds>`
- `X-Greenlight-Signature: v1=<hex-hmac-sha256>`
- `X-Greenlight-Delivery-Id: <delivery-id>` (stable unique id per delivery attempt flow)
- Canonical signed message: `v1:{timestamp}:{raw_request_body_bytes}`
- Legacy header remains for compatibility:
  - `X-Greenlight-Webhook-Secret: <secret>`

Receiver replay check recommendation:

- Reject if absolute difference between receiver time and `X-Greenlight-Timestamp` exceeds tolerance (default `300s`).
- Store and dedupe by `X-Greenlight-Delivery-Id` (or JSON `delivery_id`) to make retries idempotent.

API key storage:

- Primary source is `public.api_keys` (hashed keys).
- Hash algorithm: `sha256`.
- Suggested token format: `sk_live_...` or `sk_test_...`.

Bootstrap a key in SQL (example):

```sql
insert into public.api_keys (org_id, name, key_prefix, key_hash, status)
values (
  null,
  'local-dev',
  'sk_local_',
  encode(digest('sk_local_dev_123', 'sha256'), 'hex'),
  'active'
);
```

## POST `/api/system/api-keys`

Creates a new API key (plaintext returned once).

Status: `201`

Request:

```json
{
  "name": "ci-key",
  "org_id": null,
  "expires_at": null,
  "role": "admin"
}
```

Success:

```json
{
  "ok": true,
  "data": {
    "id": "uuid",
    "org_id": null,
    "name": "ci-key",
    "key_prefix": "sk_live_xxx",
    "status": "active",
    "expires_at": null,
    "created_at": "2026-02-23T08:00:00Z",
    "api_key": "sk_live_...plaintext..."
  }
}
```

## GET `/api/system/api-keys`

Lists API keys (metadata only; no plaintext or hash).

Query params:

- `status` (optional): `active|revoked`
- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

## GET `/api/system/audit-logs`

Admin-only API audit logs for mutating requests.

Query params (all optional):
- `request_id`
- `path` (substring match)
- `method` (`POST|PATCH|PUT|DELETE`)
- `status_code`
- `error_code`
- `agent_id` (resolved via activity event `metadata.request_id` correlation)
- `limit` (default `50`, max `200`)
- `offset` (default `0`)

Errors:
- `FORBIDDEN` when called with non-admin (org-scoped) key.

## GET `/api/system/queue/stats`

Admin queue observability summary for async eval jobs.

Query params:
- `org_id` (optional UUID; for platform-admin global view or per-org filter)

Org scoping:
- org-scoped admin keys are restricted to their own org
- global admin keys can query all orgs or a specific `org_id`

Response fields:
- `queued_count`
- `running_count`
- `succeeded_count`
- `failed_count`
- `cancelled_count`
- `retry_backlog_count` (queued jobs with prior attempts remaining)
- `oldest_queued_age_seconds`
- `checked_at`

## GET `/api/system/queue/jobs/failed`

Lists failed queue jobs (dead-letter view).

Query params:
- `org_id` (optional UUID)
- `limit` (default `50`, max `200`)
- `offset` (default `0`)

Item fields include:
- `job_id`, `run_id`, `org_id`, `agent_id`
- `run_name`, `run_status`
- `job_status`, `attempt_count`, `max_attempts`
- `error_message`, timestamps

## POST `/api/system/queue/jobs/{job_id}/retry`

Requeues a failed queue job.

Required headers:
- `Idempotency-Key`

Query params:
- `delay_seconds` (optional, default `0`, max `86400`)

Rules:
- only `failed` jobs are retryable
- returns `QUEUE_JOB_NOT_RETRYABLE` for non-failed jobs

## POST `/api/system/queue/jobs/{job_id}/cancel`

Cancels an active queue job.

Rules:
- active statuses: `queued|running`
- non-active statuses return `cancelled: false` with current status

Required headers:
- `Idempotency-Key`

## POST `/api/system/queue/jobs/failed/replay`

Bulk requeues failed queue jobs with admin guardrails.

Query params:
- `org_id` (optional; required for org filtering when caller is global admin)
- `limit` (default `20`, min `1`, max `100`)
- `delay_seconds` (default `0`, min `0`, max `3600`)
- `dry_run` (default `false`)

Required headers:
- `Idempotency-Key`

Behavior:
- selects oldest failed jobs first (`updated_at asc`)
- when `dry_run=true`, returns selected job IDs without mutating queue state
- when `dry_run=false`, updates selected failed jobs to `queued` and clears terminal fields

Response fields:
- `selected_count`
- `replayed_count`
- `job_ids`
- `dry_run`

## GET `/api/system/queue/maintenance-policy`

Returns effective queue maintenance policy for an org.

Query params:
- `org_id` (required UUID)

Behavior:
- if org has saved policy row, returns it
- otherwise returns platform defaults:
  - `stale_heartbeat_seconds=60`
  - `max_runtime_seconds=900`
  - `retention_days=14`
  - `reap_limit=100`
  - `prune_limit=500`

## POST `/api/system/queue/maintenance-policy`

Creates or updates org-level queue maintenance policy.

Request body:
- `org_id`
- `stale_heartbeat_seconds`
- `max_runtime_seconds`
- `retention_days`
- `reap_limit`
- `prune_limit`
- `schedule_alert_enabled` (optional, default `false`)
- `schedule_alert_dedupe_hit_rate_threshold` (optional, `0..1`, default `0.7`)
- `schedule_alert_min_execution_success_rate` (optional, `0..1`, default `0.9`)
- `schedule_alert_cooldown_minutes` (optional, default `60`, range `0..10080`)

## POST `/api/system/queue/maintenance/run`

Runs policy-driven queue maintenance in one operation.

Query params:
- `org_id` (required)
- `dry_run` (default `true`)
- optional overrides:
  - `stale_heartbeat_seconds`
  - `max_runtime_seconds`
  - `retention_days`
  - `reap_limit`
  - `prune_limit`

Required headers:
- `Idempotency-Key`

Behavior:
- resolves effective policy (saved org policy + optional overrides)
- runs stale reap and prune in sequence
- returns unified response with:
  - effective policy values
  - reap summary
  - prune summary
- persists an audit run record with status/duration
- returns `409 QUEUE_MAINTENANCE_ALREADY_RUNNING` if another maintenance run is currently active for the same org

## GET `/api/system/queue/maintenance/runs`

Lists maintenance run history.

Query params:
- `org_id` (optional)
- `status` (optional: `running|completed|failed`)
- `limit` (default `50`, max `200`)
- `offset` (default `0`)

## GET `/api/system/queue/maintenance/runs/{run_id}`

Returns one maintenance run record with:
- policy snapshot
- reap/prune summaries
- status/error/duration
- timestamps and trigger metadata

## POST `/api/system/queue/maintenance/reap-stale-runs`

Admin remediation endpoint for stale maintenance runs stuck in `running`.

Query params:
- `org_id` (optional)
- `max_runtime_seconds` (optional; defaults to org maintenance policy `max_runtime_seconds` when available, else `900`)
- `limit` (optional, default `100`, min `1`, max `500`)
- `dry_run` (optional, default `false`)

Required headers:
- `Idempotency-Key`

Behavior:
- selects stale maintenance runs where:
  - `status='running'`
  - `started_at < now() - max_runtime_seconds`
- when `dry_run=false`:
  - marks selected runs as `failed`
  - sets `error_message` (if missing)
  - sets `completed_at` and derived `duration_ms` (if missing)
- emits explicit audit records per reaped run in `api_audit_logs` (plus standard request audit middleware)

## POST `/api/system/queue/maintenance/schedule-trigger`

Scheduler-safe queue maintenance trigger with built-in server-side dedupe.

Request body:
- `org_id` (required)
- `schedule_name` (optional, default `default`)
- `window_minutes` (optional, default `60`, min `5`, max `1440`)
- `dry_run` (optional, default `false`)
- `force` (optional, default `false`)
- optional maintenance overrides:
  - `stale_heartbeat_seconds`
  - `max_runtime_seconds`
  - `retention_days`
  - `reap_limit`
  - `prune_limit`

Behavior:
- computes a dedupe window bucket from `window_minutes`
- if a completed run with the same dedupe key already exists in the current window for the same org+caller key:
  - returns prior run with `executed=false`, `deduped=true`
- otherwise:
  - executes maintenance run (`executed=true`, `deduped=false`)
  - tags run snapshot with scheduler metadata (`_schedule_name`, `_schedule_dedupe_key`)

## GET `/api/system/queue/maintenance/schedule-summary`

Returns scheduler observability summary for maintenance triggers.

Query params:
- `org_id` (required)
- `schedule_name` (optional; when omitted, summarizes all schedule names)
- `window_days` (optional, default `30`, min `1`, max `365`)

Returns:
- trigger totals (`trigger_count`, `executed_count`, `deduped_count`)
- `dedupe_hit_rate`
- execution outcomes from maintenance runs (`successful_executions`, `failed_executions`, `execution_success_rate`)
- recent timestamps/status (`last_triggered_at`, `last_executed_run_started_at`, `last_executed_run_status`)

## POST `/api/system/queue/maintenance/schedule-summary/notify`

Evaluates schedule summary anomalies and optionally sends a webhook/Slack notification.

Request body:
- `org_id` (required)
- `schedule_name` (optional)
- `window_days` (optional, default `30`)
- `dry_run` (optional, default `true`)
- `force_notify` (optional, default `false`)

Alert logic:
- thresholds come from org queue maintenance policy:
  - `schedule_alert_dedupe_hit_rate_threshold`
  - `schedule_alert_min_execution_success_rate`
- anomaly is detected if either:
  - `dedupe_hit_rate` >= threshold
  - `execution_success_rate` < threshold
- notifications send only when:
  - policy `schedule_alert_enabled=true` and anomaly detected, or
  - `force_notify=true`
- suppression:
  - repeated alerts with the same fingerprint are suppressed within
    `schedule_alert_cooldown_minutes` unless `force_notify=true`

## GET `/api/system/queue/maintenance/schedule-alert-delivery`

Returns operational delivery status for schedule anomaly notifications.

Query params:
- `org_id` (required)
- `schedule_name` (optional; defaults to `_all` bucket)
- `window_days` (optional, default `30`)

Returns:
- notify event totals (`total_notify_events`, `sent_count`, `failed_count`, `suppressed_count`, `skipped_count`, `dry_run_count`)
- recency markers (`last_event_at`, `last_sent_at`, `last_failed_at`, `last_suppressed_at`)
- cooldown state timestamp (`last_notified_at`)

## GET `/api/system/queue/maintenance/metrics`

Returns org-level maintenance health metrics for an observation window.

Query params:
- `org_id` (required)
- `window_days` (optional, default `30`, min `1`, max `365`)

Returns:
- run volume split by status (`running/completed/failed`)
- dry-run count
- failure rate (`failed_count / total_runs`)
- duration stats on completed runs (`avg`, `p50`, `p95`)
- most recent run status/timestamp

## POST `/api/system/queue/jobs/reap-stale`

Admin stale-job remediation endpoint for running queue jobs.

Query params:
- `org_id` (optional)
- `stale_heartbeat_seconds` (default `60`, min `5`, max `86400`)
- `max_runtime_seconds` (default `900`, min `30`, max `86400`)
- `limit` (default `100`, min `1`, max `500`)
- `dry_run` (default `false`)

Required headers:
- `Idempotency-Key`

Behavior:
- selects running jobs considered stale by heartbeat/runtime thresholds
- when `org_id` is provided and threshold params are omitted, policy defaults are used
- when `dry_run=true`, returns candidate jobs without mutations
- when `dry_run=false`:
  - marks matching queue jobs `failed`
  - marks associated running eval runs `failed`
  - records `run_reaped` activity events

## POST `/api/system/queue/jobs/prune`

Admin queue retention cleanup for terminal jobs.

Query params:
- `org_id` (optional)
- `retention_days` (default `14`, min `1`, max `3650`)
- `limit` (default `500`, min `1`, max `5000`)
- `dry_run` (default `false`)

Required headers:
- `Idempotency-Key`

Behavior:
- targets terminal queue jobs (`succeeded|failed|cancelled`) older than retention window
- when `org_id` is provided and params are omitted, policy defaults are used
- when `dry_run=true`, returns candidate IDs without mutation
- when `dry_run=false`, deletes selected queue jobs up to `limit`

## POST `/api/system/notifications/outbox/drain`

Admin-only manual drain for pending notification outbox rows.

Query params:
- `limit` (default `20`, max `200`)

Response fields:
- `picked`
- `sent`
- `failed`
- `dead`

## GET `/api/system/notifications/outbox`

Admin-only outbox list/filter endpoint.

Query params:
- `org_id` (optional UUID)
- `status` (optional: `pending|sending|sent|dead`)
- `event_type` (optional string)
- `limit` (default `50`, max `200`)
- `offset` (default `0`)

## GET `/api/system/notifications/outbox/dead-letter-summary`

Admin-only dead-letter observability summary.

Query params:
- `org_id` (optional UUID)
- `event_type` (optional string)

Response fields:
- `total_dead`
- `oldest_dead_age_seconds`
- `reason_groups[]` (`reason`, `count`)
- `age_buckets[]` (`bucket`, `count`) where bucket is one of:
  - `lt_1h`
  - `h_1_to_24`
  - `d_1_to_7`
  - `gte_7d`

## POST `/api/system/notifications/outbox/{outbox_id}/retry`

Admin-only manual retry/reset of a single outbox item.

Rules:
- resets item to `pending`
- if current status is `dead`, resets `attempt_count` to `0`
- returns `NOTIFICATION_OUTBOX_IN_PROGRESS` when current status is `sending`

## POST `/api/system/api-keys/{key_id}/revoke`

Revokes an API key by ID.

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "id": "uuid",
    "status": "revoked"
  }
}
```

## POST `/api/eval/runs`

Creates an async eval run record.

Status: `202`

Request:

```json
{
  "org_id": "uuid",
  "agent_id": "uuid",
  "template_id": "uuid-or-null",
  "golden_set_id": "uuid-or-null",
  "name": "baseline run",
  "type": "eval",
  "config": {},
  "design_context": {}
}
```

Template behavior:
- When `template_id` is provided:
  - template `config`/`design_context` are merged with payload (payload keys override template keys)
  - template `default_golden_set_id` is used when payload `golden_set_id` is null
  - `payload.type` must match template `run_type`
  - template `agent_type` (if set) must match selected agent type

## POST `/api/eval/runs/{run_id}/execute`

Executes a pending eval run synchronously (executor + judge pipeline).

Guardrail behavior before execution:
- built-in policy gates (calibration + golden set quality, when enabled)
- configured gate bindings (`/api/agents/{agent_id}/gate-bindings`)

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "run_id": "uuid",
    "status": "completed",
    "case_count": 12,
    "completed_at": "2026-02-23T08:00:00Z"
  }
}
```

Cancellation behavior:
- If cancellation is requested before or during execution, response returns:
  - `status: "cancelled"`
  - `case_count`: number of cases completed before cancellation
- If the run is already marked cancelled before execute starts:
  - `409` with `EVAL_RUN_CANCELLED`

Errors:
- `EVAL_RUN_NO_GOLDEN_SET` if run has no attached golden set.
- `EVAL_RUN_ALREADY_RUNNING` if run is currently running.
- `EVAL_RUN_STATUS_TRANSITION_INVALID` if execute is requested from non-`pending` status.
- `EVAL_EXECUTOR_CONFIG_ERROR` if executor mode is misconfigured (for example missing endpoint in `agent_http` mode).
- `EVAL_EXECUTOR_RUNTIME_ERROR` if executor call fails (network/HTTP/parse/runtime).
- `EVAL_JUDGE_CONFIG_ERROR` if `judge_mode=provider` is misconfigured (e.g. missing provider env vars).
- `EVAL_JUDGE_NOT_READY` if provider mode is selected but provider execution is not yet implemented.
- `EVAL_JUDGE_PROVIDER_ERROR` if provider call/parsing fails during execution.
- `EVAL_POLICY_CONTRACT_ERROR` if generated scores violate eval profile contract rules.
- `EVAL_CALIBRATION_GATE_FAILED`
- `EVAL_GOLDEN_SET_QUALITY_GATE_FAILED`
- `EVAL_GATE_FAILED`
- `EVAL_GATE_CONFIG_ERROR`
- `AGENT_CONTRACT_VALIDATION_FAILED`

Run config note:
- `executor_mode` in run `config` can be:
  - `auto` (default): use `agent_http` when agent has `api_endpoint`, else `simulated`
  - `simulated`: deterministic local response generation
  - `agent_http`: call agent `api_endpoint` as `POST` JSON `{ "input": "..." }`
- Optional executor fields in run `config`:
  - `executor_timeout_ms` (default `15000`)
  - `executor_headers` (object of request headers for agent endpoint)
- `judge_mode` in run `config` can be `deterministic` (default) or `provider`.
- Optional provider fields in run `config`:
  - `judge_model` (example: `gpt-4.1-mini`)
  - `judge_prompt_version` (metadata only)

Provider env vars:
- `JUDGE_PROVIDER` (currently `openai`)
- `OPENAI_API_KEY`
- `OPENAI_API_BASE` (optional override; defaults to `https://api.openai.com/v1`)

Policy contract enforcement:
- Execution resolves profile contract from:
  1. agent `eval_profile_id` (if set), else
  2. built-in profile matching agent type
- Result scores and issue tags are validated against contract scales/tags.
- Case-level replay trace metadata is persisted in `eval_results.notes` JSON string:
  - `execution_mode`
  - `execution_trace` (request/response hashes, duration, target, status preview)
  - judge mode/model/prompt metadata

## POST `/api/eval/runs/{run_id}/start`

Enqueues an eval run for async worker processing.

Status: `202`

Query params:
- `max_attempts` (optional, default `3`, min `1`, max `10`)

Errors:
- `EVAL_RUN_NOT_FOUND`
- `EVAL_RUN_ALREADY_RUNNING`
- `EVAL_RUN_STATUS_TRANSITION_INVALID`
- `EVAL_RUN_QUEUE_FAILED`
- `EVAL_CALIBRATION_GATE_FAILED`
- `EVAL_GOLDEN_SET_QUALITY_GATE_FAILED`
- `EVAL_GATE_FAILED`
- `EVAL_GATE_CONFIG_ERROR`
- `AGENT_CONTRACT_VALIDATION_FAILED`

Run state behavior:
- If the run is terminal (`completed|failed|cancelled`), `start` reopens it to `pending` before enqueue.

## POST `/api/eval/runs/{run_id}/cancel`

Cancels an active queued/running job for the run.

Status: `200`

Response includes:
- `cancelled` (bool)
- `job_id` (nullable)
- `status` (nullable; typically `cancelled`)

Side effect:
- When cancellation succeeds, run status is also updated to `cancelled`.

## GET `/api/eval/runs`

Lists eval runs with pagination and optional filters.

Query params:
- `org_id` (optional UUID; required for org-scoped keys)
- `agent_id` (optional UUID)
- `type` (optional): `eval|regression|ab_comparison|calibration`
- `status` (optional): `pending|running|completed|failed|cancelled`
- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

Status: `200`

## GET `/api/eval/runs/{run_id}/events`

Returns run-scoped activity events (`run_created`, `run_queued`, `run_started`, `run_executed`, etc).

Query params:
- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

Success:

```json
{
  "ok": true,
  "data": {
    "run_id": "uuid",
    "status": "pending",
    "created_at": "2026-02-23T08:00:00Z"
  }
}
```

## GET `/api/eval/runs/{run_id}`

Returns run metadata and result count.

Query params:

- `include_results` (boolean, default `false`)

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "id": "uuid",
    "org_id": "uuid",
    "agent_id": "uuid",
    "golden_set_id": "uuid-or-null",
    "name": "baseline run",
    "type": "eval",
    "status": "pending",
    "config": {},
    "design_context": {},
    "created_at": "2026-02-23T08:00:00Z",
    "started_at": null,
    "completed_at": null,
    "failure_reason": null,
    "result_count": 0,
    "results": null
  }
}
```

## GET `/api/eval/runs/{run_id}/results`

Returns paginated detailed case-level results for an eval run.

Query params:

- `evaluation_mode` (optional): `answer|criteria`
- `answer_correct` (optional): `yes|partially|no`
- `source_correct` (optional): `yes|partially|no`
- `response_quality` (optional): `good|average|not_good`
- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "items": [
      {
        "id": "uuid",
        "eval_run_id": "uuid",
        "case_id": "uuid",
        "agent_id": "uuid",
        "evaluation_mode": "answer",
        "actual_response": "text",
        "actual_sources": "text",
        "answer_correct": "yes",
        "answer_issues": [],
        "source_correct": "yes",
        "source_issues": [],
        "response_quality": "good",
        "quality_issues": [],
        "criteria_results": null,
        "dimension_scores": null,
        "overall_score": null,
        "reasoning": "Deterministic baseline execution.",
        "tester": "system",
        "search_mode": "default",
        "eval_date": "2026-02-23",
        "notes": null,
        "match_type": "golden_set",
        "matched_case_id": "uuid",
        "created_at": "2026-02-23T08:00:00Z"
      }
    ],
    "count": 1,
    "total_count": 1,
    "limit": 50,
    "offset": 0
  }
}
```

## GET `/api/eval/runs/{run_id}/artifacts`

Returns paginated evaluator artifacts captured during execution for each case.

Query params:

- `case_id` (optional UUID)
- `evaluation_mode` (optional): `answer|criteria`
- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "run_id": "uuid",
    "items": [
      {
        "id": "uuid",
        "eval_run_id": "uuid",
        "eval_result_id": "uuid",
        "case_id": "uuid",
        "agent_id": "uuid",
        "evaluation_mode": "answer",
        "judge_mode": "provider",
        "judge_model": "gpt-4.1-mini",
        "judge_prompt_version": "v1",
        "judge_prompt_hash": "sha256",
        "executor_mode": "agent_http",
        "case_latency_ms": 412.5,
        "execution_latency_ms": 155.2,
        "judge_latency_ms": 257.3,
        "token_usage": {"prompt_tokens": 120, "completion_tokens": 45},
        "judge_input": {"input_text": "question"},
        "judge_output": {"answer_correct": "yes"},
        "execution_trace": {"status_code": 200},
        "created_at": "2026-02-24T08:00:00Z"
      }
    ],
    "count": 1,
    "total_count": 1,
    "limit": 50,
    "offset": 0
  }
}
```

## GET `/api/eval/runs/{run_id}/review-queue`

Returns paginated human-review queue items for a run.

Query params:

- `include_reviewed` (optional bool, default `false`)
- `only_actionable` (optional bool, default `true`) filters to failed/partial cases
- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

Status: `200`

## PATCH `/api/eval/runs/{run_id}/results/{result_id}/review`

Records human reviewer decision for one eval result.

Request:

```json
{
  "decision": "accept",
  "reason": "validated by reviewer",
  "override": {}
}
```

`decision` values:
- `accept`: reviewer confirms judge output; `override` ignored.
- `override`: reviewer changes judge output; `reason` required and `override` must include supported fields.

Answer-mode override fields:
- `answer_correct` (`yes|partially|no`)
- `source_correct` (`yes|partially|no`)
- `response_quality` (`good|average|not_good`)

Criteria-mode override fields:
- `overall_score`
- `dimension_scores`
- `criteria_results`

Status: `200`

## GET `/api/eval/compare`

Compares a baseline run against a candidate run for the same agent and reports:
- summary deltas
- per-case regressions (score got worse)

Query params:

- Direct mode:
- `baseline_run_id` (UUID)
- `candidate_run_id` (UUID)
- Reference mode:
- `agent_id` (UUID)
- `baseline_ref` (string)
- `candidate_ref` (string)
- `baseline_ref` and `candidate_ref` can be:
- `active` or `current` (resolve active run registry ref by kind)
- any named ref (resolve run registry by exact name and kind)
- `latest` (resolve most recent eval run for the agent, bypassing run registry)
- `auto_create_pattern` (optional bool, default `false`) auto-opens/reuses an `issue_patterns` record when regressions are found
- `limit` (optional, default `200`, max `1000`) maximum returned regression items

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "baseline_run_id": "uuid",
    "candidate_run_id": "uuid",
    "agent_id": "uuid",
    "baseline_summary": {},
    "candidate_summary": {},
    "total_compared_cases": 120,
    "regression_count": 4,
    "regressions": [
      {
        "case_id": "uuid",
        "evaluation_mode": "answer",
        "metric": "answer_correct",
        "baseline_value": "yes",
        "candidate_value": "partially"
      }
    ],
    "answer_yes_rate_delta": -0.05,
    "source_yes_rate_delta": 0.0,
    "quality_good_rate_delta": -0.02
    "auto_pattern": {
      "enabled": true,
      "created": true,
      "pattern_id": "uuid"
    },
    "notification": {
      "sent": true,
      "event_type": "regression_detected"
    },
    "remediation": {
      "auto_closed": false,
      "updated_patterns": 0,
      "resolved_slo_violations": 0
    }
  }
}
```

Errors:
- `EVAL_RUN_COMPARE_INVALID` on invalid input mode or when baseline and candidate resolve to the same run.
- `EVAL_RUN_COMPARE_MISMATCH` if runs belong to different agents.
- `EVAL_RUN_COMPARE_REFERENCE_NOT_FOUND` when a run ref cannot be resolved.
- `PATTERN_AUTO_CREATE_FAILED` if compare succeeded but pattern write failed.

Remediation auto-close behavior:
- When `regression_count = 0`, compare attempts to auto-close remediation for that baseline/candidate pair:
  - transitions matching `regression_compare` issue patterns to `verifying` (when transition is allowed)
  - resolves matching open SLO violations for `max_regression_count`
  - emits `remediation_verified` activity + webhook event

## PATCH `/api/agents/{agent_id}/patterns/{pattern_id}`

Updates issue pattern lifecycle and metadata.

Status: `200`

Request fields (all optional):
- `status`: `detected|diagnosed|assigned|in_progress|fixed|verifying|resolved|regressed|wont_fix`
- `priority`: `critical|high|medium|low`
- `root_cause`
- `root_cause_type`: `retrieval|prompt|data|model|config`
- `suggested_fix`
- `owner`
- `related_tags` (array of strings)
- `linked_case_ids` (array of UUIDs)
- `verification_result` (object)
- `resolved_date` (`YYYY-MM-DD`)
- `status_note` (appended only when status changes)
- `force` (bool, default `false`) override transition guardrail, platform-admin keys only

Notes:
- Status changes auto-append an entry to `status_history`.
- If status is set to `resolved` and `resolved_date` is omitted, current UTC date is auto-set.
- Transition guardrail blocks invalid jumps (example: `detected -> resolved`) unless `force=true`.

Errors:
- `PATTERN_NOT_FOUND` if `pattern_id` does not belong to `agent_id`.
- `PATTERN_INVALID_TRANSITION` for blocked lifecycle jumps.
- `FORBIDDEN` if `force=true` is used by a non-platform-admin key.
- `PATTERN_UPDATE_FAILED` for update/write failures.

Success response includes:
- `notification` object with:
  - `sent` (bool)
  - `event_type` (`pattern_status_changed`)
  - `error` (optional string when webhook delivery fails)

## GET `/api/agents/{agent_id}/patterns/{pattern_id}/history`

Returns lifecycle audit history for a single issue pattern.

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "pattern_id": "uuid",
    "agent_id": "uuid",
    "status": "in_progress",
    "status_history": [
      { "from": null, "to": "detected", "at": "..." },
      { "from": "detected", "to": "assigned", "at": "...", "note": "Assigned for triage" }
    ],
    "updated_at": "2026-02-24T05:00:00Z"
  }
}
```

Errors:
- `AGENT_NOT_FOUND`
- `PATTERN_NOT_FOUND`

## GET `/api/agents/{agent_id}/activity`

Returns server-side activity feed for an agent.

Query params:
- `event_type` (optional string)
- `severity` (optional: `info|warning|error`)
- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "agent_id": "uuid",
    "items": [
      {
        "id": "uuid",
        "org_id": "uuid",
        "agent_id": "uuid",
        "event_type": "regression_compare",
        "severity": "error",
        "title": "Regression compare executed",
        "details": "baseline=9aa00c75, candidate=27a34a18, regressions=3",
        "metadata": {},
        "created_at": "2026-02-24T06:00:00Z"
      }
    ],
    "count": 1,
    "total_count": 1,
    "limit": 50,
    "offset": 0
  }
}
```

Errors:
- `AGENT_NOT_FOUND`

## GET `/api/agents/{agent_id}/slo-policy`

Returns SLO policy for agent (or `null` if not configured).

## POST `/api/agents/{agent_id}/slo-policy`

Creates/updates SLO policy for agent.

Request fields (all optional):
- `min_answer_yes_rate` (`0..1`)
- `min_source_yes_rate` (`0..1`)
- `min_quality_good_rate` (`0..1`)
- `max_run_duration_ms` (`>0`)
- `max_regression_count` (`>=0`)
- `require_calibration_gate` (`bool`)
- `min_calibration_overall_agreement` (`0..1`)
- `max_calibration_age_days` (`>=1`)
- `require_golden_set_quality_gate` (`bool`)
- `min_verified_case_ratio` (`0..1`)
- `min_active_case_count` (`>=1`)

## GET `/api/agents/{agent_id}/slo-status`

Returns current agent SLO status and recent violations.

Query params:
- `limit_violations` (optional, default `10`, max `100`)

## PATCH `/api/agents/{agent_id}/slo-violations/{violation_id}/resolve`

Marks a SLO violation as resolved.

Errors:
- `SLO_VIOLATION_NOT_FOUND`

## GET `/api/agents/{agent_id}/launch-gate`

Evaluates whether agent can launch based on:
- latest run completed
- no active critical issues
- no open SLO violations
- readiness checklist has no pending items

Returns `can_launch` and `blockers`.

## POST `/api/agents/{agent_id}/launch-decision`

Creates immutable launch decision record (`go|no_go|deferred`) and updates current readiness decision snapshot.

Rules:
- `go` is blocked when launch gate has blockers.

Errors:
- `LAUNCH_GATE_BLOCKED`

## GET `/api/agents/{agent_id}/launch-decisions`

Lists immutable launch decision history (newest first).

## POST `/api/agents/{agent_id}/launch-certify`

Creates an immutable launch certification record with evidence snapshot.

Request:

```json
{
  "decision": "go",
  "reason": "release candidate approved"
}
```

Evidence snapshot includes:
- launch gate evaluation
- latest regression compare event metadata
- computed blockers and certification status (`certified|blocked`)

## GET `/api/agents/{agent_id}/launch-certifications`

Lists launch certification history (newest first).

Not found:

```json
{
  "ok": false,
  "error": {
    "code": "EVAL_RUN_NOT_FOUND",
    "message": "Eval run <id> was not found."
  }
}
```

## GET `/api/eval/runs/{run_id}/summary`

Returns quick aggregate metrics for decision surfaces.

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "run_id": "uuid",
    "status": "pending",
    "total_results": 0,
    "answer_yes_count": 0,
    "answer_partially_count": 0,
    "answer_no_count": 0,
    "source_yes_count": 0,
    "source_partially_count": 0,
    "source_no_count": 0,
    "quality_good_count": 0,
    "quality_average_count": 0,
    "quality_not_good_count": 0,
    "answer_yes_rate": 0.0,
    "source_yes_rate": 0.0,
    "quality_good_rate": 0.0,
    "created_at": "2026-02-23T08:00:00Z",
    "completed_at": null
  }
}
```

## POST `/api/calibration/runs`

Creates a calibration run and computes agreement metrics server-side.

Status: `201`

Request:

```json
{
  "org_id": "uuid",
  "agent_id": "uuid",
  "prompt_version": "judge_prompt_v1",
  "judge_model": "gpt-4.1-mini",
  "per_case_comparison": [
    { "case_id": null, "human_label": "yes", "judge_label": "yes", "is_clean": true },
    { "case_id": null, "human_label": "partially", "judge_label": "no", "is_clean": false }
  ]
}
```

## GET `/api/calibration/runs/{calibration_id}`

Fetches one calibration run by ID.

## GET `/api/agents/{agent_id}/calibration/latest`

Fetches latest calibration run for an agent.

If none exists:

```json
{
  "ok": true,
  "data": {
    "agent_id": "uuid",
    "latest_calibration": null
  }
}
```

## GET `/api/agents/{agent_id}/calibration-gate-status`

Returns calibration gate status used to block production-grade eval execution when enabled by policy.

Fields:
- `enabled` (policy switch)
- `status` (`disabled|pass|fail`)
- `reasons` (why gate failed)
- `min_overall_agreement`, `max_age_days` (active thresholds)
- latest calibration metadata

## GET `/api/golden-sets/{golden_set_id}/quality-gate-status`

Returns golden set quality gate status used to block eval execution when enabled by policy.

Fields:
- `enabled` (policy switch)
- `status` (`disabled|pass|fail`)
- `reasons` (why gate failed)
- `min_verified_case_ratio`, `min_active_case_count` (active thresholds)
- `total_case_count`, `active_case_count`, `verified_case_count`, `verified_case_ratio`

## GET `/api/gate-definitions`

Lists active gate definitions visible to caller.

Query params:
- `org_id` (optional UUID)
- `include_builtin` (optional bool, default `true`)
- `active_only` (optional bool, default `true`)
- `limit` / `offset`

## POST `/api/gate-definitions`

Creates an org-scoped gate definition.

Required:
- `org_id`
- `key`
- `name`
- `evaluator_key`

Supported `evaluator_key` values:
- `calibration_freshness`
- `golden_set_quality`

Versioning fields:
- `contract_version` (optional; semver `x.y.z`, default `1.0.0`)

## GET `/api/agents/{agent_id}/gate-bindings`

Lists configured gate bindings for one agent.

## POST `/api/agents/{agent_id}/gate-bindings`

Creates/updates one gate binding for an agent.

Request fields:
- `gate_definition_id`
- `enabled` (optional, default `true`)
- `config` (optional object; merged with gate definition `default_config` at runtime)

Response includes:
- `definition_contract_version` (definition version snapshot stored at bind time)

## GET `/api/evaluator-definitions`

Lists active evaluator definitions visible to caller.

Query params:
- `org_id` (optional UUID)
- `include_builtin` (optional bool, default `true`)
- `active_only` (optional bool, default `true`)
- `limit` / `offset`

## POST `/api/evaluator-definitions`

Creates an org-scoped evaluator definition.

Required:
- `org_id`
- `key`
- `name`
- `evaluation_mode` (`answer|criteria`)
- `evaluator_kind` (currently `judge_service`)

Versioning fields:
- `contract_version` (optional; semver `x.y.z`, default `1.0.0`)

## GET `/api/agents/{agent_id}/evaluator-bindings`

Lists configured evaluator bindings for one agent by evaluation mode.

## POST `/api/agents/{agent_id}/evaluator-bindings`

Creates/updates one evaluator binding for an agent.

Request fields:
- `evaluator_definition_id`
- `evaluation_mode` (`answer|criteria`, must match definition mode)
- `enabled` (optional, default `true`)
- `config` (optional object; merged with evaluator definition `default_config` at runtime)

Response includes:
- `definition_contract_version` (definition version snapshot stored at bind time)

## GET `/api/run-type-definitions`

Lists active run type definitions visible to caller.

Query params:
- `org_id` (optional UUID)
- `include_builtin` (optional bool, default `true`)
- `active_only` (optional bool, default `true`)
- `run_type` (optional: `eval|regression|ab_comparison|calibration`)
- `limit` / `offset`

## POST `/api/run-type-definitions`

Creates an org-scoped run type definition.

Required:
- `org_id`
- `run_type`
- `key`
- `name`
- `handler_key` (currently: `default`, `sync_only`, `async_only`)

Versioning fields:
- `contract_version` (optional; semver `x.y.z`, default `1.0.0`)

## GET `/api/agents/{agent_id}/run-type-bindings`

Lists configured run type bindings for one agent.

## POST `/api/agents/{agent_id}/run-type-bindings`

Creates/updates one run type binding for an agent.

Request fields:
- `run_type_definition_id`
- `run_type` (must match definition run_type)
- `enabled` (optional, default `true`)
- `config` (optional object; merged with run type definition `default_config` at runtime)

Response includes:
- `definition_contract_version` (definition version snapshot stored at bind time)

## GET `/api/agents/{agent_id}/contract-status`

Returns agent contract preflight status for a run context.

Query params:
- `run_type` (`eval|regression|ab_comparison|calibration`)
- `entrypoint` (`start|execute`)
- `golden_set_id` (optional UUID; required by some gate bindings)

Response includes:
- `status` (`pass|fail`)
- `issues` (error/warning list across run handler, gate bindings, evaluator bindings)
- `resolved_handler_key`
- enabled binding counts for gates/evaluators
- version compatibility findings across `definition_contract_version` vs current definition `contract_version`

## POST `/api/contracts/upgrade-preview`

Previews impact of upgrading a contract definition version before rollout.

Required fields:
- `definition_type` (`gate|evaluator|run_type`)
- `definition_id`
- `target_contract_version` (semver `x.y.z`)

Optional:
- `include_items` (default `true`)
- `max_items` (default `200`, max `1000`)

Response includes:
- `status` (`safe|risky`)
- impact counts: `breaking_count`, `warning_count`, `invalid_count`, `unchanged_count`
- per-binding impact items (`none|warning|breaking|invalid`)

## POST `/api/contracts/apply-upgrade`

Applies contract version upgrade to a definition and optionally rolls out to bindings.

Required fields:
- `definition_type` (`gate|evaluator|run_type`)
- `definition_id`
- `target_contract_version` (semver `x.y.z`)

Optional:
- `rollout_mode`:
  - `definition_only` (default): update definition version only
  - `sync_bindings`: update definition version and set all linked binding `definition_contract_version` to target

Rules:
- builtin definitions (`org_id=null`) are immutable for upgrade apply (`CONTRACT_DEFINITION_IMMUTABLE`)

Response includes:
- `bindings_updated` count
- post-apply preview snapshot

## GET `/api/contracts/drift`

Scans contract version drift across agent bindings for one org.

Query params:
- `org_id` (optional for org-scoped keys, required for global keys)
- `agent_id` (optional; restrict scan to one agent)
- `include_healthy` (optional bool, default `false`)
- `limit` (optional, default `200`, max `1000`; applies to agent scan set)

Response includes:
- `checked_agent_count`
- drift counts: `breaking_count`, `warning_count`, `invalid_count`
- `items[]` with per-binding drift classification:
  - `none` (only when `include_healthy=true`)
  - `warning` (minor/patch drift)
  - `breaking` (major mismatch)
  - `invalid` (bad semver data)

## POST `/api/contracts/drift/promote-patterns`

Promotes drift findings into issue patterns (`primary_tag=contract_drift`) with dedupe.

Required fields:
- `org_id`

Optional:
- `agent_id` (promote for one agent only)
- `min_drift` (`warning|breaking|invalid`, default `breaking`)
- `dry_run` (default `false`)
- `limit` (default `200`, max `1000`)

Behavior:
- scans drift findings using same drift monitor rules
- eligible findings are promoted to patterns
- dedupe key for open patterns:
  - `binding_id`
  - `bound_contract_version`
  - `current_contract_version`

Response includes:
- `scanned_item_count`
- `eligible_item_count`
- `created_pattern_count`
- `reused_pattern_count`
- `pattern_ids`
- `notification` (webhook dispatch status for event `contract_drift_patterns_promoted`)

## GET `/api/system/contracts/drift-policy`

Admin endpoint returning org-level drift automation policy.

Query params:
- `org_id` (required)

Default returned when no row exists:
- `enabled=false`
- `min_drift=breaking`
- `promote_to_patterns=true`
- `scan_limit=200`
- `schedule_name=daily`
- `schedule_window_minutes=1440`
- `alert_enabled=false`
- `alert_max_dedupe_hit_rate=0.7`
- `alert_min_execution_rate=0.5`
- `alert_cooldown_minutes=60`

## POST `/api/system/contracts/drift-policy`

Admin endpoint to create/update org-level drift automation policy.

Request body:
- `org_id`
- `enabled`
- `min_drift` (`warning|breaking|invalid`)
- `promote_to_patterns` (bool)
- `scan_limit` (`1..1000`)
- `schedule_name`
- `schedule_window_minutes` (`5..10080`)
- `alert_enabled` (bool)
- `alert_max_dedupe_hit_rate` (`0..1`)
- `alert_min_execution_rate` (`0..1`)
- `alert_cooldown_minutes` (`0..10080`)

## POST `/api/system/contracts/drift/trigger`

Admin scheduler-ready trigger endpoint for drift promotion workflow.

Required headers:
- `Idempotency-Key`

Request body:
- `org_id`
- `schedule_name` (default `manual`)
- `window_minutes` (default `60`)
- `dry_run` (default `false`)
- `force` (default `false`)
- `agent_id` (optional)
- `min_drift` (optional override)
- `limit` (optional override)

Behavior:
- reads drift policy defaults for min/limit
- skips when policy disabled unless `force=true`
- skips when promotion disabled unless `force=true`
- dedupes within schedule window using audit log key
- on execute, invokes drift promotion endpoint and returns promote result

## GET `/api/system/contracts/drift/trigger-summary`

Admin endpoint with recent trigger history and aggregate trigger outcomes.

Query params:
- `org_id` (required)
- `schedule_name` (optional)
- `window_days` (default `30`)
- `limit` (default `50`, max `200`)

Response includes:
- aggregate counts:
  - `trigger_count`
  - `executed_count`
  - `deduped_count`
  - `policy_disabled_count`
  - `promotion_disabled_count`
- rates:
  - `execution_rate`
  - `dedupe_hit_rate`
- recent audit events (`items[]`) with:
  - `request_id`, `status_code`, `error_code`, `created_at`, `path`

## POST `/api/system/contracts/drift/trigger-summary/notify`

Admin endpoint to evaluate drift trigger-summary anomalies and optionally send webhook notification.

Required headers:
- `Idempotency-Key`

Request body:
- `org_id` (required)
- `schedule_name` (optional)
- `agent_id` (optional; escalation target and notification context)
- `window_days` (default `30`)
- `dry_run` (default `true`)
- `force_notify` (default `false`)

Behavior:
- reads alert controls from drift policy:
  - `alert_enabled`
  - `alert_max_dedupe_hit_rate`
  - `alert_min_execution_rate`
  - `alert_cooldown_minutes`
- anomaly when:
  - `dedupe_hit_rate >= alert_max_dedupe_hit_rate`, or
  - `execution_rate < alert_min_execution_rate`
- cooldown suppresses duplicate notifications unless `force_notify=true`
- writes explicit notify outcome audit codes:
  - `CONTRACT_DRIFT_ANOMALY_NOTIFY_SENT`
  - `CONTRACT_DRIFT_ANOMALY_NOTIFY_FAILED`
  - `CONTRACT_DRIFT_ANOMALY_NOTIFY_SUPPRESSED`
  - `CONTRACT_DRIFT_ANOMALY_NOTIFY_SKIPPED`
  - `CONTRACT_DRIFT_ANOMALY_NOTIFY_DRY_RUN`
- escalation rule:
  - if notify send fails on non-dry run, auto-creates/reuses a high-priority issue pattern:
    - `primary_tag=contract_drift_alert_delivery`

## GET `/api/system/contracts/drift/trigger-alert-delivery`

Admin endpoint for drift-trigger alert delivery observability.

Query params:
- `org_id` (required)
- `schedule_name` (optional)
- `window_days` (default `30`)

Response includes:
- notify totals:
  - `total_notify_events`
  - `sent_count`
  - `failed_count`
  - `suppressed_count`
  - `skipped_count`
  - `dry_run_count`
- last timestamps:
  - `last_event_at`
  - `last_sent_at`
  - `last_failed_at`
  - `last_suppressed_at`
  - `last_notified_at`

## POST `/api/system/contracts/drift/schedule-run`

Admin scheduler endpoint that orchestrates drift trigger + anomaly notify in one idempotent call.

Required headers:
- `Idempotency-Key`

Request body:
- `org_id` (required)
- `schedule_name` (optional, defaults from drift policy)
- `window_minutes` (optional, defaults from drift policy)
- `summary_window_days` (default `30`)
- `dry_run` (default `false`)
- `force` (default `false`) for trigger stage
- `force_notify` (default `false`) for notify stage
- `agent_id` (optional)
- `min_drift` (optional override)
- `limit` (optional override)

Behavior:
- resolves schedule defaults from drift policy
- calls:
  - `POST /api/system/contracts/drift/trigger`
  - `POST /api/system/contracts/drift/trigger-summary/notify`
- returns nested `trigger` + `notify` payloads for one-shot scheduler observability
- propagates `agent_id` into notify context so escalation can bind to target agent

## GET `/api/agents`

Lists agents with optional filters and pagination.

Query params:

- `org_id` (uuid, optional)
- `status` (optional): `backlog|build|testing|production|retired`
- `agent_type` (optional): `search_retrieval|document_generator|dashboard_assistant|triage_classification|analysis`
- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "items": [
      {
        "id": "uuid",
        "org_id": "uuid",
        "name": "Data Retrieval Agent",
        "description": "Demo retrieval agent for API smoke testing",
        "agent_type": "search_retrieval",
        "status": "build",
        "model": "gpt-4.1",
        "api_endpoint": null,
        "owner_user_id": null,
        "eval_profile_id": null,
        "created_at": "2026-02-23T08:00:00Z",
        "updated_at": "2026-02-23T08:00:00Z"
      }
    ],
    "count": 1,
    "limit": 50,
    "offset": 0
  }
}
```

## POST `/api/agents`

Registers a new agent.

Status: `201`

Request:

```json
{
  "org_id": "uuid",
  "name": "Data Retrieval Agent",
  "description": "Retrieval copilot for enterprise knowledge",
  "agent_type": "search_retrieval",
  "status": "build",
  "model": "gpt-4.1",
  "api_endpoint": null,
  "owner_user_id": null,
  "eval_profile_id": null
}
```

## GET `/api/agents/{agent_id}`

Returns one agent by ID.

Status: `200`

Not found:

```json
{
  "ok": false,
  "error": {
    "code": "AGENT_NOT_FOUND",
    "message": "Agent <id> was not found."
  }
}
```

## POST `/api/agents/{agent_id}/invoke-contract/validate`

Validates agent invocation contract and endpoint reachability for real execution mode.

Status: `200`

Request:

```json
{
  "endpoint_override": null,
  "sample_input": "contract validation probe",
  "timeout_ms": 15000,
  "headers": {}
}
```

Notes:
- Uses agent `api_endpoint` unless `endpoint_override` is provided.
- Sends `POST` JSON payload: `{ "input": "<sample_input>" }`.
- Validates response can be parsed into a usable output field.
- Returns replay hashes and extracted mapping keys for observability.

Errors:
- `AGENT_INVOKE_CONTRACT_CONFIG_ERROR` for missing/invalid endpoint config.
- `AGENT_INVOKE_CONTRACT_RUNTIME_ERROR` for HTTP/network/parse runtime failures.

Success:

```json
{
  "ok": true,
  "data": {
    "agent_id": "uuid",
    "endpoint": "https://agent.example.com/invoke",
    "valid": true,
    "issues": [],
    "status_code": 200,
    "latency_ms": 42.4,
    "content_type": "application/json",
    "response_preview": "{\"response\":\"...\"}",
    "request_hash": "sha256",
    "response_hash": "sha256",
    "response_key_used": "response",
    "source_key_used": "sources",
    "extracted_response": "text",
    "extracted_sources": "doc-a, doc-b"
  }
}
```

## GET `/api/agents/{agent_id}/latest`

Returns latest eval run and compact run summary for an agent.

Status: `200`

If the agent has no runs:

```json
{
  "ok": true,
  "data": {
    "agent_id": "uuid",
    "latest_run": null
  }
}
```

## GET `/api/agents/{agent_id}/score-trend`

Returns a paginated run score timeline for an agent.

Query params:
- `window_days` (optional, default `30`, max `365`)
- `limit` (optional, default `30`, max `200`)
- `offset` (optional, default `0`)

Status: `200`

## GET `/api/agents/{agent_id}/health`

Returns a single rollup health view for an agent:
- launch gate verdict (`can_launch`, blockers)
- latest run status
- latest completed run rates
- active issues / critical issues / open SLO violations
- readiness decision snapshot

Status: `200`

## GET `/api/orgs/{org_id}/portfolio-health`

Returns org-level portfolio health across agents:
- per-agent launch readiness posture
- latest completed score rates
- blocked vs healthy counts
- org-level average rates

Query params:
- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

Status: `200`

## POST `/api/eval/templates`

Creates an org-scoped eval run template.

Status: `201`

Request:

```json
{
  "org_id": "uuid",
  "name": "retrieval-default",
  "description": "Default retrieval eval config",
  "run_type": "eval",
  "agent_type": "search_retrieval",
  "default_golden_set_id": "uuid-or-null",
  "config": {"sample_size": "all"},
  "design_context": {"reason": "template"},
  "is_active": true
}
```

## GET `/api/eval/templates`

Lists eval templates for an org.

Query params:
- `org_id` (required UUID)
- `run_type` (optional)
- `agent_type` (optional)
- `include_inactive` (optional, default `false`)
- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

## GET `/api/eval/templates/{template_id}`

Returns one eval template by ID.

## POST `/api/agents/{agent_id}/run-registry`

Upserts a named run reference for the agent (`baseline` or `candidate`).

Status: `201`

Request:

```json
{
  "kind": "baseline",
  "name": "default",
  "run_id": "uuid",
  "is_active": true,
  "notes": "optional",
  "metadata": {}
}
```

Rules:
- `run_id` must belong to same org + agent.
- When `is_active=true`, previous active ref of same `kind` is deactivated.

## GET `/api/agents/{agent_id}/run-registry`

Lists run references for an agent.

Query params:
- `kind` (optional: `baseline|candidate`)
- `include_inactive` (optional, default `false`)
- `limit` (default `50`, max `200`)
- `offset` (default `0`)

## GET `/api/agents/{agent_id}/run-registry/resolve`

Resolves a run reference.

Query params:
- `kind` (required: `baseline|candidate`)
- `name` (optional; when omitted resolves active ref)

Returns:
- `ref: null` when no matching reference exists.

## POST `/api/agents/{agent_id}/run-registry/promote-candidate`

Promotes a candidate run to active baseline reference for the same agent.

Status: `200`

Request:

```json
{
  "candidate_run_id": "uuid (optional)",
  "candidate_ref": "active (optional, default active)",
  "baseline_run_id": "uuid (optional)",
  "baseline_name": "default",
  "require_clean_compare": true,
  "clean_compare_window_minutes": 60,
  "notes": "optional",
  "metadata": {}
}
```

Rules:
- If `candidate_run_id` is omitted, server resolves `candidate_ref`.
- `candidate_ref` supports `active|current|latest|<name>`.
- Candidate run must belong to the same org + agent.
- When `require_clean_compare=true` (default), promotion is blocked unless a `regression_compare`
  event exists with:
  - matching `baseline_run_id` + `candidate_run_id`
  - `regression_count=0`
  - `created_at` within the configured window.
- Endpoint deactivates existing active baseline ref and upserts the new active baseline.

## POST `/api/golden-sets/upload`

Creates one golden set and inserts all provided cases (canonical JSON upload).

Status: `201`

Request:

```json
{
  "org_id": "uuid",
  "agent_id": "uuid",
  "name": "Acme Retrieval GS v1",
  "description": "Core retrieval test suite",
  "generation_method": "manual",
  "source_files": ["acme-kb-v1.pdf"],
  "cases": [
    {
      "input": "What is Acme's remote work policy?",
      "expected_output": "Acme supports hybrid work with 3 in-office days per week.",
      "acceptable_sources": "HR Policy 2026",
      "evaluation_mode": "answer",
      "difficulty": "easy",
      "capability": "retrieval",
      "scenario_type": "straightforward",
      "domain": "hr",
      "verification_status": "unverified"
    }
  ]
}
```

Success:

```json
{
  "ok": true,
  "data": {
    "golden_set_id": "uuid",
    "name": "Acme Retrieval GS v1",
    "case_count": 1,
    "case_ids": ["uuid"],
    "created_at": "2026-02-23T08:00:00Z"
  }
}
```

## POST `/api/golden-sets/upload-file`

File upload (JSON + base64 payload) for server-side ingestion + normalization (`csv`, `jsonl`, `xlsx`).

Status: `201`

Request:

```json
{
  "org_id": "uuid",
  "agent_id": "uuid",
  "name": "Acme Retrieval GS v2",
  "description": "optional",
  "generation_method": "manual",
  "source_files": ["acme-kb-v2.pdf"],
  "filename": "cases.csv",
  "file_content_base64": "<base64 bytes>"
}
```

Input column aliases (case-insensitive):
- `input|query|prompt|question`
- `expected_output|expected|expected_answer|golden_answer`
- `acceptable_sources|sources|source|citations|references`
- `evaluation_mode|mode`
- `evaluation_criteria|criteria|rubric`
- `difficulty|difficulty_level`
- `capability|capability_type`
- `scenario_type|scenario`
- `verification_status|verification`

Defaults applied when missing:
- `evaluation_mode=answer`
- `difficulty=medium`
- `capability=retrieval`
- `scenario_type=straightforward`
- `verification_status=unverified`

Success includes validation report:

```json
{
  "ok": true,
  "data": {
    "golden_set_id": "uuid",
    "name": "Acme Retrieval GS v2",
    "case_count": 124,
    "case_ids": ["uuid"],
    "created_at": "2026-02-24T12:00:00Z",
    "validation_report": {
      "input_format": "csv",
      "total_rows": 130,
      "accepted_rows": 124,
      "rejected_rows": 6,
      "issues": [
        {"row": 5, "message": "row 5: ..."}
      ]
    }
  }
}
```

Errors:
- `GOLDEN_SET_FILE_PARSE_FAILED` when file cannot be parsed.
- `GOLDEN_SET_FILE_VALIDATION_FAILED` when no valid rows remain after validation.

## GET `/api/golden-sets/{golden_set_id}/cases`

Lists cases for a golden set with governance fields (`version`, `is_active`, `superseded_by`).

Query params:
- `include_inactive` (optional, default `false`)
- `limit` (optional, default `100`, max `500`)
- `offset` (optional, default `0`)

## PATCH `/api/golden-sets/{golden_set_id}/cases/{case_id}/verify`

Updates case verification status and records a review event.

Request:

```json
{
  "verification_status": "verified",
  "notes": "reviewed by QA"
}
```

## POST `/api/golden-sets/{golden_set_id}/cases/{case_id}/supersede`

Creates a new version of a case and marks the previous one inactive/superseded.

Request:

```json
{
  "input": "updated query",
  "expected_output": "updated expected output",
  "acceptable_sources": "Policy 2027",
  "evaluation_mode": "answer",
  "difficulty": "easy",
  "capability": "retrieval",
  "scenario_type": "straightforward",
  "domain": "hr",
  "verification_status": "unverified",
  "notes": "superseded by policy refresh"
}
```

## GET `/api/agents/{agent_id}/golden-sets`

Lists golden sets for one agent with case counts.

Query params:

- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "items": [
      {
        "id": "uuid",
        "org_id": "uuid",
        "agent_id": "uuid",
        "name": "Acme Retrieval GS v1",
        "description": "Core retrieval smoke set",
        "generation_method": "manual",
        "case_count": 1,
        "created_at": "2026-02-23T08:00:00Z"
      }
    ],
    "count": 1,
    "limit": 50,
    "offset": 0
  }
}
```

## GET `/api/agents/{agent_id}/patterns`

Lists issue patterns for an agent.

Query params:

- `status` (optional): `detected|diagnosed|assigned|in_progress|fixed|verifying|resolved|regressed|wont_fix`
- `priority` (optional): `critical|high|medium|low`
- `limit` (optional, default `50`, max `200`)
- `offset` (optional, default `0`)

Status: `200`

Success:

```json
{
  "ok": true,
  "data": {
    "items": [],
    "count": 0,
    "limit": 50,
    "offset": 0
  }
}
```

## POST `/api/agents/{agent_id}/patterns`

Creates one issue pattern for an agent.

Status: `201`

Request:

```json
{
  "title": "Incorrect policy citation on HR queries",
  "primary_tag": "wrong_source",
  "related_tags": ["citation_mismatch", "weak_authority"],
  "status": "detected",
  "priority": "high",
  "root_cause_type": "retrieval",
  "suggested_fix": "Boost authoritative HR policy documents",
  "linked_case_ids": []
}
```

## GET `/api/agents/{agent_id}/readiness`

Returns launch readiness object for an agent.

Status: `200`

If no readiness record exists:

```json
{
  "ok": true,
  "data": {
    "agent_id": "uuid",
    "readiness": null
  }
}
```

## POST `/api/agents/{agent_id}/readiness`

Creates or updates launch readiness for an agent (`upsert` by `agent_id`).

Status: `201`

Request:

```json
{
  "items": [
    { "id": "ops_monitoring", "status": "done", "owner": "ops_lead" },
    { "id": "rollback_plan", "status": "in_progress", "owner": "eng_manager" }
  ],
  "thresholds": {
    "pass_rate_strict": 0.8,
    "judge_agreement": 0.7
  },
  "decision": "deferred",
  "decision_notes": "Need rollback item complete",
  "decision_date": null
}
```

If latest run exists:

```json
{
  "ok": true,
  "data": {
    "agent_id": "uuid",
    "latest_run": {
      "run_id": "uuid",
      "run_name": "acme-smoke-eval-001",
      "run_type": "eval",
      "run_status": "pending",
      "created_at": "2026-02-23T08:00:00Z",
      "completed_at": null,
      "total_results": 0,
      "answer_yes_count": 0,
      "answer_partially_count": 0,
      "answer_no_count": 0,
      "source_yes_count": 0,
      "source_partially_count": 0,
      "source_no_count": 0,
      "quality_good_count": 0,
      "quality_average_count": 0,
      "quality_not_good_count": 0,
      "answer_yes_rate": 0.0,
      "source_yes_rate": 0.0,
      "quality_good_rate": 0.0
    }
  }
}
```

Success:

```json
{
  "ok": true,
  "data": {
    "id": "uuid",
    "org_id": "uuid",
    "name": "Data Retrieval Agent",
    "description": "Retrieval copilot for enterprise knowledge",
    "agent_type": "search_retrieval",
    "status": "build",
    "model": "gpt-4.1",
    "api_endpoint": null,
    "owner_user_id": null,
    "eval_profile_id": null,
    "created_at": "2026-02-23T08:00:00Z",
    "updated_at": "2026-02-23T08:00:00Z"
  }
}
```
