# Greenlight Build Progress

Short plain-English log of major foundation steps.

## 2026-02-23

### Step 1: Tier 1 Database Foundation
- Added core schema for platform primitives:
  - orgs, profiles, org_members
  - eval_profiles
  - agents
  - golden_sets, golden_set_cases
- Added strict enums and constraints to prevent taxonomy/value drift.
- Added mode validation on golden set cases so answer-based and criteria-based fields cannot be mixed incorrectly.
- Applied successfully in Supabase SQL Editor.

### Step 2: Tier 2 Evaluation Engine Schema
- Added evaluation run tables:
  - eval_runs
  - eval_results
  - calibration_runs
- Added run lifecycle checks (status must align with completed timestamps).
- Added result-shape checks by evaluation mode (answer vs criteria).
- Added calibration agreement bounds (0..1).
- Applied successfully in Supabase SQL Editor.

## Next Planned Major Step
- Seed built-in eval profiles (5 profiles) into `eval_profiles`.

## 2026-02-23 (continued)

### Step 3: Built-in Eval Profile Seed Migration
- Added idempotent seed migration for 5 built-in profiles:
  - Search/Retrieval
  - Document Generator
  - Dashboard/Analytics
  - Triage/Classification
  - Analysis
- Seeded each profile with dimensions, scoring scales, and issue tags.
- Profiles are global built-ins (`org_id = null`, `is_builtin = true`).

### Step 4: Baseline RLS Policies
- Added row-level security baseline across Tier 1 + Tier 2 tables.
- Added helper functions for org membership and role checks:
  - `is_org_member(...)`
  - `has_org_role(...)`
- Enforced org-scoped read/write access.
- Allowed built-in eval profiles to be readable by authenticated users.

### Step 5: API Foundation v1 (Minimal)
- Added FastAPI service scaffold with response envelope standard.
- Added API key auth via `Authorization: Bearer <key>`.
- Added endpoints:
  - `POST /api/eval/runs` (async run creation, returns `202`)
  - `GET /api/eval/runs/{run_id}` (status + optional results)
- Added API docs at `/docs/api-v1.md`.
- Verified end-to-end against Supabase:
  - created run `3992a76f-0774-4c23-9f6b-49f06f3547f9`
  - fetched run successfully with pending status and `result_count = 0`

### Step 6: Eval Summary Endpoint
- Added `GET /api/eval/runs/{run_id}/summary`.
- Returns compact aggregate counts and rates for answer/source/quality scoring.
- Handles zero-result runs safely with `0.0` rates.

### Step 7: Agent List Endpoint
- Added `GET /api/agents` with optional filters:
  - `org_id`, `status`, `agent_type`
  - `limit`, `offset`
- Added API docs with request/response shape.

### Step 8: Agent Create Endpoint
- Added `POST /api/agents` (register agent via API, returns `201`).
- Supports required core fields and optional ownership/profile linkage.
- Keeps envelope and error format consistent with existing endpoints.

### Step 9: Agent Detail + Latest Endpoints
- Added `GET /api/agents/{agent_id}` for single agent detail.
- Added `GET /api/agents/{agent_id}/latest` for latest eval run summary.
- Returns `latest_run: null` when no runs exist.

### Step 10: Golden Set JSON Upload Endpoint
- Added `POST /api/golden-sets/upload`.
- API now creates `golden_sets` + bulk inserts `golden_set_cases` in one transaction.
- Current supported ingestion format is canonical JSON payload.
- XLSX ingestion path is explicitly marked as planned.

### Step 11: Agent Golden Sets List Endpoint
- Added `GET /api/agents/{agent_id}/golden-sets`.
- Returns golden set metadata with aggregated `case_count`.
- Includes pagination fields (`limit`, `offset`) for UI list rendering.

### Step 12: Operations Read Endpoints
- Added `GET /api/agents/{agent_id}/patterns`.
- Added `GET /api/agents/{agent_id}/readiness`.
- These endpoints are backed by new operations tables (`issue_patterns`, `launch_readiness`).

### Step 13: Operations Write Endpoints
- Added `POST /api/agents/{agent_id}/patterns` to create issue patterns via API.
- Added `POST /api/agents/{agent_id}/readiness` as upsert (one readiness record per agent).
- `org_id` is inferred from `agent_id` to preserve tenant integrity.

### Step 14: Eval Run Execution Endpoint
- Added `POST /api/eval/runs/{run_id}/execute`.
- Endpoint moves run status through execution and writes `eval_results`.
- Supports both answer-mode and criteria-mode case shapes.
- Updates run to `completed` with `completed_at` (or `failed` with reason on error).

### Step 15: Eval Results Detail Endpoint
- Added `GET /api/eval/runs/{run_id}/results`.
- Supports pagination and filters (`evaluation_mode`, answer/source/quality fields).
- Provides case-level diagnostics for drill-down from summary views.

### Step 16: API Key Store (DB-backed Auth)
- Added `api_keys` migration with hashed key storage and status/expiry fields.
- Updated API auth to validate bearer tokens against DB (`sha256` hash match).
- Added `last_used_at` tracking on successful auth.

### Step 17: API Key Lifecycle Endpoints
- Removed env key fallback from auth path (DB-backed keys only).
- Added `POST /api/system/api-keys` (create and return plaintext key once).
- Added `POST /api/system/api-keys/{id}/revoke` (key revocation).

### Step 18: API Contract Hardening
- Added global request validation handler with standard error envelope (`VALIDATION_ERROR`).
- Added OpenAPI request examples on key write endpoints:
  - `POST /api/system/api-keys`
  - `POST /api/agents`
  - `POST /api/golden-sets/upload`
  - `POST /api/eval/runs`

### Step 19: Repeatable API Smoke Suite
- Added executable smoke script: `/scripts/smoke_api.sh`.
- Covers end-to-end core flow (health -> create run -> execute -> summary/results).
- Includes envelope contract check for validation errors.
- Added usage guide: `/docs/api-smoke.md`.

### Step 20: CI Smoke Gate (GitHub Actions)
- Added workflow: `/.github/workflows/api-smoke.yml`.
- CI starts API server, waits on health, then runs smoke suite.
- Added setup doc for required repository secrets: `/docs/ci-smoke-setup.md`.
- Improved smoke diagnostics for agent-list failure (prints API response on fail).

### Step 21: Calibration APIs
- Added `POST /api/calibration/runs` with server-computed agreement metrics.
- Added `GET /api/calibration/runs/{id}`.
- Added `GET /api/agents/{agent_id}/calibration/latest`.
- Supports storing per-case human vs judge comparisons in `calibration_runs`.

### Step 22: Pluggable Judge Service Layer
- Added service module: `/src/api/services/judge.py`.
- Moved eval scoring and calibration agreement math out of API route file.
- `execute` and calibration endpoints now call service-layer functions.
- Established clean path for future provider-backed judge/generation without endpoint redesign.

### Step 23: Provider Judge Scaffold + Error Contracts
- Added `judge_mode=provider` scaffold with env validation checks.
- Introduced typed judge errors:
  - configuration errors -> `EVAL_JUDGE_CONFIG_ERROR`
  - not-implemented provider path -> `EVAL_JUDGE_NOT_READY`
- Kept deterministic mode as default, stable execution path.

### Step 24: OpenAI Provider Judge Implementation (v1)
- Implemented OpenAI-backed provider path in judge service for:
  - answer-mode scoring
  - criteria-mode scoring
- Added JSON response parsing and provider runtime error mapping.
- Added `EVAL_JUDGE_PROVIDER_ERROR` API contract for provider execution failures.

### Step 25: API Key Visibility Endpoint
- Added `GET /api/system/api-keys` for key status/debugging.
- Returns key metadata only (id/prefix/status/expiry/last-used), no hash/plaintext.
- Added optional status filter and pagination.

### Step 26: Execution Observability Traces
- Added per-case execution trace metadata in `eval_results.notes` (JSON string):
  - judge mode/model/prompt version
  - per-case latency (ms)
- Added run-level execution summary merge into `eval_runs.design_context`:
  - case count
  - total duration (ms)
  - execution timestamp

### Step 27: Judge Service Unit Tests + CI Gate
- Added unit tests for judge service and agreement math:
  - `/tests/test_judge_service.py`
- Added `pytest` to dependencies.
- Updated CI workflow to run unit tests before smoke suite.

### Step 28: Profile-as-Policy Contract Enforcement
- Added policy service module: `/src/api/services/policy.py`.
- Enforced profile contract checks during eval execution:
  - score-scale validation
  - issue-tag allowlist validation
  - criteria required-dimension validation
- Added profile resolution strategy:
  - agent `eval_profile_id` first
  - built-in profile fallback by `agent_type`
- Added explicit API error contract: `EVAL_POLICY_CONTRACT_ERROR`.

### Step 29: UI Contract Violation Diagnostics
- Added Streamlit "Policy Contract Status" panel in run detail.
- Surfaces contract failures from run status/failure reason with clear error display.

### Step 30: Run-to-Run Regression Comparison API
- Added `GET /api/eval/compare` for baseline vs candidate comparison.
- Enforces same-agent comparison to keep deltas meaningful.
- Returns:
  - baseline/candidate summaries
  - answer/source/quality rate deltas
  - per-case regression items (when candidate score is worse)
- Added unit tests for regression scoring helpers and summary edge cases.

### Step 31: Streamlit Regression Compare Panel
- Added a new Streamlit section for run-to-run comparison.
- Inputs:
  - baseline run ID
  - candidate run ID
- Outputs:
  - compared-case count
  - regression count
  - answer/quality deltas
  - detailed regression table and raw comparison JSON
- Added explicit regression/no-regression status messaging for PM-facing usage.

### Step 32: Compare-to-Issue Pattern Automation
- Added `auto_create_pattern` option to `GET /api/eval/compare`.
- When enabled and regressions exist:
  - reuses an existing open `regression_compare` issue pattern for the same baseline/candidate pair, or
  - creates a new high-priority issue pattern with linked case IDs and delta metadata.
- Added Streamlit toggle to trigger this option from the Regression Compare section.

### Step 33: Issue Pattern Lifecycle Update API
- Added `PATCH /api/agents/{agent_id}/patterns/{pattern_id}`.
- Supports lifecycle and ownership updates for existing issue patterns:
  - status, priority, owner, root cause, suggested fix, tags, linked cases, verification payload
- Automatically appends `status_history` entries when status changes.
- Auto-stamps `resolved_date` when moving to `resolved` without an explicit date.

### Step 34: Streamlit Pattern Lifecycle Controls
- Added a new Streamlit section to manage issue patterns from UI.
- Added actions:
  - load/refresh patterns for selected agent
  - select pattern
  - update status, priority, owner, and status note via PATCH endpoint
- Added details expander for quick pattern inspection.

### Step 35: Pattern Transition Guardrails + Admin Override
- Added lifecycle transition matrix enforcement in `PATCH /api/agents/{agent_id}/patterns/{pattern_id}`.
- Invalid status jumps now return `PATTERN_INVALID_TRANSITION`.
- Added `force=true` override for platform-admin API keys only (global keys with `org_id = null`).
- Added helper tests for allowed/blocked transitions.

### Step 36: Webhook Notifications (Regression + Lifecycle)
- Added notifier service: `/src/api/services/notify.py`.
- Added best-effort webhook events:
  - `regression_detected` from compare endpoint (when regressions exist)
  - `pattern_status_changed` from pattern lifecycle updates (on status change)
- Added env controls:
  - `NOTIFY_WEBHOOK_URL`
  - `NOTIFY_WEBHOOK_EVENTS`
  - `NOTIFY_WEBHOOK_SECRET`
- Notification delivery failures are reported in response payloads and do not block core workflow writes.

### Step 37: Pattern History API
- Added `GET /api/agents/{agent_id}/patterns/{pattern_id}/history`.
- Returns pattern lifecycle state plus `status_history` audit trail.
- Enables PM/audit views without querying raw DB tables.

### Step 38: Streamlit Pattern History Panel
- Added "Load Pattern History" action in pattern lifecycle section.
- Displays current pattern status/updated timestamp plus `status_history` table.
- History is scoped to currently selected pattern for clear PM review flow.

### Step 39: Streamlit Quick Lifecycle Actions
- Added one-click pattern actions in UI:
  - Move to In Progress
  - Mark Fixed
  - Move to Verifying
  - Resolve
- Actions are enabled only when allowed by the transition guardrail.
- Each quick action calls PATCH endpoint and refreshes pattern list on success.

### Step 40: Streamlit Activity Feed
- Added a new Activity Feed section to consolidate session-level operational events.
- Feed tracks:
  - run lifecycle actions (load latest/create/execute)
  - regression comparisons
  - pattern transitions
  - notification sent/failed outcomes
- Added clear-feed control and newest-first timeline rendering.

### Step 41: Server-Side Activity Feed
- Added migration `tier6_activity_events` with RLS and indexes.
- Added backend best-effort activity writes for:
  - run created/executed
  - regression compare
  - pattern transition updates
- Added `GET /api/agents/{agent_id}/activity` endpoint with filters/pagination.
- Updated Streamlit Activity Feed with source toggle:
  - Session feed
  - Server feed (loaded from API)

### Step 42: Idempotency for Mutating APIs
- Added migration `tier7_idempotency_keys` for request replay storage.
- Added API middleware for `POST|PATCH|PUT|DELETE` under `/api/*` using `Idempotency-Key` header.
- Behavior:
  - same key + same payload => returns original stored response
  - same key + different payload => `IDEMPOTENCY_KEY_REUSED` (409)
  - duplicate while first call in progress => `IDEMPOTENCY_IN_PROGRESS` (409)
- Implemented as best-effort safety layer without breaking existing endpoint contracts.

### Step 43: Request Correlation IDs
- Added request correlation middleware with `X-Request-Id` support:
  - client-provided header is honored
  - server generates UUID when not provided
- Ensured idempotency replay/conflict responses include `X-Request-Id`.
- Added automatic `request_id` enrichment into server-side activity event metadata for cross-system tracing.

### Step 44: API Audit Logs for Mutations
- Added migration `tier8_api_audit_logs` with indexes and restrictive RLS.
- Added middleware to log mutating `/api/*` calls with:
  - `request_id`
  - `api_key_id` / `org_id` (if authenticated)
  - `method`, `path`, `status_code`, `latency_ms`
  - `error_code` extracted from standard error envelope when present
- Logging is best-effort and does not block request handling.

### Step 45: Admin Audit Log API
- Added admin-only endpoint: `GET /api/system/audit-logs`.
- Supports filtering by:
  - `request_id`
  - `path`
  - `method`
  - `status_code`
  - `error_code`
  - `agent_id` (via request-id correlation with activity metadata)
- Provides paginated audit retrieval without direct SQL access.

### Step 46: SLO Guardrails (Policy + Violations)
- Added migration `tier9_slo_guardrails`:
  - `slo_policies` (per-agent thresholds)
  - `slo_violations` (evaluated breaches)
- Added agent SLO endpoints:
  - `GET /api/agents/{agent_id}/slo-policy`
  - `POST /api/agents/{agent_id}/slo-policy`
  - `GET /api/agents/{agent_id}/slo-status`
- Added automatic SLO checks:
  - on run execute (rates + duration)
  - on run compare (max regression count)
- SLO violations emit:
  - persisted violation record
  - activity event
  - webhook notification (`slo_violation`)
- Added Streamlit SLO section for policy load/save and status visibility.

### Step 47: Launch Gate Enforcement + Decision Trail
- Added migration `tier10_launch_gate`:
  - immutable `launch_decisions` table
  - SLO violation status (`open|resolved`) to support gate blocking
- Added launch gate API:
  - `GET /api/agents/{agent_id}/launch-gate`
  - `POST /api/agents/{agent_id}/launch-decision`
  - `GET /api/agents/{agent_id}/launch-decisions`
- Added SLO violation resolution API:
  - `PATCH /api/agents/{agent_id}/slo-violations/{violation_id}/resolve`
- Enforced decision rule:
  - `go` blocked when gate has blockers
- Added launch decision activity + Slack webhook event (`launch_decision_changed`).
- Added Streamlit Launch Gate panel with:
  - gate evaluation
  - blocker list
  - submit decision
  - decision history view

### Step 48: Top-Level Launch Readiness Summary Card
- Added a launch gate summary card directly under agent selection.
- Shows immediate, always-visible gate snapshot:
  - pass/blocked
  - active critical issues
  - open SLO violations
  - readiness pending count
- Displays short blocker preview when gate is blocked.

### Step 49: Remediation Auto-Close on Clean Compare
- Added compare-flow remediation closure when `regression_count = 0`:
  - transitions matching `regression_compare` issue patterns to `verifying` (if allowed)
  - resolves matching open SLO violations for `max_regression_count`
- Emits `remediation_verified` activity event and Slack/webhook notification.
- Returns remediation summary in compare response:
  - `auto_closed`
  - `updated_patterns`
  - `resolved_slo_violations`

### Step 50: Regression Compare Remediation UI Card
- Added "Remediation Auto-Close" card in Regression Compare section.
- Displays:
  - auto-close triggered flag
  - number of patterns updated
  - number of SLO violations resolved
- Added contextual success/info messaging for closure outcome.

### Step 51: API Role Enforcement (Viewer/Member/Admin)
- Added migration `tier11_api_key_roles` to store key role in `public.api_keys`.
- Added role-aware auth context and guard dependencies:
  - `require_viewer`
  - `require_member`
  - `require_admin`
- Enforced endpoint-level permissions:
  - viewers: read-only endpoints
  - members: operational writes
  - admins: system/audit/key management and launch decisions
- Standardized forbidden response with explicit required vs actual role metadata.

### Step 52: API Versioning Compatibility Layer (`/api/v1`)
- Added middleware-based compatibility routing:
  - `/api/v1/*` is served by canonical v1 handlers.
  - Existing `/api/*` remains backward-compatible.
- Added response headers:
  - `X-API-Version: v1` on API responses.
  - `Deprecation: true` on legacy `/api/*` responses.
- Added tests to lock behavior:
  - legacy headers on `/api/*`
  - no deprecation header on `/api/v1/*`
  - no API version headers on non-API routes.

### Step 53: OpenAPI Grouping + Auth Contract
- Added OpenAPI schema customization with domain tags:
  - System, Agents, Evaluation, Golden Sets, Calibration, Issue Patterns, Guardrails, Operations
- Added bearer auth security scheme (`BearerAuth`) to API operations in `/api/*`.
- Kept non-API endpoints (for example `/health`) unsecured in OpenAPI.
- Added OpenAPI contract tests for:
  - security scheme presence
  - eval endpoint tagging/security
  - health endpoint non-security.

### Step 54: Deterministic Operation IDs + SDK Baselines
- Added deterministic OpenAPI operation IDs:
  - convention: `<http_method>_<resource_path>`
  - examples: `post_eval_runs`, `get_agents_by_agent_id_latest`
- Added OpenAPI test guardrails:
  - operation ID expected on core endpoint
  - operation IDs unique across schema
- Added local codegen script:
  - `/scripts/generate_clients.py`
  - source: live `/openapi.json` from app import
- Added generated baseline clients:
  - Python: `/sdk/python/greenlight_client.py`
  - TypeScript: `/sdk/typescript/greenlightClient.ts`

### Step 55: Typed SDK Request Models
- Upgraded SDK codegen to emit typed models from OpenAPI component schemas:
  - Python `TypedDict`/`Literal` aliases
  - TypeScript `interface`/union types
- Method signatures now use typed `body` parameters for known request schemas
  - example: `post_eval_runs(..., body?: EvalRunCreateRequest)`
- Kept response type generic (`ApiResponse`) for endpoints without strict response schemas.

### Step 56: Strict Response Envelopes on Core Endpoints
- Added `response_model=` contracts for core v1 APIs:
  - health
  - eval runs: create/execute/get/results/summary/compare
  - calibration: create/get/latest
  - agents: list/create/get/latest
  - golden sets: upload/list
- Added explicit envelope models for stable API outputs (for example `EvalRunCreateResponse`, `AgentListResponse`, `GoldenSetUploadResponse`).
- Updated SDK codegen to infer return types from OpenAPI response schema refs:
  - typed method return signatures for modeled endpoints
  - generic fallback for unmodeled endpoints
- Added OpenAPI contract test to lock typed response schema on `POST /api/eval/runs`.

### Step 57: Full Response-Model Coverage Across v1 API
- Added `response_model=` coverage for remaining endpoints:
  - system key/audit endpoints
  - SLO policy/status/resolve endpoints
  - issue pattern list/history/create/update endpoints
  - activity/readiness/launch gate/launch decision endpoints
- Added additional envelope/data models for these endpoint families.
- Verified all `/api/*` operations now emit OpenAPI response schema refs (no untyped object fallback).
- SDK generator now returns typed response envelopes for all current API operations.

### Step 58: SDK Paginator Helpers (`*_all`)
- Upgraded codegen to auto-generate list iterators for paginated endpoints (`data.items` + `limit/offset` contracts).
- Added Python helpers:
  - `get_agents_all(...)`, `get_agents_by_agent_id_patterns_all(...)`, `get_eval_runs_by_run_id_results_all(...)`, etc.
- Added TypeScript helpers:
  - `get_agents_all(...)`, `get_agents_by_agent_id_activity_all(...)`, `get_system_audit_logs_all(...)`, etc.
- Helpers use page-based fetch loops with configurable limits:
  - Python: `page_size`, `max_pages`
  - TypeScript: `pageSize`, `maxPages`

### Step 59: SDK Retry/Backoff for Transient Failures
- Upgraded generated SDK request layers to support configurable retries.
- Retry conditions:
  - HTTP `429`
  - HTTP `5xx`
  - transient network errors
- Exponential backoff settings:
  - Python client constructor: `max_retries`, `backoff_base_seconds`
  - TypeScript client constructor: `maxRetries`, `backoffBaseMs`

### Step 60: Per-Request Retry/Timeout Overrides
- Added call-level override support in generated SDK methods.
- Python generated methods now accept:
  - `timeout`
  - `max_retries`
  - `backoff_base_seconds`
- TypeScript generated methods now accept:
  - `requestOptions?: { timeoutMs, maxRetries, backoffBaseMs }`
- Paginator helpers (`*_all`) forward per-request override options to each page call.

### Step 61: Structured SDK Exceptions
- Added typed SDK exception classes in generated clients:
  - Python: `GreenlightApiError`
  - TypeScript: `GreenlightApiError`
- Exceptions now carry parsed API envelope context:
  - status code
  - platform error code
  - message
  - request id (when available)

### Step 62: Tenant Isolation + Key Hardening
- Added org-scope enforcement for org-scoped API keys across read/write endpoints:
  - run create/execute/read/results/summary/compare
  - agent create/list/read/latest
  - calibration create/read/latest
  - golden set upload/list
  - pattern, readiness, SLO, launch-gate, launch-decision, activity endpoints
  - system key list/revoke and audit-log list (filtered by caller org for scoped admins)
- Added stricter key creation behavior:
  - default key TTL (`API_KEY_DEFAULT_TTL_DAYS`, default `90`) when `expires_at` is omitted
  - org-scoped admins can only create keys in their own org scope
- Added lightweight per-minute API rate limiting middleware:
  - env: `API_RATE_LIMIT_PER_MINUTE` (default `120`)
  - response: `429 RATE_LIMITED` with `Retry-After: 60`
- Added API contract tests for cross-tenant blocking paths.

### Step 63: Real Execution Adapter Layer (Executor + Judge)
- Added execution service module: `/Users/seungyoo/Desktop/ai-agent-platform/src/api/services/execution.py`.
- Added executor modes for eval run execution:
  - `auto` (default, uses agent HTTP endpoint when present)
  - `simulated` (deterministic fallback)
  - `agent_http` (real POST call to agent `api_endpoint`)
- Updated run execution pipeline to:
  - execute each case via executor first (actual output/source)
  - score actual output via judge (`score_answer_case` / `score_criteria_case`)
  - persist execution replay trace metadata per case in `eval_results.notes`
- Added new execution error contracts:
  - `EVAL_EXECUTOR_CONFIG_ERROR`
  - `EVAL_EXECUTOR_RUNTIME_ERROR`
- Added execution service tests:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_execution_service.py`

### Step 64: Agent Invoke Contract Validator API
- Added endpoint:
  - `POST /api/agents/{agent_id}/invoke-contract/validate`
- Validates that an agent endpoint can be invoked with contract payload:
  - request body sent as `{ "input": "<sample>" }`
  - checks response shape for usable output fields
- Returns operational diagnostics:
  - endpoint/status/latency/content-type
  - response preview
  - request/response hashes
  - extracted response/source key mappings
- Added explicit error contracts:
  - `AGENT_INVOKE_CONTRACT_CONFIG_ERROR`
  - `AGENT_INVOKE_CONTRACT_RUNTIME_ERROR`
- Added API tests for:
  - successful validation path
  - cross-org forbidden access path

### Step 65: Golden Set File Ingestion API (`csv/jsonl/xlsx`)
- Added endpoint:
  - `POST /api/golden-sets/upload-file` (JSON + base64 file payload)
- Added server-side ingestion pipeline:
  - parses file (`csv`, `jsonl`, `xlsx`)
  - normalizes column aliases to canonical case schema
  - applies default taxonomy values when omitted
  - validates rows against `GoldenSetCaseUpload`
- Added validation reporting in response:
  - total/accepted/rejected row counts
  - row-level issues
- Added strict failure when all rows are invalid:
  - `GOLDEN_SET_FILE_VALIDATION_FAILED`
- Refactored shared DB write path into helper to keep JSON and file upload behavior consistent.

### Step 66: Golden Set Upload CLI Helper
- Added script:
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/upload_golden_set_file.sh`
- Script handles:
  - local file read
  - base64 conversion
  - JSON request assembly
  - API call to `/api/golden-sets/upload-file`
  - concise result output (`golden_set_id`, `case_count`, validation report)
- Added usage guide:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/golden-set-file-upload.md`

### Step 67: Async Runner Queue Foundation
- Added queue migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224120000_tier12_eval_run_queue.sql`
- Added queue APIs:
  - `POST /api/eval/runs/{run_id}/start`
  - `POST /api/eval/runs/{run_id}/cancel`
  - `GET /api/eval/runs/{run_id}/events`
- Added DB-backed worker loop:
  - `/Users/seungyoo/Desktop/ai-agent-platform/src/api/worker.py`
- Worker behavior:
  - claims queued jobs (`FOR UPDATE SKIP LOCKED`)
  - executes run via existing execution/judge pipeline
  - marks `succeeded`/`failed` with retry backoff requeue
  - emits run activity events for observability
- Added usage guide:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`

### Step 68: Queue Observability API
- Added admin endpoint:
  - `GET /api/system/queue/stats`
- Metrics included:
  - queued/running/succeeded/failed/cancelled counts
  - retry backlog count
  - oldest queued age (seconds)
  - checked timestamp
- Added org-scope enforcement for admin keys on queue metrics.
- Added API tests for:
  - stats payload contract
  - org-scope rejection on mismatched `org_id`

### Step 69: Dead-Letter Queue Operations
- Added admin endpoints:
  - `GET /api/system/queue/jobs/failed`
  - `POST /api/system/queue/jobs/{job_id}/retry`
  - `POST /api/system/queue/jobs/{job_id}/cancel`
- Added retry behavior:
  - only failed jobs are retryable
  - optional delayed requeue (`delay_seconds`)
- Added cancellation behavior:
  - cancels active queued/running jobs
  - non-active jobs return `cancelled=false` with current status
- Added queue-operation tests in API contract suite.

### Step 70: Queue-Aware CI Quality Gate
- Added CI gate script:
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
- Gate now validates async queue flow:
  - create run -> enqueue (`/start`) -> poll summary to completion
  - baseline vs candidate compare regression check
- Added CI queue health checks:
  - pre/post queue stats (`/api/system/queue/stats`)
  - dead-letter count invariant (`/api/system/queue/jobs/failed`)
- Updated workflow:
  - starts API + worker (`python3 -m src.api.worker`)
  - runs queue-aware gate instead of sync-only smoke
  - uploads `worker.log` artifact on every run
- Added docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`

### Step 71: Streamlit Queue Operations Panel
- Added Queue Ops section to `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py`:
  - load queue stats (`/api/system/queue/stats`)
  - load failed jobs (`/api/system/queue/jobs/failed`)
  - retry failed job (`/api/system/queue/jobs/{job_id}/retry`)
  - cancel job (`/api/system/queue/jobs/{job_id}/cancel`)
- Added optional sidebar field:
  - `Admin API Key (optional)` (falls back to API Key when empty)
- Keeps ops workflow runnable without terminal/API manual calls.

### Step 72: Baseline/Candidate Run Registry (Agent-Scoped)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224130000_tier13_run_registry.sql`
- Added run registry APIs:
  - `POST /api/agents/{agent_id}/run-registry`
  - `GET /api/agents/{agent_id}/run-registry`
  - `GET /api/agents/{agent_id}/run-registry/resolve`
- Supports named references by kind:
  - `baseline`
  - `candidate`
- Enforced constraints:
  - referenced run must belong to same org+agent
  - one active reference per agent+kind
- Added API contract tests for upsert/list/resolve paths.
  - details payload
- Error mapping behavior:
  - non-2xx API responses parse `{ error: { code, message, details } }` and throw structured errors
  - timeout/network failures map to `TIMEOUT` / `NETWORK_ERROR`
  - retry logic preserves structured errors and retries only when appropriate.

### Step 73: Compare by Reference (Run Registry + Latest)
- Extended `GET /api/eval/compare` to support two input modes:
  - Direct mode: `baseline_run_id` + `candidate_run_id`
  - Reference mode: `agent_id` + `baseline_ref` + `candidate_ref`
- Added reference resolution behavior:
  - `active` / `current`: resolve active run-registry ref for `baseline` or `candidate`
  - named ref: resolve by `run_registry.name`
  - `latest`: resolve most recent `eval_runs` record for the agent
- Added strict validation:
  - cannot mix direct mode and reference mode in the same request
  - all required params must be present for the selected mode
- Added API contract tests for:
  - successful compare via reference mode
  - invalid mixed-mode compare request

### Step 74: Auto-Promote Candidate to Baseline
- Added endpoint:
  - `POST /api/agents/{agent_id}/run-registry/promote-candidate`
- Behavior:
  - promote explicit `candidate_run_id` or resolve from `candidate_ref` (`active|current|latest|<name>`)
  - default safety gate: requires recent clean compare (`regression_count=0`) for baseline/candidate pair
  - gate window is configurable (`clean_compare_window_minutes`)
  - validates org+agent ownership of promoted run
  - deactivates prior active baseline and upserts promoted baseline ref
  - emits activity event `run_registry_promoted`
- Added Streamlit one-click action after clean compare:
  - `Promote Candidate -> Baseline`
- Added API contract tests for promotion success and blocked-without-clean-compare.

### Step 75: Eval Templates (Config Standardization)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224140000_tier14_eval_templates.sql`
- Added eval template APIs:
  - `POST /api/eval/templates`
  - `GET /api/eval/templates`
  - `GET /api/eval/templates/{template_id}`
- Added `template_id` support in `POST /api/eval/runs`:
  - merges template config/design context with payload overrides
  - auto-fills `golden_set_id` from template default when omitted
  - enforces run_type and agent_type compatibility
- Added Streamlit support:
  - load templates by selected agent type
  - select optional template on run creation
- Added API contract tests for template create/list and templated run creation paths.

### Step 76: Golden Set Governance (Versioning + Review Trail)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224150000_tier15_golden_set_governance.sql`
- Extended `golden_set_cases` with governance fields:
  - `version`, `is_active`, `superseded_by`, `last_reviewed_at`, `review_notes`
- Added review trail table:
  - `golden_set_case_reviews`
- Added governance APIs:
  - `GET /api/golden-sets/{golden_set_id}/cases`
  - `PATCH /api/golden-sets/{golden_set_id}/cases/{case_id}/verify`
  - `POST /api/golden-sets/{golden_set_id}/cases/{case_id}/supersede`
- Added API contract tests for list/verify/supersede success paths.

### Step 77: Queue Reliability Hardening (Heartbeat + Reaper + Runtime Guard)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224160000_tier16_queue_hardening.sql`
- Extended `eval_run_jobs` with watchdog/runtime fields:
  - `run_started_at`, `heartbeat_at`, `max_runtime_seconds`
- Added worker heartbeat registry table:
  - `eval_worker_heartbeats`
- Upgraded worker loop (`/Users/seungyoo/Desktop/ai-agent-platform/src/api/worker.py`):
  - periodic worker ping + per-job heartbeat writes
  - stale/timeout reaper for running jobs
  - max-runtime guard around execution pipeline
  - lock cleanup on success/failure/retry paths
- Updated async worker docs with new env controls.

### Step 78: Launch Certification API (Immutable Evidence Snapshot)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224170000_tier17_launch_certifications.sql`
- Added launch certification APIs:
  - `POST /api/agents/{agent_id}/launch-certify`
  - `GET /api/agents/{agent_id}/launch-certifications`
- Certification behavior:
  - evaluates launch gate + latest regression compare evidence
  - computes blockers and emits immutable certification status (`certified|blocked`)
  - stores full evidence snapshot for auditability
- Added API contract tests for certified and blocked certification paths.

### Step 79: SDK + CI Gate Alignment (Templates + Promotion Safety)
- Updated SDK usage guide (`/Users/seungyoo/Desktop/ai-agent-platform/docs/sdk-usage.md`) with:
  - template-driven run creation examples
  - promotion safety API example
- Updated CI quality gate script (`/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`) to:
  - enforce promotion safety gate after compare
  - fail pipeline if promote-candidate is blocked
- Updated CI gate docs (`/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`) to include promotion safety step.

### Step 80: Next.js Product Shell (Initial)
- Added initial Next.js app scaffold at:
  - `/Users/seungyoo/Desktop/ai-agent-platform/web`
- Added product shell features:
  - API connection bootstrap
  - agent load/select
  - launch gate + latest run load
  - compare-by-reference execution (`agent_id + baseline_ref + candidate_ref`)
- Added run guide:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/web-shell.md`

### Step 62: SDK Observability Hooks (Request/Response Logging)
- Added optional request logging callbacks in generated SDKs.
- Python:
  - client constructor `logger` callback
  - per-call `logger` override
- TypeScript:
  - client constructor `logger?: RequestLogger`
  - per-call `requestOptions.logger`
- Emitted log events are safe-by-default:
  - include request metadata, status, latency, attempt, request id, error code
  - exclude secrets/auth headers and raw body content.

### Step 63: Trace Correlation in Retry-Exhausted SDK Errors
- Improved request-id propagation in SDK request loops:
  - track last seen request id from previous HTTP responses/errors
  - attach it to final thrown `GreenlightApiError` where possible
- Applied to both SDKs:
  - Python (`request_id`)
  - TypeScript (`requestId`)
- Network/timeout failures after prior server attempts now preserve correlation context for debugging.

### Step 64: SDK Usage Guide
- Added `/docs/sdk-usage.md` with copy-paste examples for:
  - Python and TypeScript client initialization
  - pagination helpers (`*_all`)
  - retry/backoff + per-request overrides
  - structured error handling
  - logging hooks and log event shape

### Step 65: SDK Quickstart Section
- Added “Quickstart (5 min)” to `/docs/sdk-usage.md` with:
  - local API startup command
  - SDK regenerate command
  - first successful Python call
  - first successful TypeScript call

### Step 66: CI Quality Gates (SDK Drift + Contract Artifacts)
- Upgraded GitHub workflow `/.github/workflows/api-smoke.yml` to enforce:
  - SDK regeneration step
  - SDK drift check (`git diff --exit-code` on generated SDK files)
  - full pytest suite
  - smoke run against canonical `/api/v1` routes
- Added artifact publishing (`always`) for:
  - `openapi.json`
  - generated SDK files
  - `uvicorn.log`

### Step 81: AuthZ Hardening for Agent Writes
- Tightened `POST /api/agents` from viewer-access to member-access.
- Added contract test to enforce viewer-deny behavior:
  - `test_create_agent_forbidden_for_viewer_role`
- Kept eval-template auth roles consistent after patch:
  - `POST /api/eval/templates` => member
  - `GET /api/eval/templates` and `GET /api/eval/templates/{template_id}` => viewer
- Validation:
  - `PYTHONPATH=. pytest -q` => `68 passed`

### Step 82: Route-Level Auth Policy Guard
- Added guard test to prevent future auth regressions on mutating endpoints:
  - `test_mutating_api_routes_require_member_or_admin`
- Policy enforced by test:
  - every mutating `/api/*` route (`POST/PATCH/PUT/DELETE`) must depend on `require_member` or `require_admin`
  - viewer-only dependencies on mutating routes fail CI immediately
- Validation:
  - `PYTHONPATH=. pytest -q` => `69 passed`

### Step 83: Tenant Safety Hardening (DB + API Key Scope)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224180000_tier18_tenant_safety_hardening.sql`
- Database hardening:
  - added compatibility function overload `has_org_role(uuid, text[])`
  - enforced invariant: global API keys (`org_id is null`) must be `role=admin`
  - enabled + forced RLS on `public.api_keys` and denied direct `authenticated` access
- API/runtime hardening:
  - reject creation of global non-admin keys (`API_KEY_SCOPE_ROLE_INVALID`)
  - reject misconfigured global non-admin keys during auth validation
- Added tests:
  - `test_create_api_key_rejects_global_non_admin_role`
  - `test_validate_db_api_key_rejects_global_non_admin_record`
- Validation:
  - `PYTHONPATH=. pytest -q` => `71 passed`

### Step 84: Queue Concurrency + Idempotent Start Hardening
- Start endpoint now returns explicit enqueue state:
  - `enqueued=true` when a new queue job is inserted
  - `enqueued=false` when an existing queued/running job is reused
- Added dedupe activity event:
  - `run_queue_deduplicated` on repeated start calls
- Worker claim hardening:
  - claim query now enforces `attempt_count < max_attempts`
  - deterministic claim order on ties: `created_at asc, id asc`
- Retry backoff hardening:
  - deterministic helper `_retry_delay_seconds(attempt_count)`
  - capped by `EVAL_WORKER_MAX_RETRY_DELAY_SECONDS` (default `900`)
- Added tests:
  - `tests/test_worker_queue_hardening.py`
  - start dedupe tests in `tests/test_api_contract_errors.py`
- Validation:
  - `PYTHONPATH=. pytest -q` => `74 passed`

### Step 85: Transactional Notification Outbox
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224190000_tier19_notification_outbox.sql`
- New durable notification flow in API:
  - notification intents are inserted into `notification_outbox` first
  - optional immediate send (`NOTIFY_OUTBOX_SYNC_DELIVERY=true` by default)
  - failures stay queued with retry metadata; terminal failures move to `dead`
- Added worker-side outbox draining:
  - worker periodically drains pending notification events
  - interval configurable via `EVAL_WORKER_NOTIFY_DRAIN_SECONDS`
- Added admin manual drain endpoint:
  - `POST /api/system/notifications/outbox/drain?limit=...`
- Updated existing notification call sites to outbox-backed dispatch:
  - regression compare, SLO violation, launch decision, pattern status transition, remediation verified
- Added contract test:
  - `test_notification_outbox_drain_admin_endpoint`
- Validation:
  - `PYTHONPATH=. pytest -q` => `75 passed`

### Step 86: Notification Outbox Operations API
- Added admin outbox ops endpoints:
  - `GET /api/system/notifications/outbox`
    - filters: `org_id`, `status`, `event_type`, `limit`, `offset`
  - `POST /api/system/notifications/outbox/{outbox_id}/retry`
    - resets dead item attempts to `0`
    - rejects retry when item is currently `sending` (`NOTIFICATION_OUTBOX_IN_PROGRESS`)
- Added response models for outbox list and retry payloads.
- Added tests:
  - `test_notification_outbox_list_admin_endpoint`
  - `test_notification_outbox_retry_admin_endpoint`
  - `test_notification_outbox_retry_rejects_sending`
- Validation:
  - `PYTHONPATH=. pytest -q` => `78 passed`

### Step 87: Webhook HMAC Signing + Replay Window Contract
- Upgraded webhook security in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/services/notify.py`:
  - signed headers when `NOTIFY_WEBHOOK_SECRET` is set:
    - `X-Greenlight-Timestamp`
    - `X-Greenlight-Signature` (`v1=<hmac_sha256>`)
  - canonical signed payload: `v1:{timestamp}:{raw_body_bytes}`
  - legacy `X-Greenlight-Webhook-Secret` preserved for backward compatibility
- Added reusable verifier helper:
  - `verify_webhook_signature(...)` with replay-window validation support
- Added tests:
  - signature headers are attached and verifiable
  - replay-window rejection (`timestamp_out_of_window`)
- Updated API docs (`/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`) with signing + replay guidance.
- Validation:
  - `PYTHONPATH=. pytest -q` => `80 passed`

### Step 88: Delivery ID Contract for Receiver Idempotency
- Added delivery ID propagation to outbound webhooks:
  - HTTP header: `X-Greenlight-Delivery-Id`
  - JSON body field: `delivery_id`
- Delivery ID is sourced from notification outbox item ID during dispatch.
- Updated `send_webhook_event(...)` to accept optional `delivery_id`.
- Added tests:
  - `test_send_webhook_event_includes_delivery_id`
- Updated docs (`/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`) with receiver dedupe guidance:
  - dedupe by delivery ID for safe retry handling.
- Validation:
  - `PYTHONPATH=. pytest -q` => `81 passed`

### Step 89: Dead-Letter Observability for Notification Outbox
- Added admin endpoint:
  - `GET /api/system/notifications/outbox/dead-letter-summary`
- Summary includes:
  - total dead count
  - oldest dead age (seconds)
  - grouped failure reasons (`reason_groups`)
  - age buckets (`lt_1h`, `h_1_to_24`, `d_1_to_7`, `gte_7d`)
- Supports optional filters:
  - `org_id`
  - `event_type`
- Added tests:
  - `test_notification_outbox_dead_letter_summary_endpoint`
  - `test_notification_outbox_dead_letter_summary_enforces_org_scope`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
- Validation:
  - `PYTHONPATH=. pytest -q` => `83 passed`

### Step 90: Cooperative Eval Run Cancellation Tokens
- Added run-level cancellation lifecycle support:
  - new migration:
    - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224200000_tier20_eval_run_cancelled_status.sql`
  - extends `run_status` enum with `cancelled`
  - allows `eval_runs.completed_at` when status is `cancelled`
- Updated execute flow (`POST /api/eval/runs/{run_id}/execute`):
  - hard-fails if run is already cancelled (`EVAL_RUN_CANCELLED`)
  - checks cancellation request before start and between cases
  - returns successful envelope with `status=cancelled` when cancellation is detected mid-flight
- Updated cancel APIs:
  - queue job cancel now also marks eval run as `cancelled`
  - run cancel endpoint also marks eval run as `cancelled`
- Updated worker behavior:
  - when execute returns `status=cancelled`, worker finalizes queue job as `cancelled` (not failed/retried)
- Added tests:
  - `test_eval_run_execute_returns_cancelled_when_cancel_requested`
  - `test_worker_marks_job_cancelled_when_execute_returns_cancelled`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py tests/test_worker_queue_hardening.py` => `49 passed`
  - `PYTHONPATH=. pytest -q` => `85 passed`

### Step 91: Bulk Replay API for Failed Queue Jobs (Admin Guardrails)
- Added admin endpoint:
  - `POST /api/system/queue/jobs/failed/replay`
- Guardrails:
  - `limit` bounded to `1..100`
  - `delay_seconds` bounded to `0..3600`
  - optional org scoping via `org_id` with existing scope enforcement
  - `dry_run=true` mode for safe preview (no mutations)
- Behavior:
  - selects oldest failed jobs first (`updated_at asc`)
  - requeues selected jobs (`status=queued`, clears terminal state) when not dry-run
  - records `run_requeued_bulk` activity events for replayed jobs with known `agent_id`
- Added tests:
  - `test_replay_failed_queue_jobs_happy_path`
  - `test_replay_failed_queue_jobs_dry_run`
  - `test_replay_failed_queue_jobs_enforces_org_scope`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_replay_failed_queue_jobs_happy_path tests/test_api_contract_errors.py::test_replay_failed_queue_jobs_dry_run tests/test_api_contract_errors.py::test_replay_failed_queue_jobs_enforces_org_scope` => `3 passed`
  - `PYTHONPATH=. pytest -q` => `88 passed`

### Step 92: Worker Concurrency Caps (Global + Per-Org)
- Added worker-level concurrency cap controls:
  - `EVAL_WORKER_MAX_CONCURRENCY_GLOBAL` (0 = unlimited)
  - `EVAL_WORKER_MAX_CONCURRENCY_PER_ORG` (0 = unlimited)
- Updated queue claim SQL in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/worker.py`:
  - enforces global running cap before claiming queued job
  - enforces per-org running cap before claiming queued job
  - preserves deterministic claim order and attempt guard
- Added tests:
  - `test_worker_concurrency_env_defaults_and_override`
  - extended claim-query test to assert cap predicates are present
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_worker_queue_hardening.py` => `4 passed`
  - `PYTHONPATH=. pytest -q` => `89 passed`

### Step 93: Eval Run State-Machine Enforcement
- Added API-level transition guard helper in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `pending -> running|cancelled`
  - `running -> completed|failed|cancelled`
  - `completed|failed|cancelled -> pending` (controlled reopen for rerun flows)
- Updated run lifecycle endpoints/services:
  - `execute` now rejects non-`pending` starts with `EVAL_RUN_STATUS_TRANSITION_INVALID`
  - `start` reopens terminal runs to `pending` before enqueue
  - queue `retry` and bulk `failed/replay` reopen terminal runs to `pending`
- Added DB-level transition guard migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224202000_tier22_eval_run_status_transition_guard.sql`
- Worker alignment:
  - stale-job reaper now transitions run to `failed` only when run is `running`
- Added tests:
  - `test_eval_run_start_reopens_failed_run`
  - `test_eval_run_execute_rejects_terminal_status`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_eval_run_execute_rejects_terminal_status tests/test_api_contract_errors.py::test_retry_queue_job_happy_path tests/test_api_contract_errors.py::test_eval_run_start_reopens_failed_run` => `3 passed`
  - `PYTHONPATH=. pytest -q` => `91 passed`

### Step 94: Mandatory Idempotency Keys for Admin Queue Mutations
- Enforced `Idempotency-Key` header requirement for:
  - `POST /api/system/queue/jobs/{job_id}/retry`
  - `POST /api/system/queue/jobs/{job_id}/cancel`
  - `POST /api/system/queue/jobs/failed/replay`
- Added dependency in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `require_idempotency_key`
  - header is typed in FastAPI so missing key returns `VALIDATION_ERROR`
- Updated tests:
  - queue mutation tests now include explicit idempotency headers
  - added `test_queue_admin_mutations_require_idempotency_key`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`

### Step 95: Queue Fairness Scheduling (Org-Aware Claims)
- Updated worker claim logic in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/worker.py`:
  - fair org selection CTEs:
    - `running_by_org`: current running counts per org
    - `next_org`: pick org with fewest running jobs, then oldest queued work
  - `next_job` then claims oldest queued job inside selected org
  - preserves existing guards:
    - `not_before` readiness
    - attempt limit check
    - global/per-org concurrency caps
    - `for update skip locked`
- Updated tests:
  - `test_claim_query_enforces_attempt_guard_and_deterministic_order` now asserts fairness SQL predicates
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_worker_queue_hardening.py` => `4 passed`
  - `PYTHONPATH=. pytest -q` => `92 passed`

### Step 96: OpenAPI + CI Contract Gates for Queue/Admin Endpoints
- Added OpenAPI contract tests in `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`:
  - idempotency header contract on admin queue mutation endpoints
  - tag/security/typed response refs for queue admin endpoints
- Updated CI workflow `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`:
  - explicit `jq` checks on exported OpenAPI schema for:
    - required `Idempotency-Key` header on queue admin mutations
    - typed replay response envelope ref (`QueueJobsReplayResponse`)
- Updated quality-gate script `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`:
  - added step validating runtime idempotency contract for admin replay endpoint
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_openapi_contract.py` => `9 passed`
  - `PYTHONPATH=. pytest -q` => `94 passed`

### Step 97: DB State-Machine Guard for Queue Jobs
- Added DB-level transition guard migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224203000_tier23_eval_run_jobs_status_transition_guard.sql`
- New trigger/function enforces allowed `eval_run_jobs.status` transitions:
  - `queued -> running|cancelled`
  - `running -> succeeded|failed|cancelled|queued`
  - `failed -> queued`
- Purpose:
  - block illegal direct SQL mutations that bypass API/worker invariants
  - keep queue lifecycle valid even under manual/admin DB operations
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`

### Step 98: Admin Stale-Job Reap Endpoint + Contract Gates
- Added admin remediation endpoint in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `POST /api/system/queue/jobs/reap-stale`
  - supports:
    - `dry_run` preview
    - org scoping
    - heartbeat/runtime stale thresholds
    - bounded batch limit
- Mutation behavior (`dry_run=false`):
  - stale `running` queue jobs -> `failed`
  - associated `running` eval runs -> `failed`
  - emits `run_reaped` activity events
- Enforced idempotency header requirement on endpoint.
- Added tests:
  - `test_reap_stale_queue_jobs_happy_path`
  - `test_reap_stale_queue_jobs_dry_run`
  - `test_reap_stale_queue_jobs_enforces_org_scope`
  - `test_reap_stale_queue_jobs_requires_idempotency_key`
- Expanded OpenAPI contract tests to include new endpoint.
- Updated CI gates:
  - OpenAPI `jq` assertions in `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - runtime dry-run idempotency contract check in `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`

### Step 99: Admin Queue Prune Endpoint + Retention Contract
- Added admin retention endpoint in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `POST /api/system/queue/jobs/prune`
  - supports:
    - org scoping
    - retention window (`retention_days`)
    - bounded batch limit
    - `dry_run` preview
  - requires `Idempotency-Key`
- Mutation behavior (`dry_run=false`):
  - deletes terminal queue jobs (`succeeded|failed|cancelled`) older than retention window
- Added tests:
  - `test_prune_terminal_queue_jobs_happy_path`
  - `test_prune_terminal_queue_jobs_dry_run`
  - `test_prune_terminal_queue_jobs_enforces_org_scope`
  - `test_prune_terminal_queue_jobs_requires_idempotency_key`
- Expanded OpenAPI contract tests to include prune endpoint idempotency/security/typed response.
- Updated CI gates:
  - OpenAPI `jq` checks in `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - runtime prune dry-run contract in `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_prune_terminal_queue_jobs_happy_path tests/test_api_contract_errors.py::test_prune_terminal_queue_jobs_dry_run tests/test_api_contract_errors.py::test_prune_terminal_queue_jobs_enforces_org_scope tests/test_api_contract_errors.py::test_prune_terminal_queue_jobs_requires_idempotency_key tests/test_openapi_contract.py` => `13 passed`
  - `PYTHONPATH=. pytest -q` => `102 passed`

### Step 100: Org-Level Queue Maintenance Policies + Policy-Driven Defaults
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224204000_tier24_queue_maintenance_policies.sql`
- New policy APIs in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `GET /api/system/queue/maintenance-policy?org_id=...`
    - returns org policy if present; otherwise platform defaults
  - `POST /api/system/queue/maintenance-policy`
    - upsert org policy with validated bounds
- Wired policy defaults into existing admin queue ops:
  - `POST /api/system/queue/jobs/reap-stale`
    - when org is provided and params omitted, uses policy `stale_heartbeat_seconds`, `max_runtime_seconds`, `reap_limit`
  - `POST /api/system/queue/jobs/prune`
    - when org is provided and params omitted, uses policy `retention_days`, `prune_limit`
- Added tests:
  - `test_get_queue_maintenance_policy_returns_default_when_missing`
  - `test_get_queue_maintenance_policy_enforces_org_scope`
  - `test_upsert_queue_maintenance_policy_happy_path`
  - `test_reap_stale_queue_jobs_uses_policy_defaults_when_params_omitted`
- Expanded OpenAPI contract tests for maintenance policy endpoints.
- Expanded CI quality gates:
  - OpenAPI schema checks in `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - runtime maintenance-policy contract step in `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_get_queue_maintenance_policy_returns_default_when_missing tests/test_api_contract_errors.py::test_get_queue_maintenance_policy_enforces_org_scope tests/test_api_contract_errors.py::test_upsert_queue_maintenance_policy_happy_path tests/test_api_contract_errors.py::test_reap_stale_queue_jobs_uses_policy_defaults_when_params_omitted tests/test_openapi_contract.py` => `14 passed`
  - `PYTHONPATH=. pytest -q` => `107 passed`

### Step 101: Queue Maintenance Runner Endpoint (Policy-Driven Reap + Prune)
- Added admin orchestration endpoint in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `POST /api/system/queue/maintenance/run`
  - requires:
    - `org_id`
    - `Idempotency-Key`
  - supports:
    - `dry_run` mode (default true)
    - optional policy overrides (`stale_heartbeat_seconds`, `max_runtime_seconds`, `retention_days`, `reap_limit`, `prune_limit`)
- Behavior:
  - resolves effective policy (saved org policy + overrides)
  - runs stale reap then prune
  - returns combined response with:
    - effective policy
    - reap summary
    - prune summary
    - started/completed timestamps
- Added tests:
  - `test_run_queue_maintenance_happy_path`
  - `test_run_queue_maintenance_enforces_org_scope`
  - `test_run_queue_maintenance_requires_idempotency_key`
- Expanded OpenAPI contract tests to include maintenance runner endpoint.
- Expanded CI gates:
  - OpenAPI schema checks in `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - runtime maintenance runner dry-run contract in `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_run_queue_maintenance_happy_path tests/test_api_contract_errors.py::test_run_queue_maintenance_enforces_org_scope tests/test_api_contract_errors.py::test_run_queue_maintenance_requires_idempotency_key tests/test_openapi_contract.py` => `13 passed`
  - `PYTHONPATH=. pytest -q` => `110 passed`

### Step 102: Queue Maintenance Run Audit Trail + History APIs
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224205000_tier25_queue_maintenance_runs.sql`
- Added persisted maintenance run ledger:
  - `public.queue_maintenance_runs`
  - stores run lifecycle (`running|completed|failed`), policy snapshot, reap/prune summaries, error details, timing, and trigger key metadata
- Extended maintenance runner:
  - `POST /api/system/queue/maintenance/run`
  - now creates a `running` record before execution, updates to `completed` on success, and marks `failed` with error details on exceptions
- Added history APIs in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `GET /api/system/queue/maintenance/runs`
  - `GET /api/system/queue/maintenance/runs/{run_id}`
- Added tests:
  - `test_list_queue_maintenance_runs_happy_path`
  - `test_get_queue_maintenance_run_detail_happy_path`
  - `test_get_queue_maintenance_run_detail_not_found`
  - plus maintenance runner happy-path coverage update for persisted run metadata
- Expanded OpenAPI + CI gates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_run_queue_maintenance_happy_path tests/test_openapi_contract.py` => `12 passed`
  - `PYTHONPATH=. pytest -q` => `114 passed`

### Step 103: Queue Maintenance Concurrency Guard (Single Active Run Per Org)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224210000_tier26_queue_maintenance_single_active.sql`
- Added DB guard:
  - partial unique index on `public.queue_maintenance_runs(org_id)` where `status='running'`
  - enforces at most one active maintenance run per org
- Updated API behavior in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `POST /api/system/queue/maintenance/run` now maps concurrent-run conflicts to:
    - `409 QUEUE_MAINTENANCE_ALREADY_RUNNING`
- Added test:
  - `test_run_queue_maintenance_rejects_concurrent_active_run`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_run_queue_maintenance_happy_path tests/test_api_contract_errors.py::test_run_queue_maintenance_rejects_concurrent_active_run tests/test_openapi_contract.py` => `13 passed`
  - `PYTHONPATH=. pytest -q` => `115 passed`

### Step 104: Queue Maintenance Metrics Endpoint + CI Contract
- Added endpoint in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `GET /api/system/queue/maintenance/metrics`
  - query params:
    - `org_id` (required)
    - `window_days` (default `30`, `1..365`)
- Metrics returned:
  - run counts (`total`, `running`, `completed`, `failed`)
  - `dry_run_count`
  - `failure_rate`
  - completed-run duration stats (`avg_duration_ms`, `p50_duration_ms`, `p95_duration_ms`)
  - latest run snapshot (`last_run_started_at`, `last_run_status`)
- Added tests:
  - `test_get_queue_maintenance_metrics_happy_path`
  - `test_get_queue_maintenance_metrics_enforces_org_scope`
- Expanded OpenAPI contract tests:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - asserts typed schema ref `QueueMaintenanceMetricsResponse`
- Expanded CI quality gates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
    - added step 17 metrics contract check
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
    - added OpenAPI `jq` schema assertion for maintenance metrics endpoint
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_get_queue_maintenance_metrics_happy_path tests/test_api_contract_errors.py::test_get_queue_maintenance_metrics_enforces_org_scope tests/test_openapi_contract.py` => `13 passed`
  - `PYTHONPATH=. pytest -q` => `117 passed`

### Step 105: Stale Maintenance-Run Reap Endpoint + Explicit Audit Entries
- Added endpoint in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `POST /api/system/queue/maintenance/reap-stale-runs`
  - requires `Idempotency-Key`
  - supports org-scoped operation (`org_id`) with optional runtime threshold override (`max_runtime_seconds`)
- Behavior:
  - selects stale maintenance runs (`status='running'` older than threshold)
  - when `dry_run=false`, marks selected runs `failed`, sets fallback `error_message`, computes missing `duration_ms`, and sets `completed_at`
  - emits explicit per-run audit entries into `api_audit_logs` with `error_code=MAINTENANCE_RUN_REAPED` (in addition to middleware request-level audit)
- Added response models:
  - `QueueMaintenanceReapItem`
  - `QueueMaintenanceReapStaleData`
  - `QueueMaintenanceReapStaleResponse`
- Added tests:
  - `test_reap_stale_queue_maintenance_runs_happy_path`
  - `test_reap_stale_queue_maintenance_runs_enforces_org_scope`
  - `test_reap_stale_queue_maintenance_runs_requires_idempotency_key`
- Expanded OpenAPI contract checks:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - validates idempotency header + typed schema ref for new endpoint
- Expanded CI gates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
    - added step 18 stale maintenance reap dry-run contract
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
    - added OpenAPI `jq` assertions for new endpoint
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_reap_stale_queue_maintenance_runs_happy_path tests/test_api_contract_errors.py::test_reap_stale_queue_maintenance_runs_enforces_org_scope tests/test_api_contract_errors.py::test_reap_stale_queue_maintenance_runs_requires_idempotency_key tests/test_openapi_contract.py` => `14 passed`
  - `PYTHONPATH=. pytest -q` => `120 passed`

### Step 106: Scheduler-Safe Maintenance Trigger Endpoint (Server-Side Dedupe)
- Added endpoint in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `POST /api/system/queue/maintenance/schedule-trigger`
- Request model:
  - `QueueMaintenanceScheduleTriggerRequest`
  - includes `org_id`, `schedule_name`, `window_minutes`, `dry_run`, `force`, and optional maintenance overrides
- Response model:
  - `QueueMaintenanceScheduleTriggerResponse`
  - includes dedupe metadata (`window_started_at`, `dedupe_key`) and run payload
- Behavior:
  - computes deterministic dedupe key per schedule window
  - if a completed run in same org/window/caller key already exists:
    - returns existing run (`executed=false`, `deduped=true`)
  - otherwise executes maintenance run and tags snapshot with scheduler metadata
    (`_schedule_name`, `_schedule_dedupe_key`)
- Added tests:
  - `test_queue_maintenance_schedule_trigger_executes_when_not_deduped`
  - `test_queue_maintenance_schedule_trigger_dedupes_existing_window_run`
- Expanded OpenAPI contracts:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
- Expanded CI quality gate:
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
  - added step 19 asserting execute-then-dedupe behavior
- Expanded workflow OpenAPI checks:
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_queue_maintenance_schedule_trigger_executes_when_not_deduped tests/test_api_contract_errors.py::test_queue_maintenance_schedule_trigger_dedupes_existing_window_run tests/test_openapi_contract.py` => `13 passed`
  - `PYTHONPATH=. pytest -q` => `122 passed`

### Step 107: Maintenance Scheduler Summary Endpoint + Dedupe Audit Signals
- Added explicit schedule-trigger audit signals in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `SCHEDULE_TRIGGER_EXECUTED`
  - `SCHEDULE_TRIGGER_DEDUPED`
  - emitted via `api_audit_logs` for schedule trigger outcomes
- Added endpoint:
  - `GET /api/system/queue/maintenance/schedule-summary`
  - query:
    - `org_id` (required)
    - `schedule_name` (optional)
    - `window_days` (default `30`)
  - returns:
    - trigger totals (`trigger_count`, `executed_count`, `deduped_count`)
    - `dedupe_hit_rate`
    - execution outcomes (`successful_executions`, `failed_executions`, `execution_success_rate`)
    - latest timestamps/status for trigger and execution
- Added models:
  - `QueueMaintenanceScheduleSummaryData`
  - `QueueMaintenanceScheduleSummaryResponse`
- Added tests:
  - `test_get_queue_maintenance_schedule_summary_happy_path`
  - `test_get_queue_maintenance_schedule_summary_enforces_org_scope`
- Expanded OpenAPI contracts:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
- Expanded CI quality gate:
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
  - added step 20 schedule-summary contract assertion
- Expanded workflow OpenAPI checks:
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_queue_maintenance_schedule_trigger_executes_when_not_deduped tests/test_api_contract_errors.py::test_queue_maintenance_schedule_trigger_dedupes_existing_window_run tests/test_api_contract_errors.py::test_get_queue_maintenance_schedule_summary_happy_path tests/test_api_contract_errors.py::test_get_queue_maintenance_schedule_summary_enforces_org_scope tests/test_openapi_contract.py` => `15 passed`
  - `PYTHONPATH=. pytest -q` => `124 passed`

### Step 108: Policy-Driven Schedule Anomaly Notifications (Optional Slack/Webhook)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224213000_tier27_queue_maintenance_alert_thresholds.sql`
  - extends `queue_maintenance_policies` with:
    - `schedule_alert_enabled`
    - `schedule_alert_dedupe_hit_rate_threshold`
    - `schedule_alert_min_execution_success_rate`
- Updated policy API models and persistence:
  - `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`
  - `GET/POST /api/system/queue/maintenance-policy` now include schedule alert fields
- Added reusable scheduler summary computation helper:
  - `_compute_queue_maintenance_schedule_summary_data(...)`
- Improved schedule-trigger observability:
  - explicit audit log entries now include schedule-specific path tagging (`?schedule_name=...`)
  - enables accurate per-schedule summary filtering
- Added endpoint:
  - `POST /api/system/queue/maintenance/schedule-summary/notify`
  - evaluates anomalies against org policy thresholds and optionally dispatches webhook/Slack notification
  - requires `Idempotency-Key`
  - supports `dry_run` and `force_notify`
- Added models:
  - `QueueMaintenanceScheduleNotifyRequest`
  - `QueueMaintenanceScheduleNotifyData`
  - `QueueMaintenanceScheduleNotifyResponse`
- Added tests:
  - `test_notify_queue_maintenance_schedule_summary_dry_run`
  - `test_notify_queue_maintenance_schedule_summary_force_notify`
  - `test_notify_queue_maintenance_schedule_summary_requires_idempotency_key`
  - updated maintenance-policy tuple fixtures for new fields
- Expanded OpenAPI and CI contracts:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh` (step 21)
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_upsert_queue_maintenance_policy_happy_path tests/test_api_contract_errors.py::test_reap_stale_queue_jobs_uses_policy_defaults_when_params_omitted tests/test_api_contract_errors.py::test_notify_queue_maintenance_schedule_summary_dry_run tests/test_api_contract_errors.py::test_notify_queue_maintenance_schedule_summary_force_notify tests/test_api_contract_errors.py::test_notify_queue_maintenance_schedule_summary_requires_idempotency_key tests/test_api_contract_errors.py::test_get_queue_maintenance_schedule_summary_happy_path tests/test_openapi_contract.py` => `17 passed`
  - `PYTHONPATH=. pytest -q` => `127 passed`

### Step 109: Schedule Anomaly Alert Cooldown + Suppression Dedupe
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224220000_tier28_schedule_alert_cooldown.sql`
  - adds policy field:
    - `schedule_alert_cooldown_minutes`
  - adds state table:
    - `public.queue_maintenance_schedule_alert_state`
    - tracks per-org/schedule last alert fingerprint and timestamp
- Updated policy API models + persistence:
  - `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`
  - `QueueMaintenancePolicyData` / `QueueMaintenancePolicyUpsertRequest` include cooldown field
- Added cooldown helper:
  - `_check_and_mark_schedule_alert_cooldown(...)`
  - suppresses repeated identical anomaly alerts during cooldown window
- Updated schedule anomaly notify endpoint:
  - `POST /api/system/queue/maintenance/schedule-summary/notify`
  - now computes alert fingerprint and suppresses if still in cooldown
  - `force_notify=true` bypasses suppression
- Added suppression-focused test:
  - `test_notify_queue_maintenance_schedule_summary_suppressed_by_cooldown`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_upsert_queue_maintenance_policy_happy_path tests/test_api_contract_errors.py::test_reap_stale_queue_jobs_uses_policy_defaults_when_params_omitted tests/test_api_contract_errors.py::test_notify_queue_maintenance_schedule_summary_dry_run tests/test_api_contract_errors.py::test_notify_queue_maintenance_schedule_summary_force_notify tests/test_api_contract_errors.py::test_notify_queue_maintenance_schedule_summary_suppressed_by_cooldown tests/test_api_contract_errors.py::test_notify_queue_maintenance_schedule_summary_requires_idempotency_key tests/test_openapi_contract.py` => `17 passed`
  - `PYTHONPATH=. pytest -q` => `128 passed`

### Step 110: Schedule Alert Delivery Status Endpoint + Notify Outcome Audits
- Added explicit notify outcome audit signals in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `SCHEDULE_ANOMALY_NOTIFY_SENT`
  - `SCHEDULE_ANOMALY_NOTIFY_FAILED`
  - `SCHEDULE_ANOMALY_NOTIFY_SUPPRESSED`
  - `SCHEDULE_ANOMALY_NOTIFY_SKIPPED`
  - `SCHEDULE_ANOMALY_NOTIFY_DRY_RUN`
- Added endpoint:
  - `GET /api/system/queue/maintenance/schedule-alert-delivery`
  - query:
    - `org_id` (required)
    - `schedule_name` (optional)
    - `window_days` (default `30`)
  - returns delivery counts and recency markers (`last_sent_at`, `last_failed_at`, `last_suppressed_at`, `last_notified_at`)
- Added models:
  - `QueueMaintenanceScheduleAlertDeliveryData`
  - `QueueMaintenanceScheduleAlertDeliveryResponse`
- Added tests:
  - `test_get_queue_maintenance_schedule_alert_delivery_happy_path`
  - `test_get_queue_maintenance_schedule_alert_delivery_enforces_org_scope`
- Expanded OpenAPI and CI contracts:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh` (step 22)
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/async-worker.md`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_api_contract_errors.py::test_get_queue_maintenance_schedule_alert_delivery_happy_path tests/test_api_contract_errors.py::test_get_queue_maintenance_schedule_alert_delivery_enforces_org_scope tests/test_api_contract_errors.py::test_notify_queue_maintenance_schedule_summary_suppressed_by_cooldown tests/test_openapi_contract.py` => `14 passed`
  - `PYTHONPATH=. pytest -q` => `130 passed`

### Step 111: Eval Run List API (`GET /api/eval/runs`)
- Added endpoint:
  - `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`
  - supports org/agent/status/type filters with pagination
  - returns result-count-derived rate rollups per run
- Added typed models:
  - `EvalRunListItem`
  - `EvalRunListData`
  - `EvalRunListResponse`

### Step 112: Agent Score Trend API (`GET /api/agents/{agent_id}/score-trend`)
- Added endpoint:
  - `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`
  - windowed run timeline with answer/source/quality rates per run
- Added typed models:
  - `AgentScoreTrendPoint`
  - `AgentScoreTrendData`
  - `AgentScoreTrendResponse`

### Step 113: Agent Health Rollup API (`GET /api/agents/{agent_id}/health`)
- Added endpoint:
  - `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`
  - combines launch-gate signals, latest completed run rates, issue/SLO counts, readiness decision snapshot
- Added typed models:
  - `AgentHealthData`
  - `AgentHealthResponse`

### Step 114: Org Portfolio Health API (`GET /api/orgs/{org_id}/portfolio-health`)
- Added endpoint:
  - `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`
  - returns per-agent launch posture + org-level rollups
- Added typed models:
  - `PortfolioHealthAgentItem`
  - `PortfolioHealthData`
  - `PortfolioHealthResponse`
- Contract/test/docs updates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`

### Step 115: Streamlit Health/Portfolio UI Integration (Read-Only)
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py` to render the new APIs:
  - `GET /api/eval/runs`
  - `GET /api/agents/{agent_id}/score-trend`
  - `GET /api/agents/{agent_id}/health`
  - `GET /api/orgs/{org_id}/portfolio-health`
- Added a new "Health + Portfolio Snapshot" section:
  - agent launch/issue/SLO/readiness rollups
  - score trend line chart (30-day window)
  - recent eval runs table for selected agent
  - org-level portfolio KPI metrics + per-agent table (expander)
- Validation:
  - `python3 -m py_compile app/streamlit_app.py src/api/main.py`
  - `PYTHONPATH=. pytest -q tests/test_openapi_contract.py tests/test_api_contract_errors.py` => `104 passed`

### Step 116: Eval Artifact Store + API (Traceability Foundation)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224230000_tier29_eval_run_artifacts.sql`
  - creates `public.eval_run_artifacts` with:
    - judge/executor metadata (`judge_mode`, `judge_model`, `judge_prompt_version`, `judge_prompt_hash`, `executor_mode`)
    - latency fields (`case_latency_ms`, `execution_latency_ms`, `judge_latency_ms`)
    - token usage (`token_usage` jsonb)
    - judge I/O and execution trace (`judge_input`, `judge_output`, `execution_trace`)
  - adds indexes + RLS policies
- Updated execution pipeline:
  - `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`
  - `execute_eval_run` now:
    - captures judge latency
    - writes `eval_results` with `returning id`
    - writes one artifact row per executed case into `eval_run_artifacts`
- Added artifacts read endpoint:
  - `GET /api/eval/runs/{run_id}/artifacts`
  - supports filters: `case_id`, `evaluation_mode`, pagination
- Added response models:
  - `EvalRunArtifactItem`
  - `EvalRunArtifactsData`
  - `EvalRunArtifactsResponse`
- Added contract coverage:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh` (new step 25)
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`

### Step 117: Streamlit Run Artifact Viewer
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py`:
  - added section `7A) Run Artifacts`
  - calls `GET /api/eval/runs/{run_id}/artifacts`
  - shows artifact table + JSON detail panel (judge/executor traces and latency fields)

### Step 118: Human Review Workflow for Eval Results
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260224233000_tier30_eval_result_human_review.sql`
  - adds `eval_results` review fields:
    - `review_status` (`unreviewed|accepted|overridden`)
    - `reviewed_by_api_key_id`, `reviewed_at`
    - `review_decision`, `review_reason`, `review_override`
- Added APIs:
  - `GET /api/eval/runs/{run_id}/review-queue`
  - `PATCH /api/eval/runs/{run_id}/results/{result_id}/review`
- Added review diff logic:
  - computes reviewer-vs-judge deltas for key scoring fields
- Added provider metadata propagation:
  - judge provider usage/model/response-id now available for artifact persistence
- Contract/test/docs updates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh` (step 26)
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`

### Step 119: Calibration Gate Policy + Runtime Enforcement
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260225000000_tier31_calibration_gate_policy.sql`
  - extends `slo_policies` with:
    - `require_calibration_gate`
    - `min_calibration_overall_agreement`
    - `max_calibration_age_days`
- Added runtime helpers:
  - `_get_calibration_gate_status(...)`
  - `_enforce_calibration_gate(...)`
- Enforced calibration gate in:
  - `POST /api/eval/runs/{run_id}/start`
  - `POST /api/eval/runs/{run_id}/execute`
  - when enabled (policy or run config), non-calibration runs are blocked if latest calibration is missing/stale/below threshold
- Added endpoint:
  - `GET /api/agents/{agent_id}/calibration-gate-status`
- Extended SLO policy API fields:
  - `GET/POST /api/agents/{agent_id}/slo-policy` now include calibration gate controls
- Contract/test/docs updates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh` (step 27)
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`

### Step 120: Golden Set Quality Gate Policy + Runtime Enforcement
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260225010000_tier32_golden_set_quality_gate_policy.sql`
  - extends `slo_policies` with:
    - `require_golden_set_quality_gate`
    - `min_verified_case_ratio`
    - `min_active_case_count`
- Added runtime helpers:
  - `_get_golden_set_quality_gate_status(...)`
  - `_enforce_golden_set_quality_gate(...)`
- Enforced golden set quality gate in:
  - `POST /api/eval/runs/{run_id}/start`
  - `POST /api/eval/runs/{run_id}/execute`
  - when enabled (policy or run config), run start/execute is blocked if active case count or verified ratio is below threshold
- Added endpoint:
  - `GET /api/golden-sets/{golden_set_id}/quality-gate-status`
- Extended SLO policy API fields:
  - `GET/POST /api/agents/{agent_id}/slo-policy` now include golden set quality gate controls
- Streamlit updates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py`
  - shows golden set quality gate status metrics and exposes policy controls in SLO guardrails form
- Contract/test/docs updates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh` (step 28)
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`

### Step 121: Configurable Gate Definitions + Agent Bindings (Platform Extension Surface)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260225020000_tier33_gate_definitions_and_bindings.sql`
  - creates:
    - `public.gate_definitions` (builtin/org-scoped gate contracts)
    - `public.agent_gate_bindings` (agent-level gate composition)
  - seeds builtin definitions:
    - `calibration_freshness`
    - `golden_set_quality`
  - adds indexes, RLS policies, and `updated_at` triggers
- Added gate contract APIs:
  - `GET /api/gate-definitions`
  - `POST /api/gate-definitions`
  - `GET /api/agents/{agent_id}/gate-bindings`
  - `POST /api/agents/{agent_id}/gate-bindings`
- Added runtime enforcement bridge:
  - `_get_agent_gate_bindings(...)`
  - `_enforce_configured_gates(...)`
  - run start/execute now enforce DB-configured gate bindings in addition to existing policy flags
- Contract/test/docs updates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh` (step 29)
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`

### Step 122: Streamlit Gate Contract Management UI
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py` with a new `11) Gate Contracts` section:
  - Load gate definitions (`GET /api/gate-definitions`)
  - Create org-scoped gate definition (`POST /api/gate-definitions`)
  - Load agent gate bindings (`GET /api/agents/{agent_id}/gate-bindings`)
  - Upsert agent gate binding (`POST /api/agents/{agent_id}/gate-bindings`)
- Added session activity logging for gate create/binding actions to keep operational trace visibility in UI.

### Step 123: Evaluator Registry + Agent Evaluator Bindings (Platform Extension Surface)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260225030000_tier34_evaluator_registry_and_bindings.sql`
  - creates:
    - `public.evaluator_definitions` (builtin/org-scoped evaluator contracts)
    - `public.agent_evaluator_bindings` (agent-level evaluator composition by `evaluation_mode`)
  - seeds builtin evaluator definitions for `answer` and `criteria` deterministic judge service
  - adds indexes, RLS policies, and `updated_at` triggers
- Added evaluator contract APIs:
  - `GET /api/evaluator-definitions`
  - `POST /api/evaluator-definitions`
  - `GET /api/agents/{agent_id}/evaluator-bindings`
  - `POST /api/agents/{agent_id}/evaluator-bindings`
- Added runtime evaluator-binding bridge:
  - `_get_agent_evaluator_bindings(...)`
  - `_resolve_judge_config_for_eval_mode(...)`
  - `execute_eval_run` now resolves judge mode/model/prompt by case evaluation mode from binding config with run-config override precedence
- Contract/test/docs updates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh` (step 30)
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`

### Step 124: Streamlit Evaluator Contract Management UI
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py` under `11) Gate Contracts` with an **Evaluator Contracts** subsection:
  - Load evaluator definitions (`GET /api/evaluator-definitions`)
  - Create org-scoped evaluator definition (`POST /api/evaluator-definitions`)
  - Load agent evaluator bindings (`GET /api/agents/{agent_id}/evaluator-bindings`)
  - Upsert agent evaluator binding (`POST /api/agents/{agent_id}/evaluator-bindings`)
- Added session activity logging for evaluator create/binding actions.

### Step 125: Run Type Registry + Agent Run Type Bindings (Platform Extension Surface)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260225040000_tier35_run_type_registry_and_bindings.sql`
  - creates:
    - `public.run_type_definitions` (builtin/org-scoped run handler contracts by run_type)
    - `public.agent_run_type_bindings` (agent-level run type composition)
  - seeds builtin definitions for all current run types (`eval`, `regression`, `ab_comparison`, `calibration`)
  - adds indexes, RLS policies, and `updated_at` triggers
- Added run type contract APIs:
  - `GET /api/run-type-definitions`
  - `POST /api/run-type-definitions`
  - `GET /api/agents/{agent_id}/run-type-bindings`
  - `POST /api/agents/{agent_id}/run-type-bindings`
- Added runtime run-handler bridge:
  - `_get_agent_run_type_bindings(...)`
  - `_resolve_run_type_handler(...)`
  - `_enforce_run_type_handler_mode(...)`
  - `start_eval_run` and `execute_eval_run` now enforce handler mode contracts (`default|sync_only|async_only`) before queue/execute path selection
- Contract/test/docs updates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh` (step 31)
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`

### Step 126: Streamlit Run Type Contract Management UI
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py` under `11) Gate Contracts` with a **Run Type Contracts** subsection:
  - Load run type definitions (`GET /api/run-type-definitions`)
  - Create org-scoped run type definition (`POST /api/run-type-definitions`)
  - Load agent run type bindings (`GET /api/agents/{agent_id}/run-type-bindings`)
  - Upsert agent run type binding (`POST /api/agents/{agent_id}/run-type-bindings`)
- Added session activity logging for run type definition/binding actions.

### Step 127: Agent Contract Preflight Validation (Runtime + API)
- Added runtime contract preflight helpers in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `_compute_agent_contract_issues(...)`
  - `_enforce_agent_contract_issues(...)`
- Added endpoint:
  - `GET /api/agents/{agent_id}/contract-status`
  - returns pass/fail and detailed issues across run handler mode, gate bindings, and evaluator bindings for a selected run context
- Enforced preflight contract validation before run dispatch:
  - `POST /api/eval/runs/{run_id}/start`
  - `POST /api/eval/runs/{run_id}/execute`
  - failures return `AGENT_CONTRACT_VALIDATION_FAILED`
- Contract/test/docs updates:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh` (step 32)
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/ci-quality-gate.md`

### Step 128: Streamlit Contract Preflight UI
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py` under `11) Gate Contracts` with a **Contract Preflight** panel:
  - run contract status check via `GET /api/agents/{agent_id}/contract-status`
  - choose `run_type` + `entrypoint` and optional `golden_set_id`
  - renders status metrics, issues table, and raw preflight payload
- Added activity log event for preflight actions to preserve operator trace context.

### Step 129: Contract Versioning + Compatibility Checks
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260225050000_tier36_contract_versioning_and_compatibility.sql`
  - adds `contract_version` (semver) to:
    - `public.gate_definitions`
    - `public.evaluator_definitions`
    - `public.run_type_definitions`
  - adds binding snapshot field `definition_contract_version` (semver) to:
    - `public.agent_gate_bindings`
    - `public.agent_evaluator_bindings`
    - `public.agent_run_type_bindings`
  - backfills existing bindings from current definition versions.
- Extended contract models and APIs in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - definition list/create endpoints now accept/return `contract_version`
  - binding list/upsert endpoints now return and persist `definition_contract_version`
- Added semantic compatibility enforcement in contract preflight:
  - invalid semver in bound/current versions -> `error`
  - major version mismatch -> `error`
  - non-major drift (same major, different minor/patch) -> `warning`
- Validation:
  - `PYTHONPATH=. pytest -q tests/test_openapi_contract.py tests/test_api_contract_errors.py`
  - `PYTHONPATH=. pytest -q`

### Step 130: Streamlit Versioned Contract Controls
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py` under `11) Gate Contracts`:
  - definition tables now include `contract_version`
  - binding tables now include `definition_contract_version`
  - create-definition forms now include contract version input for:
    - gate definitions
    - evaluator definitions
    - run type definitions
- Validation:
  - `python3 -m py_compile /Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py /Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`
  - `PYTHONPATH=. pytest -q tests/test_openapi_contract.py tests/test_api_contract_errors.py`

### Step 131: Contract Upgrade Preview + Rollout APIs
- Added platform contract upgrade endpoints in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `POST /api/contracts/upgrade-preview`
  - `POST /api/contracts/apply-upgrade`
- Capabilities:
  - typed `definition_type` (`gate|evaluator|run_type`) over shared contract primitives
  - semver validation for target versions
  - impact analysis by binding (`none|warning|breaking|invalid`)
  - rollout modes:
    - `definition_only`
    - `sync_bindings`
  - builtin definitions are immutable on apply (`CONTRACT_DEFINITION_IMMUTABLE`)
- Added helper surface:
  - `_get_contract_definition_and_bindings(...)`
  - `_compute_contract_upgrade_preview(...)`
- Test coverage:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`

### Step 132: Streamlit Contract Upgrade Operations UI
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py` under `11) Gate Contracts`:
  - added **Contract Upgrade Workflow** panel
  - supports:
    - preview: `POST /api/contracts/upgrade-preview`
    - apply: `POST /api/contracts/apply-upgrade`
  - supports selecting loaded definitions (gate/evaluator/run_type), target version, rollout mode
  - renders risk metrics (`breaking`, `warning`, `invalid`) and per-binding impact table
  - emits activity feed events for preview/apply actions
- Validation:
  - `python3 -m py_compile /Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py /Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`
  - `PYTHONPATH=. pytest -q`

### Step 133: Contract Drift Monitor (API + UI)
- Added endpoint in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `GET /api/contracts/drift`
- Capabilities:
  - org-wide drift scan over gate/evaluator/run_type bindings
  - optional `agent_id` filter
  - optional `include_healthy` to return `none` drift rows
  - drift classification per binding:
    - `warning` (minor/patch drift)
    - `breaking` (major mismatch)
    - `invalid` (semver parse failure)
  - summary counts (`breaking_count`, `warning_count`, `invalid_count`, `checked_agent_count`)
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py`:
  - new **Contract Drift Monitor** panel in Gate Contracts
  - one-click drift load + metrics + table + activity logging
- Test coverage:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`

### Step 134: Drift-to-Pattern Promotion Workflow
- Added endpoint in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `POST /api/contracts/drift/promote-patterns`
- Capabilities:
  - promotes contract drift findings into issue patterns (`primary_tag=contract_drift`)
  - supports `min_drift` threshold (`warning|breaking|invalid`)
  - supports `dry_run`
  - dedupe-safe reuse based on binding/version tuple:
    - `binding_id`
    - `bound_contract_version`
    - `current_contract_version`
  - emits activity event `contract_drift_promote_patterns`
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py`:
  - added **Promote Drift To Issue Patterns** action in Contract Drift Monitor panel
  - includes min drift selector + dry-run option
  - renders promotion summary/details
- Test coverage:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`

### Step 135: Drift Promotion Notifications
- Enhanced `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `POST /api/contracts/drift/promote-patterns` now dispatches webhook notification event:
    - `contract_drift_patterns_promoted`
  - response now includes `notification` delivery status payload
  - activity metadata now includes notification details for traceability
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py`:
  - Contract Drift Promote action now surfaces notification state (`sent|queued|error`)
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`

### Step 136: Drift Automation Policy + Trigger (Scheduler-Ready)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260225060000_tier37_contract_drift_policies.sql`
  - creates `public.contract_drift_policies` with org-scoped defaults and RLS
- Added admin APIs in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `GET /api/system/contracts/drift-policy`
  - `POST /api/system/contracts/drift-policy`
  - `POST /api/system/contracts/drift/trigger`
- Trigger behavior:
  - policy-driven defaults for `min_drift` + `scan_limit`
  - honors policy switches:
    - `enabled`
    - `promote_to_patterns`
  - window dedupe via audit log (`CONTRACT_DRIFT_TRIGGER_DEDUPED`)
  - idempotent trigger (`Idempotency-Key` required)
  - executes drift promotion pipeline and returns nested promote result
- Test coverage:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_versioning.py`

### Step 137: Drift Automation Admin UI
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py`:
  - added **Contract Drift Automation** admin section
  - supports:
    - load/save drift policy
    - trigger policy run with `Idempotency-Key`
    - displays trigger execution + promote result metrics
  - shifted Activity Feed section to `16)` after new admin controls
- Extended `api_call(...)` helper to support custom headers for idempotent admin triggers.
- OpenAPI contract assertion strengthened:
  - `/api/system/contracts/drift/trigger` must expose required `Idempotency-Key` header.
- Validation:
  - `python3 -m py_compile /Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py /Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py`
  - `PYTHONPATH=. pytest -q`

### Step 138: Drift Trigger Summary + History
- Added admin API in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `GET /api/system/contracts/drift/trigger-summary`
- Provides:
  - aggregate trigger outcomes from audit logs:
    - executed, deduped, policy-disabled, promotion-disabled
  - execution/dedupe rates
  - recent trigger event rows for operational debugging
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py`:
  - Contract Drift Automation section now supports loading trigger summary/history
  - renders KPI row + event table + raw detail panel
- Test coverage:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`

### Step 139: Drift Trigger Alerting (Notify + Delivery)
- Added migration:
  - `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260225070000_tier38_contract_drift_alerts.sql`
  - extends `contract_drift_policies` with alert controls:
    - `alert_enabled`
    - `alert_max_dedupe_hit_rate`
    - `alert_min_execution_rate`
    - `alert_cooldown_minutes`
  - adds cooldown state table:
    - `public.contract_drift_trigger_alert_state`
- Expanded `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `POST /api/system/contracts/drift/trigger-summary/notify`
  - `GET /api/system/contracts/drift/trigger-alert-delivery`
  - shared helper for trigger summary computation, reused by summary + notify
  - policy-driven anomaly checks + cooldown suppression + webhook dispatch
  - explicit notify outcome audit codes for observability
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py`:
  - Contract Drift Automation section now supports:
    - editing alert controls in drift policy
    - notify trigger-summary action (dry-run/force)
    - alert delivery metrics panel
- Updated tests:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
- Updated API docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`

### Step 140: Drift Schedule Orchestration Endpoint
- Added scheduler-oriented API in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - `POST /api/system/contracts/drift/schedule-run`
- This endpoint orchestrates two existing primitives in one idempotent call:
  - drift trigger execution
  - trigger-summary anomaly notify
- Uses policy defaults for:
  - `schedule_name`
  - `schedule_window_minutes`
- Returns both nested outputs:
  - `trigger` (`ContractDriftTriggerData`)
  - `notify` (`ContractDriftTriggerNotifyData`)
- Updated `/Users/seungyoo/Desktop/ai-agent-platform/app/streamlit_app.py`:
  - Contract Drift Automation section now includes **Run Drift Schedule Cycle**.
- Updated tests and OpenAPI contract:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_api_contract_errors.py`
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_openapi_contract.py`
- Updated docs:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/api-v1.md`

### Step 141: Drift Scheduler Ops + Escalation Hardening
- Added scheduler execution script:
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/run_contract_drift_schedule.sh`
  - env-driven runner for `POST /api/system/contracts/drift/schedule-run`
- Added dedicated GitHub Action:
  - `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/contract-drift-schedule.yml`
  - supports cron + manual dispatch
  - boots API/worker and executes drift schedule script
- Added notify-failure escalation in `/Users/seungyoo/Desktop/ai-agent-platform/src/api/main.py`:
  - on non-dry-run notify failure:
    - resolve escalation agent (explicit `agent_id` or fallback active agent in org)
    - create/reuse high-priority issue pattern:
      - `primary_tag=contract_drift_alert_delivery`
- Added runbook:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/contract-drift-scheduler.md`
  - captures env contract, command usage, and failure handling
- Added integration test scaffold:
  - `/Users/seungyoo/Desktop/ai-agent-platform/tests/test_contract_drift_schedule_integration.py`
  - opt-in via `RUN_DB_INTEGRATION=1`

### Step 142: Light API UAT Runner
- Added one-command light testing script:
  - `/Users/seungyoo/Desktop/ai-agent-platform/scripts/light_api_uat.sh`
- Covers dev-style end-to-end API path:
  - golden-set upload
  - eval run create + execute
  - summary/results assertions
  - optional contract-drift schedule dry-run
- Added quick guide:
  - `/Users/seungyoo/Desktop/ai-agent-platform/docs/light-testing.md`
