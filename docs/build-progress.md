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
