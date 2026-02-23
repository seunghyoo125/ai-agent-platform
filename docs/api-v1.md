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

Server env:

- `DATABASE_URL` or `SUPABASE_DB_URL`

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
  "expires_at": null
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
  "golden_set_id": "uuid-or-null",
  "name": "baseline run",
  "type": "eval",
  "config": {},
  "design_context": {}
}
```

## POST `/api/eval/runs/{run_id}/execute`

Executes a pending eval run synchronously (deterministic baseline runner).

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

Errors:
- `EVAL_RUN_NO_GOLDEN_SET` if run has no attached golden set.
- `EVAL_RUN_ALREADY_RUNNING` if run is currently running.

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

Note:
- XLSX ingestion is planned as a separate upload/parse endpoint. Current endpoint expects canonical JSON payloads.

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
