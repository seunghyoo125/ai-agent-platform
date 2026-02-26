# SDK Usage Guide

This guide covers Python and TypeScript SDK usage for:
- retries/backoff
- per-request overrides
- structured error handling
- logging hooks

## Quickstart (5 min)

### 1) Start API locally

```bash
set -a; source /Users/seungyoo/Desktop/ai-agent-platform/.env; set +a
uvicorn src.api.main:app --reload --port 8001
```

### 2) Regenerate SDK from current OpenAPI

```bash
PYTHONPATH=. /Users/seungyoo/Desktop/ai-agent-platform/scripts/generate_clients.py
```

### 3) First successful call (Python)

```bash
python3 - <<'PY'
from sdk.python.greenlight_client import GreenlightClient

client = GreenlightClient("http://127.0.0.1:8001", "dev_plain_key_001")
resp = client.get_agents(params={"org_id": "23cdb862-a12f-4b6c-84ee-5cb648f9b5bb"})
print(resp.get("ok"), resp.get("data", {}).get("count"))
PY
```

### 4) First successful call (TypeScript)

```ts
import { GreenlightClient } from "../../sdk/typescript/greenlightClient";

const client = new GreenlightClient("http://127.0.0.1:8001", "dev_plain_key_001");
const resp = await client.get_agents({
  query: { org_id: "23cdb862-a12f-4b6c-84ee-5cb648f9b5bb" },
});
console.log(resp.ok, resp.data?.count);
```

## Python

```python
from sdk.python.greenlight_client import GreenlightApiError, GreenlightClient

def log_event(event: dict) -> None:
    print(event)

client = GreenlightClient(
    base_url="http://127.0.0.1:8001",
    api_key="dev_plain_key_001",
    timeout=30,
    max_retries=3,
    backoff_base_seconds=0.25,
    logger=log_event,
)

try:
    agents = client.get_agents_all(page_size=100)
    print(f"loaded={len(agents)}")

    run = client.post_eval_runs(
        body={
            "org_id": "23cdb862-a12f-4b6c-84ee-5cb648f9b5bb",
            "agent_id": "e3660b25-47cf-47f3-ab53-c080fb7ffdcc",
            "golden_set_id": "6755aac9-2d1e-46bd-8962-5731dbe4b6b5",
            "name": "sdk-run-001",
            "type": "eval",
            "config": {"sample_size": "all"},
            "design_context": {"reason": "sdk usage test"},
        },
        timeout=10,
        max_retries=1,
        backoff_base_seconds=0.1,
    )
    print(run["data"]["run_id"])

    # Template-driven run creation
    templated_run = client.post_eval_runs(
        body={
            "org_id": "23cdb862-a12f-4b6c-84ee-5cb648f9b5bb",
            "agent_id": "e3660b25-47cf-47f3-ab53-c080fb7ffdcc",
            "template_id": "11111111-1111-1111-1111-111111111111",
            "name": "sdk-templated-run-001",
            "type": "eval",
            "config": {"judge_mode": "deterministic"},
            "design_context": {"reason": "templated run"},
        }
    )
    print(templated_run["data"]["run_id"])
except GreenlightApiError as e:
    print(
        "api error",
        {
            "status_code": e.status_code,
            "code": e.code,
            "message": e.message,
            "request_id": e.request_id,
            "details": e.details,
        },
    )
```

## TypeScript

```ts
import {
  GreenlightApiError,
  GreenlightClient,
  type RequestLogEvent,
} from "../../sdk/typescript/greenlightClient";

const logger = (event: RequestLogEvent) => {
  console.log(event);
};

const client = new GreenlightClient(
  "http://127.0.0.1:8001",
  "dev_plain_key_001",
  3,      // maxRetries
  250,    // backoffBaseMs
  30000,  // timeoutMs
  logger,
);

async function main() {
  try {
    const agents = await client.get_agents_all({ pageSize: 100 });
    console.log(`loaded=${agents.length}`);

    const run = await client.post_eval_runs({
      body: {
        org_id: "23cdb862-a12f-4b6c-84ee-5cb648f9b5bb",
        agent_id: "e3660b25-47cf-47f3-ab53-c080fb7ffdcc",
        golden_set_id: "6755aac9-2d1e-46bd-8962-5731dbe4b6b5",
        name: "sdk-run-001",
        type: "eval",
        config: { sample_size: "all" },
        design_context: { reason: "sdk usage test" },
      },
      requestOptions: {
        timeoutMs: 10000,
        maxRetries: 1,
        backoffBaseMs: 100,
      },
    });
    console.log(run.data?.run_id);

    const templatedRun = await client.post_eval_runs({
      body: {
        org_id: "23cdb862-a12f-4b6c-84ee-5cb648f9b5bb",
        agent_id: "e3660b25-47cf-47f3-ab53-c080fb7ffdcc",
        template_id: "11111111-1111-1111-1111-111111111111",
        name: "sdk-templated-run-001",
        type: "eval",
        config: { judge_mode: "deterministic" },
        design_context: { reason: "templated run" },
      },
    });
    console.log(templatedRun.data?.run_id);
  } catch (e) {
    if (e instanceof GreenlightApiError) {
      console.error({
        statusCode: e.statusCode,
        code: e.code,
        message: e.message,
        requestId: e.requestId,
        details: e.details,
      });
      return;
    }
    throw e;
  }
}

main();
```

## Promotion Safety Example

After a clean compare, promotion can be enforced via API:

```bash
curl -s -X POST "http://127.0.0.1:8001/api/v1/agents/<AGENT_ID>/run-registry/promote-candidate" \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "baseline_run_id":"<BASELINE_RUN_ID>",
    "candidate_run_id":"<CANDIDATE_RUN_ID>",
    "baseline_name":"default",
    "require_clean_compare":true,
    "clean_compare_window_minutes":120
  }' | jq
```

## Log Event Shape

`RequestLogEvent` fields:
- `event`: `http_request | http_error | network_error`
- `method`
- `path`
- `statusCode` (optional)
- `durationMs`
- `attempt`
- `requestId` (optional)
- `errorCode` (optional)
- `hasBody`
- `queryKeys`
