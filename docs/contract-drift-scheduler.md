# Contract Drift Scheduler Runbook

This runbook defines the operational contract for automated contract drift schedule runs.

## Endpoint

- `POST /api/system/contracts/drift/schedule-run`
- Requires header: `Idempotency-Key`
- Auth: admin API key

## Required Environment

- `SUPABASE_DB_URL`
- `BASE_URL`
- `API_KEY` (admin scope)
- `ORG_ID`

## GitHub Actions Secrets Checklist

For `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/contract-drift-schedule.yml`, set:

- `SUPABASE_DB_URL`
- `SMOKE_ADMIN_API_KEY`
- `SMOKE_ORG_ID`
- `SMOKE_AGENT_ID`

Optional:

- `OPENAI_API_KEY` (only if schedule-run path executes provider-judge evals)

## Optional Environment

- `API_PREFIX` (default `/api`)
- `SCHEDULE_NAME` (default `daily`)
- `WINDOW_MINUTES` (default `1440`)
- `SUMMARY_WINDOW_DAYS` (default `30`)
- `DRY_RUN` (`true|false`, default `false`)
- `FORCE` (`true|false`, default `false`)
- `FORCE_NOTIFY` (`true|false`, default `false`)
- `AGENT_ID` (optional)
- `MIN_DRIFT` (`warning|breaking|invalid`, optional)
- `LIMIT` (optional)

## Operational Flow

1. Trigger drift promotion workflow.
2. Evaluate trigger-summary anomaly against policy thresholds.
3. Send anomaly notification (subject to cooldown and policy).
4. If notification send fails on non-dry run, auto-create/reuse high-priority issue pattern.

## Signals to Watch

- Trigger result:
  - `data.trigger.executed`
  - `data.trigger.deduped`
- Notify result:
  - `data.notify.anomaly_detected`
  - `data.notify.notified`
  - `data.notify.notification.sent`
- Escalation:
  - `data.notify.escalation_pattern`

## Manual Command

```bash
BASE_URL=http://127.0.0.1:8001 \
API_PREFIX=/api/v1 \
API_KEY=dev_plain_key_001 \
ORG_ID=<ORG_ID> \
AGENT_ID=<AGENT_ID> \
./scripts/run_contract_drift_schedule.sh
```

## Failure Handling

- If API call fails: inspect API logs (`uvicorn.log`) and DB connectivity.
- If notify send fails:
  - check webhook settings
  - inspect notification outbox/dead-letter endpoints
  - inspect `issue_patterns` for `primary_tag=contract_drift_alert_delivery`
- If repeated suppression:
  - inspect cooldown state table `contract_drift_trigger_alert_state`
  - verify alert thresholds and anomaly fingerprint changes.

## Integration Test Timing

Recommended cadence:

1. Per PR: run fast unit/contract suite (`pytest -q`).
2. Before merge to `main`: run opt-in DB integration tests once.
3. Nightly or scheduled CI: run DB integration tests against non-prod Supabase project.

Run integration tests manually:

```bash
RUN_DB_INTEGRATION=1 PYTHONPATH=. pytest -q tests/test_contract_drift_schedule_integration.py
```
